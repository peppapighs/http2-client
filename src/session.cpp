#include "session.h"

#include "util.h"
#include "scope_guard.h"

#include <chrono>
#include <iostream>

namespace http2_client {
session::session(io_context &io_context, const std::string &host,
                 const std::string &port, const std::string &scheme)
    : host_(host), port_(port), scheme_(scheme), resolver_(io_context),
      deadline_timer_(io_context), timeout_(30), response_timer_(io_context) {}

session::~session() {}

awaitable<void> session::connect() {
  auto executor = co_await this_coro::executor;

  try {
    deadline_timer_.expires_after(timeout_);
    co_spawn(executor, handle_deadline(), detached);

    auto endpoints =
        co_await resolver_.async_resolve(host_, port_, use_awaitable);

    co_await create_connection(endpoints);

    if (!setup_session())
      co_return;

    socket().set_option(ip::tcp::no_delay(true));

    co_await handle_write();
    co_spawn(executor, handle_read(), detached);
  } catch (const std::exception &e) {
    std::cerr << "[connect] " << e.what() << std::endl;
    terminate();
  }
}

awaitable<void> session::handle_deadline() {
  while (!is_terminated_) {
    co_await deadline_timer_.async_wait(use_awaitable);
    if (deadline_timer_.expiry() <= std::chrono::steady_clock::now()) {
      std::cerr << "[handle_timeout] timeout" << std::endl;
      deadline_timer_.expires_at(
          std::chrono::time_point<std::chrono::steady_clock>::max());
      terminate();
      co_return;
    }
  }
}

awaitable<void> session::handle_read() {
  try {
    while (!is_terminated_) {
      deadline_timer_.expires_after(timeout_);

      auto bytes_transferred = co_await read_socket();

      {
        is_mem_op_blocked_ = true;
        auto guard = scope_guard([this] { is_mem_op_blocked_ = false; });

        auto rv = nghttp2_session_mem_recv(session_, read_buffer_.data(),
                                           bytes_transferred);
        if (rv != static_cast<ssize_t>(bytes_transferred)) {
          std::cerr << "[handle_read] " << nghttp2_strerror(rv) << std::endl;
          terminate();
          co_return;
        }
      }

      co_await handle_write();

      if (should_terminate()) {
        terminate();
        co_return;
      }
    }
  } catch (const std::exception &e) {
    if (!should_terminate())
      std::cerr << "[handle_read] " << e.what() << std::endl;
    terminate();
  }
}

awaitable<void> session::handle_write() {
  while (!is_terminated_ && !is_writing_ && !is_mem_op_blocked_) {
    if (data_ptr_) {
      std::copy_n(data_ptr_, data_len_,
                  write_buffer_.begin() + write_buffer_offset_);
      write_buffer_offset_ += data_len_;
      data_ptr_ = nullptr;
      data_len_ = 0;
    }

    {
      is_mem_op_blocked_ = true;
      auto guard = scope_guard([this] { is_mem_op_blocked_ = false; });

      while (true) {
        const uint8_t *data_ptr;
        auto data_len = nghttp2_session_mem_send(session_, &data_ptr);
        if (data_len < 0) {
          std::cerr << "[handle_write] " << nghttp2_strerror(data_len)
                    << std::endl;
          terminate();
          co_return;
        }

        if (data_len == 0)
          break;

        if (write_buffer_offset_ + data_len > write_buffer_.size()) {
          data_ptr_ = data_ptr;
          data_len_ = data_len;
          break;
        }

        std::copy_n(data_ptr, data_len,
                    write_buffer_.begin() + write_buffer_offset_);
        write_buffer_offset_ += data_len;
      }
    }

    if (write_buffer_offset_ == 0) {
      if (should_terminate())
        terminate();
      co_return;
    }

    is_writing_ = true;
    deadline_timer_.expires_after(timeout_);
    co_await write_socket();

    is_writing_ = false;
    write_buffer_offset_ = 0;
  }
}

void session::terminate() {
  if (is_terminated_)
    return;

  is_terminated_ = true;
  deadline_timer_.cancel();
  response_timer_.cancel();

  shutdown_socket();
}

awaitable<void> session::close() {
  if (is_terminated_)
    co_return;

  nghttp2_session_terminate_session(session_, NGHTTP2_NO_ERROR);
  co_await handle_write();
}

awaitable<std::optional<response>> session::request(const std::string &method,
                                                    const std::string &path,
                                                    body_generator body,
                                                    header_map headers) {
  auto uri = boost::urls::parse_origin_form(path);
  if (!uri) {
    std::cerr << "[request] invalid path: " << path << std::endl;
    co_return std::nullopt;
  }

  std::vector<nghttp2_nv> nva;
  nva.reserve(headers.size() + 4);
  nva.push_back(name_value(":method", method));
  nva.push_back(name_value(":scheme", scheme_));
  nva.push_back(name_value(":authority", host_));
  nva.push_back(name_value(":path", path));
  for (auto &header : headers)
    nva.push_back(name_value(header.first, header.second));

  nghttp2_data_provider *provider_ptr = nullptr;
  nghttp2_data_provider provider;

  if (body) {
    body_ = std::move(body);
    provider.read_callback =
        [](nghttp2_session *_, int32_t stream_id, uint8_t *buf, size_t length,
           uint32_t *data_flags, nghttp2_data_source *source, void *user_data) {
          auto http_session = static_cast<session *>(user_data);
          bool eof = false;
          auto n = http_session->body()(buf, length, eof);
          if (eof)
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
          return static_cast<ssize_t>(n);
        };
    provider_ptr = &provider;
  }

  auto stream_id = nghttp2_submit_request(session_, nullptr, nva.data(),
                                          nva.size(), provider_ptr, this);
  if (stream_id < 0) {
    std::cerr << "[request] " << nghttp2_strerror(stream_id) << std::endl;
    co_return std::nullopt;
  }

  stream_id_ = stream_id;
  response_timer_.expires_at(
      std::chrono::time_point<std::chrono::steady_clock>::max());

  co_await handle_write();

  try {
    co_await response_timer_.async_wait(use_awaitable);
  } catch (const boost::system::system_error &error) {
    if (error.code() != boost::asio::error::operation_aborted) {
      std::cerr << "[request] " << error.what() << std::endl;
      co_return std::nullopt;
    }
  }

  auto res = build_response();

  headers.clear();
  body_stream_.clear();
  body_ = nullptr;

  co_return res;
}

steady_timer &session::response_timer() { return response_timer_; }

int32_t &session::stream_id() { return stream_id_; }

header_map &session::headers() { return headers_; }

std::stringstream &session::body_stream() { return body_stream_; }

body_generator &session::body() { return body_; }

response session::build_response() const {
  response res;
  for (auto &header : headers_) {
    if (header.first == ":status") {
      res.status_ = std::stoi(header.second);
      continue;
    }
    res.headers_.emplace(std::move(header));
  }
  res.body_ = body_stream_.str();

  return res;
}

namespace {
int on_header_callback(nghttp2_session *_, const nghttp2_frame *frame,
                       const uint8_t *name, size_t namelen,
                       const uint8_t *value, size_t valuelen, uint8_t flags,
                       void *user_data) {
  auto http_session = static_cast<session *>(user_data);
  if (frame->hd.stream_id != http_session->stream_id())
    return 0;

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat != NGHTTP2_HCAT_RESPONSE)
      break;

    std::string header_name(reinterpret_cast<const char *>(name), namelen);
    for (auto &c : header_name)
      c = std::tolower(c);

    http_session->headers().emplace(
        std::move(header_name),
        std::string(reinterpret_cast<const char *>(value), valuelen));
    break;
  }

  return 0;
}
} // namespace

namespace {
int on_data_chunk_recv_callback(nghttp2_session *_, uint8_t flags,
                                int32_t stream_id, const uint8_t *data,
                                size_t len, void *user_data) {
  auto http_session = static_cast<session *>(user_data);
  if (stream_id != http_session->stream_id())
    return 0;

  http_session->body_stream().write(reinterpret_cast<const char *>(data), len);

  return 0;
}
} // namespace

namespace {
int on_stream_close_callback(nghttp2_session *_, int32_t stream_id,
                             uint32_t error_code, void *user_data) {
  auto http_session = static_cast<session *>(user_data);
  if (stream_id != http_session->stream_id())
    return 0;

  http_session->stream_id() = -1;
  http_session->response_timer().cancel();

  return 0;
}
} // namespace

bool session::setup_session() {
  nghttp2_session_callbacks *callbacks;
  nghttp2_session_callbacks_new(&callbacks);

  auto guard =
      scope_guard([callbacks]() { nghttp2_session_callbacks_del(callbacks); });

  nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                   on_header_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      callbacks, on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(
      callbacks, on_stream_close_callback);

  auto rv = nghttp2_session_client_new(&session_, callbacks, this);
  if (rv != 0) {
    std::cerr << "[setup_session] " << nghttp2_strerror(rv) << std::endl;
    return false;
  }

  const uint32_t window_size = 256 * 1024 * 1024;

  std::array<nghttp2_settings_entry, 2> iv{
      {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
       {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, window_size}}};
  nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, iv.data(), iv.size());
  nghttp2_session_set_local_window_size(session_, NGHTTP2_FLAG_NONE, 0,
                                        window_size);

  return true;
}

bool session::should_terminate() const {
  return !is_writing_ && !nghttp2_session_want_read(session_) &&
         !nghttp2_session_want_write(session_);
}
} // namespace http2_client