#include "session_tls.h"

#include "util.h"

#include <iostream>

namespace http2_client {
const std::string session_tls::scheme = "https";

session_tls::session_tls(io_context &io_context, ssl::context &tls_context,
                         const std::string &host, const std::string &port)
    : session(io_context, host, port, scheme),
      socket_(io_context, tls_context) {
  socket_.set_verify_callback(ssl::host_name_verification(host));

  auto uri = boost::urls::parse_uri_reference(host);
  if (!uri)
    throw std::runtime_error("[session_tls] invalid host");
  if (uri->host_type() == boost::urls::host_type::name)
    SSL_set_tlsext_host_name(socket_.native_handle(), host.c_str());
}

session_tls::~session_tls() {}

awaitable<void>
session_tls::create_connection(ip::tcp::resolver::results_type endpoints) {
  co_await boost::asio::async_connect(socket(), endpoints, use_awaitable);
  co_await socket_.async_handshake(ssl::stream_base::client, use_awaitable);

  if (!is_http2_negotiated(socket_))
    throw std::runtime_error("[create_connection] http2 not negotiated");
}

awaitable<std::size_t> session_tls::read_socket() {
  co_return co_await socket_.async_read_some(buffer(read_buffer_),
                                             use_awaitable);
}

awaitable<void> session_tls::write_socket() {
  co_await boost::asio::async_write(
      socket_, buffer(write_buffer_, write_buffer_offset_), use_awaitable);
}

ip::tcp::socket &session_tls::socket() { return socket_.next_layer(); }

void session_tls::shutdown_socket() {
  socket_.shutdown();
  socket_.lowest_layer().close();
}
} // namespace http2_client