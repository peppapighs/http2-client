#pragma once

#include "http2_client.h"

#include <sstream>

namespace http2_client {
using namespace boost::asio;

class session {
public:
  session(io_context &io_context, ssl::context &tls_context,
          const std::string &host, const std::string &port,
          const std::string &scheme);
  ~session();

  awaitable<void> connect();
  awaitable<void> handle_deadline();
  awaitable<void> handle_read();
  awaitable<void> handle_write();
  awaitable<void> close();
  awaitable<std::optional<response>> request(const std::string &method,
                                             const std::string &path,
                                             body_generator body,
                                             header_map headers);

  void terminate();
  steady_timer &response_timer();
  int32_t &stream_id();
  header_map &headers();
  std::stringstream &body_stream();
  body_generator &body();
  response build_response() const;
  bool setup_session();
  bool should_terminate() const;

  virtual awaitable<void>
  create_connection(ip::tcp::resolver::results_type endpoints) = 0;
  virtual awaitable<std::size_t> read_socket() = 0;
  virtual awaitable<void> write_socket() = 0;

  virtual ip::tcp::socket &socket() = 0;
  virtual void shutdown_socket() = 0;

protected:
  std::array<uint8_t, 16 * 1024> read_buffer_;
  std::array<uint8_t, 64 * 1024> write_buffer_;
  std::size_t write_buffer_offset_ = 0;

private:
  const std::string host_;
  const std::string port_;
  const std::string scheme_;

  ip::tcp::resolver resolver_;

  steady_timer deadline_timer_;
  std::chrono::seconds timeout_;

  const uint8_t *data_ptr_ = nullptr;
  std::size_t data_len_ = 0;

  nghttp2_session *session_ = nullptr;

  steady_timer response_timer_;
  int32_t stream_id_ = -1;
  header_map headers_;
  std::stringstream body_stream_;
  body_generator body_ = nullptr;

  bool is_terminated_ = false;
  bool is_writing_ = false;
  bool is_mem_op_blocked_ = false;
};
} // namespace http2_client