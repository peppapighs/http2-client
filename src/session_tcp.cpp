#include "session_tcp.h"

namespace http2_client {
const std::string session_tcp::scheme = "http";
const std::string session_tcp::default_port = "80";

session_tcp::session_tcp(io_context &io_context, const std::string &host,
                         const std::string &port)
    : session(io_context, host, port, scheme), socket_(io_context) {}

session_tcp::~session_tcp() {}

awaitable<void>
session_tcp::create_connection(ip::tcp::resolver::results_type endpoints) {
  co_await boost::asio::async_connect(socket(), endpoints, use_awaitable);
}

awaitable<std::size_t> session_tcp::read_socket() {
  co_return co_await socket_.async_read_some(buffer(read_buffer_),
                                             use_awaitable);
}

awaitable<void> session_tcp::write_socket() {
  co_await boost::asio::async_write(
      socket_, buffer(write_buffer_, write_buffer_offset_), use_awaitable);
}

ip::tcp::socket &session_tcp::socket() { return socket_; }

void session_tcp::shutdown_socket() { socket_.lowest_layer().close(); }
} // namespace http2_client