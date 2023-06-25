#pragma once

#include "session.h"

namespace http2_client {
class session_tls : public session {
public:
  session_tls(io_context &io_context, ssl::context &tls_context,
              const std::string &host, const std::string &port);
  ~session_tls();

  awaitable<void>
  create_connection(ip::tcp::resolver::results_type endpoints) override;
  awaitable<std::size_t> read_socket() override;
  awaitable<void> write_socket() override;

  ip::tcp::socket &socket() override;
  void shutdown_socket() override;

private:
  ssl::stream<ip::tcp::socket> socket_;
};
} // namespace http2_client