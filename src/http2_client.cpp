#include "http2_client.h"

#include "session_tcp.h"
#include "session_tls.h"
#include "util.h"

#include <cstdlib>
#include <fstream>
#include <iostream>

namespace http2_client {
client::client(io_context &io_context, ssl::context &tls_context,
               const std::string &host, const std::string &port)
    : session_(
          std::make_shared<session_tls>(io_context, tls_context, host, port)) {}

client::client(io_context &io_context, const std::string &host,
               const std::string &port)
    : session_(std::make_shared<session_tcp>(io_context, host, port)) {}

client::client() : session_(nullptr) {}
client::~client() {}

awaitable<void> client::connect() { co_await session_->connect(); }

awaitable<void> client::close() { co_await session_->close(); }

awaitable<std::optional<response>> client::request(const std::string &method,
                                                   const std::string &path,
                                                   body_generator body,
                                                   const header_map &headers) {
  co_return co_await session_->request(method, path, body, headers);
}

namespace {
std::ofstream keylog_file;
}

ssl::context create_context(ssl::context::method method, bool verify_peer) {
  auto tls_context = ssl::context(method);
  tls_context.set_default_verify_paths();
  if (verify_peer)
    tls_context.set_verify_mode(ssl::verify_peer);

  auto context = tls_context.native_handle();

#ifndef OPENSSL_NO_NEXTPROTONEG
  SSL_CTX_set_next_proto_select_cb(
      context,
      [](auto ssl, auto out, auto outlen, auto in, auto inlen, auto arg) {
        if (select_protocol(out, outlen, in, inlen))
          return SSL_TLSEXT_ERR_OK;
        return SSL_TLSEXT_ERR_NOACK;
      },
      nullptr);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  auto proto_list = make_alpn_string();
  SSL_CTX_set_alpn_protos(context, proto_list.data(), proto_list.size());
#endif

  auto keylog_filename = std::getenv("SSLKEYLOGFILE");
  if (keylog_filename) {
    keylog_file.open(keylog_filename, std::ios_base::app);
    if (keylog_file.is_open())
      SSL_CTX_set_keylog_callback(context, [](auto ssl, auto line) {
        keylog_file << line << std::endl;
      });
  }

  return tls_context;
}
} // namespace http2_client