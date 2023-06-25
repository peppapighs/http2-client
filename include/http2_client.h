#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/url.hpp>

#include <nghttp2/nghttp2.h>

#include <openssl/ssl.h>

#include <map>
#include <optional>

namespace http2_client {
using namespace boost::asio;

using header_map = std::multimap<std::string, std::string>;
using body_generator =
    std::function<std::size_t(uint8_t *buf, std::size_t len, bool &eof)>;

struct response {
  int32_t status;
  header_map headers;
  std::string body;
};

class session;

class client {
public:
  client(io_context &io_context, ssl::context &tls_context,
         const std::string &host, const std::string &port);
  client(io_context &io_context, const std::string &host,
         const std::string &port);

  client();
  ~client();

  awaitable<void> connect();
  awaitable<void> close();
  awaitable<std::optional<response>> request(const std::string &method,
                                             const std::string &path,
                                             body_generator body = nullptr,
                                             const header_map &headers = {});

private:
  std::shared_ptr<session> session_;
};

ssl::context create_context(ssl::context::method method,
                            bool verify_peer = true);
} // namespace http2_client