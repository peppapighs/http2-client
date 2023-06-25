#include "http2_client.h"

#include <iostream>

using namespace boost::asio;

awaitable<void> run(http2_client::client &client) {
  co_await client.connect();

  auto res = co_await client.request("GET", "/", nullptr, {});
  if (res) {
    std::cout << "status: " << res->status_ << std::endl;
    for (auto &[key, value] : res->headers_)
      std::cout << key << ": " << value << std::endl;
    std::cout << std::endl;
    std::cout << res->body_ << std::endl;
  }

  co_await client.close();
}

int main(int argc, char *argv[]) {
  io_context io_context;

  auto tls_context =
      http2_client::create_context(ssl::context::tlsv12_client, false);
  auto client =
      http2_client::client(io_context, tls_context, "https://nghttp2.org");

  co_spawn(io_context, run(client), detached);
  io_context.run();
}