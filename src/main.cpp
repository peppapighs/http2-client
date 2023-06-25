#include "http2_client.h"

#include <boost/program_options.hpp>

#include <fstream>
#include <iostream>

namespace po = boost::program_options;
using namespace boost::asio;

void required_option(const po::variables_map &vm, const char *opt) {
  if (!vm.count(opt))
    throw std::logic_error(std::string("option '") + opt + "' is required.");
}

void conflicting_options(const po::variables_map &vm, const char *opt1,
                         const char *opt2) {
  if (vm.count(opt1) && !vm[opt1].defaulted() && vm.count(opt2) &&
      !vm[opt2].defaulted())
    throw std::logic_error(std::string("conflicting options '") + opt1 +
                           "' and '" + opt2 + "'.");
}

void option_dependency(const po::variables_map &vm, const char *for_what,
                       const char *required_option) {
  if (vm.count(for_what) && !vm[for_what].defaulted())
    if (vm.count(required_option) == 0 || vm[required_option].defaulted())
      throw std::logic_error(std::string("option '") + for_what +
                             "' requires option '" + required_option + "'.");
}

http2_client::body_generator make_string_body(const std::string &data) {
  auto data_buffer =
      std::make_shared<std::pair<const std::string &, std::size_t>>(
          std::move(data), 0);

  return [data_buffer](uint8_t *buf, std::size_t len, bool &eof) {
    auto &[data, offset] = *data_buffer;
    auto n = std::min(len, data.size() - offset);
    std::copy_n(data.data() + offset, n, buf);
    offset += n;
    if (offset == data.size()) {
      eof = true;
      offset = 0;
    }
    return n;
  };
}

http2_client::body_generator make_file_body(const std::string &path) {
  auto data_buffer = std::make_shared<std::ifstream>(path, std::ios::binary);
  if (!*data_buffer)
    throw std::runtime_error("[http2-client] failed to open file: " + path);

  return [data_buffer](uint8_t *buf, std::size_t len, bool &eof) {
    auto &data = *data_buffer;
    data.read(reinterpret_cast<char *>(buf), len);
    auto n = data.gcount();
    if (n < len) {
      eof = true;
      data.clear();
      data.seekg(0);
    }
    return n;
  };
}

std::string trim(const std::string &s) {
  auto first = s.find_first_not_of(" \t\r\n");
  if (first == std::string::npos)
    return "";
  auto last = s.find_last_not_of(" \t\r\n");
  return s.substr(first, last - first + 1);
}

awaitable<void> run(http2_client::client &client, const std::string &method,
                    const std::string &path, http2_client::body_generator body,
                    const http2_client::header_map &headers, int iterations,
                    bool verbose) {
  co_await client.connect();

  for (int i = 0; i < iterations; i++) {
    auto response = co_await client.request(method, path, body, headers);
    if (verbose && response) {
      std::cerr << "status: " << response->status << std::endl;
      for (auto &[name, value] : response->headers)
        std::cerr << name << ": " << value << std::endl;
      std::cerr << response->body << std::endl;
      std::cerr << std::endl;
    }
  }

  co_await client.close();
}

int main(int argc, char *argv[]) {
  po::options_description general_options("General options");
  general_options.add_options()("help,h", "produce help message")("verbose,v",
                                                                  "show log");

  po::options_description request_options("Request options");
  request_options.add_options()(
      "location,L", po::value<std::string>()->value_name("<location>"),
      "location")(
      "method,m",
      po::value<std::string>()->value_name("<method>")->default_value("POST"),
      "method")("data,d", po::value<std::string>()->value_name("<data>"),
                "data to send")("file,f",
                                po::value<std::string>()->value_name("<file>"),
                                "read data from file")(
      "header,H",
      po::value<std::vector<std::string>>()->composing()->value_name(
          "<header>"),
      "http header(s)")("insecure", "do not verify the server certificate")(
      "iterations,i",
      po::value<int>()->value_name("<iterations>")->default_value(1),
      "number of iterations");

  po::options_description all_options("Allowed options");
  all_options.add(general_options).add(request_options);

  io_context io_context;
  http2_client::client client;

  try {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, all_options), vm);
    po::notify(vm);

    if (vm.count("help")) {
      std::cerr << all_options << std::endl;
      return 0;
    }

    required_option(vm, "location");
    conflicting_options(vm, "data", "file");

    std::string method = vm["method"].as<std::string>();

    auto parsed_url =
        boost::urls::parse_uri_reference(vm["location"].as<std::string>());
    if (!parsed_url)
      throw std::logic_error(parsed_url.error().message());

    if (!parsed_url->has_scheme())
      throw std::logic_error("missing url scheme");

    std::string scheme = parsed_url->scheme();
    std::string host = parsed_url->host();
    std::string port = parsed_url->port();
    std::string path = parsed_url->path();

    if (port.empty()) {
      switch (parsed_url->scheme_id()) {
      case boost::urls::scheme::https:
        port = "443";
        break;
      case boost::urls::scheme::http:
        port = "80";
        break;
      default:
        throw std::logic_error("unsupported scheme");
      }
    }

    if (path.empty())
      path = "/";

    if (scheme == "https") {
      auto tls_context = http2_client::create_context(
          ssl::context::sslv23_client, !vm.count("insecure"));
      client = http2_client::client(io_context, tls_context, host, port);
    } else {
      if (vm.count("insecure") && !vm["insecure"].defaulted())
        throw std::logic_error("--insecure is only supported "
                               "for https scheme");
      client = http2_client::client(io_context, host, port);
    }

    http2_client::body_generator body = nullptr;
    if (vm.count("data"))
      body = make_string_body(vm["data"].as<std::string>());
    else if (vm.count("file"))
      body = make_file_body(vm["file"].as<std::string>());

    http2_client::header_map headers;
    if (vm.count("header")) {
      for (auto &header : vm["header"].as<std::vector<std::string>>()) {
        auto pos = header.find(':');
        if (pos == std::string::npos)
          throw std::logic_error("invalid header: " + header);
        headers.emplace(trim(header.substr(0, pos)),
                        trim(header.substr(pos + 1)));
      }
    }

    int iterations = vm["iterations"].as<int>();
    if (iterations < 1)
      throw std::logic_error("invalid iterations");

    co_spawn(io_context,
             run(client, method, path, std::move(body), headers, iterations,
                 vm.count("verbose")),
             detached);

    io_context.run();
  } catch (const std::exception &e) {
    std::cerr << "[http2-client] " << e.what() << std::endl;
    std::cerr << "Try '" << argv[0] << " -h' for more information."
              << std::endl;
    return 1;
  }
}