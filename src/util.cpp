#include "util.h"

namespace http2_client {
bool select_protocol(unsigned char **out, unsigned char *outlen,
                     const unsigned char *in, unsigned int inlen) {
  for (auto &proto : HTTP2_ALPN) {
    for (auto ptr = in; ptr + proto.size() <= in + inlen; ptr += *ptr + 1) {
      if (std::equal(ptr, ptr + proto.size(), proto.begin(), proto.end())) {
        *out = const_cast<unsigned char *>(ptr);
        *outlen = proto.size();
        return true;
      }
    }
  }
  return false;
}

std::vector<unsigned char> make_alpn_string() {
  std::vector<unsigned char> result;
  for (auto &proto : HTTP2_ALPN)
    result.insert(result.end(), proto.begin(), proto.end());
  return result;
}

bool is_http2_negotiated(ssl::stream<ip::tcp::socket> &socket) {
  auto context = socket.native_handle();

  const unsigned char *next_proto = nullptr;
  unsigned int next_proto_len = 0;

#ifndef OPENSSL_NO_NEXTPROTONEG
  SSL_get0_next_proto_negotiated(context, &next_proto, &next_proto_len);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  if (next_proto == nullptr)
    SSL_get0_alpn_selected(context, &next_proto, &next_proto_len);
#endif

  if (next_proto == nullptr)
    return false;

  for (auto &proto : HTTP2_ALPN) {
    if (next_proto_len == proto.size() - 1 &&
        std::equal(next_proto, next_proto + next_proto_len, proto.begin() + 1,
                   proto.end()))
      return true;
  }

  return false;
}
} // namespace http2_client