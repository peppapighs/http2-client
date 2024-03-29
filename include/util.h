#pragma once

#include "http2_client.h"

namespace http2_client {
const std::vector<std::vector<unsigned char>> HTTP2_ALPN = {
    {'\x02', 'h', '2'},
    {'\x05', 'h', '2', '-', '1', '4'},
    {'\x05', 'h', '2', '-', '1', '6'},
};

struct name_value : public nghttp2_nv {
  template <std::size_t name_len>
  name_value(const char (&name)[name_len], const std::string &value)
      : nghttp2_nv{
            const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(name)),
            const_cast<uint8_t *>(
                reinterpret_cast<const uint8_t *>(value.c_str())),
            name_len - 1,
            value.size(),
            NGHTTP2_NV_FLAG_NO_COPY_NAME,
        } {}

  template <std::size_t name_len, std::size_t value_len>
  name_value(const char (&name)[name_len], const char (&value)[value_len])
      : nghttp2_nv{
            const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(name)),
            const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(value)),
            name_len - 1,
            value_len - 1,
            NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE,
        } {}

  name_value(const std::string &name, const std::string &value)
      : nghttp2_nv{
            const_cast<uint8_t *>(
                reinterpret_cast<const uint8_t *>(name.c_str())),
            const_cast<uint8_t *>(
                reinterpret_cast<const uint8_t *>(value.c_str())),
            name.size(),
            value.size(),
            NGHTTP2_NV_FLAG_NONE,
        } {}
};

bool select_protocol(unsigned char **out, unsigned char *outlen,
                     const unsigned char *in, unsigned int inlen);

std::vector<unsigned char> make_alpn_string();

bool is_http2_negotiated(ssl::stream<ip::tcp::socket> &socket);
} // namespace http2_client