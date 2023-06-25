# http2-client

HTTP/2 Client using Coroutines. This project is for my personal exploration of performing asynchronous I/O using C++20-style coroutines.

## Build

Install the following dependencies:

- C++20 compiler
- CMake 3.12.0+
- Boost 1.81.0+
- OpenSSL
- nghttp2

or use the following command to install dependencies using Conda:

```bash
conda env create -f conda.yml
```

Build the project:

```bash
./make.sh
```

## Run

```bash
build/http2-client -h
build/http2-client -L "https://nghttp2.org" -m "GET" -v
```

## Notes

Set environment variable `SSLKEYLOGFILE` to path of a file to TLS master secrets logging. This is useful for debugging TLS connections using Wireshark.
