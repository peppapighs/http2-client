#pragma once

#include <functional>

namespace http2_client {
class scope_guard {
public:
  scope_guard(std::function<void()> &&on_exit);
  ~scope_guard();

private:
  std::function<void()> on_exit_;
};
} // namespace http2_client