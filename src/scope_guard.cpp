#include "scope_guard.h"

namespace http2_client {
scope_guard::scope_guard(std::function<void()> &&on_exit)
    : on_exit_(std::move(on_exit)) {}

scope_guard::~scope_guard() { on_exit_(); }
} // namespace http2_client