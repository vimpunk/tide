#ifndef TIDE_SCOPE_GUARD_HEADER
#define TIDE_SCOPE_GUARD_HEADER

#include <functional>

namespace tide {
namespace util {

class scope_guard
{
    std::function<void()> function_;
    bool is_active_ = true;

public:

    explicit scope_guard(std::function<void()> f) : function_(std::move(f)) {}

    ~scope_guard()
    {
        if(is_active_ && function_) { function_(); }
    }

    void disable()
    {
        is_active_ = false;
    }
};

} // namespace tide
} // namespace util

#endif // TIDE_SCOPE_GUARD_HEADER
