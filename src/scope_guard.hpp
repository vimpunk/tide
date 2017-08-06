#ifndef TIDE_SCOPE_GUARD_HEADER
#define TIDE_SCOPE_GUARD_HEADER

#include <functional>

namespace tide {
namespace util {

class scope_guard
{
    std::function<void()> m_function;
    bool m_is_active = true;

public:

    explicit scope_guard(std::function<void()> f) : m_function(std::move(f)) {}

    ~scope_guard()
    {
        if(m_is_active && m_function) { m_function(); }
    }

    void disable()
    {
        m_is_active = false;
    }
};

} // namespace tide
} // namespace util

#endif // TIDE_SCOPE_GUARD_HEADER
