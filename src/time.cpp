#include "time.hpp"

#include <atomic>

namespace tide {

namespace cached_clock {
static time_point g_cached_time(clock::now());

time_point now() noexcept
{
    return g_cached_time;
}

void update()
{
    g_cached_time = clock::now();
}
}

namespace ts_cached_clock {
static std::atomic<time_point> g_cached_time(clock::now());

time_point now() noexcept
{
    return g_cached_time.load(std::memory_order_relaxed);
}

void update()
{
    g_cached_time.store(clock::now(), std::memory_order_relaxed);
}

void set(time_point time)
{
    g_cached_time.store(std::move(time), std::memory_order_relaxed);
}
}

} // namespace tide
