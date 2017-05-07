#include "time.hpp"

namespace cached_clock
{
    static time_point g_cached_time(clock_type::now());

    time_point now() noexcept
    {
        return g_cached_time;
    }

    void update()
    {
        g_cached_time = clock_type::now();
    }
}
