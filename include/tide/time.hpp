#ifndef TIDE_TIME_HEADER
#define TIDE_TIME_HEADER

#include <chrono>

#include <asio/high_resolution_timer.hpp>

namespace tide {

using clock_type = std::chrono::high_resolution_clock;

using time_point = clock_type::time_point;
using duration = clock_type::duration;

using std::chrono::microseconds;
using std::chrono::milliseconds;
using std::chrono::seconds;
using std::chrono::minutes;
using std::chrono::hours;

using std::chrono::duration_cast;
using std::chrono::time_point_cast;

using deadline_timer = asio::basic_waitable_timer<clock_type>;

/**
 * To avoid some of the overhead of system calls when fetching the current time, a
 * global cached time_point instance can be used where accuracy is not instrumental.
 *
 * Some event loop should call update() at fixed intervals to update the cached clock.
 * Currently this is done by one of torrent_engine's internal update method.
 */
namespace cached_clock
{
    time_point now() noexcept;
    void update();
}

/**
 * This is a thread-safe version of the above cached_clock. A specialization is
 * provided so that modules that don't execute in parallel don't have to incur the
 * overhead of synchronziation.
 */
namespace ts_cached_clock
{
    time_point now() noexcept;
    void update();
}

template<typename Unit, typename Duration>
int64_t to_int(const Duration& d)
{
    return duration_cast<Unit>(d).count();
}

inline duration elapsed_since(const time_point& t)
{
    return cached_clock::now() - t;
}

template<typename Duration, typename Handler>
void start_timer(deadline_timer& timer, const Duration& expires_in, Handler handler)
{
    std::error_code ec;
    // setting this cancels pending async waits (which is what we want)
    timer.expires_from_now(expires_in, ec);
    timer.async_wait(std::move(handler));
}

} // namespace tide

#endif // TIDE_TIME_HEADER
