#ifndef TORRENT_TIME_HEADER
#define TORRENT_TIME_HEADER

#include <chrono>

#include <asio/high_resolution_timer.hpp>

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

template<typename Duration>
int64_t total_microseconds(const Duration& d)
{
    return duration_cast<microseconds>(d).count();
}

template<typename Duration>
int64_t total_milliseconds(const Duration& d)
{
    return duration_cast<milliseconds>(d).count();
}

template<typename Duration>
int64_t total_seconds(const Duration& d)
{
    return duration_cast<seconds>(d).count();
}

#endif // TORRENT_TIME_HEADER
