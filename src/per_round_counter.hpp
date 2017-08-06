#ifndef TIDE_PER_ROUND_COUNTER_HEADER
#define TIDE_PER_ROUND_COUNTER_HEADER

#include "time.hpp"

#include <cassert>

namespace tide {

/**
 * Accumulates some value for Interval Units (seconds by default), after which the value
 * is reset. Using cached_clock, it automatically resets itself if more than Interval
 * Units have passed.
 * This can be used to tally the number of bytes transferred in a second, for instance.
 */
template<
    size_t Interval,
    typename TimeUnit = seconds
> class per_round_counter
{
    mutable int m_prev_round_value = 0;
    mutable int m_value = 0;
    mutable time_point m_last_update_time;

public:

    per_round_counter() : m_last_update_time(cached_clock::now()) {}

    void clear() noexcept
    {
        m_last_update_time = cached_clock::now();
        m_prev_round_value = m_value = 0;
    }

    void update(const int n) noexcept
    {
        update_impl(n);
    }

    int value() const noexcept
    {
        update_impl(0);
        return m_value;
    }

    /** Returns the difference between the current round and the previous round. */
    int deviation() const noexcept
    {
        update_impl(0);
        return m_value - m_prev_round_value;
    }

private:

    void update_impl(const int n) const noexcept
    {
        const TimeUnit elapsed = duration_cast<TimeUnit>(
            cached_clock::now() - m_last_update_time);
        if((elapsed >= TimeUnit(Interval)) && (elapsed < TimeUnit(2 * Interval)))
        {
            m_prev_round_value = m_value;
            m_value = n;
            m_last_update_time += elapsed;
        }
        else if(elapsed >= TimeUnit(2 * Interval))
        {
            // since more than 2 rounds have passed, meaning there was nothing added to
            // counter, the previous value is 0
            m_prev_round_value = 0;
            m_value = n;
            m_last_update_time += elapsed;
        }
        else
        {
            m_value += n;
        }
    }
};

/*
class counter
{
    int m_prev_value = 0;
    int m_value = 0;
public:

    operator int() const noexcept { return m_value; }

    counter& operator+=(const int n) noexcept
    {
        m_value += n;
        return *this;
    }

    void clear() { m_value = 0; }

    void reset(const int elapsed_ms)
    {
 
    }
};
*/

} // namespace tide

#endif // TIDE_PER_ROUND_COUNTER_HEADER
