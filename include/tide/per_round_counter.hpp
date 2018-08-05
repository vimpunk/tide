#ifndef TIDE_PER_ROUND_COUNTER_HEADER
#define TIDE_PER_ROUND_COUNTER_HEADER

#include "time.hpp"

#include <cassert>

namespace tide {

/**
 * Accumulates some value for Interval TimeUnits (seconds by default), after which the
 * value is reset. Using clock, it automatically resets itself if more than
 * Interval TimeUnits have passed.  This can be used to tally the number of bytes
 * transferred in a second, for instance.
 */
template <size_t Interval, typename TimeUnit = seconds>
class per_round_counter
{
    mutable int prev_round_value_ = 0;
    mutable int value_ = 0;
    mutable time_point last_update_time_;

public:
    per_round_counter() : last_update_time_(clock::now()) {}

    void clear() noexcept
    {
        last_update_time_ = clock::now();
        prev_round_value_ = value_ = 0;
    }

    void update(const int n) noexcept { update_impl(n); }

    int value() const noexcept
    {
        update_impl(0);
        return value_;
    }

    /** Returns the difference between the current round and the previous round. */
    int deviation() const noexcept
    {
        update_impl(0);
        return value_ - prev_round_value_;
    }

private:
    void update_impl(const int n) const noexcept
    {
        // TODO maybe change to clock::now()
        const auto elapsed
                = duration_cast<milliseconds>(clock::now() - last_update_time_);
        if((elapsed >= TimeUnit(Interval)) && (elapsed < TimeUnit(2 * Interval))) {
            // If more than a second but less than a second has passed, the
            // current value becomes the previous value and the new value
            // becomes the current value.
            prev_round_value_ = value_;
            value_ = n;
        } else if(elapsed >= TimeUnit(2 * Interval)) {
            // Since more than two rounds have passed, meaning there was nothing
            // added to counter, the previous value becomes 0.
            prev_round_value_ = 0;
            value_ = n;
        } else {
            value_ += n;
        }
        last_update_time_ += elapsed;
    }
};

/*
class counter
{
    int prev_value_ = 0;
    int value_ = 0;
public:

    operator int() const noexcept { return value_; }

    counter& operator+=(const int n) noexcept
    {
        value_ += n;
        return *this;
    }

    void clear() { value_ = 0; }

    void reset(const int elapsed_ms)
    {

    }
};
*/

} // namespace tide

#endif // TIDE_PER_ROUND_COUNTER_HEADER
