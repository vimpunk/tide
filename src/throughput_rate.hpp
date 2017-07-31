#ifndef TIDE_THROUGHPUT_RATE_HEADER
#define TIDE_THROUGHPUT_RATE_HEADER

#include "time.hpp"

#include <cassert>

namespace tide {

/**
 * This is an exponential moving average accumulator that can be used for measuring
 * anything where a bytes/second unit makes sense, such as measuring network throughput,
 * where updates need not occur at frequent intervals (in fact, any unit can be used in
 * the place of bytes). This means that samples can be added at irregular intervals
 * since the number of seconds that have elapsed since the last update is taken into
 * account when updating. Therefore it is crucial that when the activity to be measured
 * has started, that reset be called to initialize the starting time point used to
 * measure the time elapsed till the next update.
 *
 * NOTE: due to using cached_clock the values are only estimates (which also means that
 * cached_clock must be updated at regular intervals).
 *
 * NOTE: it has a 1 second granularity, meaning its value is recalculated only every
 * 1 second. Therefore it should not be used where a finer granularity is required.
 */
class throughput_rate
{
    // Updated every time m_rate is updated with a time value aligned to one second
    // compared to the starting point.
    mutable time_point m_last_update_time;

    // m_rate is updated at every second, so if a full second hasn't yet elapsed since
    // m_last_update_time, the bytes are buffered here until then.
    mutable int64_t m_accumulator = 0;
    mutable int m_rate = 0;
    mutable int m_peak = 0;
    mutable int m_prev_second_rate = 0;

public:

    throughput_rate() : m_last_update_time(cached_clock::now()) {}

    void reset()
    {
        m_last_update_time = cached_clock::now();
        m_rate = m_prev_second_rate = m_accumulator = m_peak = 0;
    }

    /**
     * Every time a transfer occured on the link whose throughput rate this object is
     * monitoring, this function should be called with the number of transferred bytes.
     */
    void update(const int num_bytes) noexcept
    {
        update_impl(num_bytes);
    }

    int rate() const noexcept
    {
        // if no update occured in more than a second it means that no bytes were
        // transferred on the link, so simulate a throughput of 0 since the last update
        update_impl(0);
        const int r = m_rate;
        if(r > m_peak)
        {
            m_peak = r;
        }
        return r;
    }

    int peak() const noexcept
    {
        // see comment above, plus this also updates peak value if it changed
        rate();
        return m_peak;
    }

    /** Returns the difference between last second's and the current throughput rate. */
    int deviation() const noexcept
    {
        // see comment above
        rate();
        return m_rate - m_prev_second_rate;
    }

private:

    /**
     * Since the getters need to update as well but conceptually they are const methods
     * a const update method is provided, so that the publicly exposed update method is
     * not marked const which would be semantically incorrect.
     */
    void update_impl(int num_bytes) const noexcept
    {
        // make sure to round down to seconds as we only care about full second values
        // (see comment below)
        const milliseconds elapsed_ms = duration_cast<milliseconds>(
            cached_clock::now() - m_last_update_time);
        if((elapsed_ms >= seconds(1)) && (elapsed_ms < seconds(2)))
        {
            // if a full second has elapsed since the last update time, but less than 2,
            // we only have to do one update, and restart accumulation with num_bytes
            update_rate(m_accumulator);
            m_accumulator = num_bytes;
            m_last_update_time += seconds(1);
        }
        else if(elapsed_ms == seconds(2))
        {
            // exactly 2 seconds elapsed, which means we have to update the rate in the
            // first second with's left in m_accumulator, the second with num_bytes, and
            // reset m_accumulator to 0
            update_rate(m_accumulator);
            update_rate(num_bytes);
            m_accumulator = 0;
            m_last_update_time += seconds(2);
        }
        else if(elapsed_ms > seconds(2))
        {
            // more than 2 seconds elapsed, meaning that there was no throughput for
            // at least elapsed_ms - seconds(1) time, therefore, update the upload rate in
            // the first second of the elapsed time with whatever is left in
            // m_accumulator, then simulate a throughput of 0 bytes for the remaining
            // seconds
            const seconds elapsed_s = duration_cast<seconds>(elapsed_ms);
            update_rate(m_accumulator);
            for(auto i = 0; i < elapsed_s.count() - 1; ++i) { update_rate(0); }
            m_accumulator = num_bytes;
            // updates happen at full seconds and since the bytes left in m_accumulator
            // are going added when the next full second is reached, we must keep the
            // update time points aligned at full seconds (relative to our starting
            // point) as well
            m_last_update_time += elapsed_s;
        }
        else
        {
            m_accumulator += num_bytes;
        }
    }

    void update_rate(const int value) const noexcept
    {
        m_prev_second_rate = m_rate;
        m_rate = m_rate * 0.6 + value * 0.4;
    }
};

} // namespace tide

#endif // TIDE_THROUGHPUT_RATE_HEADER
