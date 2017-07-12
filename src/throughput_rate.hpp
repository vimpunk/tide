#ifndef TIDE_THROUGHPUT_RATE_HEADER
#define TIDE_THROUGHPUT_RATE_HEADER

#include "sliding_average.hpp"
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
 */
class throughput_rate
{

    // Updated every time m_rate is updated with a time value aligned to one second
    // compared to the starting point.
    mutable time_point m_last_update_time;

    // m_rate is updated at every second, so if a full second hasn't yet elapsed since
    // m_last_update_time, the bytes are buffered here until then.
    mutable int64_t m_num_bytes_left = 0;
    mutable int m_rate = 0;
    mutable int m_peak = 0;
    mutable int m_prev_second_rate = 0;

public:

    throughput_rate() : m_last_update_time(cached_clock::now()) {}

    void reset()
    {
        m_last_update_time = cached_clock::now();
        m_rate = m_prev_second_rate = m_num_bytes_left = m_peak = 0;
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
    void update_impl(const int num_bytes) const noexcept // TODO verify(noexcept)
    {
        m_num_bytes_left += num_bytes;
        const time_point now = cached_clock::now();
        const duration elapsed = now - m_last_update_time;

        if(elapsed >= seconds(1))
        {
            // the number of bytes that was transferred over the link in the time
            // elapsed is partitioned up in proportion to the number of full and the
            // fraction of a second that passed, and only update m_rate with the full
            // second's number of bytes and leave the fraction second's ratio for the
            // next update (this ensures that the running average accumulator records
            // consistent values)
            const auto elapsed_ms = total_milliseconds(elapsed);
            const int full_elapsed_s = elapsed_ms / 1000;
            assert(full_elapsed_s >= 1);
            // the number of bytes that was transmitted in a full second
            const int full_second_num_bytes = m_num_bytes_left / full_elapsed_s;
            for(auto i = 0; i < full_elapsed_s; ++i)
            {
                m_prev_second_rate = m_rate;
                m_rate = m_rate * 0.6 + full_second_num_bytes * 0.4;
                //m_rate.update(full_second_num_bytes);
                m_num_bytes_left -= full_second_num_bytes;
            }
            // updates happen at full seconds and since the bytes left over here are
            // going to be added when the next full second is reached, we must keep the
            // update time points aligned at full seconds (relative to our starting
            // point) as well
            m_last_update_time = m_last_update_time + seconds(full_elapsed_s);
        }
    }
};

} // namespace tide

#endif // TIDE_THROUGHPUT_RATE_HEADER
