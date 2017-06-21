#ifndef TORRENT_THROUGHPUT_RATE_HEADER
#define TORRENT_THROUGHPUT_RATE_HEADER

#include "sliding_average.hpp"
#include "time.hpp"

#include <cassert>

namespace tide {

/**
 * This is an exponential moving average accumulator that can be used for measuring
 * anything where a bytes/second unit makes sense, such as measuring network throughput,
 * where updates need not occur at frequent intervals. This means that samples can be
 * added at irregular intervals since the number of seconds that have elapsed since the
 * last update is taken into account when updating. Therefore it is crucial that when
 * the activity to be measured has started, that reset be called to initialize the
 * starting time point used to measure the time elapsed till the next update.
 *
 * NOTE: due to using cached_clock the values are only estimates (which also means that
 * cached_clock must be updated at regular intervals).
 */
template<int WindowSizeSeconds> class throughput_rate
{
    // TODO we should probably use a different avergae accumulator here as this follows
    // the trend too slowly
    mutable sliding_average<WindowSizeSeconds> m_rate;
    mutable time_point m_last_update_time;
    mutable int64_t m_num_bytes_left = 0;
    mutable int m_peak = 0;

public:

    throughput_rate() : m_last_update_time(cached_clock::now()) {}

    /**
     * Every time a transfer occured on the link whose throughput rate this object is
     * monitoring, this function should be called with the number of transferred bytes.
     */
    void update(const int num_bytes) noexcept
    {
        update_impl(num_bytes);
    }

    int bytes_per_second() const noexcept
    {
        // if no update occured in more than a second it means that no bytes were
        // transferred on the link, so simulate a throughput of 0 since the last update
        update_impl(0);
        const int bps = m_rate.mean();
        if(bps > m_peak)
        {
            m_peak = bps;
        }
        return bps;
    }

    int peak() const noexcept
    {
        return m_peak;
    }

    int deviation() const noexcept
    {
        // see comment above
        update_impl(0);
        return m_rate.deviation();
    }

private:

    /**
     * Since the getters need to update as well but conceptually they are more likely to
     * be called in a const context, a const update method is provided, so that the
     * publicly exposed update method is not marked const which would be semantically
     * incorrect.
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
                m_rate.update(full_second_num_bytes);
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

#endif // TORRENT_THROUGHPUT_RATE_HEADER
