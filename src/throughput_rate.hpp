#ifndef TORRENT_THROUGHPUT_RATE_HEADER
#define TORRENT_THROUGHPUT_RATE_HEADER

#include "sliding_average.hpp"
#include "time.hpp"

/**
 * This is an exponential moving average accumulator that can be used for measuring
 * anything where a bytes/second unit makes sense, such as measuring network throughput,
 * and where updates don't occur at frequent intervals. This means that samples can be
 * added at irregular intervals since the number of seconds that have elapsed since the
 * last update is taken into account within update. Therefore it is crucial that when
 * the activity to be measured has started, that reset be called to initialize the
 * starting time point used to measure the time elapsed till the next update.
 *
 * NOTE: due to using cached_clock the values are only estimates (which also means that
 * cached_clock must be updated at regular intervals).
 */
template<
    int8_t WindowSizeSeconds
> class throughput_rate
{
    sliding_average<WindowSizeSeconds> m_rate;
    time_point m_last_update_time;
    int64_t m_num_leftover_bytes = 0;

public:

    throughput_rate() : m_last_update_time(cached_clock::now()) {}

    /**
     * Every time a transfer occured on the link whose throughput rate this object is
     * monitoring, this function should be called with the number of transferred bytes.
     */
    void update(int num_bytes)
    {
        num_bytes += m_num_leftover_bytes;
        const time_point now = cached_clock::now();
        const duration elapsed = now - m_last_update_time;

        if(elapsed < seconds(1))
        {
            m_num_leftover_bytes += num_bytes;
        }
        else
        {
            // the number of bytes that was transferred over the link in the time
            // elapsed is partitioned up in proportion to the number of full and the
            // fraction of a second that passed, and only update m_rate with the full
            // second's number of bytes and leave the fraction second's ratio for the
            // next update (this ensures that the running average accumulator records
            // consistent values)
            auto elapsed_ms = total_milliseconds(elapsed);
            const int full_elapsed_s = total_seconds(elapsed);
            // the number of bytes that was transmitted in a full second
            const int full_second_num_bytes = num_bytes / full_elapsed_s;

            for(auto i = 0; i < full_elapsed_s; ++i)
            {
                m_rate.add_sample(full_second_num_bytes);
                num_bytes -= full_second_num_bytes;
            }
            // updates happen at full seconds and since the bytes left over here are
            // going to be added when the next full second is reached, we must keep the
            // update time points aligned at full seconds (relative to our starting
            // point) as well
            m_last_update_time = m_last_update_time + seconds(full_elapsed_s);
            m_num_leftover_bytes = num_bytes;
        }
    }

    int bytes_per_second()
    {
        // if no update occured in more than a second it means that no bytes were
        // transferred on the link, so simulate a throughput of 0 since the last update
        update(0);
        m_rate.mean();
    }

    int deviation()
    {
        // see comment above
        update(0);
        return m_rate.deviation();
    }
};

/*
// this is the version where updating the sliding average at regular intervals is
// ensured by the user should you need it
template<
    int8_t SampleSize
> class throughput_rate
{
    sliding_average<SampleSize> m_rate;
    int64_t m_byte_count = 0;

public:

    void update()
    {
        m_rate.add_sample(m_byte_count);
        m_byte_count = 0;
    }

    void record(const int num_bytes)
    {
        m_byte_count += num_bytes;
    }

    int bytes_per_second() const noexcept
    {
        m_rate.mean();
    }

    int deviation() const noexcept
    {
        m_rate.deviation();
    }
};
*/

#endif // TORRENT_THROUGHPUT_RATE_HEADER
