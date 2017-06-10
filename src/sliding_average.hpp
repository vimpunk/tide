#ifndef TORRENT_SLIDING_AVERAGE_HEADER
#define TORRENT_SLIDING_AVERAGE_HEADER

#include <cmath>

namespace tide {

/**
 * This is an exponential moving average accumulator, which addresss the initial bias
 * that occurs when all values are initialized with zero or with the first sample (which
 * would bias the average toward the first value). This is achieved by initially giving
 * a low gain for the average and slowly increasing it until InvertedGain is reached.
 *
 * For example, the first sample should have a gain of 1 as the average has no meaning.
 * When adding the second sample, the average has some meaning, but since it only has
 * one sample in it, the gain should be low. In the next round however, the gain may be
 * larger. This increase is repeated until InvertedGain is reached.
 * This way, even early samples have a reasonable impact on the average, which is
 * important in a torrent app.
 *
 * This is an exact copy of libtorrent's implementation:
 * http://blog.libtorrent.org/2014/09/running-averages/
 * https://github.com/arvidn/moving_average/blob/master/moving_average.hpp
 */
template<int InvertedGain> class sliding_average
{
    int m_mean = 0;
    int m_deviation = 0;
    int m_num_samples = 0;

public:

    void add_sample(int s) noexcept
    {
        // to avoid integer truncation samples are multiplied by 64, and when requesting
        // the mean, 32 is added to it before dividing back by 64 to the actual value
        s *= 64;
        int deviation = 0;
        if(m_num_samples > 0)
        {
            deviation = std::abs(m_mean - s);
        }
        if(m_num_samples < InvertedGain)
        {
            ++m_num_samples;
        }
        m_mean += (s - m_mean) / m_num_samples;
        if(m_num_samples > 1)
        {
            m_deviation += (deviation - m_deviation) / (m_num_samples - 1);
        }
    }

    int mean() const noexcept
    {
        return m_num_samples > 0 ? (m_mean + 32) / 64
                                 : 0;
    }

    int deviation() const noexcept
    {
        return m_num_samples > 1 ? (m_deviation + 32) / 64
                                 : 0;
    }

    void clear() noexcept
    {
        m_mean = m_deviation = m_num_samples = 0;
    }
};

} // namespace tide

#endif // TORRENT_SLIDING_AVERAGE_HEADER
