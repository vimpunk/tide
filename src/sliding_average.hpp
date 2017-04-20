#ifndef TORRENT_SLIDING_AVERAGE_HEADER
#define TORRENT_SLIDING_AVERAGE_HEADER

#include <cmath>

/**
 * This is an exact copy of libtorrent's implementation:
 * http://blog.libtorrent.org/2014/09/running-averages/
 * https://github.com/arvidn/moving_average/blob/master/moving_average.hpp
 */
template<int InvertedGain> class sliding_average
{
    int m_mean = 0;
    int m_avg_deviation = 0;
    int m_num_samples = 0;

public:

    void add_sample(int s)
    {
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
            m_avg_deviation += (deviation - m_avg_deviation) / (m_num_samples - 1);
        }
    }

    int mean() const noexcept
    {
        return m_num_samples > 0 ? (m_mean + 32) / 64
                                 : 0;
    }

    int deviation() const noexcept
    {
        return m_num_samples > 1 ? (m_avg_deviation + 32) / 64
                                 : 0;
    }
};

#endif // TORRENT_SLIDING_AVERAGE_HEADER
