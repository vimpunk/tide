#ifndef TIDE_AVERAGE_COUNTER_HEADER
#define TIDE_AVERAGE_COUNTER_HEADER

#include <cstdint>

namespace tide {

class average_counter
{
    int64_t m_sum = 0;
    int m_num_samples = 0;

public:

    void add_sample(const int64_t s) noexcept
    {
        m_sum += s;
        ++m_num_samples;
    }

    double mean() const noexcept
    {
        if(m_num_samples == 0)
        {
            return 0;
        }
        return double(m_sum) / m_num_samples;
    }
};

} // namespace tide

#endif // TIDE_AVERAGE_COUNTER_HEADER
