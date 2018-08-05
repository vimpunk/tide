#ifndef TIDE_AVERAGE_COUNTER_HEADER
#define TIDE_AVERAGE_COUNTER_HEADER

#include <cstdint>

namespace tide {

class average_counter
{
    int64_t sum_ = 0;
    int num_samples_ = 0;

public:
    void add_sample(const int64_t s) noexcept
    {
        sum_ += s;
        ++num_samples_;
    }

    double mean() const noexcept
    {
        if(num_samples_ == 0) {
            return 0;
        }
        return double(sum_) / num_samples_;
    }
};

} // namespace tide

#endif // TIDE_AVERAGE_COUNTER_HEADER
