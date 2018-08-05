#ifndef TIDE_SLIDING_AVERAGE_HEADER
#define TIDE_SLIDING_AVERAGE_HEADER

#include <cmath>

namespace tide {

/**
 * This is an exponential moving average accumulator, which addresss the initial
 * bias that occurs when all values are initialized with zero or with the first
 * sample (which would bias the average toward the first value). This is
 * achieved by initially giving a low gain for the average and slowly increasing
 * it until InvertedGain is reached.
 *
 * For example, the first sample should have a gain of 1 as the average has no
 * meaning.  When adding the second sample, the average has some meaning, but
 * since it only has one sample in it, the gain should be low. In the next round
 * however, the gain may be larger. This increase is repeated until InvertedGain
 * is reached.  This way, even early samples have a reasonable impact on the
 * average, which is important in a torrent app.
 *
 * This is an exact copy of libtorrent's implementation:
 * http://blog.libtorrent.org/2014/09/running-averages/
 * https://github.com/arvidn/moving_average/blob/master/moving_average.hpp
 */
template <typename T, T InvertedGain>
class sliding_average
{
    T mean_{};
    T deviation_{};
    T num_samples_{};

public:
    void update(T s) noexcept
    {
        // to avoid integer truncation samples are multiplied by 64, and when requesting
        // the mean, 32 is added to it before dividing back by 64 to the actual value
        s *= T(64);
        T deviation = T(0);
        if(num_samples_ > T(0)) {
            deviation = std::abs(mean_ - s);
        }
        if(num_samples_ < InvertedGain) {
            ++num_samples_;
        }
        mean_ += (s - mean_) / num_samples_;
        if(num_samples_ > T(1)) {
            deviation_ += (deviation - deviation_) / (num_samples_ - T(1));
        }
    }

    T mean() const noexcept
    {
        return num_samples_ > T(0) ? (mean_ + T(32)) / T(64) : T(0);
    }

    T deviation() const noexcept
    {
        return num_samples_ > T(1) ? (deviation_ + T(32)) / T(64) : T(0);
    }

    void reset() noexcept { mean_ = deviation_ = num_samples_ = T(0); }
};

} // namespace tide

#endif // TIDE_SLIDING_AVERAGE_HEADER
