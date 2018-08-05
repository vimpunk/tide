#ifndef TIDE_EXPONENTIAL_BACKOFF_HEADER
#define TIDE_EXPONENTIAL_BACKOFF_HEADER

namespace tide {

/** A simple binary exponential backoff generator. */
template <int Max>
class exponential_backoff
{
    int value_;

public:
    explicit exponential_backoff(int t = 2) : value_(t) {}

    void reset(int t = 2) noexcept { value_ = t; }

    int operator()() noexcept
    {
        if(value_ == Max) {
            return Max;
        }
        const auto tmp = value_;
        value_ <<= 1;
        if(value_ > Max) {
            value_ = Max;
        }
        return tmp;
    }
};

} // namespace tide

#endif // TIDE_EXPONENTIAL_BACKOFF_HEADER
