#ifndef TIDE_EXPONENTIAL_BACKOFF_HEADER
#define TIDE_EXPONENTIAL_BACKOFF_HEADER

namespace tide {

/** A simple binary exponential backoff generator. */
template<int Max> class exponential_backoff
{
    int m_value;

public:

    explicit exponential_backoff(int t = 2) : m_value(t) {}

    void reset(int t = 2) noexcept { m_value = t; }

    int operator()() noexcept
    {
        if(m_value == Max) { return Max; }
        const auto tmp = m_value;
        m_value <<= 1;
        if(m_value > Max)
        {
            m_value = Max;
        }
        return tmp;
    }
};

} // namespace tide

#endif // TIDE_EXPONENTIAL_BACKOFF_HEADER
