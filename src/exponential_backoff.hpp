#ifndef TIDE_EXPONENTIAL_BACKOFF_HEADER
#define TIDE_EXPONENTIAL_BACKOFF_HEADER

namespace tide {

/** A simple binary exponential backoff generator. */
template<int Max> class exponential_backoff
{
    int m_value = 2;

public:

    void reset() noexcept { m_value = 2; }

    int operator()() noexcept
    {
        const auto tmp = m_value;
        m_value <<= 1;
        if(m_value > Max) { m_value = Max; }
        return tmp;
    }
};

} // namespace tide

#endif // TIDE_EXPONENTIAL_BACKOFF_HEADER
