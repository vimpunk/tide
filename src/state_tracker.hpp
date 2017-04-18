#ifndef TORRENT_STATE_TRACKER_HEADER
#define TORRENT_STATE_TRACKER_HEADER

#include <cstdint>

template<typename Int> struct state_tracker;
template<typename Int>
bool operator==(const state_tracker<Int>&, const state_tracker<Int>&) noexcept;

/**
 * This is a very lightweight wrapper around the conventional integer manipulation with
 * power-of-two enums.
 *
 * NOTE: IT IS NOT A BITSET, the supplied (enum) values must be some power of two, e.g.:
 * enum state { idle = 0, sending = 1, receiving = 2, processing = 4 };
 * If this cannot be satisfied, use std::bitset<>.
 *
 * The storage size can be manipulated by specifying the integer type to be used, which
 * should be an unsigned type. It should be used in the stead of a host of flags or
 * manipulating integers with enum values.
 *
 * The maximum number of unique states it can hold is restricted by the underlying OS'
 * largest integer type.
 */
template<
    typename Int = uint64_t
> struct state_tracker
{
    using size_type = Int;

private:

    size_type m_state = 0;

public:

    bool is(const size_type s) const noexcept
    {
        return m_state & s;
    }

    void started(const size_type s) noexcept
    {
        if(s == 0)
        {
            m_state = 0;
        }
        else
        {
            m_state |= s;
        }
    }

    void stopped(const size_type s) noexcept
    {
        if(s != 0)
        {
            m_state &= ~s;
        }
    }

    void reset() noexcept
    {
        m_state = 0;
    }

    friend bool operator==<Int>(const state_tracker&, const state_tracker&) noexcept;
};

template<typename Int>
inline bool operator==(const state_tracker<Int>& a, const state_tracker<Int>& b) noexcept
{
    return a.m_state == b.m_state;
}

template<typename Int>
inline bool operator!=(const state_tracker<Int>& a, const state_tracker<Int>& b) noexcept
{
    return !(a == b);
}

#endif // TORRENT_STATE_TRACKER_HEADER
