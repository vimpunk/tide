#ifndef TORRENT_FLAG_SET_HEADER
#define TORRENT_FLAG_SET_HEADER

#include <type_traits>
#include <cstdint>
#include <cstdlib>

namespace tide {

template<typename Enum, Enum> struct flag_set;
template<typename Enum, Enum N>
bool operator==(const flag_set<Enum, N>&, const flag_set<Enum, N>&) noexcept;

namespace util
{
    /** Credit: https://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2 */
    constexpr uint32_t nearest_pow2(uint32_t x) noexcept
    {
        --x;
        x |= x >> 1;
        x |= x >> 2;
        x |= x >> 4;
        x |= x >> 8;
        x |= x >> 16;
        ++x;
        return x;
    }

    constexpr size_t min_num_bits(const size_t n) noexcept
    {
        return n < 8 ? 8 : n;
    }

    template<size_t N> struct integral_type_for
    {
        using type = typename integral_type_for<min_num_bits(nearest_pow2(N))>::type;
    };

    template<> struct integral_type_for<64> { using type = uint64_t; };
    template<> struct integral_type_for<32> { using type = uint32_t; };
    template<> struct integral_type_for<16> { using type = uint16_t; };
    template<> struct integral_type_for<8> { using type = uint8_t; };

    template<
        typename Integral,
        typename Enum,
        typename = typename std::enable_if<
            std::is_convertible<
                typename std::underlying_type<Enum>::type, 
                Integral
            >::value
        >::type
    > constexpr Integral enum_cast(Enum e)
    {
        return static_cast<Integral>(e);
    }
} // namespace util

/**
 * This is a very lightweight wrapper around the conventional integer manipulation with
 * power-of-two enums used to record various flags. First, this abstraction does not
 * necessitate power-of-two enum values, which is error prone and not very resilient 
 * to change -- this conversion is done internally. Second, type safety is provided in
 * that only the initial enum type is accepted and the underlying type used to store the
 * values is large enough to hold all flags. This, however, is limited to 64 bits,
 * because it uses an integer as its underlying type (thus max int64_t).
 *
 * This class should be used over a std::bitset<> whenever the maximum number of states
 * is relatively small, in which case this class should be faster.
 *
 * Example
 * -------
 * Traditional way:
 * op_state |= op_t::send;
 * op_state &= ~op_t::send;
 * if(op_state & op_t::send) { ... }
 *
 * With flag_set:
 * op_state.set(op_t::send);
 * op_state.unset(op_t::send);
 * if(op_state[op_t::send]) { ... }
 */
template<
    typename Enum,
    Enum NumFlags
> struct flag_set
{
    static_assert(
        util::enum_cast<size_t>(NumFlags) <= 64, "The maximum number of flags is 64."
    );

    using value_type = bool;
    using size_type = size_t;
    using const_reference = value_type;
    using enum_type = Enum;
    using underlying_type = typename util::integral_type_for<
        util::enum_cast<size_type>(NumFlags)
    >::type;

    class reference
    {
        friend class flag_set;
        underlying_type& m_flags;
        underlying_type m_mask;

        reference(underlying_type& flags, underlying_type mask)
            : m_flags(flags)
            , m_mask(mask)
        {}

    public:

        operator bool() const noexcept
        {
            return m_flags & m_mask;
        }

        reference& operator=(bool x) noexcept
        {
            if(x)
                m_flags |= m_mask;
            else
                m_flags &= ~m_mask;
            return *this;
        }

        reference& operator=(const reference& other) noexcept
        {
            return operator=(static_cast<bool>(other));
        }

        friend bool operator==(const reference& a, const reference& b) noexcept
        {
            return &a.m_flags == &b.m_flags;
        }

        friend bool operator!=(const reference& a, const reference& b) noexcept
        {
            return !(a == b);
        }
    };

private:
    underlying_type m_flags = 0;
public:

    size_type size() const noexcept
    {
        return util::enum_cast<size_type>(NumFlags);
    }

    bool is_empty() const noexcept
    {
        return m_flags == 0;
    }

    /** Used to query whether any flags are set. */
    operator bool() const noexcept
    {
        return !is_empty();
    }

    /** Used to query whether flag is active. */
    const_reference operator[](const enum_type flag) const noexcept
    {
        return m_flags & bit_mask(flag);
    }

    reference operator[](const enum_type flag) noexcept
    {
        return reference(m_flags, bit_mask(flag));
    }

    void set(const enum_type flag) noexcept
    {
        m_flags |= bit_mask(flag);
    }

    void unset(const enum_type flag) noexcept
    {
        m_flags &= ~bit_mask(flag);
    }

    void clear() noexcept
    {
        m_flags = 0;
    }

    friend bool operator==<Enum, NumFlags>(const flag_set&, const flag_set&) noexcept;

private:

    static underlying_type bit_mask(const enum_type flag) noexcept
    {
        return 1 << util::enum_cast<underlying_type>(flag);
    }
};

template<typename Enum, Enum N>
inline bool operator==(const flag_set<Enum, N>& a, const flag_set<Enum, N>& b) noexcept
{
    return a.m_flags == b.m_flags;
}

template<typename Enum, Enum N>
inline bool operator!=(const flag_set<Enum, N>& a, const flag_set<Enum, N>& b) noexcept
{
    return !(a == b);
}

} // namespace tide

#endif // TORRENT_FLAG_SET_HEADER
