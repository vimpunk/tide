#ifndef TIDE_FLAG_SET_HEADER
#define TIDE_FLAG_SET_HEADER

#include "num_utils.hpp"

#include <initializer_list>
#include <type_traits>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <string>

namespace tide {

template<typename Flag, Flag> struct flag_set;
template<typename Flag, Flag N>
constexpr bool operator==(const flag_set<Flag, N>&, const flag_set<Flag, N>&) noexcept;

namespace util {

constexpr size_t min_num_bits(const size_t n) noexcept
{
    return n < 8 ? 8 : n;
}

template<size_t N> struct integral_type_for
{
    using type = typename integral_type_for<min_num_bits(nearest_power_of_two(N))>::type;
};

template<> struct integral_type_for<64> { using type = uint64_t; };
template<> struct integral_type_for<32> { using type = uint32_t; };
template<> struct integral_type_for<16> { using type = uint16_t; };
template<> struct integral_type_for<8> { using type = uint8_t; };

template<
    typename To,
    typename From,
    typename = typename std::enable_if<
        std::is_integral<From>::value || std::is_enum<From>::value
    >::type
> constexpr To int_cast(From i)
{
    return static_cast<To>(i);
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
 * This class should be used over a std::bitset whenever the maximum number of states
 * is relatively small, in which case this class should be faster (std::bitset's minimum
 * size is 8 bytes in most implementations).
 *
 * Example
 * -------
 * Traditional way:
 * op_state |= op_t::send;
 * op_state &= ~op_t::send;
 * if(op_state & op_t::send) { ... }
 *
 * With flag_set:
 * op_state.set(op_t::send); // or op_state[op_t::send] = true;
 * op_state.unset(op_t::send); // or op_state[op_t::send] = false;
 * if(op_state[op_t::send]) { ... }
 */
template<
    typename Flag,
    Flag NumFlags
> struct flag_set
{
    static_assert(util::int_cast<size_t>(NumFlags) <= 64,
        "The maximum number of flags is 64.");

    using value_type = bool;
    using size_type = size_t;
    using const_reference = value_type;
    using flag_type = Flag;
    // note: we can't just use std::underlying_type<Flag> because an int representation
    // of an enum value does not map to the number of bits needed to express that many
    // flags (e.g. the value 64 can be represented by a single 8-bit int, but we'd need
    // an uint64_t to represent 64 flags)
    using underlying_type = typename util::integral_type_for<
        util::int_cast<size_type>(NumFlags)
    >::type;

    class reference
    {
        friend class flag_set;
        underlying_type& flags_;
        underlying_type mask_;

        reference(underlying_type& flags, underlying_type mask)
            : flags_(flags)
            , mask_(mask)
        {}

    public:

        operator bool() const noexcept
        {
            return flags_ & mask_;
        }

        reference& operator=(bool x) noexcept
        {
            if(x)
                flags_ |= mask_;
            else
                flags_ &= ~mask_;
            return *this;
        }

        reference& operator=(const reference& other) noexcept
        {
            return operator=(static_cast<bool>(other));
        }

        friend bool operator==(const reference& a, const reference& b) noexcept
        {
            return &a.flags_ == &b.flags_;
        }

        friend bool operator!=(const reference& a, const reference& b) noexcept
        {
            return !(a == b);
        }
    };

private:
    underlying_type flags_ = 0;
public:

    flag_set() = default;
    constexpr flag_set(underlying_type flags) : flags_(flags) {}
    constexpr flag_set(const std::initializer_list<flag_type>& flags) { assign(flags); }

    constexpr void assign(underlying_type flags) { flags_ = flags; }

    constexpr void assign(const std::initializer_list<flag_type>& flags)
    {
        for(const auto flag : flags) { set(flag); }
    }

    // TODO make this a popcount equivalent function and add a max_size function
    constexpr size_type size() const noexcept
    {
        return util::int_cast<size_type>(NumFlags);
    }

    constexpr bool empty() const noexcept
    {
        return flags_ == 0;
    }

    constexpr bool is_full() const noexcept
    {
        return flags_ == std::numeric_limits<underlying_type>::max();
    }

    /** Used to query whether any flags are set. */
    constexpr operator bool() const noexcept { return !empty(); }

    constexpr underlying_type data() const noexcept { return flags_; }

    /** Used to query whether flag is active. */
    constexpr const_reference operator[](const flag_type flag) const noexcept
    {
        return flags_ & bit_mask(flag);
    }

    constexpr reference operator[](const flag_type flag) noexcept
    {
        return reference(flags_, bit_mask(flag));
    }

    constexpr void set(const flag_type flag) noexcept
    {
        flags_ |= bit_mask(flag);
    }

    constexpr void unset(const flag_type flag) noexcept
    {
        flags_ &= ~bit_mask(flag);
    }

    constexpr void clear() noexcept
    {
        flags_ = 0;
    }

    /**
     * Returns a bit-by-bit representation of the flag_set, ordered from least significant
     * to the most significant bit.
     */
    std::string to_string() const
    {
        std::string s(size(), '0');
        for(int i = 0; i < size(); ++i)
        {
            if(operator[](i))
            {
                s[size() - 1 - i] = '1';
            }
        }
        return s;
    }

    friend bool operator==<Flag, NumFlags>(const flag_set&, const flag_set&) noexcept;

private:

    static underlying_type bit_mask(const flag_type flag) noexcept
    {
        return underlying_type(1) << util::int_cast<underlying_type>(flag);
    }
};

template<typename Flag, Flag N>
constexpr bool operator==(const flag_set<Flag, N>& a, const flag_set<Flag, N>& b) noexcept
{
    return a.flags_ == b.flags_;
}

template<typename Flag, Flag N>
constexpr bool operator!=(const flag_set<Flag, N>& a, const flag_set<Flag, N>& b) noexcept
{
    return !(a == b);
}

} // namespace tide

#endif // TIDE_FLAG_SET_HEADER
