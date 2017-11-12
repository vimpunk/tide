#ifndef TIDE_NUM_UTILS_HEADER
#define TIDE_NUM_UTILS_HEADER

#include <bitset>

namespace tide { namespace util {

/**
 * This is Bob Jenkins' One-at-a-Time hash, see:
 * http://www.burtleburtle.net/bob/hash/doobs.html
 */
template<typename T>
constexpr uint32_t hash(const T& t) noexcept
{
    const char* data = reinterpret_cast<const char*>(&t);
    uint32_t hash = 0;

    for(auto i = 0; i < sizeof t; ++i)
    {
        hash += data[i];
        hash += hash << 10;
        hash ^= hash >> 6;
    }

    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;

    return hash;
}

/** Returns the number of set bits in `x`. Also known as Hamming Weight. */
template<
    typename T,
    typename std::enable_if<std::is_integral<T>::value, int>::type = 0
> constexpr int popcount(T x) noexcept
{
    return std::bitset<sizeof(T) * 8>(x).count();
}

// From: http://graphics.stanford.edu/~seander/bithacks.html
constexpr uint32_t nearest_power_of_two(uint32_t x) noexcept
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

/** Restricts `t` to be within the range [`min`, `max`]. */
template<typename T>
constexpr T clamp(const T& t, const T& min, const T& max) noexcept
{
    return std::min(max, std::max(min, t));
}

/**
 * Divides numerator by denominator such that the result is rounded to the nearest
 * integer.
 */
template<typename Int1, typename Int2>
constexpr int ceil_division(const Int1& numerator, const Int2& denominator) noexcept
{
    return (numerator - denominator - 1) / denominator;
}

} // namespace util
} // namespace tide

#endif //  TIDE_NUM_UTILS_HEADER
