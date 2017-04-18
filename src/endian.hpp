#ifndef TORRENT_ENDIAN_HEADER
#define TORRENT_ENDIAN_HEADER

#include <cstdint>
#include <boost/detail/endian.hpp>

namespace
{
    constexpr int16_t swap_i16(int16_t n) noexcept
    {
        return (n << 8) | ((n >> 8) & 0xFF);
    }

    constexpr uint16_t swap_u16(uint16_t n) noexcept
    {
        return (n << 8) | (n >> 8);
    }

    constexpr int32_t swap_i32(int32_t n) noexcept
    {
        n = ((n << 8) & 0xFF00FF00) | ((n >> 8) & 0xFF00FF);
        return (n << 16) | ((n >> 16) & 0xFFFF);
    }

    constexpr uint32_t swap_u32(uint32_t n) noexcept
    {
        n = ((n << 8) & 0xFF00FF00) | ((n >> 8) & 0xFF00FF);
        return (n << 16) | (n >> 16);
    }

    constexpr uint64_t swap_u64(uint64_t n) noexcept
    {
        n = ((n << 8)  & 0xFF00FF00FF00FF00ULL) | ((n >> 8)  & 0x00FF00FF00FF00FFULL);
        n = ((n << 16) & 0xFFFF0000FFFF0000ULL) | ((n >> 16) & 0x0000FFFF0000FFFFULL);
        return (n << 32) | (n >> 32);
    }

    constexpr int64_t swap_i64(int64_t n) noexcept
    {
        n = ((n << 8)  & 0xFF00FF00FF00FF00ULL) | ((n >> 8)  & 0x00FF00FF00FF00FFULL);
        n = ((n << 16) & 0xFFFF0000FFFF0000ULL) | ((n >> 16) & 0x0000FFFF0000FFFFULL);
        return (n << 32) | ((n >> 32) & 0xFFFFFFFFULL);
    }
} // anonymus namespace

constexpr int16_t i16_network_to_host(const int16_t n) noexcept
{
#if defined(BOOST_BIG_ENDIAN)
    return n;
#elif defined(BOOST_LITTLE_ENDIAN)
    return swap_i16(n);
#endif
}

constexpr uint16_t u16_network_to_host(const uint16_t n) noexcept
{
#if defined(BOOST_BIG_ENDIAN)
    return n;
#elif defined(BOOST_LITTLE_ENDIAN)
    return swap_u16(n);
#endif
}

constexpr int32_t i32_network_to_host(const int32_t n) noexcept
{
#if defined(BOOST_BIG_ENDIAN)
    return n;
#elif defined(BOOST_LITTLE_ENDIAN)
    return swap_i32(n);
#endif
}

constexpr uint32_t u32_network_to_host(const uint32_t n) noexcept
{
#if defined(BOOST_BIG_ENDIAN)
    return n;
#elif defined(BOOST_LITTLE_ENDIAN)
    return swap_u32(n);
#endif
}

constexpr int64_t i64_network_to_host(const int64_t n) noexcept
{
#if defined(BOOST_BIG_ENDIAN)
    return n;
#elif defined(BOOST_LITTLE_ENDIAN)
    return swap_i64(n);
#endif
}

constexpr uint64_t u64_network_to_host(const uint64_t n) noexcept
{
#if defined(BOOST_BIG_ENDIAN)
    return n;
#elif defined(BOOST_LITTLE_ENDIAN)
    return swap_u64(n);
#endif
}

constexpr int16_t i16_host_to_network(const int16_t h) noexcept
{
    return i16_network_to_host(h);
}

constexpr uint16_t u16_host_to_network(const uint16_t h) noexcept
{
    return u16_network_to_host(h);
}

constexpr int32_t i32_host_to_network(const int32_t h) noexcept
{
    return i32_network_to_host(h);
}

constexpr uint32_t u32_host_to_network(const uint32_t h) noexcept
{
    return u32_network_to_host(h);
}

constexpr int64_t i64_host_to_network(const int64_t h) noexcept
{
    return i64_network_to_host(h);
}

constexpr uint64_t u64_host_to_network(const uint64_t h) noexcept
{
    return u64_network_to_host(h);
}

/**
 * Input it must point to the first byte in a sequence of bytes that is at least 4 long.
 * Parses the byte sequence for a 32 bit int and converts byte order from network byte
 * order to host's byte order.
 */
template<typename InputIt>
constexpr uint32_t parse_u32(InputIt it) noexcept
{
    const uint32_t a = *it++ << 24;
    const uint32_t b = *it++ << 16;
    const uint32_t c = *it++ << 8;
    const uint32_t d = *it++;
    return u32_network_to_host(a + b + c + d);
}

template<typename InputIt>
constexpr int32_t parse_i32(InputIt it) noexcept
{
    return parse_u32(it);
}

#endif // TORRENT_ENDIAN_HEADER
