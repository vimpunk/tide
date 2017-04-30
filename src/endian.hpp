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

constexpr int16_t network_to_host_i16(const int16_t n) noexcept
{
#if defined(BOOST_BIG_ENDIAN)
    return n;
#elif defined(BOOST_LITTLE_ENDIAN)
    return swap_i16(n);
#endif
}

constexpr uint16_t network_to_host_u16(const uint16_t n) noexcept
{
#if defined(BOOST_BIG_ENDIAN)
    return n;
#elif defined(BOOST_LITTLE_ENDIAN)
    return swap_u16(n);
#endif
}

constexpr int32_t network_to_host_i32(const int32_t n) noexcept
{
#if defined(BOOST_BIG_ENDIAN)
    return n;
#elif defined(BOOST_LITTLE_ENDIAN)
    return swap_i32(n);
#endif
}

constexpr uint32_t network_to_host_u32(const uint32_t n) noexcept
{
#if defined(BOOST_BIG_ENDIAN)
    return n;
#elif defined(BOOST_LITTLE_ENDIAN)
    return swap_u32(n);
#endif
}

constexpr int64_t network_to_host_i64(const int64_t n) noexcept
{
#if defined(BOOST_BIG_ENDIAN)
    return n;
#elif defined(BOOST_LITTLE_ENDIAN)
    return swap_i64(n);
#endif
}

constexpr uint64_t network_to_host_u64(const uint64_t n) noexcept
{
#if defined(BOOST_BIG_ENDIAN)
    return n;
#elif defined(BOOST_LITTLE_ENDIAN)
    return swap_u64(n);
#endif
}

constexpr int16_t host_to_network_i16(const int16_t h) noexcept
{
    return network_to_host_i16(h);
}

constexpr uint16_t host_to_network_u16(const uint16_t h) noexcept
{
    return network_to_host_u16(h);
}

constexpr int32_t host_to_network_i32(const int32_t h) noexcept
{
    return network_to_host_i32(h);
}

constexpr uint32_t host_to_network_u32(const uint32_t h) noexcept
{
    return network_to_host_u32(h);
}

constexpr int64_t host_to_network_i64(const int64_t h) noexcept
{
    return network_to_host_i64(h);
}

constexpr uint64_t host_to_network_u64(const uint64_t h) noexcept
{
    return network_to_host_u64(h);
}

// The below functions are meant for parsing from a byte stream, and reconstructing
// integers (that are at least two bytes wide) from Network Byte Order to Host Byte
// Order, and should be used in place of manually reconstructing the integer and passing
// it to above host-network conversion functions.

namespace detail
{
    template<typename T, typename InputIt>
    constexpr T parse(InputIt it) noexcept
    {
        T h = 0;
        for(auto i = 0; i < int(sizeof(T)); ++i)
        {
            h <<= 8;
            h |= static_cast<uint8_t>(*it++);
        }
        return h;
    }
}

/**
 * Input it must point to the first byte in a sequence of bytes that is at least 2 long.
 * Parses the byte sequence for a 16 bit int and converts byte order from network byte
 * order to host's byte order.
 */
template<typename InputIt>
constexpr uint16_t parse_u16(InputIt it) noexcept
{
    return detail::parse<uint16_t>(it);
}

template<typename InputIt>
constexpr int16_t parse_i16(InputIt it) noexcept
{
    return detail::parse<int16_t>(it);
}

/**
 * Input it must point to the first byte in a sequence of bytes that is at least 4 long.
 * Parses the byte sequence for a 32 bit int and converts byte order from network byte
 * order to host's byte order.
 */
template<typename InputIt>
constexpr uint32_t parse_u32(InputIt it) noexcept
{
    return detail::parse<uint32_t>(it);
}

template<typename InputIt>
constexpr int32_t parse_i32(InputIt it) noexcept
{
    return detail::parse<int32_t>(it);
}

#endif // TORRENT_ENDIAN_HEADER
