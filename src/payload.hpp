#ifndef TORRENT_PAYLOAD_HEADER
#define TORRENT_PAYLOAD_HEADER

#include "endian.hpp"

#include <algorithm>
#include <iterator>
#include <cassert>
#include <vector>

#include <asio/buffers_iterator.hpp>

namespace tide {

/**
 * Used to represent an outgoing raw network messages and provides convenient
 * multi-byte integer host to network conversion with builder semantics.
 */
struct payload
{
    std::vector<uint8_t> data;

    payload() = default;

    payload(const int size)
    {
        data.reserve(size);
    }

    payload(std::vector<uint8_t> d) : data(std::move(d)) {}

    template<size_t N>
    payload(const uint8_t (&arr)[N])
        : data(std::begin(arr)
        , std::end(arr))
    {}

    payload& i8(const int8_t h)
    {
        data.emplace_back(h);
        return *this;
    }

    payload& u8(const uint8_t h)
    {
        data.emplace_back(h);
        return *this;
    }

    payload& i16(const int16_t h)
    {
        add_integer<int16_t>(h);
        return *this;
    }

    payload& u16(const uint16_t h)
    {
        add_integer<uint16_t>(h);
        return *this;
    }

    payload& i32(const int32_t h)
    {
        add_integer<int32_t>(h);
        return *this;
    }

    payload& u32(const uint32_t h)
    {
        add_integer<uint32_t>(h);
        return *this;
    }

    payload& i64(const int64_t h)
    {
        add_integer<int64_t>(h);
        return *this;
    }

    payload& u64(const uint64_t h)
    {
        add_integer<uint64_t>(h);
        return *this;
    }

    template<typename InputIt>
    payload& range(InputIt begin, InputIt end)
    {
        data.insert(data.cend(), begin, end);
        return *this;
    }

    template<typename Buffer>
    payload& buffer(const Buffer& buffer)
    {
        return range(std::begin(buffer), std::end(buffer));
        
    }

    template<typename ConstBufferSequence>
    payload& buffers(const ConstBufferSequence& buffers)
    {
        return range(asio::buffers_begin(buffers), asio::buffers_end(buffers));
    }

private:

    template<typename Int>
    void add_integer(Int x)
    {
        const auto pos = data.size();
        data.resize(data.size() + sizeof(Int));
        endian::write<Int>(x, &data[pos]);
    }
};

/** Similar to the above, but used when the payload size is known at compile time. */
template<size_t N> class fixed_payload
{
    // We can't push_back on an array so we need to know where to place the next byte,
    // which this field indicates.
    int m_pos = 0;

public:

    std::array<uint8_t, N> data;

    constexpr void clear() noexcept
    {
        m_pos = 0;
    }

    constexpr fixed_payload& i8(const int8_t h)
    {
        data[m_pos++] = h;
        return *this;
    }

    constexpr fixed_payload& u8(const uint8_t h)
    {
        data[m_pos++] = h;
        return *this;
    }

    constexpr fixed_payload& i16(const int16_t h)
    {
        add_integer<int16_t>(h);
        return *this;
    }

    constexpr fixed_payload& u16(const uint16_t h)
    {
        add_integer<uint16_t>(h);
        return *this;
    }

    constexpr fixed_payload& i32(const int32_t h)
    {
        add_integer<int32_t>(h);
        return *this;
    }

    constexpr fixed_payload& u32(const uint32_t h)
    {
        add_integer<uint32_t>(h);
        return *this;
    }

    constexpr fixed_payload& i64(const int64_t h)
    {
        add_integer<int64_t>(h);
        return *this;
    }

    constexpr fixed_payload& u64(const uint64_t h)
    {
        add_integer<uint64_t>(h);
        return *this;
    }

    template<typename InputIt>
    fixed_payload& range(InputIt begin, InputIt end)
    {
        const auto d = std::distance(begin, end);
        assert(m_pos + d <= N);
        std::copy(begin, end, data.data() + m_pos);
        m_pos += d;
        return *this;
    }

    template<typename Buffer>
    fixed_payload& buffer(const Buffer& b)
    {
        return range(std::begin(b), std::end(b));
    }

    template<typename ConstBufferSequence>
    fixed_payload& buffers(const ConstBufferSequence& buffers)
    {
        return range(asio::buffers_begin(buffers), asio::buffers_end(buffers));
    }

private:

    template<typename Int>
    constexpr void add_integer(const Int x)
    {
        assert(m_pos + sizeof(Int) <= N && "fixed_payload overflow");
        endian::write<Int>(x, &data[m_pos]);
        m_pos += sizeof(Int);
    }
};

} // namespace tide

#endif // TORRENT_PAYLOAD_HEADER
