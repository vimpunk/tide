#ifndef TORRENT_PAYLOAD_HEADER
#define TORRENT_PAYLOAD_HEADER

#include <iterator>
#include <vector>

#include <asio/buffers_iterator.hpp>

/**
 * Used to represent an outgoing raw BitTorrent messages and provides convenient
 * multi-byte integer host to network conversion with builder semantics.
 */
struct payload
{
    std::vector<uint8_t> data;

    payload(const int size)
    {
        data.reserve(size);
    }

    payload(std::vector<uint8_t> d) : data(std::move(d)) {}

    template<size_t N>
    payload(const uint8_t (&arr)[N]) : data(std::begin(arr), std::end(arr)) {}

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
        data.insert(data.cend(), std::begin(buffer), std::end(buffer));
        return *this;
    }

    template<typename ConstBufferSequence>
    payload& buffers(const ConstBufferSequence& buffers)
    {
        data.insert(
            data.cend(),
            asio::buffers_begin(buffers),
            asio::buffers_end(buffers)
        );
        return *this;
    }

private:

    template<typename Int>
    void add_integer(Int x)
    {
        for(int shift = 8 * (sizeof(Int) - 1); shift >= 0; shift -= 8)
        {
            const uint8_t octet = (x >> shift) & 0xff;
            data.emplace_back(octet);
        }
    }
};

#endif // TORRENT_PAYLOAD_HEADER
