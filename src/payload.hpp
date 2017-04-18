#ifndef TORRENT_PAYLOAD_HEADER
#define TORRENT_PAYLOAD_HEADER

#include "endian.hpp"

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
        const int16_t n = i16_host_to_network(h);
        data.emplace_back(n >> 8);
        data.emplace_back(n);
        return *this;
    }

    payload& u16(const uint16_t h)
    {
        const uint16_t n = u16_host_to_network(h);
        data.emplace_back(n >> 8);
        data.emplace_back(n);
        return *this;
    }

    payload& i32(const int32_t h)
    {
        const int32_t n = i32_host_to_network(h);
        data.emplace_back(n >> 24);
        data.emplace_back(n >> 16);
        data.emplace_back(n >> 8);
        data.emplace_back(n);
        return *this;
    }

    payload& u32(const uint32_t h)
    {
        const uint32_t n = u32_host_to_network(h);
        data.emplace_back(n >> 24);
        data.emplace_back(n >> 16);
        data.emplace_back(n >> 8);
        data.emplace_back(n);
        return *this;
    }

    payload& i64(const int64_t h)
    {
        const int64_t n = i64_host_to_network(h);
        data.emplace_back(n >> 56);
        data.emplace_back(n >> 48);
        data.emplace_back(n >> 40);
        data.emplace_back(n >> 32);
        data.emplace_back(n >> 24);
        data.emplace_back(n >> 16);
        data.emplace_back(n >> 8);
        data.emplace_back(n);
        return *this;
    }

    payload& u64(const uint64_t h)
    {
        const uint64_t n = u64_host_to_network(h);
        data.emplace_back(n >> 56);
        data.emplace_back(n >> 48);
        data.emplace_back(n >> 40);
        data.emplace_back(n >> 32);
        data.emplace_back(n >> 24);
        data.emplace_back(n >> 16);
        data.emplace_back(n >> 8);
        data.emplace_back(n);
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

    template<typename Buffer>
    payload& buffer(Buffer&& buffer)
    {
        data.insert(
            data.cend(),
            std::make_move_iterator(std::cbegin(buffer)),
            std::make_move_iterator(std::cend(buffer))
        );
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
};

#endif // TORRENT_PAYLOAD_HEADER
