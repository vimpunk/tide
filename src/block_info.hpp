#ifndef TORRENT_BLOCK_INFO_HEADER
#define TORRENT_BLOCK_INFO_HEADER

#include "units.hpp"

struct block_info
{
    enum { default_length = 0x4000 };

    piece_index_t index;
    int offset;
    int length;

    block_info() = default;
    block_info(piece_index_t piece_, int offset_, int length_)
        : index(piece_)
        , offset(offset_)
        , length(length_)
    {}
};

inline bool operator==(const block_info& a, const block_info& b) noexcept
{
    return a.index == b.index
        && a.offset == b.offset
        && a.length == b.length;
}

inline bool operator!=(const block_info& a, const block_info& b) noexcept
{
    return !(a == b);
}

inline bool operator<(const block_info& a, const block_info& b) noexcept
{
    if(a.index == b.index)
    {
        if(a.offset == b.offset)
        {
            return a.length < b.length;
        }
        else
        {
            return a.offset < b.offset;
        }
    }
    else
    {
        return a.index < b.index;
    }
}

#include <functional>

namespace std
{
    template<> struct hash<block_info>
    {
        size_t operator()(const block_info& b) const noexcept
        {
            return std::hash<piece_index_t>()(b.index)
                 * 101 + std::hash<int>()(b.offset)
                 * (31 ^ std::hash<int>()(b.length))
                 * 79 + 51;
        }
    };
} // namespace std

#endif // TORRENT_BLOCK_INFO_HEADER
