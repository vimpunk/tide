#ifndef TORRENT_BLOCK_INFO_HEADER
#define TORRENT_BLOCK_INFO_HEADER

#include "units.hpp"

#include <functional>

namespace tide {

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

static const block_info invalid_block(-1, -1, -1);

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

/** Used to represent requests we had sent out. */
struct pending_block : public block_info
{
    bool has_timed_out = false;

    pending_block(piece_index_t index, int offset, int length)
        : block_info(index, offset, length)
    {}

    pending_block(block_info b) : block_info(std::move(b)) {}
};

inline bool operator==(const pending_block& a, const pending_block& b) noexcept
{
    return static_cast<const block_info&>(a) == static_cast<const block_info&>(b)
        && a.has_timed_out == b.has_timed_out;
}

inline bool operator==(const pending_block& a, const block_info& b) noexcept
{
    return static_cast<const block_info&>(a) == b;
}

inline bool operator==(const block_info& b, const pending_block& a) noexcept
{
    return a == b;
}

inline bool operator!=(const pending_block& a, const pending_block& b) noexcept
{
    return !(a == b);
}

inline bool operator!=(const pending_block& a, const block_info& b) noexcept
{
    return !(a == b);
}

inline bool operator!=(const block_info& b, const pending_block& a) noexcept
{
    return !(a == b);
}

} // namespace tide

namespace std
{
    template<> struct hash<tide::block_info>
    {
        size_t operator()(const tide::block_info& b) const noexcept
        {
            return std::hash<tide::piece_index_t>()(b.index)
                 * 101 + std::hash<int>()(b.offset)
                 * (31 ^ std::hash<int>()(b.length))
                 * 79 + 51;
        }
    };

    template<> struct hash<tide::pending_block>
    {
        size_t operator()(const tide::pending_block& b) const noexcept
        {
            return std::hash<tide::block_info>()(static_cast<const tide::block_info&>(b))
                 + std::hash<bool>()(b.has_timed_out);
        }
    };
} // namespace std

#endif // TORRENT_BLOCK_INFO_HEADER
