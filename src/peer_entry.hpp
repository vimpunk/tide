#ifndef TIDE_PEER_ENTRY_HEADER
#define TIDE_PEER_ENTRY_HEADER

#include "units.hpp"
#include "socket.hpp"

namespace tide {

/** Represents a peer collected from a tracker. */
struct peer_entry
{
    sha1_hash id;
    tcp::endpoint endpoint;

    bool operator==(const peer_entry& other) const noexcept
    {
        return id == other.id;
    }

    bool operator!=(const peer_entry& other) const noexcept
    {
        return id != other.id;
    }

    bool operator<(const peer_entry& other) const noexcept
    {
        return id < other.id;
    }
};

} // namespace tide

#endif // TIDE_PEER_ENTRY_HEADER
