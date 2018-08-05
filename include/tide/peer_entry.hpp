#ifndef TIDE_PEER_ENTRY_HEADER
#define TIDE_PEER_ENTRY_HEADER

#include "socket.hpp"
#include "types.hpp"

namespace tide {

/** Represents a peer collected from a tracker. */
struct peer_entry
{
    peer_id_t id;
    tcp::endpoint endpoint;

    bool operator==(const peer_entry& other) const noexcept { return id == other.id; }

    bool operator!=(const peer_entry& other) const noexcept { return id != other.id; }

    bool operator<(const peer_entry& other) const noexcept { return id < other.id; }
};

} // namespace tide

#endif // TIDE_PEER_ENTRY_HEADER
