#ifndef TORRENT_PEER_ENTRY_HEADER
#define TORRENT_PEER_ENTRY_HEADER

#include "units.hpp"
#include "socket.hpp"

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

#endif // TORRENT_PEER_ENTRY_HEADER
