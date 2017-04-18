#ifndef TORRENT_PEER_ENTRY_HEADER
#define TORRENT_PEER_ENTRY_HEADER

#include "units.hpp"
#include "socket"

/** Represents a(n unconnected) peer collected from a tracker. */
struct peer_entry
{
    std::string host;
    peer_id peer_id;
    uint16_t port;

    bool operator==(const peer_entry& other) const noexcept
    {
        return peer_id == other.peed_id;
    }

    bool operator!=(const peer_entry& other) const noexcept
    {
        return peer_id != other.peed_id;
    }

    bool operator<(const peer_entry& other) const noexcept
    {
        return peer_id < other.peed_id;
    }
};


struct ipv4_peer_entry
{
    address_v4::bytes_type ip;
    uint16_t port;
};


struct ipv6_peer_entry
{
    address_v6::bytes_type ip;
    uint16_t port;
};

#endif // TORRENT_PEER_ENTRY_HEADER
