#ifndef TORRENT_TORRENT_INFO_HEADER
#define TORRENT_TORRENT_INFO_HEADER

#include "file_info.hpp"
#include "socket.hpp"
#include "units.hpp"

#include <vector>

struct torrent_info
{
    // The unique torrent id which is used within the torrent engine to quickly
    // differentiate between torrents.
    // It is only valid while the torrent engine is running.
    torrent_id_t id;

    // The 20 byte hash used to identify torrents.
    sha1_hash info_hash;

    // All the files in this torrent.
    std::vector<file_info> files;

    // The total size of the download, i.e. the sum of all file lengths.
    int64_t size;
    // A value between 0 and 1.
    double completion;

    // The total number of piece bytes exchanged with all peers in this torrent. Does
    // not include protocol overhead (both BitTorrent protocol and TCP/IP protocol).
    int64_t total_downloaded_piece_bytes = 0;
    int64_t total_uploaded_piece_bytes = 0;

    // The total number of all bytes, excluding the underlying network protocol overhead,
    // exchaned with all peers in this torrent
    // (i.e. total_piece_{up,down}loaded + BitTorrent protocol overhead).
    int64_t total_downloaded_bytes = 0;
    int64_t total_uploaded_bytes = 0;

    // If we receive a piece that we already have, this is incremented.
    int64_t total_wasted_bytes = 0;

    int64_t piece_length;
    int64_t last_piece_length;

    int num_pieces;

    // Latest upload and download rates in bytes/s, including BT protocol.
    int up_rate = 0;
    int down_rate = 0;

    // Latest upload and download rates in bytes/s of actual file pieces.
    int piece_up_rate = 0;
    int piece_down_rate = 0;

    // The highest upload and download rate recorded among all connections.
    int peek_up_rate = 0;
    int peek_down_rate = 0;

    // The rate cap in bytes/s for this torrent (i.e. all peers in this torrent). No
    // limit is employed if the values are -1 (the default).
    int up_rate_limit = -1;
    int down_rate_limit = -1;

    // The number of requests to which we haven't gotten any response.
    int num_timed_out_requests = 0;

    bool is_seeding = false;
};

#endif // TORRENT_TORRENT_INFO_HEADER
