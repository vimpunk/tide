#ifndef TORRENT_STATS_HEADER
#define TORRENT_STATS_HEADER

#include "throughput_rate.hpp"
#include "sliding_average.hpp"

#include <cstddef>

namespace tide {

/**
 * This serves as a base class for network and disk statistics aggregation, used by
 * peer_session and torrent_info.
 */
struct stats
{
    // The total number of piece bytes exchanged. Does not include protocol overhead
    // (i.e. neither BitTorrent protocol and TCP/IP protocol).
    // Note that it also includes pieces that later turned out to be invalid and had
    // to be wasted. For the valid downloaded bytes, see total_verified_piece_bytes.
    int64_t total_downloaded_piece_bytes = 0;
    int64_t total_uploaded_piece_bytes = 0;

    // The total number of all bytes exchanged excluding the underlying network protocol 
    // overhead (i.e. total_piece_{up,down}loaded + BitTorrent protocol overhead).
    int64_t total_downloaded_bytes = 0;
    int64_t total_uploaded_bytes = 0;

    // This field is only updated once the piece has been fully downloaded and its
    // verified. It should not be used to gauge download speed.
    int64_t total_verified_piece_bytes = 0;
    int64_t total_failed_piece_bytes = 0;

    // If we receive a piece that we already have, this is incremented by its length.
    int64_t total_wasted_bytes = 0;

    int total_bytes_written_to_disk = 0;
    int total_bytes_read_from_disk = 0;

    // The number of bytes that written or are waiting to be written to and read
    // from disk.
    int num_pending_disk_write_bytes = 0;
    int num_pending_disk_read_bytes = 0;

    // The number of piece bytes we're expecting to receive. This is decremented by the
    // block's length that was received, or if requests got cancelled.
    int num_outstanding_bytes = 0;

    // The number of corrupt pieces that didn't pass the hash test.
    int num_hash_fails = 0;

    // If peer sends requests while it's choked this counter is increased. After 300
    // such requests, peer is disconnected.
    int num_illicit_requests = 0;

    // Record the number of unwanted blocks we receive from peer. After a few we
    // disconnect so as to avoid being flooded.
    int num_unwanted_blocks = 0;
    int num_disk_io_failures = 0;
    int num_timed_out_requests = 0;

    // The number of requests that peers hasn't served yet.
    //int download_queue_size = 0;
    // The number of requests from peer that haven't been answered yet.
    //int upload_queue_size = 0;

};

} // namespace tide

#endif // TORRENT_STATS_HEADER
