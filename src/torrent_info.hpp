#ifndef TORRENT_TORRENT_INFO_HEADER
#define TORRENT_TORRENT_INFO_HEADER

#include "file_info.hpp"
#include "flag_set.hpp"
#include "settings.hpp"
#include "socket.hpp"
#include "units.hpp"
#include "time.hpp"

#include <vector>

namespace tide {

/**
 * This class is a means of bookkeeping for torrent, to hold and update all relevant
 * information. Each torrent has a single instance, and if any party needs some info
 * about torrent but need otherwise not interact with torrent, it is given a reference
 * to this info class.
 *
 * So while it is mostly used for internal bookkeeping, it's suitable for reporting
 * expansive statistics about a torrent, though this may be slightly costly.
 */
struct torrent_info
{
    // The unique torrent id which is used within the torrent engine to quickly
    // differentiate between torrents.
    // It is only valid while the torrent engine is running.
    torrent_id_t id;

    // The 20 byte hash used to identify torrents.
    sha1_hash info_hash;

    // All the files in this torrent. At this point all file paths have been sanitized
    // and made system conformant, so it is safe to use them. Paths are relative and
    // must be appended to save_path if the absolute path is required. This is so that
    // when torrent is moved, only the save_path has to be changed.
    std::vector<file_info> files;

    // The absolute path denoting where the torrent will be downloaded.
    path save_path;

    // Torrent's name and the name of the root directory if it has more than one file.
    std::string name;

    // The total size of the download, i.e. the sum of all file lengths that we are
    // downloading.
    int64_t size;

    int piece_length;
    int last_piece_length;

    // The total number of pieces in this torrent, the number of pieces that user needs
    // (which is the same as num_pieces torrent is downloading all files), and the
    // number of downloaded and verified pieces.
    int num_pieces;
    int num_wanted_pieces;
    int num_downloaded_pieces = 0;

    int num_seeders = 0;
    int num_leechers = 0;
    int num_unchoked_peers = 0;

    // Counting the number of times the choking algorithm has been invoked. This is done
    // so that every 3rd time we can run optimistic_unchoke.
    int num_choke_cycles = 0;

    // Latest payload (piece) upload and download rates in bytes/s.
    int upload_rate = 0;
    int download_rate = 0;

    // The highest upload and download rate recorded among all connections.
    int peak_upload_rate = 0;
    int peak_download_rate = 0;

    // The total number of bad pieces in the entire connection.
    int num_hash_fails = 0;

    // The number of requests to which we haven't gotten any response.
    int num_timed_out_requests = 0;

    int total_bytes_written_to_disk = 0;
    int total_bytes_read_from_disk = 0;

    // The number of bytes that are waiting to be written to and read from disk,
    // but are queued up.
    int num_pending_disk_write_bytes = 0;
    int num_pending_disk_read_bytes = 0;

    // The number of piece bytes we're expecting to receive from all peers.
    int num_outstanding_bytes = 0;

    // The total number of piece bytes exchanged with all peers in this torrent. Does
    // not include protocol overhead (both BitTorrent protocol and TCP/IP protocol).
    // Note that it also includes pieces that later turned out to be invalid and had to
    // be wasted. For the valid downloaded bytes, see downloaded_size.
    int64_t total_downloaded_piece_bytes = 0;
    int64_t total_uploaded_piece_bytes = 0;

    // The total number of all bytes, excluding the underlying network protocol overhead,
    // exchanged with all peers in this torrent
    // (i.e. total_piece_{up,down}loaded + BitTorrent protocol overhead).
    int64_t total_downloaded_bytes = 0;
    int64_t total_uploaded_bytes = 0;

    // The number of file bytes that have been downloaded and either passed the hash
    // test or didn't.
    int64_t total_verified_piece_bytes;
    int64_t total_failed_piece_bytes;

    // If we receive a piece that we already have, this is incremented.
    int64_t total_wasted_bytes = 0;

    seconds total_seed_time;
    seconds total_leech_time;
    time_point download_started_time;
    time_point download_finished_time;
    time_point last_announce_time;
    time_point last_choke_time;

    torrent_settings settings;

    enum class state_t : uint8_t
    {
        stopped,
        // Torrent's disk space is being allocated, which means that a torrent_storage
        // instance and the directory structure is being created.
        allocating,
        // If torrent is continued from a previous session, its directory structure and
        // files download before must be verified.
        verifying_files,
        // Torrent is announcing itself to one or several trackers and is waiting for
        // a response.
        announcing,
        seeding,
        max
    };

    flag_set<state_t, state_t::max> state;
};

inline int get_piece_length(const torrent_info& info, const piece_index_t piece) noexcept
{
    return piece == info.num_pieces -1
        ? info.last_piece_length
        : info.piece_length;
}

} // namespace tide

#endif // TORRENT_TORRENT_INFO_HEADER
