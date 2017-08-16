#ifndef TIDE_TORRENT_INFO_HEADER
#define TIDE_TORRENT_INFO_HEADER

#include "file_info.hpp"
#include "flag_set.hpp"
#include "settings.hpp"
#include "types.hpp"
#include "stats.hpp"
#include "time.hpp"

#include <vector>

namespace tide {

// TODO maybe separate basic info and stats into two classes
/**
 * This class is a means of bookkeeping for torrent, to hold and update all relevant
 * information. Each torrent has a single instance, and if any party needs some info
 * about torrent but need otherwise not interact with torrent, it is given a reference
 * to this info class.
 *
 * So while it is mostly used for internal bookkeeping, it's suitable for reporting
 * expansive statistics about a torrent, though this may be slightly costly.
 */
struct torrent_info : public stats
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
    //
    // priority_files contains indices of entries in files.
    std::vector<file_info> files;
    std::vector<file_index_t> priority_files;

    // The absolute path denoting where the torrent will be downloaded.
    path save_path;

    // Torrent's name and the name of the root directory if it has more than one file.
    std::string name;

    // The total size of the download and the number of bytes that we're actually
    // downloading.
    int64_t size;
    int64_t wanted_size;

    int piece_length;
    int last_piece_length;

    // The total number of pieces in this torrent, the number of pieces that user needs
    // (which is the same as num_pieces torrent is downloading all files), and the
    // number of downloaded and verified pieces.
    int num_pieces;
    int num_wanted_pieces;
    int num_downloaded_pieces = 0;
    // TODO comment
    int num_pending_pieces = 0;

    // The total number of blocks in this torrent.
    int num_blocks;
    // The number of unserviced requests that all peer_sessions in torrent have issued.
    // It's decremented if we cancel or drop a request. This is used to determine when
    // to enter end-game mode. Note that some blocks may be requested by multiple peers,
    // so if this value reaches num_blocks, it may not mean that we have requested all
    // blocks in torrent, but it's a close enough approximation.
    // TODO or, we could enter end game when the number of pending pieces + num_downloaded_pieces
    // equals num_pieces, which would be another rough approximation
    int num_pending_blocks = 0;

    int num_seeders = 0;
    int num_leechers = 0;
    int num_unchoked_peers = 0;

    // The number of peers to which we're currently connecting but have as yet not been
    // connected. This is used to cap the number of "half-open" connections. This is
    // only for outbound connections.
    int num_connecting_sessions = 0;

    // The number of peer sessions that disconnected, and are waiting for torrent to
    // erase them from torrent's internal list. This is incremented by each peer that 
    // disconnects. (It's used as an optimization, as otherwise torrent would have to
    // loop through all its peer sessions, and this way it only needs to if there are 
    // actually stopped sessions, and it can exit early if all sessions have been
    // cleaned up.)
    int num_lingering_disconnected_sessions = 0;

    // Counting the number of times the choking algorithm has been invoked. This is done
    // so that every 3rd time we can run optimistic_unchoke.
    int num_choke_cycles = 0;

    seconds total_seed_time;
    seconds total_leech_time;
    time_point download_started_time;
    time_point download_finished_time;
    time_point last_announce_time;
    time_point last_unchoke_time;
    time_point last_optimistic_unchoke_time;

    torrent_settings settings;

    enum state : uint8_t
    {
        // If this state is not set, no other state may be set. TODO guarantee
        active,
        // Torrent's disk space is being allocated, which means that a torrent_storage
        // instance and the directory structure is being created.
        allocating,
        // If torrent is continued from a previous session, its directory structure and
        // files download before must be verified.
        verifying_files,
        // Writing resume data to disk.
        saving_state,
        // Torrent is announcing itself to one or several trackers and is waiting for
        // a response.
        announcing,
        seeding,
        // When a download is almost complete, there's a tendency for the last few
        // blocks to trickle in slowly. Torrent enters end-game mode when all of its
        // blocks have been requested, after which it rerequests all missing blocks
        // from all of its peers that have them.
        end_game,
        max
    };

    flag_set<state, state::max> state;
};

// TODO perhaps make this a torrent_info member function
inline int get_piece_length(const torrent_info& info, const piece_index_t piece) noexcept
{
    if(piece == info.num_pieces - 1)
        return info.last_piece_length;
    else
        return info.piece_length;
}

} // namespace tide

#endif // TIDE_TORRENT_INFO_HEADER
