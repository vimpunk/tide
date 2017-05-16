#ifndef TORRENT_TORRENT_HEADER
#define TORRENT_TORRENT_HEADER

//#include "torrent_info.hpp"
#include "torrent_args.hpp"
//#include "piece_picker.hpp"
//#include "settings.hpp"
//#include "disk_io.hpp"
#include "units.hpp"
#include "time.hpp"

#include <memory>
#include <vector>

class piece_download_locator;
class bandwidth_controller;
class torrent_settings;
class piece_download;
class torrent_info;
class peer_session;
class piece_picker;
class disk_io;

class torrent
{
    disk_io& m_disk_io;

    // There is one instance of this in engine, which is passed to each peer_session so
    // they can request bandwidth quota.
    bandwidth_controller& m_bandwidth_controller;

    // These are the global settings that is passed to each peer. Torrent's settings,
    // however, are in m_info (for settings related to a torrent may be customized for
    // each torrent but session settings and peer settings are global).
    torrent_settings& m_settings;

    // These are all the connected peers. The first upload slots number of peers are
    // ordered according to the choking algorithms rating (i.e. upload rate).
    std::vector<std::unique_ptr<peer_session>> m_peer_sessions;

    // This is used for internal stats and info bookkeeping, and is passed to submodules
    // that contribute to stats aggregation.
    std::shared_ptr<torrent_info> m_info;

    // Passed to every peer_session.
    std::shared_ptr<piece_picker> m_piece_picker;

    // This is where all current active piece downloads (from any peer in torrent)
    // can be accessed. When this torrent becomes a seeder, the memory for this is
    // released (will no longer need it).
    std::shared_ptr<piece_download_locator> m_piece_download_locator;

    // This is the original .torrent file of this torrent. It is kept in memory for
    // the piece SHA-1 hashes.
    bmap m_metainfo;

    // Since torrent may be accessed by user's thread, we need mutual exclusion.
    std::mutex m_torrent_mutex;

    // The choke "loop" runs every 10 seconds, reorders the peers according to the choke
    // algorithms peer score and unchokes the top 4, and chokes the rest. Every 30
    // seconds a single peer is optimistically unchoked to give it a chance and see
    // whether it has better perfromance than the current unchoked peers.
    deadline_timer m_choker_timer;

public:

    torrent(
        disk_io& disk_io,
        bandwidth_controller& bandwidth_controller,
        torrent_settings& settings,
        torrent_args args
    );

    bool is_paused() const noexcept;
    bool is_running() const noexcept;

    torrent_info info() const;
    void piece_availability(std::vector<int>& piece_map);

    void pause();
    void resume();

    /** file_index must be the position of the file in the original .torrent metainfo. */
    void prioritize_file(const int file_index);
    void deprioritize_file(const int file_index);
    void prioritize_piece(const piece_index_t piece);
    void deprioritize_piece(const piece_index_t piece);

    void change_settings(const torrent_settings& settings);

    void force_tracker_reannounce();
};

#endif // TORRENT_TORRENT_HEADER
