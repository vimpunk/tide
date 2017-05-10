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

    bandwidth_controller& m_bandwidth_controller;

    torrent_settings& m_settings;

    torrent_info m_info;

    // These are all the connected peers. The first upload slots number of peers are
    // ordered according to the choking algorithms rating (i.e. upload rate).
    std::vector<peer_session> m_peer_sessions;

    // Passed to every peer_session.
    std::shared_ptr<piece_picker> m_piece_picker;

    // This is where all current active piece downloads (from any peer in torrent)
    // can be accessed. When this torrent becomes a seeder, the memory for this is
    // released (will no longer need it).
    std::shared_ptr<piece_download_locator> m_piece_download_locator;

    // We aggregate all peer's stats in a torrent wide torrent_info instance.
    std::shared_ptr<torrent_info> m_torrent_info;

    duration m_seed_time;
    duration m_leech_time;
    duration m_active_time;
    duration m_pause_time;

    // This is the original .torrent file of this torrent. It is kept in memory for
    // the piece SHA-1 hashes.
    bmap m_metainfo;

    // A downloaded piece may overlap into an unwanted file, in which case those extra
    // bytes are discarded. But this also means that we must not announce having those
    // pieces as we won't be able to serve some of its bytes, so this bitfield is used
    // to check whether we can announce a piece.
    std::vector<bool> m_wanted_files;

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
