#ifndef TORRENT_TORRENT_HEADER
#define TORRENT_TORRENT_HEADER

//#include "torrent_info.hpp"
#include "torrent_args.hpp"
#include "interval.hpp"
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
class tracker;
class disk_io;

/**
 * This class represents a torrent download/upload. It manages all peer connections
 * associated with a torrent. This is an internal class, user may only interact with
 * torrent indirectly via a torrent_handle.
 */
class torrent
{
    disk_io& m_disk_io;

    // There is one instance of this in engine, which is passed to each peer_session
    // through its torrent, so they can request bandwidth quota.
    bandwidth_controller& m_bandwidth_controller;

    // These are the global settings that is passed to each peer_session. Torrent's
    // settings, however, are in m_info (for settings related to a torrent may be
    // customized for each torrent but session settings and individual peer settings
    // are global).
    const settings& m_global_settings;

    // These are all the connected peers. The first upload slots number of peers are
    // ordered according to the choking algorithms rating (i.e. upload rate).
    std::vector<std::unique_ptr<peer_session>> m_peer_sessions;

    // Trackers are ordered the same way as they were specified in the metainfo file,
    // i.e. the first tracker has the highest priority and is always used unless an
    // error occurs, in which case we try the next. If metainfo didn't have an
    // announce-list, this is a single tracker.
    std::vector<std::shared_ptr<tracker>> m_trackers;

    // This is used for internal stats and info bookkeeping, and is passed to submodules
    // that contribute to stats aggregation.
    std::shared_ptr<torrent_info> m_info;

    // Passed to every peer_session.
    std::shared_ptr<piece_picker> m_piece_picker;

    // This is where all current active piece downloads (from any peer in torrent)
    // can be accessed. When this torrent becomes a seeder, the memory for this is
    // released for optimization as it is no longer needed at that point.
    std::shared_ptr<piece_download_locator> m_piece_downloads;

    // Since torrent may be accessed by user's thread (through torrent_handle), we need
    // mutual exclusion. TODO work this out
    std::mutex m_torrent_mutex;

    // The choke "loop" runs every 10 seconds, reorders the peers according to the choke
    // algorithms peer score and unchokes the top max_upload_slots number of peers, and
    // chokes the rest. Every 30 seconds a single peer is optimistically unchoked to
    // give it a chance and see whether it has better perfromance than the currentr
    // unchoked peers.
    deadline_timer m_choker_timer;
    deadline_timer m_announce_timer;

    // A function that returns true if the first peer_session is favored over the second
    // is used to sort a torrent's peer list such that the peers that we want to unchoke
    // are placed in the front of the list.
    using unchoke_comparator = bool (*)(const peer_session&, const peer_session&);

    // Depending on user set choking algorithm and the torrent state, we have different
    // criteria for picking peers to unchoke, e.g. when we're downloading, the
    // traditional (and default) criterion is a peers upload capacity in the last 20
    // seconds, while when torrent is seeding, peers that have better download capacity
    // are preferred.
    unchoke_comparator m_unchoke_comparator;

    // Counting the number of times the choking algorithm has been invoked. This is done
    // so that every 3rd time we can optimistic_unchoke.
    int m_num_chokes = 0;

    bool m_is_paused = false;
    bool m_is_gracefully_paused = false;
    bool m_is_aborted = false;

    // This is set to true as soon as any change occurs in state/statistics since the
    // last time torrent's state was saved to disk.
    bool m_needs_to_save_state = false;

    time_point m_last_tracker_announcement_time;

    // This is the original .torrent file of this torrent. It is kept in memory for
    // the piece SHA-1 hashes.
    bmap m_metainfo;

public:

    /**
     * This is called for new torrents.
     *
     * NOTE: at this point of execution args is assumed to be checked, file paths
     * sanitized etc, so it is crucial that engine does this.
     */
    torrent(
        torrent_id_t id,
        disk_io& disk_io,
        bandwidth_controller& bandwidth_controller,
        torrent_settings& global_settings,
        std::vector<std::shared_ptr<tracker>> m_trackers,
        torrent_args args
    );

    /** This is called for continued torrents. */
    // TODO
    torrent(
        torrent_id_t id,
        disk_io& disk_io,
        bandwidth_controller& bandwidth_controller,
        torrent_settings& global_settings,
        std::vector<std::shared_ptr<tracker>> m_trackers,
        torrent_state state
    );

    /**
     * Since torrent is not exposed to the public directly, users may interact with a
     * torrent via a torrent_handle, which this function returns of the torrent.
     *
     * If torrent could not be set up successfully, the returned handle is invalid.
     */
    torrent_handle get_handle();

    bool is_paused() const noexcept;
    bool is_running() const noexcept;

    torrent_info info() const;
    void piece_availability(std::vector<int>& piece_map);

    /**
     * gracious_pause should be preferred over pause because it will wait for all
     * current operations to complete before closing connections.
     */
    void pause();
    void gracious_pause();
    void resume();

    /** file_index must be the position of the file in the original .torrent metainfo. */
    void prioritize_file(const int file_index);
    void deprioritize_file(const int file_index);
    void prioritize_piece(const piece_index_t piece);
    void deprioritize_piece(const piece_index_t piece);

    void change_settings(const torrent_settings& settings);

    void force_tracker_announce();

    /**
     * This saves torrent's current state to disk. This is done automatically as well,
     * but can be requested manually here.
     */
    void save_torrent_state();

private:
    
    void initialize_torrent_info(torrent_args& args);

    /**
     * This is the callback provided for each peer_session to call when they finish
     * downloading and veryfing a piece. If the piece was good, this function notifies
     * all our connected peers that we have a new piece available for download.
     * Otherwise the piece is unreserved from the picker to be downloaded again.
     */
    void on_new_piece(const piece_index_t piece, const bool is_valid);

    // -------------
    // -- tracker --
    // -------------

    void make_tracker_announcement();
    void handle_tracker_error(const std::error_code& error, tracker_response response);

    // -------------
    // -- choking --
    // -------------

    /**
     * For good TCP performance it is crucial that the number of upload slots, i.e.
     * unchoked peers that may download from us, is capped. We must also avoid choking
     * and unchoking too quickly (fibrilating), to give peers a chance to prove their
     * worth. Thus the choking algorithm is run every 10 seconds, and unchokes
     * max_upload_slots number of peers, as configured in settings.
     */
    void choke();

    /**
     * In order to potentially find peers that have better upload performance (when
     * we're leeching), or better download performance (when we're seeding) than our
     * current unchoked peers, a random peer is picked every 30 seconds (this should
     * give them sufficient time for us to gauage their performance), however, newly
     * connected peers are three times more likely to be picked as other peers.
     */
    void optimistic_unchoke();

    /**
     * These are the currently supported peer score comparators for the choking
     * algorithm. Before we decide which peers to {un,}choke, m_peer_sessions is sorted
     * according to m_unchoke_comparator, which is one of these functions.
     * Returns true if a is favored over b, false otherwise.
     */
    static bool compare_upload_rate(const peer_session& a, const peer_session& b) noexcept;
    static bool compare_download_rate(const peer_session& a, const peer_session& b) noexcept;

    void handle_disk_error(const std::error_code& error);

    /**
     * Returns an interval of piece indices of the pieces that are, even if partially,
     * in this file.
     */
    interval pieces_in_file(const int file_index) const noexcept;

    enum class log_event
    {
        disk,
        tracker,
        choke
    };

    template<typename... Args>
    void log(const log_event event, const std::string& format, Args&&... args) const;
};

#endif // TORRENT_TORRENT_HEADER
