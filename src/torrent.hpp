#ifndef TORRENT_TORRENT_HEADER
#define TORRENT_TORRENT_HEADER

#include "torrent_storage_handle.hpp"
#include "torrent_info.hpp"
#include "peer_session.hpp"
#include "torrent_args.hpp"
#include "string_view.hpp"
#include "interval.hpp"
#include "bdecoder.hpp"
#include "units.hpp"
#include "time.hpp"

#include <memory>
#include <mutex>
#include <vector>

namespace tide {

class bandwidth_controller;
class torrent_settings;
class endpoint_filter;
class piece_download;
class piece_picker;
class event_channel;
class tracker_entry;
class disk_io;
struct settings;

/**
 * This class represents a torrent download/upload. It manages all peer connections
 * associated with a torrent. This is an internal class, user may only interact with
 * torrent indirectly via a torrent_handle.
 *
 * It must not be destructed as long as there are outstanding async operations run by it.
 *
 * NOTE: torrent must be stored in a shared_ptr because it uses enable_shared_from_this
 * to pass a shared_ptr to itself to disk_io for async disk operations so as to ensure
 * that async operations not completed before shutting down don't refer to invalid
 * memory.
 */
class torrent : protected std::enable_shared_from_this<torrent>
{
    // This is main network io_service that runs everything network related. It's used
    // to instantiate peer_sessions.
    asio::io_service& m_ios;

    // Torrent only interacts with disk_io to allocate itself if it's a new torrent, or
    // to verify the previously downloaded files' integrity, if it's continued. Then, it
    // periodically saves its resume state to disk, but other than that, a reference is
    // passed to each peer_session.
    disk_io& m_disk_io;

    // There is one instance of this in engine, which is passed to each peer_session
    // through its torrent, so they can request bandwidth quota.
    bandwidth_controller& m_bandwidth_controller;

    // These are the global settings that is passed to each peer_session. Torrent's
    // settings, however, are in m_info (for settings related to a torrent may be
    // customized for each torrent but session settings and individual peer settings
    // are global).
    const settings& m_global_settings;

    // User may decide to block certain IPs or ports, and may decide have various
    // policies regarding local networks (TODO), so before registering the availability
    // of a peer, it first must be passed to this filter to see if we can connect to it.
    endpoint_filter& m_endpoint_filter;

    // Alerts to user are sent via this.
    event_channel& m_event_channel;

    // Some storage specific operations are done directly via torrent's storage, but
    // the actual disk interaction is done indirectly through m_disk_io.
    torrent_storage_handle m_storage;

    // These are all the connected peers. The first upload slots number of peers are
    // ordered according to the choking algorithms rating (i.e. upload rate).
    std::vector<std::shared_ptr<peer_session>> m_peer_sessions;

    // Trackers are ordered the same way as they were specified in the metainfo file,
    // i.e. the first tracker has the highest priority and is always used unless an
    // error occurs, in which case we try the next. If metainfo didn't have an
    // announce-list, this is a single tracker.
    // Note that the tiers (list of list of trackers) has been flattened into a single
    // list for better memory layout.
    std::vector<tracker_entry> m_trackers;

    // All peer endpoints returned in a tracker announce response are stored here.
    // When we need to connect to peers, we first check whether there are any available
    // here, and if not, only then do we request more from the tracker. As soon as a
    // connection is being established to peer, its endpoint is removed from this
    // list and a corresponding peer_session is added to m_peer_sessions.
    std::vector<tcp::endpoint> m_available_peers;

    // This is used for internal stats and state bookkeeping, and is passed to each
    // peer_session, each of which updates the network and disk related fields, so
    // torrent doesn't have to periodically loop over each peer_session to collect
    // stats. This way stats collection is relatively inexpensive.
    std::shared_ptr<torrent_info> m_info;

    // Passed to every peer_session, tracks the availability of every piece in the swarm
    // and decides, using this knowledge, which piece to pick next (which by default is
    // the rarest piece in the swarm, unless sequential download is set).
    std::shared_ptr<piece_picker> m_piece_picker;

    // This is where all current active piece downloads (from any peer in torrent)
    // can be accessed, thus this is passed to every peer_session so that thay may help
    // others to complete their piece download and add their own. When this torrent
    // becomes a seeder, the memory for this is released for optimization as at that
    // point it's no longer needed.
    // TODO since we're searching, adding and removing here all the time, perhaps
    //  this should be a std::set despite the bad effect on cache?
    std::shared_ptr<std::vector<std::shared_ptr<piece_download>>> m_downloads;

    // Since torrent may be accessed by user's thread (through torrent_handle), we need
    // mutual exclusion. TODO work this out
    mutable std::mutex m_torrent_mutex;

    // The update cycle runs every second (TODO), cleans up finished peer_sessions,
    // connects to new peers, if necessary, and does general housekeeping. Also, every
    // ten seconds it invokes the choking algorithm, which reorders the peers according
    // to the choke algorithms peer score and unchokes the top max_upload_slots number
    // of peers, and chokes the rest, but every thirty seconds the optimistic_unchoke
    // algorithm is run.
    // However, if torrent is paused or there are no peers, the update cycle does not
    // run, because there isn't anything that needs to be updated. As soon as it's 
    // continued and connects to peers, it is reinstated.
    deadline_timer m_update_timer;

    // The announce cycle runs separately, because even if we aren't connected to any
    // peers (though if torrent is paused, this doesn't run either), we periodically
    // contact tracker in hopes of acquiring peers.
    deadline_timer m_announce_timer;

    // A function that returns true if the first peer_session is favored over the second
    // is used to sort a torrent's peer list such that the peers that we want to unchoke
    // are placed in the front of the list.
    using unchoke_comparator = bool (*)(const peer_session&, const peer_session&);

    // Depending on user set choking algorithm and the torrent state, we have different
    // criteria for picking peers to unchoke, e.g. when we're downloading, the
    // traditional (and default) criterion is a peer's upload capacity in the last 20
    // seconds, while when torrent is seeding, peers that have better download capacity
    // are preferred.
    unchoke_comparator m_unchoke_comparator;

    bool m_is_paused = false;
    bool m_is_aborted = false;

    // This is set to true as soon as any change occurs in state/statistics since the
    // last time torrent's state was saved to disk, which means that we need to persist
    // torrent state to disk.
    // The events that set this flag:
    // * new piece downloaded
    // * recurring 30 second timeout
    // *
    bool m_is_state_changed = false;

    // This is the original .torrent file of this torrent. It is kept in memory for
    // m_piece_hashes.
    bmap m_metainfo;
    string_view m_piece_hashes;

public:

    // TODO add alert/event channel as param
    /**
     * This is called for new torrents. It issues an asynchronous tracker announce to
     * get peers to which we can connect, then issues an async (TODO or sync) disk_io
     * torrent allocation job that sets up the download directory strucure and creates
     * an internal torrent entry in disk_io. torrent_args::save_path should at this
     * point be verified, but there could still be an error in allocating, such as if
     * we have no permission to write to the destination path or space has run out.
     *
     * NOTE: at this point of execution args is assumed to be checked, file paths
     * sanitized etc, so it is crucial that engine do this.
     */
    torrent(torrent_id_t id, asio::io_service& ios, disk_io& disk_io,
        bandwidth_controller& bandwidth_controller, torrent_settings& global_settings,
        std::vector<tracker_entry> trackers, endpoint_filter& endpoint_filter,
        event_channel& event_channel, torrent_args args);

    /**
     * This is called for continued torrents. engine retrieves the resume state data and
     * constructs just enough information to instantiate the torrent, but the rest of
     * the work is done by torrent. First, torrent must launch a disk job to verify the
     * integrity of the previously established storage structure (directories and files).
     * If storage is found to be corrupted, torrent halts execution and posts an alert
     * to user for them to sort this out. Though at the same time a tracker announce is
     * started in the assumption that storage is intact (which should be in the majority
     * of cases) to save time, after which regular execution commences.
     */
    torrent(torrent_id_t id, asio::io_service& ios, disk_io& disk_io,
        bandwidth_controller& bandwidth_controller, torrent_settings& global_settings,
        std::vector<tracker_entry> trackers, endpoint_filter& endpoint_filter,
        event_channel& event_channel, torrent_args args);

    /**
     * Since torrent is not exposed to the public directly, users may interact with a
     * torrent via a torrent_handle, which this function returns for this torrent.
     *
     * If torrent could not be set up successfully, the returned handle is invalid.
     */
    torrent_handle get_handle();
    torrent_storage_handle get_storage_handle();

    /**
     * It's unknown to which torrent incoming connections belong, so at first they
     * belong to no torrent until peer's info_hash is received. After this, peer_session
     * calls the torrent attacher handler provided by engine passing it peer's info_hash,
     * after which engine attempts to match it to existing torrents' info_hash, and if
     * found, invokes this function of torrent. At this point peer is filtered by engine.
     */
    void attach_peer_session(std::shared_ptr<peer_session> session);

    std::vector<peer_session::stats> peer_stats() const;
    void peer_stats(std::vector<peer_session::stats>& s) const;
    std::vector<peer_session::detailed_stats> detailed_peer_stats() const;
    void detailed_peer_stats(std::vector<peer_session::detailed_stats>& s) const;

    torrent_info info() const;
    void info(torrent_info& info) const;
    const info_hash& info_hash() const noexcept;
    void piece_availability(std::vector<int>& piece_map);

    seconds total_seed_time() const noexcept;
    seconds total_leech_time() const noexcept;
    seconds total_active_time() const noexcept;

    time_point download_started_time() const noexcept;
    time_point download_ended_time() const noexcept;

    bool is_paused() const noexcept;
    bool is_running() const noexcept;
    bool is_leech() const noexcept;
    bool is_seed() const noexcept;

    /**
     * pause should be preferred over abort as it will wait for all current operations
     * to complete before closing connections (e.g. mid-transmission blocks will be
     * completed, so will storage checks) and trackers are notified of our leave.
     */
    void pause();
    void abort();
    void resume();

    /** file_index must be the position of the file in the original .torrent metainfo. */
    void prioritize_file(const int file_index);
    void deprioritize_file(const int file_index);
    void prioritize_piece(const piece_index_t piece);
    void deprioritize_piece(const piece_index_t piece);

    void apply_settings(const torrent_settings& settings);

    void set_max_upload_slots(const int n);
    void set_max_upload_rate(const int n);
    void set_max_download_rate(const int n);
    void set_max_connections(const int n);
    int max_upload_slots() const noexcept;
    int max_upload_rate() const noexcept;
    int max_download_rate() const noexcept;
    int max_connections() const noexcept;

    /**
     * Announces to trackers are usually spaced fixed intervals apart (this is set by
     * the tracker) and torrent doesn't violate this. However user may request an
     * announce, in which case this will override the tracker timer.
     */
    void force_tracker_announce();

    /**
     * This saves torrent's current state to disk. This is done automatically as well,
     * but can be requested manually here.
     */
    void save_torrent_state();

    void force_storage_integrity_check();
    void force_resume_data_check();

    /**
     * If torrent is multi-file, the root directory in which the files are stored is
     * renamed, otherwise nothing happens.
     *
     * Upon completing the operation, an alert is posted.
     */
    void rename_torrent(std::string name);
    void move_torrent(std::string new_path);

    /** This will erase all downloaded data and metadata (resume state) as well. */
    void erase_torrent_files();

private:

    void initialize_torrent_info(const torrent_id_t id, torrent_args& args);

    /**
     * This is the main update cycle that is invoked every second. It removes
     * peer_sessions that are finished, connects to peers, if necessary, launches scrape
     * and announce requests if not enough peers are available, and invokes the choking
     * algorithm every 10 seconds.
     */
    void update(const std::error_code& error = std::error_code());

    /**
     * This is called when all pieces that user wanted to download have been downloaded.
     * Torrent becomes a seeder now, even if it doesn't have 100% of the torrent.
     */
    void on_download_complete();

    /**
     * This is the callback provided for each peer_session to call when they finish
     * downloading and veryfing a piece. If the piece was good, this function notifies
     * all our connected peers that we have a new piece available for download.
     * Otherwise the piece is unreserved from the picker to be downloaded again.
     *
     * Note that the piece_download instance needs to be passed to this handler as a
     * peer may be on parole, which means that it claims a piece_download and does not
     * put it in m_downloads, so torrent would have no way of finding it, which
     * it needs to do to post the hash result through piece_download to the peers that 
     * participated in the downloaded.
     */
    void on_new_piece(piece_download& download, const bool is_valid);
    void handle_valid_piece(piece_download& download);
    void handle_corrupt_piece(piece_download& download);
    void ban_peer(peer_session& peer);

    /**
     * peer_sessions that are finished (connection is closed with no intentions of
     * restarting) mark themselves as such, and when we want to work with peer_sessions
     * we first have to remove the dead entries.
     TODO running an O(n) algorithm and potential reallocation may be expensive if tun
     too frequently -- profile how often it's run
     */
    void remove_finished_peer_sessions();
    void on_peer_session_finished(peer_session& session);

    void connect_peers();
    void connect_peer(tcp::endpoint& peer);
    void close_peer_session(peer_session& session);

    // -------------
    // -- tracker --
    // -------------

    bool wants_peers() const noexcept;

    /**
     * If event is `none` or `started`, we announe to a single most suitable tracker,
     * otherwise (event is `completed` or `stopped`) we announce to all trackers to
     * torrent has announced in the past.
     */
    void announce_to_tracker(
        tracker_request::event_t event = tracker_request::event_t::none,
        const bool force = false);
    void on_announce_response(tracker_entry& tracker_entry,
        const std::error_code& error, tracker_response response);
    tracker_request create_tracker_request(
        tracker_request::event_t event) const noexcept;

    /**
     * Adds a peer returned in an announce response if we're not already connected to
     * peer, if it's not us, and if m_endpoint_filter allows it.
     */
    void add_peer(tcp::endpoint peer);

    /**
     * Scraping is done when we just want information about a torrent (how many seeders,
     * leechers, and received 'completed' events). TODO purpose of this?
     */
    void scrape_tracker();
    void on_scrape_response(const std::error_code& error, scrape_response response);

    /**
     * Trackers are ordered in tiers, and the first tracker in the first tier is used
     * until it times out or results in an error, then we moved onto the next tracker
     * and so on. If no error occured with any of the trackers so far, this will
     * always return *m_trackers[0].
     */
    tracker_entry& pick_tracker(const bool force);
    bool can_announce_to(const tracker_entry& t) const noexcept;

    // -------------
    // -- storage --
    // -------------

    void on_torrent_allocated(const std::error_code& error,
        torrent_storage_handle storage);
    void handle_disk_error(const std::error_code& error);
    void check_storage_integrity();
    void on_storage_integrity_checked(const std::error_code& error);

    torrent_state write_torrent_state() const;

    void lost_pieces(std::vector<piece_index_t> pieces);

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
    void unchoke();

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
    struct choke_ranker
    {
        static bool upload_rate_based(
            const peer_session& a, const peer_session& b) noexcept;
        static bool download_rate_based(
            const peer_session& a, const peer_session& b) noexcept;
    };

    // -----------
    // -- utils --
    // -----------

    enum class log_event
    {
        disk,
        tracker,
        choke
    };

    template<typename... Args>
    void log(const log_event event, const std::string& format, Args&&... args) const;
};

inline bool torrent::is_leech() const noexcept
{
    return !is_seed();
}

inline bool torrent::is_seed() const noexcept
{
    return m_info.state[torrent_info::state_t::seeding];
}

inline torrent_handle torrent::get_handle() noexcept
{
    return torrent_handle(this);
}

} // namespace tide

#endif // TORRENT_TORRENT_HEADER
