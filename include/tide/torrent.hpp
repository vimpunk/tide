#ifndef TIDE_TORRENT_HEADER
#define TIDE_TORRENT_HEADER

#include "bdecode.hpp"
#include "bencode.hpp"
#include "error_code.hpp"
#include "interval.hpp"
#include "log.hpp"
#include "peer_session.hpp"
#include "piece_picker.hpp"
#include "rate_limiter.hpp"
#include "socket.hpp"
#include "string_view.hpp"
#include "time.hpp"
#include "torrent_args.hpp"
#include "torrent_handle.hpp"
#include "torrent_info.hpp"
#include "torrent_storage_handle.hpp"
#include "tracker.hpp"
#include "types.hpp"

#include <memory>
#include <mutex>
#include <vector>

namespace tide {

class torrent_settings;
class endpoint_filter;
class piece_download;
class alert_queue;
class disk_io;
struct settings;
struct engine_info;

/**
 * This class represents a torrent download/upload. It manages all peer
 * connections associated with a torrent. This is an internal class, user may
 * only interact with torrent indirectly via a `torrent_handle`.
 *
 * `torrent` is NOT thread-safe, i.e. the user thread must never call any of its
 * methods directly (this means `engine` must not call `torrent` methods within
 * methods invoked on the user thread). For this, `torrent_handle` has been
 * devised, which is a thread-safe interface for `torrent`.
 *
 * NOTE: `torrent` must be stored in a `std::shared_ptr` because it uses
 * `std::enable_shared_from_this` to pass a `std::shared_ptr` to itself to
 * `disk_io` for async disk operations so as to ensure that async operations not
 * completed before shutting down don't refer to invalid memory.
 */
class torrent : public std::enable_shared_from_this<torrent>
{
    friend class torrent_frontend;
    friend class torrent_handle;

    // This is main network `io_context` that runs everything network related.
    // It's used to instantiate `peer_session`s.
    asio::io_context& ios_;

    // Torrent only interacts with `disk_io` to allocate itself if it's a new
    // torrent, or to verify previously downloaded files' integrity, if it's
    // continued. Then, it periodically saves its resume state to disk, but
    // other than that, a reference is passed to each `peer_session` through
    // a `torrent_frontend` instance.
    disk_io& disk_io_;

    // `global_rate_limiter_` is `engine` wide and neither `torrent` nor its
    // `peer_session`s refer to it directly. Instead, `local_rate_limiter_` acts
    // as a frontend to `global_rate_limiter_` and applies torrent specific rate
    // limits.
    rate_limiter& global_rate_limiter_;
    torrent_rate_limiter local_rate_limiter_;

    // These are the global settings that are passed to each `peer_session`.
    // Torrent's settings, however, are in info_ (for settings related to
    // a torrent may be customized for each torrent but session settings and
    // individual peer settings are global).
    const settings& global_settings_;

    // Engine related stats and info may be accessed via this reference. It
    // contains a few important bits, such as the global maximum number of
    // connections, which may never be exceeded even if a `torrent` has space
    // for more connections.  TODO since we're only using
    // engine_info::num_connections, just take a reference to that value, and
    // not the entire info as we don't need it.
    engine_info& global_info_;

    // User may decide to block certain IPs or ports, and may decide have
    // various policies regarding local networks (TODO), so before registering
    // the availability of a peer, it first must be passed to this filter to see
    // if we can connect to it.
    endpoint_filter& endpoint_filter_;

    // Alerts to user are sent via this.
    alert_queue& alert_queue_;

    // Some storage specific operations are done directly via torrent's storage,
    // but the actual disk interaction is done indirectly through `disk_io_`.
    torrent_storage_handle storage_;

    // These are all the connected peers. The first min(peer_sessions_.size(),
    // settings::max_upload_slots) number of peers are ordered according to the
    // choke algorithm's rating.
    std::vector<std::shared_ptr<peer_session>> peer_sessions_;

    // If torrent is stopped, `peer_session`s are not erased, but put here, as
    // we might be able to reconnect them.
    // std::vector<std::shared_ptr<peer_session>> stopped_peer_sessions_;

    // Trackers are ordered the same way as they were specified in the metainfo
    // file, i.e. the first tracker has the highest priority and is always used
    // unless an error occurs, in which case we try the next. If metainfo didn't
    // have an announce-list, this is a single tracker.
    // Note that the tiers (list of list of trackers) has been flattened into
    // a single list for better memory layout.
    std::vector<tracker_entry> trackers_;

    // All peer endpoints returned in a tracker announce response are stored
    // here.  When we need to connect to peers, we first check whether there are
    // any available here, and if not, only then do we request more from the
    // tracker. As soon as a connection is being established to peer, its
    // endpoint is removed from this list and a corresponding `peer_session` is
    // added to `peer_sessions_`.
    std::vector<tcp::endpoint> available_peers_;

    // Passed to every `peer_session`, tracks the availability of every piece in
    // the swarm and decides, using this knowledge, which piece to pick next
    // (which by default is the rarest piece in the swarm, unless sequential
    // download is set).
    piece_picker piece_picker_;

    // This is where all current active piece downloads (from any peer in
    // torrent) can be accessed, thus this is passed to every `peer_session` so
    // that thay may help others to complete their piece download and add their
    // own. When this torrent becomes a seeder, the memory for this is released
    // for optimization as at that point it's no longer needed.
    std::vector<std::shared_ptr<piece_download>> downloads_;

    // This is used for internal stats and state bookkeeping, and is passed to
    // each `peer_session`, each of which updates the network and disk related
    // fields, so torrent doesn't have to periodically loop over each
    // `peer_session` to collect stats. This way stats collection is relatively
    // inexpensive.
    torrent_info info_;

    // Since torrent is exposed to user through `torrent_handle` and since
    // torrent runs on a different thread than where these query functions are
    // likely to be called, it's public query methods need to enforce mutual
    // exclusion on their data. So as not to lock a mutex every time
    // a `peer_session` or torrent's internals work with info_, a copy of info_
    // is kept, and thus acquiring a mutex is only necessary while handling this
    // copy. Moreover, it need only be updated on demand, further decreasing the
    // use of mutexes.
    torrent_info ts_info_;
    mutable std::mutex ts_info_mutex_;

    // The update cycle runs every second, cleans up finished `peer_session`s,
    // connects to new peers, if necessary, makes tracker annoucnes, and does
    // general housekeeping.  Also, every ten seconds it invokes the choking
    // algorithm, which reorders the peers according to the choke algorithms
    // peer score and unchokes the top `max_upload_slots` number of peers, and
    // chokes the rest, but every thirty seconds the `optimistic_unchoke`
    // algorithm is run.  It runs even when we have no peers, because we still
    // need to update statistics (seed/leech time, throughput rates and other).
    // This is stopped when torrent is stopped.
    deadline_timer update_timer_;

    // A function that returns true if the first `peer_session` is favored over
    // the second is used to sort a torrent's peer list such that the peers that
    // we want to unchoke are placed in the front of the list.
    using unchoke_comparator = bool (*)(const peer_session&, const peer_session&);

    // Depending on user set choking algorithm and the torrent state, we have
    // different criteria for picking peers to unchoke, e.g. when we're
    // downloading, the traditional (and default) criterion is a peer's upload
    // capacity in the last 20 seconds, while when torrent is seeding, peers
    // that have better download capacity are preferred.
    unchoke_comparator unchoke_comparator_;

    // This is set to true as soon as any change occurs in state/statistics
    // since the last time torrent's state was saved to disk, which means that
    // we need to persist torrent state to disk.
    // The events that set this flag:
    // * new piece downloaded
    // * recurring 30 second timeout
    // *
    bool has_state_changed_ = false;

    // TODO don't store this here
    std::string piece_hashes_;

public:
    /**
     * This is called for new torrents. It applies `args` and sets the
     * `piece_picker` strategy.
     *
     * NOTE: at this point of execution args is assumed to be checked, file
     * paths sanitized etc, so it is crucial that `engine` do this.
     */
    torrent(torrent_id_t id, asio::io_context& ios, disk_io& disk_io,
            rate_limiter& global_rate_limiter, const settings& global_settings,
            engine_info& global_info, std::vector<tracker_entry> trackers,
            endpoint_filter& endpoint_filter, alert_queue& alert_queue,
            torrent_args args);

    /**
     * This is called for continued torrents. `engine` retrieves the resume
     * state data and constructs just enough information to instantiate the
     * torrent, but the rest of the work is done by torrent, albeit only after
     * invoking `start`.
     */
    torrent(torrent_id_t id, asio::io_context& ios, disk_io& disk_io,
            rate_limiter& global_rate_limiter, const settings& global_settings,
            engine_info& global_info, std::vector<tracker_entry> trackers,
            endpoint_filter& endpoint_filter, alert_queue& alert_queue, bmap resume_data);

    /**
     * Since torrent is not exposed to the public directly, users may interact
     * with a torrent via a `torrent_handle`, which this function returns for
     * this torrent.
     *
     * If torrent could not be set up successfully, the returned handle is
     * invalid.
     */
    torrent_handle get_handle() noexcept;
    torrent_storage_handle get_storage_handle() noexcept;

    /**
     * The constructor only sets up torrent but does not start it, this has to
     * be done explicitly; or if torrent has been stopped it can be resumed with
     * this.
     *
     * If the torrent is new: It issues an asynchronous tracker announce to get
     * peers to which we can connect, then issues an synchronous `disk_io`
     * torrent allocation job that sets up the download directory strucure and
     * creates an internal torrent entry in `disk_io`.  torrent_args::save_path
     * should at this point be verified, but there could still be an error in
     * allocating, such as if we have no permission to write to the destination
     * path or space has run out.
     *
     * If the torrent is continued:
     * First, torrent must launch an async disk job to verify the integrity of
     * the previously established storage structure (directories and files). If
     * storage i found to be corrupted, torrent halts execution and posts an
     * alert to user for them to sort this out. Though at the same time an async
     * tracker announce is started in the assumption that storage is intact
     * (which should be in the majority of cases) to save time, after which
     * regular execution commences.
     */
    void start();

    /**
     * `stop` should be preferred over `abort` as it will wait for all current
     * operations to complete before closing connections (e.g. mid-transmission
     * blocks will be completed, so will storage checks) and trackers are
     * notified of our leave.
     */
    void stop();
    void abort();

    /**
     * It's unknown to which torrent incoming connections belong, so at first
     * they belong to no torrent until peer's `info_hash` is received. After
     * this, `peer_session` calls the torrent attacher handler provided by
     * `engine` passing it peer's info_hash, after which `engine` attempts to
     * match it to an existing torrents' info_hash, and if found, invokes this
     * function. At this point peer is filtered by `engine`.
     * TODO this comment is a mess, rewrite.
     */
    void attach_peer_session(std::shared_ptr<peer_session> session);

    /**
     * `file_index` must be the position of the file in the original .torrent
     * metainfo.
     */
    void make_file_top_priority(const int file_index);
    void prioritize_file(const int file_index);
    void deprioritize_file(const int file_index);
    void prioritize_piece(const piece_index_t piece);
    void deprioritize_piece(const piece_index_t piece);

    /**
     * If torrent is auto managed, it means `engine` will manage its settings
     * (cap its throughput rates and apply other fields using the global
     * defaults in `settings::torrent`), whereas if it's not, torrent has its
     * own settings that override the global defaults.
     */
    bool is_auto_managed() const noexcept;

    /** If torrent is not already auto managed, this makes it so. */
    void auto_manage() noexcept;

    void apply_settings(const torrent_settings& s);

    /*
    const torrent_settings& settings() const noexcept
    {
        if(is_auto_managed())
            return global_settings.torrent;
        else
            return info_.settings;
    }
    TODO
    */

    void set_max_upload_slots(const int n);
    void set_max_upload_rate(const int n);
    void set_max_download_rate(const int n);
    void set_max_connections(const int n);

    int max_upload_slots() const noexcept;
    int max_download_rate() const noexcept;
    int max_upload_rate() const noexcept;
    int max_connections() const noexcept;

    /**
     * Closes `n` or fewer peer connections and returns the number of
     * connections that were closed.
     */
    int close_n_connections(const int n);

    /*
    std::vector<peer_session::stats> peer_stats() const;
    void peer_stats(std::vector<peer_session::stats>& s) const;
    std::vector<peer_session::detailed_stats> detailed_peer_stats() const;
    void detailed_peer_stats(std::vector<peer_session::detailed_stats>& s) const;

    void piece_availability(std::vector<int>& piece_map);
    */

    const torrent_info& info() const;

    int download_rate() const noexcept;
    int upload_rate() const noexcept;

    torrent_id_t id() const noexcept;
    const sha1_hash& info_hash() const noexcept;

    seconds total_seed_time() const noexcept;
    seconds total_leech_time() const noexcept;
    seconds total_active_time() const noexcept;

    bool has_reached_share_ratio_limit() const noexcept;
    bool has_reached_share_time_ratio_limit() const noexcept;
    bool has_reached_seed_time_limit() const noexcept;

    time_point download_started_time() const noexcept;
    time_point download_finished_time() const noexcept;

    /** Total peers includes connected and available (i.e. not connected) peers. */
    int total_peers() const noexcept;
    int num_connected_peers() const noexcept;
    int num_seeders() const noexcept;
    int num_leechers() const noexcept;

    bool is_stopped() const noexcept;
    bool is_running() const noexcept;
    bool is_leech() const noexcept;
    bool is_seed() const noexcept;

    /**
     * This saves torrent's current state to disk. This is done automatically if
     * a change to torrent's state occurs, but user may request it manually. It
     * will not issue a `disk_io` job if torrent's state has not changed since
     * the last save.
     */
    void save_resume_data();

    /**
     * Announces to trackers are usually spaced fixed intervals apart (this is
     * set by the tracker) and `torrent` tries not to violate this. However user
     * may request an announce, in which case this will override the tracker
     * timer.
     */
    void force_tracker_announce();
    void force_tracker_announce(string_view url);

    void force_storage_integrity_check();
    void force_resume_data_check();

    /**
     * If torrent is multi-file, the root directory in which the files are
     * stored is renamed, otherwise nothing happens.
     *
     * Upon completing the operation, an alert is posted.
     */
    void rename_torrent(std::string name);
    void move_torrent(std::string new_path);

    /** This will erase all downloaded data and metadata (resume state) as well. */
    void erase_torrent_files();

private:
    /** Initializes fields common to both constructors. */
    torrent(torrent_id_t id, const int num_pieces, asio::io_context& ios,
            disk_io& disk_io, rate_limiter& rate_limiter, const settings& global_settings,
            engine_info& engine_info, std::vector<tracker_entry> trackers,
            endpoint_filter& endpoint_filter, alert_queue& alert_queue);

    void apply_torrent_args(torrent_args& args);

    /**
     * This is the main update cycle that is invoked every second. It removes
     * `peer_session`s that are finished, connects to peers, if necessary,
     * launches scrape and announce requests if not enough peers are available,
     * and invokes the choking algorithm every 10 seconds and so on.
     * It only runs if there are active or connecting peer sessions available,
     * otherwise there is nothing to update. If we get from tracker more peers
     * to connect, the update cycle is reinstated.
     */
    void update(const error_code& error = error_code());

    /**
     * Copies the parts of info_ into ts_info_ that change (i.e. no redundant
     * copies of constants structures such as the `info_hash`, files etc are
     * done).
     */
    void update_thread_safe_info();

    int num_connectable_peers() const noexcept;

    /**
     * Checks whether the current number of connected peers is such that we need
     * to connect more peers.
     */
    bool should_connect_peers() const noexcept;

    /** Checks whether we need to request peers from tracker. */
    bool needs_peers() const noexcept;

    /**
     * This is called when all pieces that user wanted to download have been
     * downloaded.  Torrent becomes a seeder now, even if it doesn't have 100%
     * of the torrent.
     */
    void on_download_complete();

    /**
     * This is the callback provided for each `peer_session` to call when they
     * finish downloading and veryfing a piece. If the piece was good, this
     * function notifies all our connected peers that we have a new piece
     * available for download.  Otherwise the piece is unreserved from the
     * picker to be downloaded again.
     *
     * Note that the piece_download instance needs to be passed to this handler
     * as a peer may be on parole, which means that it claims a piece_download
     * and does not put it in downloads_, so torrent would have no way of
     * finding it, which it needs to do to post the hash result through
     * piece_download to the peers that participated in the downloaded.
     */
    void on_new_piece(piece_download& download, const bool is_valid);
    void handle_valid_piece(piece_download& download);
    void handle_corrupt_piece(piece_download& download);
    void ban_peer(peer_session& peer);

    /**
     * `peer_session`s that are finished (connection is closed with no
     * intentions of restarting) mark themselves as such, and when we want to
     * work with `peer_sessions_` we first have to remove the dead entries.
     *
     * TODO updated
     */
    void remove_finished_peer_sessions();

    /**
     * This is invoked by each disconnected `peer_session` through its
     * `torrent_frontend` instance.
     */
    void on_peer_session_stopped(peer_session& session);

    void connect_peers();
    void connect_peer(tcp::endpoint& peer);
    void close_peer_session(peer_session& session);

    // -------
    // tracker
    // -------

    /**
     * If event is `none` or `started`, we announe to a single most suitable
     * tracker, otherwise (event is `completed` or `stopped`) we announce to all
     * trackers to which torrent we've announced in the past.
     */
    void announce(const int event = tracker_request::none, const bool force = false);

    tracker_request prepare_tracker_request(const int event) const noexcept;
    int calculate_num_want() const noexcept;

    void on_announce_response(tracker_entry& tracker, const error_code& error,
            tracker_response response, const int event);
    void on_announce_error(
            tracker_entry& tracker, const error_code& error, const int event);

    /**
     * Adds a peer returned in an announce response if we're not already
     * connected to it, if it's not already in available_peers_, if it's not us,
     * and if endpoint_filter_ allows it.
     */
    void add_peer(tcp::endpoint peer);

    /**
     * Scraping is done when we just want information about a torrent (how many
     * seeders, leechers, and received 'completed' events). TODO purpose of
     * this?
     */
    void scrape_tracker();
    void on_scrape_response(const error_code& error, scrape_response response);

    /**
     * Trackers are ordered in tiers, and the first tracker in the first tier is
     * used until it times out or results in an error, then we moved onto the
     * next tracker and so on. If no error occured with any of the trackers so
     * far, this will always return *trackers_[0].
     * TODO return an iterator
     */
    tracker_entry* pick_tracker(const bool force);
    bool can_announce_to(const tracker_entry& t) const noexcept;
    bool can_force_announce_to(const tracker_entry& t) const noexcept;

    // -------------
    // -- storage --
    // -------------

    void on_torrent_allocated(const error_code& error, torrent_storage_handle storage);
    void handle_disk_error(const error_code& error);
    void check_storage_integrity();
    void on_storage_integrity_checked(const error_code& error);

    bool should_save_resume_data() const noexcept;
    void on_resume_data_saved(const error_code& error);

    bmap_encoder create_resume_data() const;
    void restore_resume_data(const bmap& resume_data);

    void lost_pieces(std::vector<piece_index_t> pieces);

    // -------
    // choking
    // -------

    /** Places n candidates to be unchoked at the beginning of `peer_sessions_`. */
    void sort_unchoke_candidates(const int n);
    int num_to_unchoke(const bool unchoke_optimistically) const noexcept;

    /**
     * For good TCP performance it is crucial that the number of upload slots,
     * i.e.  unchoked peers that may download from us, is capped. We must also
     * avoid choking and unchoking too quickly (fibrilating), to give peers
     * a chance to prove their worth. Thus the choking algorithm is run every 10
     * seconds, and unchokes min(settings::max_upload_slots,
     * peer_sessions_.size()) number of peers.
     */
    void unchoke();

    /**
     * In order to potentially find peers that have better upload performance
     * (when we're leeching), or better download performance (when we're
     * seeding) than our current unchoked peers, a random peer is picked every
     * 30 seconds (this should give them sufficient time for us to gauage their
     * performance), however, newly connected peers are three times more likely
     * to be picked as other peers. This is to ensure that new peers have
     * something to share and to cultivate a greater spread of pieces among all
     * peers so more peers can participate in the upload (otherwise only the
     * four best uploaders would be uploading to each other).
     */
    void optimistic_unchoke();

    /**
     * These are the currently supported peer score comparators for the choking
     * algorithm. Before we decide which peers to {un,}choke, peer_sessions_ is
     * sorted according to unchoke_comparator_, which is one of these functions.
     *
     * Returns true if a is favored over b, false otherwise.
     */
    struct choke_ranker
    {
        static bool upload_rate_based(
                const peer_session& a, const peer_session& b) noexcept;
        static bool download_rate_based(
                const peer_session& a, const peer_session& b) noexcept;
    };

    // -----
    // utils
    // -----

    enum class log_event
    {
        update,
        download,
        upload,
        disk,
        tracker,
        choke,
        peer
    };

    template <typename... Args>
    void log(const log_event event, const char* format, Args&&... args) const;
    template <typename... Args>
    void log(const log_event event, const log::priority priority, const char* format,
            Args&&... args) const;
};

inline bool torrent::is_auto_managed() const noexcept
{
    return info_.is_auto_managed;
}

inline int torrent::max_upload_slots() const noexcept
{
    return info_.settings.max_upload_slots;
}

inline int torrent::max_upload_rate() const noexcept
{
    return info_.settings.max_upload_rate;
}

inline int torrent::max_download_rate() const noexcept
{
    return info_.settings.max_download_rate;
}

inline int torrent::max_connections() const noexcept
{
    return info_.settings.max_connections;
}

inline const torrent_info& torrent::info() const
{
    return info_;
}

inline int torrent::download_rate() const noexcept
{
    return info_.download_rate.rate();
}
inline int torrent::upload_rate() const noexcept
{
    return info_.upload_rate.rate();
}

inline torrent_id_t torrent::id() const noexcept
{
    return info_.id;
}
inline const sha1_hash& torrent::info_hash() const noexcept
{
    return info_.info_hash;
}

inline seconds torrent::total_seed_time() const noexcept
{
    return info_.total_seed_time;
}

inline seconds torrent::total_leech_time() const noexcept
{
    return info_.total_leech_time;
}

inline seconds torrent::total_active_time() const noexcept
{
    return total_seed_time() + total_leech_time();
}

inline bool torrent::has_reached_share_ratio_limit() const noexcept
{
    return global_settings_.share_ratio_limit != values::none
            && info_.total_uploaded_piece_bytes / info_.total_downloaded_piece_bytes
            >= global_settings_.share_ratio_limit;
}

inline bool torrent::has_reached_share_time_ratio_limit() const noexcept
{
    return global_settings_.share_time_ratio_limit != values::none
            && total_seed_time() / total_leech_time()
            >= global_settings_.share_time_ratio_limit;
}

inline bool torrent::has_reached_seed_time_limit() const noexcept
{
    // TODO is seconds(0) not a valid seed_time_limit value?
    return global_settings_.seed_time_limit != seconds(0)
            && total_seed_time() >= global_settings_.seed_time_limit;
}

inline time_point torrent::download_started_time() const noexcept
{
    return info_.download_started_time;
}

inline time_point torrent::download_finished_time() const noexcept
{
    return info_.download_finished_time;
}

inline int torrent::total_peers() const noexcept
{
    return peer_sessions_.size() + available_peers_.size();
}

inline int torrent::num_connected_peers() const noexcept
{
    // we use this metric because if torrent is paused it does not clear `peer_sessions_`
    // in the hopes of reconnecting them, so calling `peer_sessions_`.size would not be
    // accurate
    return num_seeders() + num_leechers();
}

inline int torrent::num_seeders() const noexcept
{
    return info_.num_seeders;
}
inline int torrent::num_leechers() const noexcept
{
    return info_.num_leechers;
}

inline torrent_handle torrent::get_handle() noexcept
{
    return torrent_handle(shared_from_this());
}

inline torrent_storage_handle torrent::get_storage_handle() noexcept
{
    return storage_;
}

inline bool torrent::is_stopped() const noexcept
{
    return !is_running();
}

inline bool torrent::is_running() const noexcept
{
    return info_.state[torrent_info::active];
}

inline bool torrent::is_leech() const noexcept
{
    return !is_seed();
}

inline bool torrent::is_seed() const noexcept
{
    return info_.state[torrent_info::state::seeding];
}

inline void torrent::force_tracker_announce()
{
    announce(tracker_request::none, true);
}

} // namespace tide

#endif // TIDE_TORRENT_HEADER
