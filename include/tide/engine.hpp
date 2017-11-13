#ifndef TIDE_ENGINE_HEADER
#define TIDE_ENGINE_HEADER

#include "endpoint_filter.hpp"
#include "torrent_handle.hpp"
#include "torrent_args.hpp"
#include "rate_limiter.hpp"
#include "alert_queue.hpp"
#include "engine_info.hpp"
#include "settings.hpp"
#include "metainfo.hpp"
#include "disk_io.hpp"
#include "torrent.hpp"
#include "types.hpp"

#include <system_error>
#include <functional>
#include <cstdint>
#include <thread>
#include <vector>
#include <mutex>

#include <asio/io_service.hpp>

namespace tide {

class endpoint_filter;
class peer_session;

/**
 * This class represents a torrent application. It is the highest level wrapper around,
 * and glue for, all components in a torrent application. It is also the public
 * interface through which the library user interacts with torrents, e.g. starting and
 * removing them, customizing settings and most other stateful things are done through
 * this class.
 */
class engine
{
    // All disk related tasks are done through this class, so only a single object
    // exists at any given time. Each torrent instance, and their peer_sessions receive
    // a reference to this object.
    disk_io disk_io_;

    rate_limiter rate_limiter_;

    // Rules may be applied for filtering specific IP addresses and ports.
    endpoint_filter endpoint_filter_;
    
    // Internal entities within tide::engine communicate with user asynchronously via
    // an alert channel. This is done by accumulating alerts in this queue until user 
    // manually extracts them. It's thread-safe.
    alert_queue alert_queue_;

    // `torrent`s are categorized by whether they're leeches or seeds. Leeches, i.e. our
    // downloads, are prioritizied over seeds, e.g. when upload slots are distributed,
    // the connections in `leeches_` are much more likely to receive a slot than those
    // in `seeds_`. This is to optimize for the primary use case of BitTorrent:
    // downloading.
    std::vector<std::shared_ptr<torrent>> leeches_;
    std::vector<std::shared_ptr<torrent>> seeds_;

    // Torrents may have a priority ordering, which is determined by a torrent's id's
    // position in this queue. Entries at the front have a higher priority.
    //std::vector<torrent_id_t> torrent_priority_;

    // Every single tracker used by all torrents is stored here. This is because several
    // torrents share the same tracker, so when a torrent is created, we first check
    // if its tracker(s) already exist(s), and if so, we can pass the existing instance
    // to torrent. A tracker is removed from here when all torrents that use it have
    // been removed (checked using `std::shared_ptr`'s reference count).
    std::vector<std::shared_ptr<tracker>> trackers_;

    // Incoming connections are stored here until the handshake has been concluded after
    // which we can determine to which torrent the peer belongs.
    std::vector<std::shared_ptr<peer_session>> incoming_connections_;

    // This contains all the user configurable options, a const reference to which is
    // passed down to most components of the engine.
    settings settings_;

    // This is the io_service that runs all network related connections. This is also
    // passed to disk_io for callbacks to be posted on network thread.
    asio::io_service network_ios_;

    // We want to keep `network_ios_` running indefinitely until shutdown, so keep it
    // busy with this work object.
    asio::io_service::work work_;

    // This is the acceptor on which we're listening for inbound TCP connections.
    tcp::acceptor acceptor_;

    // `network_ios_` is not run on user's thread, but on a separate network thread, so
    // user does not have to handle thread synchronization. All torrents must be created
    // on the network thread so that all its operations execute there.
    std::thread network_thread_;

    // The main engine loop is hooked up to this timer, which executes the update
    // procedure every 100ms.
    deadline_timer update_timer_;

    engine_info info_;

public:

    /**
     * The constructor immediately starts `engine`'s internal update cycle on a new
     * thread, even if there are no torrents as yet.
     *
     * If no settings are specified, engine will use the default settings.
     */
    engine();
    explicit engine(const settings& s);

    /** Pauses and resumes all torrents in `engine`. */
    void pause();
    void resume();

    /**
     * Returns a queue of all the alerts that occurred since the last call to this
     * function. Events are chronologically ordered.
     */
    std::deque<std::unique_ptr<alert>> alerts();

    /** Returns whether engine has managed to set up a listening port. */
    bool is_listening() const noexcept;
    uint16_t listener_port() const noexcept;

    //disk_io::stats get_disk_io_stats() const;
    //engine_info get_engine_stats() const;
    //settings get_settings() const;

    void apply_settings(settings s);
    void apply_disk_io_settings(disk_io_settings s);
    void apply_torrent_settings(torrent_settings s);
    void apply_peer_session_settings(peer_session_settings s);

    /**
     * This is an asynchronous function that reads in the .torrent file located at path
     * and parses it into a legible metainfo object, which is then passed to user via
     * the alert system. This is the same metainfo that must be passed to add_torrent's
     * torrent_args.
     *
     * The advantage of using this function over manually reading and parsing .torrent
     * is making use of engine's existing multithreaded disk IO infrastructure, but it's
     * not necessary to start a torrent.
     */
    void parse_metainfo(const path& path);

    /**
     * Sets up and starts a torrent with the supplied arguments in args. Once the
     * internal torrent object is fully instantiated (which may not mean that it started
     * tracker or peer connections, or that it has been allocated on the disk), a
     * torrent_handle is obtained and posted to user via the alert system (TODO).
     * Thus, the actual setup runs asynchronously. The user is notified of each state
     * transition in torrent's setup progress via the alert system.
     *
     * An exception is thrown if args is invalid, which is verified before launching any
     * asynchronous setup operations.
     *
     * NOTE: the obtained `torrent_handle` must be saved somewhere as this is the means
     * through which the user may interact with a torrent.
     */
    void add_torrent(torrent_args args);

    enum class remove_options
    {
        // Deletes the downloaded files and the metadata (torrent state) of this torrent
        delete_files_and_state,
        // Only remove the metadata/torrent state file that is used to continue torrents
        // after `engine` shuts down.
        delete_state
    };

    /**
     * Closes all peer conenctions in this torrent and tells the tracker that we're
     * leaving the swarm. Once the torrent is fully torn down, an alert is posted.
     */
    void remove_torrent(const torrent_handle& torrent, remove_options options);

    //torrent_handle find_torrent(const sha1_hash& info_hash);
    //torrent_handle find_torrent(const torrent_id_t id);

    void set_torrent_queue_position(const torrent_handle& torrent, const int pos);
    void increment_torrent_queue_position(const torrent_handle& torrent);
    void decrement_torrent_queue_position(const torrent_handle& torrent);
    void move_torrent_to_queue_top(const torrent_handle& torrent);
    void move_torrent_to_queue_bottom(const torrent_handle& torrent);

private:

    template<typename Function>
    void for_each_torrent(Function fn);

    torrent_id_t next_torrent_id() noexcept;

    /**
     * If any of torrent's trackers are already present in `trackers_`, those are
     * returned, and any that is not is created, added to `trackers_`, and returned.
     * The trackers in announce-list come first, in the order they were specified, then,
     * if the traditional tracker is not in the announce-list (which is an uncommon
     * scenario), it is added last, as these are rarely used if an announce-list is
     * present.
     */
    std::vector<tracker_entry> get_trackers(const metainfo& metainfo);
    bool has_tracker(string_view url) const noexcept;

    void update(const std::error_code& error = std::error_code());

    /** Moves all torrents that became seeds in `leeches_` to `seeds_`. */
    void relocate_new_seeds();

    /**
      TODO
     */
    void update_leeches();
    void update_seeds();

    bool is_torrent_slow(const torrent& t) const noexcept;
    bool is_leech_slow(const torrent& t) const noexcept;
    bool is_seed_slow(const torrent& t) const noexcept;

    void verify(torrent_args& args) const;
    void verify(const settings& s) const;
    void verify(const disk_io_settings& s) const;
    void verify(const torrent_settings& s) const;
    void verify(const peer_session_settings& s) const;

    void fill_in_defaults(torrent_args& args);
    void fill_in_defaults(settings& s);
    void fill_in_defaults(disk_io_settings& s);
    void fill_in_defaults(torrent_settings& s);
    void fill_in_defaults(peer_session_settings& s);

    void apply_disk_io_settings_impl(disk_io_settings s);
    void apply_torrent_settings_impl(torrent_settings s);
    void apply_peer_session_settings_impl(peer_session_settings s);

    void apply_max_connections_setting(const int max_connections);
    void apply_max_active_leeches_setting(const int max_active_leeches);
    void apply_max_active_seeds_setting(const int max_active_seeds);
    static void apply_max_active_torrents_setting(
        std::vector<std::shared_ptr<torrent>>& torrents,
        int& num_active, const int max_active);
    void apply_max_upload_slots_setting(const int max_upload_slots);

    /**
     * Finds `torrent` and the queue within which it resides, which may `leeches_` or
     * `seeds_`, and executes `fn` such that it passes a reference to the queue of
     * torrents within which `torrent` was found and an iterator to the torrent if and
     * only if `torrent` was found. Otherwise `fn` is not executed.
     */
    template<typename Function>
    void find_torrent_and_execute(const torrent_handle& torrent, Function fn);

    static void move_torrent_to_position(
        std::vector<std::shared_ptr<torrent>>& torrents,
        int curr_pos, const int pos);
};

inline bool engine::is_listening() const noexcept { return false; } // for now
inline uint16_t engine::listener_port() const noexcept { return settings_.listener_port; }

} // namespace tide

#endif // TIDE_ENGINE_HEADER
