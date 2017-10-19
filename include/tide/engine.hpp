#ifndef TIDE_ENGINE_HEADER
#define TIDE_ENGINE_HEADER

#include "bandwidth_controller.hpp"
#include "endpoint_filter.hpp"
#include "torrent_handle.hpp"
#include "torrent_args.hpp"
#include "alert_queue.hpp"
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
 * and glue for all components in a torrent. It is also the public interface through
 * which the library user interacts with torrents, e.g. starting and removing torrents,
 * customizing settings and most other stateful things are done through this class.
 */
class engine
{
    // All disk related tasks are done through this class, so only a single object
    // exists at any given time. Each torrent instance, and their peer_sessions receive
    // a reference to this object.
    disk_io disk_io_;

    bandwidth_controller bandwidth_controller_;

    // Rules may be applied for filtering specific IP addresses and ports.
    endpoint_filter endpoint_filter_;
    
    // Internal entities within tide::engine communicate with user asynchronously via
    // an alert channel. This is done by accumulating alerts in this queue until user 
    // manually extracts them. It's thread-safe.
    alert_queue alert_queue_;

    // All torrents (active and inactive) are stored here.
    std::vector<std::shared_ptr<torrent>> torrents_;

    // Torrents may have a priority ordering, which is determined by a torrent's id's
    // position in this queue. Entries at the front have a higher priority.
    std::vector<torrent_id_t> torrent_priority_;

    // Every single tracker used by all torrents is stored here. This is because many
    // torrents share the same tracker, so when a torrent is created, we first check
    // if its trackers already exists, and if so, we can pass the existing instance to
    // torrent. A tracker is removed from here when all torrents that use it have been
    // removed (checked using shared_ptr's reference count).
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

    // We want to keep network_ios_ running indefinitely until shutdown, so keep it
    // busy with this work object.
    asio::io_service::work work_;

    // network_ios_ is not run on user's thread, but on a separate network thread, so
    // user does not have to handle thread synchronization. All torrents must be created
    // on the network thread so that all its operations execute there.
    std::thread network_thread_;

    // Since the engine uses system time extensively, the time returned by the system
    // is cached and only updated every 100ms, which should save some costs as most
    // components don't need a higher resolution anyway.
    deadline_timer cached_clock_updater_;

public:

    /** If no settings are specified, engine will use the default settings. */
    engine();
    explicit engine(const settings& s);

    void pause();
    void resume();

    /**
     * Returns a queue of all the alerts that occurred since the last call to this
     * function. Events are chronologically ordered.
     */
    std::deque<std::unique_ptr<alert>> alerts();

    /** Returns whether engine has managed to set up a listening port. */
    bool is_listening() const noexcept;
    uint16_t listen_port() const noexcept;

    //disk_io::stats get_disk_io_stats() const;
    //engine_info get_engine_stats() const;
    //settings get_settings() const;
    //void apply_settings(const settings& s);

    //std::vector<alert> get_recent_alerts();

    /**
     * Returns a torrent_handle to every torrent managed by engine (and variations).
     * This is useful if user doesn't keep track of torrents, but this is not
     * recommended to avoid the allocation overhead of the returned vector.
     */
    //std::vector<torrent_handle> torrents();
    //std::vector<torrent_handle> downloading_torrents();
    //std::vector<torrent_handle> uploading_torrents();
    //std::vector<torrent_handle> paused_torrents();

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
     * NOTE: the obtained torrent_handle must be saved somewhere as this is the means
     * through which the user may interact with a torrent.
     */
    void add_torrent(torrent_args args);

    enum class remove_options
    {
        // Deletes the downloaded files and the metadata (torrent state) of this torrent
        files_and_state,
        // Only remove the metadata/torrent state file that is used to continue torrents
        // after the engine has shut down.
        state
    };

    /**
     * Closes all peer conenctions in this torrent and tells the tracker that we're
     * leaving the swarm. Once the torrent is fully torn down, an alert is posted.
     */
    void remove_torrent(const torrent_handle& torrent, remove_options options);

    //torrent_handle find_torrent(const sha1_hash& info_hash);
    //torrent_handle find_torrent(const torrent_id_t id);

    // TODO perhaps rename these {set,{in,de}crement,etc}_torrent_queue_position
    void set_torrent_priority(const torrent_handle& torrent, const int queue_pos);
    void increment_torrent_priority(const torrent_handle& torrent);
    void decrement_torrent_priority(const torrent_handle& torrent);
    void make_torrent_top_priority(const torrent_handle& torrent);
    void make_torrent_least_priority(const torrent_handle& torrent);

private:

    void verify_torrent_args(torrent_args& args) const;
    torrent_id_t next_torrent_id() noexcept;

    /**
     * If any of torrent's trackers are already present in trackers_, those are
     * returned, and any that is not is created, added to trackers_ and returned.
     * The trackers in announce-list come first, in the order they were specified, then,
     * if the traditional tracker is not in the announce-list (which is an uncommon
     * scenario), it is added last, as these are rarely used if an announce-list is
     * present.
     */
    std::vector<tracker_entry> get_trackers(const metainfo& metainfo);
    bool has_tracker(string_view url) const noexcept;

    // -----------
    // -- utils --
    // -----------

    void update_cached_clock();
};

} // namespace tide

#endif // TIDE_ENGINE_HEADER
