#ifndef TORRENT_ENGINE_HEADER
#define TORRENT_ENGINE_HEADER

#include "event_channel.hpp"
#include "torrent_handle.hpp"
#include "torrent_args.hpp"
#include "settings.hpp"
#include "metainfo.hpp"
#include "disk_io.hpp"
#include "torrent.hpp"
#include "units.hpp"

#include <unordered_map>
#include <system_error>
#include <functional>
#include <cstding>
#include <thread>
#include <vector>
#include <mutex>

#include <asio/io_service.hpp>

namespace tide {

class endpoint_filter;

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
    disk_io m_disk_io;

    bandwidth_controller m_bandwidth_controller;

    // Rules may be applied for filtering specific IP addresses and ports.
    endpoint_filter m_endpoint_filter;
    
    // Internal entities within tide::engine communicate with user asynchronously via
    // this event channel. This is done by accumulating events (stats, alerts, async
    // op results etc) and user periodically, at their own convenience, query for the
    // latest queue of events. thread-safe.
    event_channel m_event_channel;

    // All active and inactive torrents are stored here.
    std::unordered_map<torrent_id_t, torrent> m_torrents;

    // Torrents may have a priority ordering. TODO perhaps use a vector
    std::deque<torrent_id_t> m_torrent_priority;

    // Every single tracker used by all torrents is stored here. This is because many
    // torrents share the same tracker, so when a torrent is created, we first check
    // if its trackers already exist, and if so, we can pass the existing instance to
    // torrent. A tracker is removed from here when all torrents that use it have been
    // removed (checked using shared_ptr's reference count).
    std::vector<std::shared_ptr<tracker>> m_trackers;

    // This contains all the user configurable options, a const reference to which is
    // passed down to pretty much all components of the engine.
    settings m_settings;

    // This is the io_service that runs all network related connections. This is also
    // passed to disk_io for callbacks to be posted on network thread.
    asio::io_service m_network_ios;

    // We want to keep m_network_ios running indefinitely until shutdown, so keep it
    // busy with this work object.
    asio::io_service::work m_work;

    // m_network_ios is not run on user's thread, but on a separate network thread, so
    // user does not have to handle thread synchronization. All torrents must be created
    // on the network thread so that all its operations execute there.
    std::thread m_network_thread;

    // Since the engine uses system time extensively, the time returend by the system
    // is cached and only updated every 100ms, which should save some costs and most
    // components don't need a higher resolution that this.
    deadline_timer m_cached_clock_updater;

public:

    /** If no settings are specified, engine will use the default settings. */
    engine();
    explicit engine(const settings& s);

    void pause();
    void resume();

    /** Returns whether engine has managed to set up a listening port. */
    bool is_listening() const noexcept;
    uint16_t listen_port() const noexcept;

    disk_io_info get_disk_io_stats() const;
    engine_info get_engine_stats() const;
    settings get_settings() const;
    void apply_settings(const settings& s);

    //std::vector<alert> get_recent_alerts();

    /**
     * Returns a torrent_handle to every torrent managed by engine (and variations).
     * This is useful if user doesn't keep track of torrents, but this is not
     * recommended to avoid the allocation overhead of the returned vector.
     */
    std::vector<torrent_handle> torrents();
    std::vector<torrent_handle> downloading_torrents();
    std::vector<torrent_handle> uploading_torrents();
    std::vector<torrent_handle> paused_torrents();

    /**
     * This is an asynchronous function that reads in the .torrent file located at path
     * and parses it into a legible metainfo object, which is then passed to user via
     * the alert system. This is the same metainfo that must be passed to add_torrent's
     * torrent_args.
     *
     * The advantage of using this function over manually reading and parsing .torrent
     * is making use of engine's existing multithreaded disk IO infrastructure, but it
     * may of course be done another way.
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

    torrent_handle find_torrent(const sha1_hash& info_hash);
    torrent_handle find_torrent(const torrent_id_t& id);

    // TODO perhaps rename these {set,{in,de}crement,etc}_torrent_queue_position
    void set_torrent_priority(const torrent_handle& torrent, const int queue_pos);
    void increment_torrent_priority(const torrent_handle& torrent);
    void decrement_torrent_priority(const torrent_handle& torrent);
    void make_torrent_top_priority(const torrent_handle& torrent);
    void make_torrent_least_priority(const torrent_handle& torrent);

private:

    void verify_torrent_args(torrent_args& args) const;
    torrent_id_t get_torrent_id() noexcept;

    /**
     * If any of torrent's trackers are already present in m_trackers, those are
     * returned, and any that is not is created, added to m_trackers and returned.
     * The trackers in announce-list come first, in the order they were specified, then,
     * if the traditional tracker is not in the announce-list (which is an uncommon
     * scenario), it is added last, as these are rarely used if an announce-list is
     * present.
     */
    std::vector<tracker_entry> get_trackers(const metainfo& metainfo);
    bool has_tracker(string_view url) const noexcept;

    /**
     * Events (notifications, stats, data) are accumulated in an event queue in engine,
     * which user may periodically request. This indirection is necessary because most
     * user interactions result in asynchronous operations that run on a different
     * thread, so regular callbacks or return values cannot be used. Instead, completed
     * async operations place their alert in the alert queue and user periodically
     * drains this queue.
     */
    template<typename Alert, typename... Args> void post_alert(Args&&... args);
};

} // namespace tide

#endif // TORRENT_ENGINE_HEADER
