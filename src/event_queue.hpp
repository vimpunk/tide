#ifndef TIDE_EVENT_CHANNEL_HEADER
#define TIDE_EVENT_CHANNEL_HEADER

#include "time.hpp"
#include "metainfo.hpp"
#include "disk_io.hpp"
#include "torrent_info.hpp"
#include "torrent_handle.hpp"
#include "peer_session.hpp"

#include <string>
#include <memory>
#include <queue>
#include <mutex>

namespace tide {

/** This is an interface that all events must implement. */
struct event
{
    enum category
    {
        // May be errors, warnings or miscelaneous.
        alert,
        // Many operations user requests run asynchronously (e.g. allocating a torrent)
        // but invoking a user provided handler is not feasible due to engine running on
        // a different thread, so all such results are passed as an event.
        async_result,
        // torrent, peer_session, disk_io statistics are also forwarded as events.
        stats
    };

    time_point timestamp;

    event() : timestamp(cached_clock::now()) {}
    virtual const char* what() const noexcept = 0;
    virtual enum category category() const noexcept = 0;
};

// -- basic event categories --

/** This is a base class for all stats related events. */
struct stats_event : public event
{
    enum category category() const noexcept override { return stats; }
};

/** This is a base class for all alerts. */
struct alert_event : public event
{
    enum category category() const noexcept override { return alert; }
};

/** This is a base class for all events that return an async operation's results. */
struct async_completion_event : public event
{
    enum category category() const noexcept override { return async_result; }
};

// -- specializations --
// - stats -

struct torrent_stats : public stats_event
{
    torrent_info stats;
    torrent_stats(torrent_info s) : stats(std::move(s)) {}
    const char* what() const noexcept override { return "torrent stats event"; }
};

struct peer_session_stats : public stats_event
{
    peer_session::stats stats;
    peer_session_stats(peer_session::stats s) : stats(std::move(s)) {}
    const char* what() const noexcept override { return "peer session stats event"; }
};

struct detailed_peer_session_stats : public stats_event
{
    peer_session::detailed_stats stats;
    detailed_peer_session_stats(peer_session::detailed_stats s) : stats(std::move(s)) {}
    const char* what() const noexcept override { return "peer session stats event"; }
};

struct disk_io_stats : public stats_event
{
    disk_io::stats stats;
    disk_io_stats(disk_io::stats s) : stats(std::move(s)) {}
    const char* what() const noexcept override { return "disk io stats event"; }
};

// - alerts -

struct torrent_stopped_alert : public alert_event
{
};

struct download_complete_alert : public alert_event
{
};

// - async_completions -

struct async_completion_error : public async_completion_event
{
    std::error_code error;
    async_completion_error(std::error_code e) : error(e) {}
    const char* what() const noexcept override
    { return "error completing async operation"; }
};

struct metainfo_parse_completion : public async_completion_event
{
    class metainfo metainfo;
    metainfo_parse_completion(class metainfo m) : metainfo(std::move(m)) {}
    const char* what() const noexcept override
    { return "async metainfo parse completion"; }
};

struct add_torrent_completion : public async_completion_event
{
    class torrent_handle torrent_handle;
    add_torrent_completion(class torrent_handle h) : torrent_handle(std::move(h)) {}
    const char* what() const noexcept override { return "torrent successfully added"; }
};

struct remove_torrent_completion : public async_completion_event
{
};

/**
 * This is the entity through which internal components can send notifications to the
 * end user of the library. This is done with objects derived from the event base class.
 *
 * It is thread-safe, i.e. users thread can safely retrieve the latest events without
 * having to do external mutual exclusion.
 */
class event_queue
{
    std::queue<std::unique_ptr<event>> m_queue;
    std::mutex m_queue_mutex;

public:

    /** Constructs a new event in place. */
    template<typename Event, typename... Args> void emplace(Args&&... args);

    /** Removes and returns all events that have been placed in the queue under a mutex. */
    std::queue<std::unique_ptr<event>> extract_events();
};

template<typename Event, typename... Args>
void event_queue::emplace(Args&&... args)
{
    std::lock_guard<std::mutex> l(m_queue_mutex);
    m_queue.emplace(std::make_unique<Event>(std::forward<Args>(args)...));
}

inline std::queue<std::unique_ptr<event>> event_queue::extract_events()
{
    std::queue<std::unique_ptr<event>> queue;
    std::lock_guard<std::mutex> l(m_queue_mutex);
    queue.swap(m_queue);
    return queue;
}

} // namespace tide

#endif // TIDE_EVENT_CHANNEL_HEADER
