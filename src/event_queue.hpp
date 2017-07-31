#ifndef TIDE_EVENT_CHANNEL_HEADER
#define TIDE_EVENT_CHANNEL_HEADER

#include "time.hpp"
#include "torrent_info.hpp"
#include "peer_session.hpp"

#include <string>
#include <memory>
#include <queue>
#include <mutex>

namespace tide {

/** This is an interface that all events must implement. */
struct event
{
    enum category_t
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
    virtual category_t category() const noexcept = 0;
};

// -- basic event categories --

/** This is a base class for all stats related events. */
struct stats_event : public event
{
    category_t category() const noexcept override { return stats; }
};

/** This is a base class for all alerts. */
struct alert_event : public event
{
    category_t category() const noexcept override { return alert; }
};

/** This is a base class for all events that return an async operation's results. */
struct async_completion_event : public event
{
    category_t category() const noexcept override { return async_result; }
};

// -- specializations --
// - stats -

struct torrent_stats : public stats_event
{
    torrent_info stats;
    const char* what() const noexcept override { return "torrent stats event"; }
};

struct peer_session_stats : public stats_event
{
    peer_session::stats stats;
    const char* what() const noexcept override { return "peer session stats event"; }
};

struct detailed_peer_session_stats : public stats_event
{
    peer_session::detailed_stats stats;
    const char* what() const noexcept override { return "peer session stats event"; }
};

struct disk_io_stats : public stats_event
{
    const char* what() const noexcept override { return "disk io stats event"; }
};

// - alerts -

// - async_completions -

struct add_torrent_completion : public async_completion_event
{
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

    std::queue<std::unique_ptr<event>> extract_events();
};

template<typename Event, typename... Args>
void event_queue::emplace(Args&&... args)
{
    // TODO just a placeholder
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
