#ifndef TIDE_EVENT_CHANNEL_HEADER
#define TIDE_EVENT_CHANNEL_HEADER

#include "time.hpp"

#include <string>
#include <memory>
#include <queue>
#include <mutex>

namespace tide {

/** This is an interface that all events must implement. */
struct event
{
    time_point timestamp;
    virtual const char* what() const = 0;
    virtual std::string message() const = 0;
};

/** This is a base class for all stats related events. */
struct stats_event : public event
{
};

/** This is a base class for all alerts. */
struct alert_event : public event
{
};

/** This is a base class for all events that return an async operation's results. */
struct async_result_event : public event
{
};

/**
 * This is the entity through which internal components can send notifications to the
 * end user of the library. This is done through events, of which various types exists,
 * such as alerts, async operation results, stats etc.
 *
 * It is thread-safe, i.e. users thread can safely retrieve the latest events without
 * having to do external mutual exclusion.
 */
class event_queue
{
public:

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

private:

    std::queue<std::unique_ptr<event>> m_internal_events;
    std::queue<std::unique_ptr<event>> m_external_events;
    std::mutex m_mutex;

public:

    /** Constructs a new event in place. */
    template<typename Event, typename... Args> void emplace(Args&&... args);
};

template<typename Event, typename... Args>
void event_queue::emplace(Args&&... args)
{
    // TODO just a placeholder
    m_internal_events.emplace(std::make_unique<Event>(std::forward<Args>(args)...));
}

} // namespace tide

#endif // TIDE_EVENT_CHANNEL_HEADER
