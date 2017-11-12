#ifndef TIDE_ALERT_QUEUE_HEADER
#define TIDE_ALERT_QUEUE_HEADER

#include "alerts.hpp"

#include <memory>
#include <deque>
#include <mutex>

namespace tide {

/**
 * This is the entity through which internal components can send notifications to the
 * end user of the library. This is done with objects derived from the alert base class.
 *
 * It is thread-safe, i.e. users thread can safely retrieve the latest alerts without
 * having to do external mutual exclusion.
 */
class alert_queue
{
    std::deque<std::unique_ptr<alert>> queue_;
    std::mutex queue_mutex_;

    // If the number of alerts in queue_ reaches this value, new entries will push out
    // the oldest entries in queue_.
    int capacity_;

public:

    alert_queue(const int capacity = 0) : capacity_(capacity) {}

    /** Constructs a new alert in place. */
    template<typename Event, typename... Args> void emplace(Args&&... args);

    /**
     * Removes and returns all alerts that have been placed in the queue in a
     * thread-safe manner (under a mutex).
     */
    std::deque<std::unique_ptr<alert>> extract_alerts();
};

template<typename Event, typename... Args>
void alert_queue::emplace(Args&&... args)
{
    std::lock_guard<std::mutex> l(queue_mutex_);
    queue_.emplace_back(std::make_unique<Event>(std::forward<Args>(args)...));
    if(queue_.size() > capacity_) { queue_.pop_front(); }
}

inline std::deque<std::unique_ptr<alert>> alert_queue::extract_alerts()
{
    std::deque<std::unique_ptr<alert>> queue;
    std::lock_guard<std::mutex> l(queue_mutex_);
    queue.swap(queue_);
    return queue;
}

} // namespace tide

#endif // TIDE_ALERT_QUEUE_HEADER
