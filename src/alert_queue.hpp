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
    std::deque<std::unique_ptr<alert>> m_queue;
    std::mutex m_queue_mutex;

    // If the number of alerts in m_queue reaches this value, new entries will push out
    // the oldest entries in m_queue.
    int m_capacity;

public:

    alert_queue(const int capacity = 0) : m_capacity(capacity) {}

    /** Constructs a new alert in place. */
    template<typename Event, typename... Args> void emplace(Args&&... args);

    /** Removes and returns all alerts that have been placed in the deque under a mutex. */
    std::deque<std::unique_ptr<alert>> extract_alerts();
};

template<typename Event, typename... Args>
void alert_queue::emplace(Args&&... args)
{
    std::lock_guard<std::mutex> l(m_queue_mutex);
    m_queue.emplace_back(std::make_unique<Event>(std::forward<Args>(args)...));
    if(m_queue.size() == m_capacity)
    {
        m_queue.pop_front();
    }
}

inline std::deque<std::unique_ptr<alert>> alert_queue::extract_alerts()
{
    std::deque<std::unique_ptr<alert>> queue;
    std::lock_guard<std::mutex> l(m_queue_mutex);
    queue.swap(m_queue);
    return queue;
}

} // namespace tide

#endif // TIDE_ALERT_QUEUE_HEADER
