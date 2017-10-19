#ifndef TIDE_THREAD_POOL_HEADER
#define TIDE_THREAD_POOL_HEADER

#include "time.hpp"

#include <condition_variable>
#include <functional>
#include <memory>
#include <thread>
#include <atomic>
#include <deque>
#include <mutex>

namespace tide {

struct thread_pool
{
    using job_type = std::function<void()>;

private:

    // Only the user's thread may change this vector, threads may not touch it, so no
    // synchronization is necessary.
    std::vector<std::thread> threads_;

    // Threads are notified of new jobs via this condition variable while they are
    // holding onto job_queue_mutex_.
    std::condition_variable job_available_;

    // All jobs are first placed in this queue from which they are retrieved by threads.
    //
    // NOTE: must only be handled after acquiring job_queue_mutex_.
    std::deque<job_type> job_queue_;

    mutable std::mutex job_queue_mutex_;

    std::atomic<bool> is_joining_{false};

    // The total time in milliseonds all threads spent working (executing jobs) and
    // idling (waiting for jobs). Reaping dead threads is not counted.
    std::atomic<int> work_time_{0};
    std::atomic<int> idle_time_{0};
    std::atomic<int> num_idle_threads_{0};
    std::atomic<int> num_executed_jobs_{0};

    // This is the max number of threads that we may have running. It is only accessed
    // on the caller's thread, no mutual exclusion is necessary.
    int concurrency_;

public:

    /**
     * If the number of threads is not specified, it is calculated as a function of the
     * number of cores of the underlying hardware.
     */
    thread_pool();
    explicit thread_pool(int concurrency);
    ~thread_pool();

    bool is_idle() const;
    int num_threads() const;
    int num_active_threads() const;
    int num_idle_threads() const;
    int num_pending_jobs() const;
    int concurrency() const noexcept;

    /**
     * If the new value is lower than the current number of running threads, threads
     * will be signaled to stop. If all threads are currently executing, the stop signal
     * is heeded once each thread to be torn down is finished with its current job.
     */
    void set_concurrency(const int n);

    /**
     * Post a callable job to thread pool for execution at an unspecified time. If there
     * is an idle thread, task is executed immediately, if not, a new thread might be
     * spun up, if concurrency limit is not reached, otherwise it is queud up for later
     * execution.
     */
    void post(job_type job);

    /** Removes all jobs that are queued up. Does not affect currently executing jobs. */
    void clear_pending_jobs();

    /** Stops n or all threads by waiting for them to finish all jobs in thread pool. */
    void join();
    void join(const int n);

private:

    /**
     * If there is an idle thread, hands off job to it, if not, checks if we can spin
     * up a new thread to which the new job can be given.
     */
    void handle_new_job();

    void run(std::thread& thread);
    void execute_jobs(std::thread& thread, std::unique_lock<std::mutex> job_queue_lock);

};

inline int thread_pool::concurrency() const noexcept
{
    return concurrency_;
}

inline bool thread_pool::is_idle() const
{
    return num_idle_threads() == num_threads();
}

inline int thread_pool::num_threads() const
{
    return threads_.size();
}

inline int thread_pool::num_active_threads() const
{
    return num_threads() - num_idle_threads();
}

inline int thread_pool::num_idle_threads() const
{
    return num_idle_threads_.load(std::memory_order_relaxed);
}

inline int thread_pool::num_pending_jobs() const
{
    std::lock_guard<std::mutex> l(job_queue_mutex_);
    return job_queue_.size();
}

} // namespace tide

#endif // TIDE_THREAD_POOL_HEADER
