#ifndef TORRENT_THREAD_POOL_HEADER
#define TORRENT_THREAD_POOL_HEADER

#include "time.hpp"

#include <condition_variable>
#include <functional>
#include <memory>
#include <thread>
#include <atomic>
#include <deque>
#include <mutex>

/**
 * This is a dynamically managed, configurable thread pool capable of running any type
 * of function.
 *
 * The number of threads is dynamically adjusted according to the workload, which means
 * new threads (up to the concurrency limit, which is user definable or auto configured)
 * are spun up when the load is high, and threads are torn down when the workload is
 * low. This requires that a thread idle for 60 seconds, after which it will be torn
 * down.
 * Factors such as the cost of setting up a thread are taken into consideration, so new
 * threads are only spun up if the current workload justifies it, otherwise new jobs are
 * queued up even if we haven't reached the concurrency limit.
 */
//template<
    //typename JobType = std::function<void()>
    // TODO support custom callables
//> struct thread_pool
struct thread_pool
{
    using job_type = std::function<void()>;

private:

    struct worker
    {
        std::thread thread;

        // If a worker has not had work for 60 consecutive seconds, it marks itself as
        // stopped, waiting for another thread to reap it.
        // TODO what if we only have on worker. caller thread should also check this
        // in fact, why not just let caller thread reap dead threads?
        std::atomic<bool> is_active;

        // Among waiting workers we pick the one that has done work the most recently,
        // so we need each worker to have its own condition variable with which we can
        // wake it up.
        // NOTE: wait() must be called while holding onto m_job_queue_mutex.
        std::condition_variable job_available;
    };

    // All jobs are first placed in this queue from which they are retrieved by workers.
    //
    // NOTE: must only be handled after acquiring m_job_queue_mutex.
    std::deque<job_type> m_job_queue;

    // All workers are stored in a single list, but conceptually this list is divided
    // into two parts.
    //
    // First there is the waiters' stack, which comprises the idle workers waiting for
    // a job. When a worker becomes idle, it places itself on top of this stack. When
    // we're looking for a free worker who can execute a new job, we pick the one on
    // the top of the stack, for tho reasons. First, it ensurse that if we have too many
    // workers for the current workload, those on the bottom will eventually "starve" of
    // work and will thus spin down and mark themselves for removal. The other factor
    // is that workers who have done work more recently are preferred, since by reusing
    // recent threads we increase our chances of finding the thread's cache still hot,
    // which may further improve performance.
    //
    // The last idle worker's position in the conceptual stack is denoted by
    // m_last_idle_worker_pos, all other workers after this are busy with jobs. Thus,
    // when we pick the idle worker on the top, we simply decrement this index. (There
    // is a slight complication to this, see comment in move_to_active.) Placing an active
    // worker back into the waiters' stack is a bit more convoluted, as it requires that
    // we search for its position, swap it with the first active worker, then increment
    // m_last_idle_worker_pos, moving it to the new top of the stack.
    // 
    // New workers are placed in the beginning of the queue, since new workers are only
    // spun up when there is demand for work and no idle workers around. So all new
    // workers start out as idle and depend on the job scheduler to notify them of the
    // new work.
    //
    // NOTE: must only be handled after acquiring m_workers_mutex.
    std::deque<std::shared_ptr<worker>> m_workers;

    mutable std::mutex m_job_queue_mutex;
    mutable std::mutex m_workers_mutex;

    // When this is set to false it is used to notify each worker that thread pool is
    // shutting down.
    std::atomic<bool> m_is_running;

    std::atomic<int> m_num_executed_jobs;

    // The total time in milliseonds all threads spent working (executing jobs) and
    // idling (waiting for jobs). Reaping dead workers is not counted.
    std::atomic<int> m_work_time;
    std::atomic<int> m_idle_time;

    // See m_workers comment. -1 means there are no idle workers at the moment.
    //
    // NOTE: must only be handled after acquiring m_workers_mutex.
    int m_last_idle_worker_pos = -1;

    // This is the max number of threads that we may have running. It is only accessed
    // on the caller's thread no mutual exclusion is necessary.
    int m_concurrency;

public:

    struct info
    {
        int num_idle_threads;
        int num_active_threads;
        int num_executed_jobs;
        int num_pending_jobs;
        int ms_spent_working;
        int ms_spent_idling;
    };

    /**
     * If the number of threads is not specified, it is calculated as a function of the
     * number of cores the underlying hardware has.
     */
    thread_pool();
    explicit thread_pool(int concurrency);
    ~thread_pool();

    bool is_idle() const;
    int num_threads() const;
    int num_active_threads() const;
    int num_idle_threads() const;
    int num_pending_jobs() const;
    info get_info() const;

    /**
     * If the new value is lower than the current number of running threads, threads
     * will be signaled to stop. If all threads are currently executing, the stop signal
     * is heeded once each thread to be torn down is finished with its current job.
     */
    void change_concurrency(const int n);

    /**
     * Post a callable job to thread pool for execution at an unspecified time, though
     * this may be changed with the priority level. If there is an idle thread, task is 
     * executed immediately, if not, a new thread might be spun up, if concurrency limit
     * is not reached, otherwise it is queud up for later execution.
     */
    void post(job_type job);

    /** Removes all jobs that are queued up. Does not affect currently executing jobs. */
    void clear_pending_jobs();

    /** Stops all threads by waiting for them to finish their current jobs. */
    void join_all();

    /**
     * Stops all threads by interrupting current jobs. This is not recommended but may
     * at times be necessary.
     */
    void abort_all();

private:

    /**
     * If user doesn't specify the maximum number of threads that may be used within
     * thread pool, we try to come up with an appropriate number based on the number of
     * CPU cores.
     */
    static int auto_concurrency();

    /**
     * If there is an idle worker, hands off job to it, if not, checks if we can spin
     * up a new thread to which the new job can be given.
     */
    void handle_new_job();

    /**
     * This is the main loop that each worker runs until it's torn down.
     * Instructs the worker to wait for new jobs and execute them, along with the rest
     * of the job queue if there are more jobs, after which it goes back to sleep. At
     * the end of each loop a thread checks if there are any dead workers and releases
     * them.
     */
    void run(std::shared_ptr<worker> worker);

    /**
     * When a worker starts executing a job, it moves itself out of the waiters' stack,
     * and when it finishes it moves itself back to the top of the stack.
     */
    void move_to_active(const worker& worker);
    void move_to_idle(const worker& worker);

    /**
     * This is called from run, executes as many jobs as the worker executing this
     * method can grab.
     * NOTE: the supplied job_queue_lock must be holding m_job_queue_mutex.
     */
    void execute_jobs(std::unique_lock<std::mutex> job_queue_lock);

    /** If a thread unexpectedly terminated, this function decides what should happen. */
    // TODO make this a user settable policy, i.e. what should happen with exceptions
    // during execution
    void handle_untimely_worker_demise(std::shared_ptr<worker> worker);

    /**
     * Joins the first n workers but does NOT remove them from m_workers.
     * NOTE: m_workers_mutex must be held when calling this function.
     */
    void join_n(const int n);

    /**
     * Before doing any jobs, one worker checks if there are any dead/finished workers
     * that need to be removed.
     */
    void reap_dead_workers();
};

#endif // TORRENT_THREAD_POOL_HEADER
