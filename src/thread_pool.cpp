#include "thread_pool.hpp"

#include <iostream>
#define LOG(m) do { std::cerr << m << '\n'; } while(0)

thread_pool::thread_pool() : thread_pool(auto_concurrency()) {}

thread_pool::thread_pool(int concurrency)
    : m_num_executed_jobs(0)
    , m_work_time(0)
    , m_idle_time(0)
    , m_concurrency(concurrency <= 0 ? 1 : concurrency)
{}

thread_pool::~thread_pool()
{
    join_all();
}

// NOTE: do NOT use these query functions within private functions as some of them
// must acquire a mutex which the private functions might already own.

bool thread_pool::is_idle() const
{
    std::lock_guard<std::mutex> l(m_workers_mutex);
    return m_workers.size() == m_last_idle_worker_pos + 1;
}

int thread_pool::num_threads() const
{
    std::lock_guard<std::mutex> l(m_workers_mutex);
    return m_workers.size();
}

int thread_pool::num_active_threads() const
{
    std::lock_guard<std::mutex> l(m_workers_mutex);
    return m_workers.size() - (m_last_idle_worker_pos + 1);
}

int thread_pool::num_idle_threads() const
{
    std::lock_guard<std::mutex> l(m_workers_mutex);
    return m_last_idle_worker_pos + 1;
}

thread_pool::info thread_pool::get_info() const
{
    info i;
    i.num_idle_threads = num_idle_threads();
    i.num_active_threads = num_active_threads();
    i.num_executed_jobs = m_num_executed_jobs.load(std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> l(m_job_queue_mutex);
        i.num_pending_jobs = m_job_queue.size();
    }
    i.ms_spent_working = m_work_time.load(std::memory_order_relaxed);
    i.ms_spent_idling = m_idle_time.load(std::memory_order_relaxed);
    return i;
}

void thread_pool::change_concurrency(const int n)
{
    if(n < m_concurrency)
    {
        std::lock_guard<std::mutex> l(m_workers_mutex);
        const int num_to_join = m_workers.size() - n;
        if(num_to_join > 0)
        {
            join_n(num_to_join);
            m_workers.erase(m_workers.begin(), m_workers.begin() + num_to_join);
        }
    }
    else
    {
        m_concurrency = n;
    }
}

void thread_pool::clear_pending_jobs()
{
    std::lock_guard<std::mutex> l(m_job_queue_mutex);
    m_job_queue.clear();
}

void thread_pool::post(job_type job)
{
    {
        std::lock_guard<std::mutex> l(m_job_queue_mutex);
        m_job_queue.emplace_back(std::move(job));
    }
    handle_new_job();
}

void thread_pool::join_all()
{
    std::lock_guard<std::mutex> l(m_workers_mutex);
    join_n(m_workers.size());
    m_workers.clear();
    m_last_idle_worker_pos = -1;
    // we need not acqurie the mutex here as there are no longer threads to exclude
    m_job_queue.clear();
}

void thread_pool::join_n(const int n)
{
    for(auto i = 0; i < n; ++i)
    {
        //LOG("[X] joining " << m_workers[i]->thread.get_id());
        // if worker is idle, i.e. it's waiting for a job via the job_available condvar,
        // wake it up and tell it that we're shutting down (otherwise worker is active
        // so it will periodically check for the its is_dead condition, so no need
        // to notify it)
        m_workers[i]->is_dead.store(true, std::memory_order_release);
        if(i <= m_last_idle_worker_pos)
        {
            m_workers[i]->job_available.notify_one();
        }
        // this should never fire because if it doth, we f-ed up mutual exclusion
        assert(m_workers[i]->thread.joinable());
        m_workers[i]->thread.join();
    }
}

void thread_pool::abort_all()
{
    // TODO
}

void thread_pool::handle_new_job()
{
    std::unique_lock<std::mutex> workers_lock(m_workers_mutex);
    //LOG("\t(new job) m_last_idle_worker_pos: " << m_last_idle_worker_pos);
    if(m_last_idle_worker_pos >= 0)
    {
        // if there are any idle workers, notify the one at the top of the waiters' stack
        m_workers[m_last_idle_worker_pos]->job_available.notify_one();
    }
    else if(m_workers.empty() || (m_workers.size() < m_concurrency))
    {
        //LOG("[NEW] creating new worker");
        // we don't have any threads or any idle threads but we haven't reached
        // our concurrency limit so spin up a new worker
        // TODO optimize this. if workload has been steadily decreasing in the near
        // past, we don't want to spin up a new thread, otherwise we do, e.g.:
        // if(m_load_avg.is_trend_upward()) or if(some threashold reached)
        std::shared_ptr<worker> w = std::make_shared<worker>();
        w->is_dead.store(false, std::memory_order_relaxed);
        m_workers.emplace_front(w);
        // we just added an idle worker, move marker to the right by one
        ++m_last_idle_worker_pos;
        // we don't want to spin up a new thread while holding the mutex
        workers_lock.unlock();

        // the completion of thread constructor synchronizes-with the beginning of the
        // invocation of the copy of the provided function, i.e. it inter-thread
        // happens-before calling the function, which means we'll have a valid thread
        // object in worker->thread by the time run(worker) would need to use it
        w->thread = std::thread([this, w]
        {
            run(w);
        });

        // we know where the new worker is, we don't need to access it through m_workers
        // and m_last_idle_worker_pos TODO verify whether this is correct
        w->job_available.notify_one();
    }
}

class scope_guard
{
    std::function<void()> m_function;
    bool m_is_active = true;

public:

    explicit scope_guard(std::function<void()> f) : m_function(std::move(f)) {}

    ~scope_guard()
    {
        if(m_is_active && m_function)
        {
            m_function();
        }
    }

    void disable()
    {
        m_is_active = false;
    }
};

void thread_pool::run(std::shared_ptr<worker> worker)
{
    scope_guard termination_guard([this, worker]
    {
        handle_untimely_worker_demise(worker);
    });
    while(!worker->is_dead.load(std::memory_order_acquire))
    {
        //LOG("\t" << std::this_thread::get_id() << " looping");
        time_point idle_start = ts_cached_clock::now();
        std::unique_lock<std::mutex> job_queue_lock(m_job_queue_mutex);
        worker->job_available.wait_for(job_queue_lock, seconds(15), [this, worker]
        {
            // wake up if worker is begin shut down, a new job is available, or if
            // worker has idled for a minute
            return worker->is_dead.load(std::memory_order_acquire)
                || !m_job_queue.empty();
        });
        m_idle_time.fetch_add(total_milliseconds(ts_cached_clock::now() - idle_start));

        // thread woke up because thread_pool is stopping worker or thread hasn't
        // worked in the past minute; either way, stop execution
        if(worker->is_dead.load(std::memory_order_acquire))
        {
            //LOG("[D...] " << worker->thread.get_id());
            break;
        }
        else if(m_job_queue.empty())
        {
            //LOG("[STARVE] " << worker->thread.get_id());
            job_queue_lock.unlock();
            worker->is_dead.store(true, std::memory_order_release);
            break;
        }

        // if this returns false it means worker is being shut down (this is to avoid
        // loading worker->is_dead again, as execute_jobs already does it)
        if(!execute_jobs(*worker, std::move(job_queue_lock)))
        {
            break;
        }
        reap_dead_workers();
    }
    termination_guard.disable();
}

bool thread_pool::execute_jobs(worker& worker, std::unique_lock<std::mutex> job_queue_lock)
{
    assert(job_queue_lock.owns_lock());

    // we're guaranteed to have at least the job we were notified about, so claim
    // that job before releasing the job queue lock and do the transfer of this
    // worker to the active workers list and the job execution outside the lock
    auto job = std::move(m_job_queue.front());
    m_job_queue.pop_front();
    job_queue_lock.unlock();

    move_to_active(worker);

    for(;;)
    {
        //LOG("[W] " << std::this_thread::get_id() << " working");
        time_point work_start = ts_cached_clock::now();
        // TODO exception safety
        job();
        m_work_time.fetch_add(total_milliseconds(ts_cached_clock::now() - work_start));
        m_num_executed_jobs.fetch_add(1, std::memory_order_relaxed);

        // we're shutting down, stop execution immediately
        if(worker.is_dead.load(std::memory_order_acquire))
        {
            return false;
        }

        job_queue_lock.lock();
        if(m_job_queue.empty())
        {
            job_queue_lock.unlock();
            break;
        }
        job = std::move(m_job_queue.front());
        m_job_queue.pop_front();
        job_queue_lock.unlock();
    }

    // move worker to the top of the waiter's stack as it's done working for now
    move_to_idle(worker);
    return true;
}

void thread_pool::move_to_active(const worker& worker)
{
    std::unique_lock<std::mutex> l(m_workers_mutex);

    // theoretically we'd only have to decreement m_last_idle_worker_pos by one since
    // we always wake up the worker on the top of the waiters' stack, but between
    // notifying worker and its wake an active worker might have become idle and placed
    // itself on top of the stack, so we must find this worker and bubble it up to the
    // top of the stack
    int worker_pos = m_last_idle_worker_pos;
    // there must be at least one idle worker
    //LOG("\tm_last_idle_worker_pos: " << m_last_idle_worker_pos);
    assert(worker_pos >= 0);
    while((worker_pos >= 0) && (m_workers[worker_pos].get() != &worker))
    {
        --worker_pos;
    }
    assert(worker_pos >= 0);
    //LOG("\tworker_pos : " << worker_pos);

    // to preserve the order of the stack (we can't just swap worker with the top as
    // in move_to_idle (the active workers partition is not ordered)), we must
    // bubble worker to the top
    int pos = worker_pos + 1;
    while(pos <= m_last_idle_worker_pos)
    {
        m_workers[worker_pos].swap(m_workers[pos]);
        ++worker_pos, ++pos;
    }

    // now that worker was moved to the top of the waiters' stack, decrement the last
    // idle worker's position as this worker is about to become active
    --m_last_idle_worker_pos;
}

void thread_pool::move_to_idle(const worker& worker)
{
    std::unique_lock<std::mutex> l(m_workers_mutex);

    const int first_active_pos = m_last_idle_worker_pos + 1;
    int pos = first_active_pos;
    // there must be at least one active worker
    assert(pos >= 0);
    //LOG("\tfirst_active_pos : " << first_active_pos);

    // since other workers may have become active since this worker had become active,
    // it may be anywhere beyond the last idle worker marker, so we have to find it
    while((pos < m_workers.size()) && (m_workers[pos].get() != &worker))
    {
        ++pos;
    }
    assert(pos < m_workers.size()); // this should never fire
    //LOG("\tworker_pos : " << pos);

    if(pos != first_active_pos)
    {
        // swap worker with the first active worker, if this worker is not already it
        // so that it can become the top of the waiters' stack
        m_workers[pos].swap(m_workers[first_active_pos]);
    }
    // move last idle worker marker one to the right as worker just became idle
    ++m_last_idle_worker_pos;
}

void thread_pool::reap_dead_workers()
{
    std::unique_lock<std::mutex> l(m_workers_mutex, std::defer_lock);
    if(!l.try_lock())
    {
        // we couldn't acquire the mutex, someone is working with it, so let that
        // someone take care of cleaning up later
        return;
    }
    while(!m_workers.empty())
    {
        // dead threads are always on the bottom of the waiters' stack
        std::shared_ptr<worker> worker = m_workers.front();
        if(worker->is_dead.load(std::memory_order_relaxed))
        {
            //LOG("[RRRR] reaping dead worker " << worker->thread.get_id());
            m_workers.pop_front();
            // we got one less idle worker, so decrement this
            --m_last_idle_worker_pos;
            // joining a thread may take some time so release the lock
            l.unlock();
            assert(worker->thread.joinable());
            worker->thread.join();
            // lock for the next round
            l.lock();
        }
        else
        {
            // workers are ordered by dead to active, so if we hit an active worker
            // we processed all dead workers
            break;
        }
    }
}

void thread_pool::handle_untimely_worker_demise(std::shared_ptr<worker> worker)
{
    // TODO we must remove this worker from m_workers and adjust the stack logic
    // we don't know if worker died while waiting or working, so the whole workers list
    // must be searched

}

int thread_pool::auto_concurrency()
{
    // TODO devise or adapt a formula, such as this, just more fitting for our use
    // 2 * num_cores * cpu_utilization_percentage * (1 + wait_time / compute_time)
    return 2 * std::thread::hardware_concurrency();
}
