#include "thread_pool.hpp"
#include "scope_guard.hpp"

#include <iostream>
#define LOG(m) do { std::cerr << m << '\n'; } while(0)

namespace tide {

/**
 * If user doesn't specify the maximum number of threads that may be used within
 * thread pool, we try to come up with an appropriate number based on the number of
 * CPU cores.
 */
inline int auto_concurrency()
{
    // TODO devise or adapt a formula, such as this, just more fitting for our use
    // 2 * num_cores * cpu_utilization_percentage * (1 + wait_time / compute_time)
    return 2 * std::thread::hardware_concurrency();
}

thread_pool::thread_pool() : thread_pool(auto_concurrency()) {}

thread_pool::thread_pool(int concurrency)
    : m_concurrency(concurrency <= 0 ? 2 : concurrency)
{}

thread_pool::~thread_pool()
{
    join();
}

void thread_pool::set_concurrency(const int n)
{
    if(n < m_concurrency)
    {
        const int num_to_join = m_threads.size() - n;
        if(num_to_join > 0) { join(num_to_join); }
    }
    else
    {
        m_concurrency = n;
    }
}

void thread_pool::post(job_type job)
{
    std::unique_lock<std::mutex> l(m_job_queue_mutex);
    m_job_queue.emplace_back(std::move(job));
    l.unlock();
    handle_new_job();
}

void thread_pool::clear_pending_jobs()
{
    std::lock_guard<std::mutex> l(m_job_queue_mutex);
    m_job_queue.clear();
}

void thread_pool::join()
{
    join(m_threads.size());
}

void thread_pool::join(const int n)
{
    m_is_joining.store(true, std::memory_order_release);
    m_job_available.notify_all();
    for(auto i = 0; i < m_threads.size(); ++i)
    {
        if(m_threads[i].joinable()) { m_threads[i].join(); }
    }
    m_threads.erase(m_threads.begin(), m_threads.begin() + n);
}

inline void thread_pool::handle_new_job()
{
    if(m_num_idle_threads.load(std::memory_order_acquire) == 0
       && m_threads.size() < m_concurrency)
    {
        m_threads.emplace_back(std::thread());
        auto& thread = m_threads.back();
        // the completion of thread constructor synchronizes-with the beginning of the
        // invocation of the copy of the provided function, i.e. it inter-thread
        // happens-before calling the function, which means we'll have a valid thread
        // object in thread->thread by the time run(thread) would need to use it
        thread = std::thread([this, &thread] { run(thread); });
    }
    m_job_available.notify_one();
}

inline void thread_pool::run(std::thread& thread)
{
    util::scope_guard termination_guard([this, &thread]
        { assert(0 && "TODO"); });
    while(!m_is_joining.load(std::memory_order_acquire))
    {
        //LOG("\t" << std::this_thread::get_id() << " looping");
        time_point idle_start = ts_cached_clock::now();
        std::unique_lock<std::mutex> job_queue_lock(m_job_queue_mutex);
        // wake up if thread pool is beign joined or a new job is available
        m_job_available.wait(job_queue_lock, [this, &thread]
        {
            return m_is_joining.load(std::memory_order_acquire) || !m_job_queue.empty();
        });
        m_idle_time.fetch_add(to_int<milliseconds>(ts_cached_clock::now() - idle_start),
            std::memory_order_relaxed);

        // thread woke up because thread_pool is stopping thread or thread hasn't
        // worked in the past minute; either way, stop execution
        if(m_is_joining.load(std::memory_order_acquire)) { break; }

        execute_jobs(thread, std::move(job_queue_lock));
    }
    termination_guard.disable();
}

inline void thread_pool::execute_jobs(std::thread& thread,
    std::unique_lock<std::mutex> job_queue_lock)
{
    assert(job_queue_lock.owns_lock());

    while(!m_job_queue.empty())
    {
        auto job = std::move(m_job_queue.front());
        m_job_queue.pop_front();
        job_queue_lock.unlock();

        const time_point work_start = ts_cached_clock::now();
        job(); // TODO exception safety
        m_work_time.fetch_add(to_int<milliseconds>(ts_cached_clock::now() - work_start),
            std::memory_order_relaxed);
        m_num_executed_jobs.fetch_add(1, std::memory_order_relaxed);

        job_queue_lock.lock();
    }
}

} // namespace tide
