#include "thread_pool.hpp"
#include "scope_guard.hpp"

namespace tide {

/**
 * If user doesn't specify the maximum number of threads that may be used within
 * thread pool, we try to come up with an appropriate number based on the number of
 * CPU cores.
 */
inline int auto_concurrency()
{
    // todo: devise or adapt a formula, such as this, but more fit for our use case:
    // 2 * num_cores * cpu_utilization_percentage * (1 + wait_time / compute_time)
    return 2 * std::thread::hardware_concurrency();
}

thread_pool::thread_pool() : thread_pool(auto_concurrency()) {}

thread_pool::thread_pool(int concurrency)
    : concurrency_(concurrency <= 0 ? 2 : concurrency)
{}

thread_pool::~thread_pool()
{
    join();
}

void thread_pool::set_concurrency(const int n)
{
    if(n <= 0) {
        return;
    }
    if(n < concurrency_) {
        const int num_to_join = threads_.size() - n;
        if(num_to_join > 0) {
            join(num_to_join);
        }
    } else {
        concurrency_ = n;
    }
}

void thread_pool::post(job_type job)
{
    std::unique_lock<std::mutex> l(job_queue_mutex_);
    job_queue_.emplace_back(std::move(job));
    l.unlock();
    handle_new_job();
}

void thread_pool::clear_pending_jobs()
{
    std::lock_guard<std::mutex> l(job_queue_mutex_);
    job_queue_.clear();
}

void thread_pool::join()
{
    join(threads_.size());
}

void thread_pool::join(const int n)
{
    is_joining_.store(true, std::memory_order_release);
    job_available_.notify_all();
    for(auto i = 0; i < threads_.size(); ++i) {
        if(threads_[i].joinable()) {
            threads_[i].join();
        }
    }
    threads_.erase(threads_.begin(), threads_.begin() + n);
}

inline void thread_pool::handle_new_job()
{
    if(num_idle_threads_.load(std::memory_order_acquire) == 0
            && threads_.size() < concurrency_) {
        threads_.emplace_back(std::thread());
        auto& thread = threads_.back();
        // the completion of thread constructor synchronizes-with the beginning of the
        // invocation of the copy of the provided function, i.e. it inter-thread
        // happens-before calling the function, which means we'll have a valid thread
        // object in thread->thread by the time run(thread) would need to use it
        thread = std::thread([this, &thread] { run(thread); });
    }
    job_available_.notify_one();
}

inline void thread_pool::run(std::thread& thread)
{
    util::scope_guard termination_guard([this, &thread] { assert(0 && "TODO"); });
    while(!is_joining_.load(std::memory_order_acquire)) {
        time_point idle_start = ts_cached_clock::now();
        std::unique_lock<std::mutex> job_queue_lock(job_queue_mutex_);
        // wake up if thread pool is beign joined or a new job is available
        job_available_.wait(job_queue_lock, [this, &thread] {
            return is_joining_.load(std::memory_order_acquire) || !job_queue_.empty();
        });
        idle_time_.fetch_add(to_int<milliseconds>(ts_cached_clock::now() - idle_start),
                std::memory_order_relaxed);

        // thread woke up because thread_pool is stopping thread or thread hasn't
        // worked in the past minute; either way, stop execution
        if(is_joining_.load(std::memory_order_acquire)) {
            break;
        }

        execute_jobs(thread, std::move(job_queue_lock));
    }
    termination_guard.disable();
}

inline void thread_pool::execute_jobs(
        std::thread& thread, std::unique_lock<std::mutex> job_queue_lock)
{
    assert(job_queue_lock.owns_lock());

    while(!job_queue_.empty()) {
        auto job = std::move(job_queue_.front());
        job_queue_.pop_front();
        job_queue_lock.unlock();

        const time_point work_start = ts_cached_clock::now();
        job(); // TODO exception safety
        work_time_.fetch_add(to_int<milliseconds>(ts_cached_clock::now() - work_start),
                std::memory_order_relaxed);
        num_executed_jobs_.fetch_add(1, std::memory_order_relaxed);

        job_queue_lock.lock();
    }
}

} // namespace tide
