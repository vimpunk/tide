#include "torrent_handle.hpp"
#include "torrent.hpp"

#include <asio/io_context.hpp>

namespace tide {

torrent_handle::torrent_handle(std::weak_ptr<torrent> t)
    : torrent_(std::move(t))
    , ios_(&torrent_.lock()->ios_)
{}

void torrent_handle::pause()
{
    thread_safe_execution([this](torrent& t) { t.stop(); });
}

void torrent_handle::resume()
{
    thread_safe_execution([this](torrent& t) { t.start(); });
}

void torrent_handle::prioritize_file(const int file_index)
{
    thread_safe_execution([this, file_index](torrent& t)
        { t.prioritize_file(file_index); });
}

void torrent_handle::deprioritize_file(const int file_index)
{
    thread_safe_execution([this, file_index](torrent& t)
        { t.deprioritize_file(file_index); });
}

void torrent_handle::prioritize_piece(const piece_index_t piece)
{
    thread_safe_execution([this, piece](torrent& t) { t.prioritize_piece(piece); });
}

void torrent_handle::deprioritize_piece(const piece_index_t piece)
{
    thread_safe_execution([this, piece](torrent& t) { t.deprioritize_piece(piece); });
}

void torrent_handle::apply_settings(const torrent_settings& settings)
{
    thread_safe_execution([this, settings](torrent& t) { t.apply_settings(settings); });
}

void torrent_handle::force_tracker_announce(string_view url)
{
    thread_safe_execution([this, url](torrent& t) { t.force_tracker_announce(url); });
}

void torrent_handle::set_max_upload_slots(const int n)
{
    thread_safe_execution([this, n](torrent& t) { t.set_max_upload_slots(n); });
}

void torrent_handle::set_max_upload_rate(const int n)
{
    thread_safe_execution([this, n](torrent& t) { t.set_max_upload_rate(n); });
}

void torrent_handle::set_max_download_rate(const int n)
{
    thread_safe_execution([this, n](torrent& t) { t.set_max_download_rate(n); });
}

void torrent_handle::set_max_connections(const int n)
{
    thread_safe_execution([this, n](torrent& t) { t.set_max_connections(n); });
}

template<typename Function>
void torrent_handle::thread_safe_execution(Function function)
{
    std::shared_ptr<torrent> t = torrent_.lock();
    if(t)
    {
        t->ios_.post([function = std::move(function), t = t] { function(*t); });
    }
}

torrent_info torrent_handle::info() const
{
    auto t = torrent_.lock();
    if(t)
    {
        std::unique_lock<std::mutex> _(t->ts_info_mutex_);
        return t->ts_info_;
    }
    else
    {
        return {};
    }
}

#define TRY_RETURN_INFO_FIELD(field) do { \
    auto t = torrent_.lock(); \
    if(t) \
    { \
        std::unique_lock<std::mutex> _(t->ts_info_mutex_); \
        return t->ts_info_.field; \
    } \
    else \
    { \
        return {}; \
    } \
} while(0)

int torrent_handle::max_upload_slots() const noexcept
{
    TRY_RETURN_INFO_FIELD(settings.max_upload_slots);
}

int torrent_handle::max_upload_rate() const noexcept
{
    TRY_RETURN_INFO_FIELD(settings.max_upload_rate);
}

int torrent_handle::max_download_rate() const noexcept
{
    TRY_RETURN_INFO_FIELD(settings.max_download_rate);
}

int torrent_handle::max_connections() const noexcept
{
    TRY_RETURN_INFO_FIELD(settings.max_connections);
}

torrent_id_t torrent_handle::id() const noexcept
{
    TRY_RETURN_INFO_FIELD(id);
}

sha1_hash torrent_handle::info_hash() const noexcept
{
    TRY_RETURN_INFO_FIELD(info_hash);
}

seconds torrent_handle::total_seed_time() const noexcept
{
    TRY_RETURN_INFO_FIELD(total_seed_time);
}

seconds torrent_handle::total_leech_time() const noexcept
{
    TRY_RETURN_INFO_FIELD(total_leech_time);
}

seconds torrent_handle::total_active_time() const noexcept
{
    auto t = torrent_.lock();
    if(t)
    {
        std::unique_lock<std::mutex> _(t->ts_info_mutex_);
        return t->ts_info_.total_seed_time + t->ts_info_.total_leech_time;
    }
    else
    {
        return seconds{0};
    }
}

time_point torrent_handle::download_started_time() const noexcept
{
    TRY_RETURN_INFO_FIELD(download_started_time);
}

time_point torrent_handle::download_finished_time() const noexcept
{
    TRY_RETURN_INFO_FIELD(download_finished_time);
}

int torrent_handle::total_peers() const noexcept
{
    // TODO also include the unconnected/available peers.
    return num_connected_peers();
}

int torrent_handle::num_connected_peers() const noexcept
{
    auto t = torrent_.lock();
    if(t)
    {
        std::unique_lock<std::mutex> _(t->ts_info_mutex_);
        return t->ts_info_.num_seeders + t->ts_info_.num_leechers;
    }
    else
    {
        return 0;
    }
}

int torrent_handle::num_seeders() const noexcept
{
    TRY_RETURN_INFO_FIELD(num_seeders);
}

int torrent_handle::num_leechers() const noexcept
{
    TRY_RETURN_INFO_FIELD(num_leechers);
}

bool torrent_handle::is_stopped() const noexcept
{
    return !is_stopped();
}

bool torrent_handle::is_running() const noexcept
{
    TRY_RETURN_INFO_FIELD(state[torrent_info::active]);
}

bool torrent_handle::is_leech() const noexcept
{
    return !is_seed();
}

bool torrent_handle::is_seed() const noexcept
{
    TRY_RETURN_INFO_FIELD(state[torrent_info::seeding]);
}

bool operator==(const torrent_handle& a, const torrent& b)
{
    return a.torrent_.lock().get() == &b;
}

bool operator==(const torrent& a, const torrent_handle& b)
{
    return b == a;
}

bool operator!=(const torrent_handle& a, const torrent& b)
{
    return !(a == b);
}

bool operator!=(const torrent& a, const torrent_handle& b)
{
    return !(a == b);
}

/*
void torrent_handle::piece_availability(std::vector<int>& piece_map)
{
    // TODO can we even do this in a thread-safe manner?
}
*/

} // namespace tide
