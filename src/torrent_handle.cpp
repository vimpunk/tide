#include "torrent_handle.hpp"
#include "torrent.hpp"

#include <asio/io_service.hpp>

namespace tide {

torrent_handle::torrent_handle(std::weak_ptr<torrent> t)
    : torrent_(std::move(t))
    , ios_(&torrent_.lock()->ios_)
    , info_(&torrent_.lock()->ts_info_)
    , info_mutex_(&torrent_.lock()->ts_info_mutex_)
{}

torrent_info torrent_handle::info() const
{
    if(is_valid())
        return *info_;
    else
        return {};
}

void torrent_handle::piece_availability(std::vector<int>& piece_map)
{
}

void torrent_handle::pause()
{
    thread_safe_execution([this] { torrent_.lock()->stop(); });
}

void torrent_handle::resume()
{
    thread_safe_execution([this] { torrent_.lock()->start(); });
}

void torrent_handle::prioritize_file(const int file_index)
{
    thread_safe_execution([this, file_index]
        { torrent_.lock()->prioritize_file(file_index); });
}

void torrent_handle::deprioritize_file(const int file_index)
{
    thread_safe_execution([this, file_index]
        { torrent_.lock()->deprioritize_file(file_index); });
}

void torrent_handle::prioritize_piece(const piece_index_t piece)
{
    thread_safe_execution([this, piece]
        { torrent_.lock()->prioritize_piece(piece); });
}

void torrent_handle::deprioritize_piece(const piece_index_t piece)
{
    thread_safe_execution([this, piece]
        { torrent_.lock()->deprioritize_piece(piece); });
}

void torrent_handle::apply_settings(const torrent_settings& settings)
{
    thread_safe_execution([this, settings]
        { torrent_.lock()->apply_settings(settings); });
}

void torrent_handle::force_tracker_reannounce(string_view url)
{

}

template<typename F>
void torrent_handle::thread_safe_execution(F&& function)
{
    auto t = torrent_.lock();
    if(t)
    {
        t->ios_.post([function = std::move(function)] { function(); });
    }
}

} // namespace tide
