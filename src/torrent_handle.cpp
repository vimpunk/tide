#include "torrent_handle.hpp"
#include "torrent.hpp"

#include <asio/io_service.hpp>

namespace tide {

torrent_handle::torrent_handle(std::weak_ptr<torrent> t)
    : m_torrent(std::move(t))
    , m_ios(&m_torrent.lock()->m_ios)
    , m_info(&m_torrent.lock()->m_ts_info)
    , m_info_mutex(&m_torrent.lock()->m_ts_info_mutex)
{}

torrent_info torrent_handle::info() const
{
    if(is_valid())
        return *m_info;
    else
        return {};
}

void torrent_handle::piece_availability(std::vector<int>& piece_map)
{
}

void torrent_handle::pause()
{
    thread_safe_execution([this] { m_torrent.lock()->stop(); });
}

void torrent_handle::resume()
{
    thread_safe_execution([this] { m_torrent.lock()->start(); });
}

void torrent_handle::prioritize_file(const int file_index)
{
    thread_safe_execution([this, file_index]
        { m_torrent.lock()->prioritize_file(file_index); });
}

void torrent_handle::deprioritize_file(const int file_index)
{
    thread_safe_execution([this, file_index]
        { m_torrent.lock()->deprioritize_file(file_index); });
}

void torrent_handle::prioritize_piece(const piece_index_t piece)
{
    thread_safe_execution([this, piece]
        { m_torrent.lock()->prioritize_piece(piece); });
}

void torrent_handle::deprioritize_piece(const piece_index_t piece)
{
    thread_safe_execution([this, piece]
        { m_torrent.lock()->deprioritize_piece(piece); });
}

void torrent_handle::apply_settings(const torrent_settings& settings)
{
    thread_safe_execution([this, settings]
        { m_torrent.lock()->apply_settings(settings); });
}

void torrent_handle::force_tracker_reannounce(string_view url)
{

}

template<typename F>
void torrent_handle::thread_safe_execution(F&& function)
{
    auto t = m_torrent.lock();
    if(t)
    {
        t->m_ios.post([function = std::move(function)] { function(); });
    }
}

} // namespace tide
