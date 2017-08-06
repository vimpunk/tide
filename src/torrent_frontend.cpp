#include "torrent_frontend.hpp"
#include "piece_download.hpp"
#include "piece_picker.hpp"
#include "torrent_info.hpp"
#include "block_info.hpp"
#include "torrent.hpp"
#include "disk_io.hpp"

namespace tide {

torrent_frontend::torrent_frontend(torrent& t)
    : m_torrent(t.shared_from_this())
{}

disk_buffer torrent_frontend::get_disk_buffer(const int length)
{
    return m_torrent->m_disk_io.get_disk_buffer(length);
}

class piece_picker& torrent_frontend::piece_picker() noexcept
{
    return *m_torrent->m_piece_picker;
}

const class piece_picker& torrent_frontend::piece_picker() const noexcept
{
    return *m_torrent->m_piece_picker;
}

torrent_info& torrent_frontend::info() noexcept
{
    return *m_torrent->m_info;
}

const torrent_info& torrent_frontend::info() const noexcept
{
    return *m_torrent->m_info;
}

std::vector<std::shared_ptr<piece_download>>& torrent_frontend::downloads() noexcept
{
    return *m_torrent->m_downloads;
}

const std::vector<std::shared_ptr<piece_download>>&
torrent_frontend::downloads() const noexcept
{
    return *m_torrent->m_downloads;
}

// NOTE: must not capture `this` as `this` is owned by a peer_session that may die by
// the time some of the handlers are invoked, so only capture m_torrent.

void torrent_frontend::save_block(
    const block_info& block_info, disk_buffer block_data, piece_download& download,
    std::function<void(const std::error_code&)> handler)
{
    m_torrent->m_disk_io.save_block(m_torrent->m_info->id, block_info,
        std::move(block_data), std::move(handler), 
        [t = m_torrent, &download](bool is_valid)
        { t->on_new_piece(download, is_valid); });
}

void torrent_frontend::fetch_block(const block_info& block_info,
    std::function<void(const std::error_code&, block_source)> handler)
{
    m_torrent->m_disk_io.fetch_block(m_torrent->m_info->id,
        block_info, std::move(handler));
}

void torrent_frontend::on_peer_session_stopped(peer_session& session)
{
    m_torrent->on_peer_session_gracefully_stopped(session);
}

} // namespace tide

