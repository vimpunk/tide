#include "torrent_frontend.hpp"
#include "piece_download.hpp"
#include "piece_picker.hpp"
#include "torrent_info.hpp"
#include "block_info.hpp"
#include "torrent.hpp"
#include "disk_io.hpp"

namespace tide {

torrent_frontend::torrent_frontend(torrent& t)
    : torrent_(t.shared_from_this())
{}

disk_buffer torrent_frontend::get_disk_buffer(const int length)
{
    return torrent_->disk_io_.get_disk_buffer(length);
}

class piece_picker& torrent_frontend::piece_picker() noexcept
{
    return torrent_->piece_picker_;
}

const class piece_picker& torrent_frontend::piece_picker() const noexcept
{
    return torrent_->piece_picker_;
}

torrent_info& torrent_frontend::info() noexcept
{
    return torrent_->info_;
}

const torrent_info& torrent_frontend::info() const noexcept
{
    return torrent_->info_;
}

std::vector<std::shared_ptr<piece_download>>& torrent_frontend::downloads() noexcept
{
    return torrent_->downloads_;
}

const std::vector<std::shared_ptr<piece_download>>&
torrent_frontend::downloads() const noexcept
{
    return torrent_->downloads_;
}

// NOTE: must not capture `this` as `this` is owned by a peer_session that may die by
// the time some of the handlers are invoked, so only capture torrent_.

void torrent_frontend::save_block(
    const block_info& block_info, disk_buffer block_data, piece_download& download,
    std::function<void(const std::error_code&)> handler)
{
    torrent_->disk_io_.save_block(torrent_->info_.id, block_info,
        std::move(block_data), std::move(handler), 
        [t = torrent_, &download](bool is_valid)
        { t->on_new_piece(download, is_valid); });
}

void torrent_frontend::fetch_block(const block_info& block_info,
    std::function<void(const std::error_code&, block_source)> handler)
{
    torrent_->disk_io_.fetch_block(torrent_->info_.id,
        block_info, std::move(handler));
}

void torrent_frontend::on_peer_session_stopped(peer_session& session)
{
    torrent_->on_peer_session_gracefully_stopped(session);
}

} // namespace tide

