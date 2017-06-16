#include "torrent_disk_io_frontend.hpp"
#include "piece_download.hpp"
#include "block_info.hpp"
#include "torrent.hpp"

torrent_disk_io_frontend::torrent_disk_io_frontend(torrent& t)
    : m_torrent(t.shared_from_this())
{}

disk_buffer torrent_disk_io_frontend::get_write_buffer()
{
    return m_torrent->m_disk_io.get_write_buffer();
}

/**
 * This saves a block to disk and once done, gives back disk_io the disk_buffer
 * holding the block data, invokes handler, and passes to disk_io torrent's
 * piece completion handler, which when invoked, posts the piece's hash result to
 * all the peers attached to piece_download, to which the saved block belongs.
 */
void torrent_disk_io_frontend::save_block(
    const block_info& block_info, disk_buffer block_data, piece_download& download,
    std::function<void(const std::error_code&)> handler)
{
    m_torrent->m_disk_io.save_block(m_torrent->m_info.id, block_info,
        std::move(block_data), std::move(handler), 
        [m_torrent, &download](bool is_valid)
        { m_torrent->on_new_piece(download, is_valid); });
}

void torrent_disk_io_frontend::fetch_block(const block_info& block_info,
    std::function<void(const std::error_code&, block_source)> handler)
{
    m_torrent->disk_io.fetch_block(m_torrent->m_info.id, block_info, std::move(handler));
}
