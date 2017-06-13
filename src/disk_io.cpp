#include "torrent_info.hpp"
#include "file_info.hpp"
#include "settings.hpp"
#include "disk_io.hpp"

#include <cmath>
#include <map>

#include <iostream>

namespace tide {

disk_io::disk_io(asio::io_service& network_ios, const disk_io_settings& settings)
    : m_network_ios(network_ios)
    , m_settings(settings)
    , m_disk_buffer_pool(0x4000)
{}

disk_io::~disk_io()
{
}

bool disk_io::is_overwhelmed() const noexcept
{
    // TODO this should be determined according to some threshold/watermark system
    return false;
}

void disk_io::change_cache_size(const int64_t n)
{
}

void disk_io::read_all_torrent_states(
    std::function<void(const std::error_code&, std::vector<torrent_state>)> handler)
{
}

void disk_io::read_metainfo(const path& path,
    std::function<void(const std::error_code&, metainfo)> handler)
{
}

void disk_io::allocate_torrent(
    std::shared_ptr<torrent_info> info, string_view piece_hashes,
    std::function<void(const std::error_code&, torrent_storage_handle)> handler)
{
    //m_torrents.emplace(info->id, torrent_storage(info, piece_hashes));
}

void disk_io::move_torrent(const torrent_id_t torrent, std::string new_path,
    std::function<void(const std::error_code&)> handler)
{
}

void disk_io::rename_torrent(const torrent_id_t torrent, std::string name,
    std::function<void(const std::error_code&)> handler)
{
}

void disk_io::erase_torrent_files(const torrent_id_t torrent,
    std::function<void(const std::error_code&)> handler)
{
}

void disk_io::erase_torrent_metadata(const torrent_id_t torrent,
    std::function<void(const std::error_code&)> handler)
{
}

void disk_io::save_torrent_state(const torrent_id_t torrent, const torrent_state& state,
    std::function<void(const std::error_code&)> handler)
{
}

void disk_io::read_torrent_state(const torrent_id_t torrent,
    std::function<void(const std::error_code&, torrent_state)> handler)
{
}

void disk_io::check_storage_integrity(std::function<void(const std::error_code&)> handler)
{
}

void disk_io::create_sha1_digest(const_view<uint8_t> data,
    std::function<void(sha1_hash)> handler)
{
}

disk_buffer disk_io::get_write_buffer()
{
    return disk_buffer(reinterpret_cast<uint8_t*>(m_disk_buffer_pool.malloc()));
}

void disk_io::return_write_buffer(disk_buffer buffer)
{
    m_disk_buffer_pool.free(reinterpret_cast<void*>(buffer.data()));
}

void disk_io::save_block(const torrent_id_t torrent,
    const block_info& block_info, disk_buffer block_data,
    std::function<void(const std::error_code&)> save_handler,
    std::function<void(bool)> piece_completion_handler)
{
    auto it = m_torrents.find(torrent);
    if(it == m_torrents.end())
    {
        std::cerr << "error, torrent not found\n";
        return;
    }
    // TODO ONLY FOR THE DURATION OF THE TESTS
    /*
    m_network_ios.post(
        [save_handler = std::move(save_handler)]
        {
            save_handler(std::error_code());
        }
    );
    m_network_ios.post(
        [piece_completion_handler = std::move(piece_completion_handler), it, block_info]
        {
            torrent_entry torrent_entry = *it->second;
            torrent_entry.hashed_block(block_info, std::move(piece_completion_handler));
        }
    );
    */
}

void disk_io::fetch_block(const torrent_id_t torrent, const block_info& block_info,
    std::function<void(const std::error_code&, block_source)> handler)
{
}

} // namespace tide
