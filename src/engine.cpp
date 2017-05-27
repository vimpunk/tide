#include "engine.hpp"

#include <stdexcept>
#include <cassert>

void engine::add_torrent(torrent_args args, std::function<void(torrent_handler)> handler)
{
    verify_torrent_args(args);
    // TODO fill in default args if user didn't provide optional settings
    m_network_ios.post([this, args = std::move(args), handler = std::move(handler)]
    {
        // torrent calls disk_io::allocate_torrent() so we don't have to here
        const torrent_id_t id = get_torrent_id();
        auto it = m_torrents.emplace(
            id, torrent(id, m_disk_io, m_bandwidth_controller, m_settings, args)
        ).first;
        assert(it != m_torrents.end());
        handler(it->second.get_handle());
    });
}

void engine::verify_torrent_args(torrent_args& args) const
{
    // TODO this is mostly a rough outline just to have something for the time being
    if(args.metainfo.source.is_empty())
    {
        throw std::invalid_argument("TODO");
    }
}
