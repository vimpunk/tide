#include "string_utils.hpp"
#include "engine.hpp"

#include <algorithm>
#include <stdexcept>
#include <cassert>

namespace tide {

std::vector<torrent_handle> engine::torrents()
{
    std::vector<torrent_handle> torrents;
    torrents.reserve(m_torrents.size());
    for(auto t : m_torrents)
    {
        torrents.emplace_back(t.second.get_handle());
    }
    return torrents;
}

std::vector<torrent_handle> engine::downloading_torrents()
{
    std::vector<torrent_handle> torrents;
    for(auto e : m_torrents)
    {
        torrent& t = e.second;
        if(t.is_downloading())
        {
            torrents.emplace_back(t.get_handle());
        }
    }
    return torrents;
}

std::vector<torrent_handle> engine::uploading_torrents()
{
    std::vector<torrent_handle> torrents;
    for(auto e : m_torrents)
    {
        torrent& t = e.second;
        if(t.is_uploading())
        {
            torrents.emplace_back(t.get_handle());
        }
    }
    return torrents;
}

std::vector<torrent_handle> engine::paused_torrents()
{
    std::vector<torrent_handle> torrents;
    for(auto e : m_torrents)
    {
        torrent& t = e.second;
        if(t.is_paused())
        {
            torrents.emplace_back(t.get_handle());
        }
    }
    return torrents;
}

void parse_metainfo(const path& path)
{
    m_network_ios.post([this]
    {
        m_disk_io.read_metainfo(path,
            [this](const std::error_code& error, metainfo metainfo)
            { /* TODO post metainfo to alert system */ });
    });
}

void engine::add_torrent(torrent_args args)
{
    verify_torrent_args(args);
    // TODO fill in default args if user didn't provide optional settings
    m_network_ios.post([this, args = std::move(args)]
    {
        // torrent calls disk_io::allocate_torrent() so we don't have to here
        const torrent_id_t torrent_id = get_torrent_id();
        auto it = m_torrents.emplace(torrent_id, torrent( torrent_id,
                m_disk_io, m_bandwidth_controller, m_settings,
                get_trackers(args.metainfo), m_endpoint_filter, m_event_queue,
                std::move(args))).first;
        assert(it != m_torrents.end());
        // TODO post torrent handle to user
        //post_event<torrent_created_event>(it->second.handle());
    });
}

inline void engine::verify_torrent_args(torrent_args& args) const
{
    // TODO this is mostly a rough outline just to have something for the time being
    if(args.metainfo.source.is_empty())
        throw std::invalid_argument("torrent_args::metainfo must not be empty");
    if(args.path.empty())
        throw std::invalid_argument("torrent_args::path must not be empty");
    for(auto url : args.metainfo.announce_list)
    {
        if(!util::starts_with(url, "udp://") && !util::starts_with(url, "http://"))
        {
            throw std::invalid_argument(
                "metainfo::announce url must contain a protocol identifier"
            );
        }
    }
    if(!util::starts_with(args.metainfo.announce, "udp://")
       && !util::starts_with(args.metainfo.announce, "http://"))
    {
        throw std::invalid_argument(
            "metainfo::announce url must contain a protocol identifier"
        );
    }
    // TODO check if save path is valid and exists
}

inline torrent_id_t engine::get_torrent_id() noexcept
{
    static torrent_id_t s_id = 0;
    return s_id++;
}

std::vector<tracker_entry> engine::get_trackers(const metainfo& metainfo)
{
    // announce may be the same as one of the entries of announce-list, so check it
    bool is_announce_distinct = true;
    for(metainfo::tracker_entry tracker : metainfo.announce_list)
    {
        if(tracker.url == metainfo.announce)
        {
            is_announce_distinct = false;
            break;
        }
    }
    std::vector<tracker_entry> trackers;
    trackers.reserve(metainfo.announce_list.size() + is_announce_distinct ? 1 : 0);
    auto add_tracker = [this, &trackers](const metainfo::tracker_entry& tracker)
    {
        // FIXME TODO shit, tracker's url and the url in metainfo are not the same, as
        // the protocol identifier is stripped from url before being passed to tracker
        tracker_entry entry;
        entry.tier = tracker.tier;
        auto it = std::find_if(m_trackers.begin(), m_trackers.end(),
            [&tracker](const std::shared_ptr<tracker>& t)
            { return t->url() == tracker.url; });
        if(it != m_trackers.end())
        {
            entry.tracker = *it;
            trackers.emplace_back(std::move(entry));
        }
        else
        {
            // at this point tracker urls must be valid
            if(util::is_udp_tracker(url))
            {
                entry.tracker = std::make_shared<udp_tracker>(
                    url, m_network_ios, m_settings);
                trackers.emplace_back(std::move(entry));
            }
            else if(util::is_http_tracker(url))
            {
                //entry.tracker = std::make_shared<http_tracker>(
                    //url, m_network_ios, m_settings);
                //trackers.emplace_back(std::move(entry));
            }
            m_trackers.emplace_back(trackers.back().tracker);
        }
    };
    for(auto tracker : metainfo.announce_list)
    {
        add_tracker(tracker);
    }
    if(is_announce_distinct)
    {
        tracker_entry entry;
        entry.url = metainfo.announce;
        entry.tier = !trackers.empty() ? trackers.back().tier + 1 : 0;
        add_tracker(entry);
    }
    return trackers;
}

} // namespace tide
