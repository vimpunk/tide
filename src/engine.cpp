#include "string_utils.hpp"
#include "engine.hpp"

#include <algorithm>
#include <stdexcept>
#include <cassert>

namespace tide {

engine::engine()
    : disk_io_(network_ios_, settings_)
    , work_(network_ios_)
    , cached_clock_updater_(network_ios_)
{
    update_cached_clock();
}

engine::engine(const settings& s) : engine()
{
    settings_ = s;
}

void engine::update_cached_clock()
{
    cached_clock::update();
    start_timer(cached_clock_updater_, milliseconds(100),
        [this](const auto& /*error*/) { update_cached_clock(); });
}

void engine::pause()
{
    network_ios_.post([this] { for(auto& torrent : torrents_) { torrent->stop(); } });
}

void engine::resume()
{
    network_ios_.post([this] { for(auto& torrent : torrents_) { torrent->start(); } });
}

std::deque<std::unique_ptr<alert>> engine::alerts()
{
    return alert_queue_.extract_alerts();
}

void engine::parse_metainfo(const path& path)
{
    network_ios_.post([this, path]
    {
        disk_io_.read_metainfo(path,
            [this](const std::error_code& error, metainfo m)
            {
            /*
                if(error)
                    alert_queue_.emplace<async_completion_error>(error);
                else
                    alert_queue_.emplace<metainfo_parse_completion>(std::move(m));
            */
            });
    });
}

void engine::add_torrent(torrent_args args)
{
    verify_torrent_args(args);
    // TODO fill in default args if user didn't provide optional settings
    network_ios_.post([this, args = std::move(args)]
    {
        // torrent calls disk_io::allocate_torrent() so we don't have to here
        const torrent_id_t torrent_id = next_torrent_id();
        torrents_.emplace_back(std::make_shared<torrent>(torrent_id, network_ios_,
            disk_io_, bandwidth_controller_, settings_, get_trackers(args.metainfo),
            endpoint_filter_, alert_queue_, std::move(args)));
        alert_queue_.emplace<torrent_added_alert>(torrents_.back()->get_handle());
    });
}

inline void engine::verify_torrent_args(torrent_args& args) const
{
    // TODO this is mostly a rough outline just to have something for the time being
    if(args.metainfo.source.empty())
        throw std::invalid_argument("torrent_args::metainfo must not be empty");
    if(args.save_path.empty())
        throw std::invalid_argument("torrent_args::path must not be empty");

    for(auto tracker : args.metainfo.announce_list)
    {
        // TODO obviously the full url needs to be tested
        if(!util::starts_with(tracker.url, "udp://")
           && !util::starts_with(tracker.url, "http://"))
        {
            throw std::invalid_argument(
                "metainfo::announce url must contain a protocol identifier");
        }
    }

    if(!args.metainfo.announce.empty()
       && !util::starts_with(args.metainfo.announce, "udp://")
       && !util::starts_with(args.metainfo.announce, "http://"))
    {
        throw std::invalid_argument(
            "metainfo::announce url must contain a protocol identifier");
    }
    // TODO check if save path is valid and exists
}

inline torrent_id_t engine::next_torrent_id() noexcept
{
    static torrent_id_t s_id = 0;
    return s_id++;
}

std::vector<tracker_entry> engine::get_trackers(const metainfo& metainfo)
{
    // announce may be the same as one of the entries in announce-list, so check
    bool is_announce_distinct = true;
    if(metainfo.announce.empty())
    {
        is_announce_distinct = false;
    }
    else
    {
        for(const metainfo::tracker_entry& tracker : metainfo.announce_list)
        {
            if(tracker.url == metainfo.announce)
            {
                is_announce_distinct = false;
                break;
            }
        }
    }

    std::vector<tracker_entry> trackers;
    trackers.reserve(metainfo.announce_list.size() + is_announce_distinct ? 1 : 0);

    const auto add_tracker = [this, &trackers](const metainfo::tracker_entry& tracker)
    {
        tracker_entry entry;
        entry.tier = tracker.tier;
        auto it = std::find_if(trackers_.begin(), trackers_.end(),
            [&tracker](const auto& t) { return t->url() == tracker.url; });
        if(it != trackers_.end())
        {
            entry.tracker = *it;
            trackers.emplace_back(std::move(entry));
        }
        else
        {
            // at this point tracker urls must be valid TODO where is it ensured?
            if(util::is_udp_tracker(tracker.url))
            {
                entry.tracker = std::make_shared<udp_tracker>(
                    network_ios_, tracker.url, settings_);
                trackers.emplace_back(std::move(entry));
            }
            else if(util::is_http_tracker(tracker.url))
            {
                // we don't yet support http trackers
                return;
                //entry.tracker = std::make_shared<http_tracker>(
                    //network_ios_, tracker.url, settings_);
                //trackers.emplace_back(std::move(entry));
            }
            // add new tracker to the engine's tracker collection as well
            trackers_.emplace_back(trackers.back().tracker);
        }
    };

    for(auto tracker : metainfo.announce_list) { add_tracker(tracker); }
    if(is_announce_distinct)
    {
        metainfo::tracker_entry entry;
        entry.url = metainfo.announce;
        entry.tier = !trackers.empty() ? trackers.back().tier + 1 : 0;
        add_tracker(entry);
    }
    return trackers;
}

} // namespace tide
