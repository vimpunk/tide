#include "torrent_disk_io_frontend.hpp"
#include "bandwidth_controller.hpp"
#include "endpoint_filter.hpp"
#include "piece_download.hpp"
#include "string_utils.hpp"
#include "piece_picker.hpp"
#include "event_queue.hpp"
#include "sha1_hasher.hpp"
#include "settings.hpp"
#include "disk_io.hpp"
#include "torrent.hpp"
#include "random.hpp"
#include "view.hpp"

#include <algorithm>
#include <iostream>
#include <cmath> // floor, min, max, pow

namespace tide {

// torrent needs to be kept alive until all async ops complete, so we bind a
// shared_ptr to torrent to each async op's handler along with `this`
#define SHARED_THIS this, self(shared_from_this())

torrent::torrent(
    torrent_id_t id,
    asio::io_service& ios,
    disk_io& disk_io,
    bandwidth_controller& bandwidth_controller,
    const settings& global_settings,
    std::vector<tracker_entry> trackers,
    endpoint_filter& endpoint_filter,
    event_queue& event_queue
)
    : m_ios(ios)
    , m_disk_io(disk_io)
    , m_bandwidth_controller(bandwidth_controller)
    , m_global_settings(global_settings)
    , m_endpoint_filter(endpoint_filter)
    , m_event_queue(event_queue)
    , m_trackers(std::move(trackers))
    , m_info(std::make_shared<torrent_info>())
    , m_downloads(std::make_shared<std::vector<std::shared_ptr<piece_download>>>())
    , m_update_timer(ios)
    , m_announce_timer(ios)
    , m_unchoke_comparator(&torrent::choke_ranker::download_rate_based)
{
    // make sure engine gave us valid trackers
    for(const auto& e : m_trackers) assert(e.tracker);
    m_info->id = id;
}

// for new torrents
torrent::torrent(
    torrent_id_t id,
    asio::io_service& ios,
    disk_io& disk_io,
    bandwidth_controller& bandwidth_controller,
    const settings& global_settings,
    std::vector<tracker_entry> trackers,
    endpoint_filter& endpoint_filter,
    event_queue& event_queue,
    torrent_args args
)
    : torrent(id, ios, disk_io, bandwidth_controller, global_settings,
        std::move(trackers), endpoint_filter, event_queue) 
{
    apply_torrent_args(args);
}

// for resumed torrents
// TODO
torrent::torrent(
    torrent_id_t id,
    asio::io_service& ios,
    disk_io& disk_io,
    bandwidth_controller& bandwidth_controller,
    const settings& global_settings,
    std::vector<tracker_entry> trackers,
    endpoint_filter& endpoint_filter,
    event_queue& event_queue,
    bmap resume_data
)
    : torrent(id, ios, disk_io, bandwidth_controller, global_settings,
        std::move(trackers), endpoint_filter, event_queue) 
{
    restore_resume_data(resume_data);
}

void torrent::apply_torrent_args(torrent_args& args)
{
    m_piece_hashes = args.metainfo.piece_hashes;
    m_piece_picker = std::make_shared<piece_picker>(args.metainfo.num_pieces);

    // TODO how expensive is this?
    m_info->info_hash = create_sha1_digest(
        args.metainfo.source.find_bmap("info").encode());
    m_info->save_path = std::move(args.save_path);
    m_info->num_pieces = args.metainfo.num_pieces;
    m_info->size = args.metainfo.total_length;
    m_info->piece_length = args.metainfo.piece_length;
    m_info->last_piece_length =
        m_info->size - (m_info->num_pieces - 1) * m_info->piece_length;
    m_info->settings = std::move(args.settings);
    m_info->files = std::move(args.metainfo.files);
    // we'll apply file priorities once storage is allocated
    // TODO we should probably apply priorities right away
    m_info->priority_files = std::move(args.priority_files);

    m_info->wanted_size = 0;
    for(const auto& f : m_info->files)
    {
        if(f.is_wanted) { m_info->wanted_size += f.length; }
    }

    if(args.name.empty())
    {
        args.metainfo.source.try_find_string("name", m_info->name);
    }
    else
    {
        m_info->name = std::move(args.name);
    }
}

void torrent::restore_resume_data(const bmap& resume_data)
{
    //m_piece_hashes
    //m_piece_picker = std::make_shared<piece_picker>(args.metainfo.num_pieces);
}

void torrent::start()
{
    if(m_info->state[torrent_info::active]) { return; }

    log(log_event::update, "starting torrent");
    m_info->state[torrent_info::active] = true;
    if(!m_storage)
    {
        log(log_event::disk, "allocating torrent storage");
        m_info->state[torrent_info::allocating] = true;
        std::error_code error;
        auto handle = m_disk_io.allocate_torrent(m_info, m_piece_hashes, error);
        on_torrent_allocated(error, handle);
    }
    announce(tracker_request::started);
    if(!m_peer_sessions.empty())
    {
        log(log_event::update, "trying to reconnect %i peers", m_peer_sessions.size());
        for(auto& session : m_peer_sessions) { session->start(); }
        update();
    }
}

void torrent::stop()
{
    if(!m_info->state[torrent_info::active]) { return; }

    log(log_event::update, "stopping torrent");

    // TODO should we stop these when the last peer disconnected?
    m_update_timer.cancel();
    m_announce_timer.cancel();

    announce(tracker_request::stopped);
    for(auto& session : m_peer_sessions)
    {
        if(!session->is_stopped())
        {
            // choke all peers to prevent responding to new requests (this is necessary,
            // since we're gracefully disconnecting peers, so they may be around for a 
            // while till all async ops finish, during which peers may send us requests)
            session->choke_peer();
            session->stop([SHARED_THIS, &session = *session]
                { on_peer_session_graceful_stop_complete(session); });
        }
    }
}

// TODO rename...
void torrent::on_peer_session_graceful_stop_complete(peer_session& session)
{
    on_peer_session_finished(session);
    if(num_connected_peers() == 0)
    {
        m_info->state[torrent_info::active] = false;
        assert(m_info->num_seeders = 0);
        assert(m_info->num_leechers = 0);
        assert(m_info->num_unchoked_peers = 0);
        save_state();
        // TODO send alert event that we finished shutting down
    }
}

void torrent::abort()
{
    // TODO if we're being stopped gracefully, we might want to switch from graceful to
    // abort instead of returning
    if(!m_info->state[torrent_info::active]) { return; }

    log(log_event::update, "aborting torrent");

    m_update_timer.cancel();
    m_announce_timer.cancel();

    for(auto& session : m_peer_sessions)
    {
        if(!session->is_disconnected()) { session->abort(); }
    }
    m_info->state[torrent_info::active] = false;
    m_info->num_seeders = 0;
    m_info->num_leechers = 0;
    m_info->num_unchoked_peers = 0;
    save_state();
}

void torrent::on_torrent_allocated(
    const std::error_code& error, torrent_storage_handle storage)
{
    if(error || !storage)
    {
        log(log_event::disk, "ERROR allocating disk storage");
        // TODO send alert
        // TODO what to do when we couldn't allocate file? could this even occur?
        // what are the possible errors? no save path? shouldn't that be checked
        // at a higher level?
        ++m_info->num_disk_io_failures;
        if(m_info->num_disk_io_failures < 100)
        {
            // TODO allocation is no longer async
            //m_disk_io.allocate_torrent(m_info, m_piece_hashes,
                //[SHARED_THIS](const std::error_code& ec, torrent_storage_handle storage)
                //{ on_torrent_allocated(ec, storage); });
        }
        return;
    }
    log(log_event::disk, "torrent allocated");
    m_storage = storage;
    m_info->state[torrent_info::allocating] = false;
    for(const file_index_t file : m_info->priority_files)
    {
        log(log_event::disk, "making file (%s) priority",
            m_info->files[file].path.c_str());
        m_piece_picker->make_priority(m_storage.pieces_in_file(file));
    }
}

void torrent::save_state()
{
    if(!m_is_state_changed) { return; }

    log(log_event::disk, "saving torrent state");
    m_is_state_changed = false;
    m_info->state[torrent_info::saving_state] = true;
    m_disk_io.save_torrent_resume_data(m_info->id, create_resume_data(),
        [SHARED_THIS](const std::error_code& error) { on_state_saved(error); });
}

void torrent::on_state_saved(const std::error_code& error)
{
    m_info->state[torrent_info::saving_state] = false;
    if(error)
    {
        m_is_state_changed = false;
        const auto reason = error.message();
        log(log_event::disk, "failed to save torrent state: %s", reason.c_str());
    }
    log(log_event::disk, "torrent state saved");
}

bmap_encoder torrent::create_resume_data() const
{
    bmap_encoder resume_data;

    // info
    resume_data["info_hash"] = std::string(
        m_info->info_hash.begin(), m_info->info_hash.end());
    resume_data["bitfield"] = is_seed() ? "have_all"
                                        : m_piece_picker->my_bitfield().to_string();
    resume_data["save_path"] = m_info->save_path.c_str();
    resume_data["name"] = m_info->name;
    // TODO maybe deduce these by adding together the file lengths when we read them back
    resume_data["size"] = m_info->size;
    resume_data["wanted_size"] = m_info->wanted_size;
    resume_data["num_pieces"] = m_info->num_pieces;
    resume_data["num_wanted_pieces"] = m_info->num_wanted_pieces;
    resume_data["num_downloaded_pieces"] = m_info->num_downloaded_pieces;
    resume_data["piece_hashes"] = m_piece_hashes.data();
    blist_encoder files_list;
    for(const auto& f : m_info->files)
    {
        bmap_encoder file_map;
        file_map["path"] = f.path.c_str();
        file_map["length"] = f.length;
        file_map["completion"] = f.completion * 100;
        file_map["is_wanted"] = f.is_wanted ? 1 : 0;
        files_list.push_back(file_map);
    }
    resume_data["files"] = files_list;
    blist_encoder priority_files;
    for(const auto& f : m_info->priority_files)
    {
        priority_files.push_back(f);
    }
    resume_data["priority_files"] = priority_files;
    blist_encoder partial_pieces;
    for(const auto& d : *m_downloads)
    {
        bmap_encoder piece;
        piece["index"] = d->piece_index();
        blist_encoder blocks;
        int i = 0;
        for(const piece_download::block block : d->blocks())
        {
            if(block.status == piece_download::block::status::received)
            {
                // save the block indices, they are at 0x4000 offsets
                blocks.push_back(i);
            }
            ++i;
        }
        piece["blocks"] = blocks;
        partial_pieces.push_back(piece);
    }
    resume_data["partial_pieces"] = std::move(partial_pieces);

    // settings
    resume_data["download_sequentially"] = m_info->settings.download_sequentially;
    resume_data["stop_when_downloaded"] = m_info->settings.stop_when_downloaded;
    resume_data["prefer_udp_trackers"] = m_info->settings.prefer_udp_trackers;
    resume_data["max_upload_slots"] = m_info->settings.max_upload_slots;
    resume_data["max_connections"] = m_info->settings.max_connections;
    resume_data["max_upload_rate"] = m_info->settings.max_upload_rate;
    resume_data["max_download_rate"] = m_info->settings.max_download_rate;

    // stats
    resume_data["seed_time"] = total_seconds(m_info->total_seed_time);
    resume_data["leech_time"] = total_seconds(m_info->total_leech_time);
    resume_data["download_started_time"] = total_seconds(
        m_info->download_started_time.time_since_epoch());
    resume_data["download_finished_time"] = total_seconds(
        m_info->download_finished_time.time_since_epoch());
    resume_data["total_downloaded_piece_bytes"] = m_info->total_downloaded_piece_bytes;
    resume_data["total_uploaded_piece_bytes"] = m_info->total_uploaded_piece_bytes;
    resume_data["total_downloaded_bytes"] = m_info->total_downloaded_bytes;
    resume_data["total_uploaded_bytes"] = m_info->total_uploaded_bytes;
    resume_data["total_verified_piece_bytes"] = m_info->total_verified_piece_bytes;
    resume_data["total_failed_piece_bytes"] = m_info->total_failed_piece_bytes;
    resume_data["total_wasted_bytes"] = m_info->total_wasted_bytes;
    resume_data["total_bytes_written_to_disk"] = m_info->total_bytes_written_to_disk;
    resume_data["total_bytes_read_from_disk"] = m_info->total_bytes_read_from_disk;
    resume_data["num_hash_fails"] = m_info->num_hash_fails;
    resume_data["num_illicit_requests"] = m_info->num_illicit_requests;
    resume_data["num_unwanted_blocks"] = m_info->num_unwanted_blocks;
    resume_data["num_disk_io_failures"] = m_info->num_disk_io_failures;
    resume_data["num_timed_out_requests"] = m_info->num_timed_out_requests;

    return resume_data;
}

void torrent::announce(tracker_request::event_t event, const bool force)
{
    if(m_trackers.empty())
    {
        log(log_event::tracker, "cannot announce: no trackers");
        return;
    }
    else if(m_is_aborted) // TODO TODO
    {
        // TODO we should allow announces when we're in graceful stop mode
        log(log_event::tracker, "cannot announce: torrent aborted");
        return;
    }
    m_info->state[torrent_info::announcing] = true;
    tracker_request request = create_tracker_request(event);

    // if the event is stopped or completed, we need to send it to all trackers to which
    // we have announced in the past, otherwise just pick the most suitable tracker, as
    // otherwise we're just requesting more peers
    if((event == tracker_request::stopped) || (event == tracker_request::completed))
    {
        for(auto& entry : m_trackers)
        {
            // don't send the 'stopped' and 'completed' events more than once, or if we 
            // haven't contacted tracker at all (haven't sent a 'started' event)
            if((entry.has_sent_completed && (event == tracker_request::completed))
               || (entry.has_sent_stopped && (event == tracker_request::stopped)))
            {
                continue;
            }
            else if(entry.has_sent_started && entry.tracker->is_reachable())
            {
                log(log_event::tracker, "sending event(%s) to tracker(%s)",
                    event == tracker_request::completed ? "completed" : "stopped",
                    entry.tracker->url().c_str());
                entry.tracker->announce(request, [SHARED_THIS, &entry, event]
                    (const std::error_code& ec, tracker_response response)
                    { on_announce_response(entry, ec, std::move(response), event); });
            }
        }
    }
    else
    {
        tracker_entry* t = pick_tracker(force);
        // TODO ehhh, this is not completely correct
        if(t == nullptr)
        {
            if(m_trackers.empty() && m_peer_sessions.empty() && m_available_peers.empty())
            {
                stop();
            }
            return;
        }
        tracker_entry& entry = *t;
        // if we haven't sent the 'started' event before, this is the first time
        // contacting tracker--in which case we must send a 'started' event
        if(!entry.has_sent_started)
        {
            request.event = tracker_request::started;
        }
        log(log_event::tracker, "sending event(%s) to tracker(%s)",
            event == tracker_request::started ? "started" : "none",
            entry.tracker->url().c_str());
        entry.tracker->announce(std::move(request),
            [SHARED_THIS, &entry, event](const std::error_code& ec, tracker_response r)
            { on_announce_response(entry, ec, std::move(r), event); });
    }
}

inline tracker_request torrent::create_tracker_request(
    tracker_request::event_t event) const noexcept
{
    tracker_request request;
    request.info_hash = m_info->info_hash;
    request.peer_id = m_global_settings.client_id;
    request.downloaded = m_info->total_downloaded_piece_bytes;
    request.uploaded = m_info->total_uploaded_piece_bytes;
    request.left = m_info->size - m_info->wanted_size;
    request.port = m_global_settings.listener_port;
    request.event = event;
    request.compact = true; // I think?
    request.num_want = event == tracker_request::started
                    || event == tracker_request::none
                       ? calculate_num_want()
                       : 0;
    return request;
}

inline int torrent::calculate_num_want() const noexcept
{
    // TODO this is just a placeholder/outline
    const int n = m_info->settings.max_connections - m_peer_sessions.size();
    if(n < 30) { return 30; }
    return n;
}

inline tracker_entry* torrent::pick_tracker(const bool force)
{
    assert(!m_trackers.empty());
    // even if we're forcing the reannounce, first try to see if we can find a tracker
    // to which we can announce without forcing some other tracker
    for(auto& t : m_trackers)
    {
        if(can_announce_to(t)) { return &t; }
    }
    // if we're forcing a reannounce, we don't have to check whether the wait interval
    // is up, we need only know that we can reach tracker
    if(force)
    {
        for(auto& t : m_trackers)
        {
            if(!t.tracker->had_protocol_error() && t.tracker->is_reachable())
                return &t;
        }
    }
    return nullptr;
}

inline bool torrent::can_announce_to(const tracker_entry& t) const noexcept
{
    return t.tracker->is_reachable()
        && !t.tracker->had_protocol_error()
        && cached_clock::now() - t.last_announce_time >= t.interval;
}

void torrent::on_announce_response(tracker_entry& tracker, const std::error_code& error,
    tracker_response response, const tracker_request::event_t event)
{
    m_info->state[torrent_info::announcing] = false;
    if(error)
    {
        on_announce_error(tracker, error, event);
        return;
    }

    log(log_event::tracker, "received announce response from %s (peers: %i; "
        "interval: %i; seeders: %i; leechers: %i; tracker_id: %s)",
        tracker.tracker->url().c_str(), response.peers.size()
        + response.ipv4_peers.size() + response.ipv6_peers.size(), response.interval,
        response.num_seeders, response.num_leechers, response.tracker_id.c_str());

    const auto now = cached_clock::now();
    m_info->last_announce_time = now;
    tracker.last_announce_time = now; 
    if(event == tracker_request::started)
        tracker.has_sent_started = true;
    else if(event == tracker_request::completed)
        tracker.has_sent_completed = true;
    else if(event == tracker_request::stopped)
        tracker.has_sent_stopped = true;

    if(!response.warning_message.empty())
    {
        // TODO send alert if appropriate
        log(log_event::tracker, "warning: %s", response.warning_message.c_str());
        tracker.warning_message = std::move(response.warning_message);
    }

    m_available_peers.reserve(m_available_peers.size()
        + response.ipv4_peers.size() + response.ipv6_peers.size());
    for(auto& ep : response.ipv4_peers) { add_peer(std::move(ep)); }
    for(auto& ep : response.ipv6_peers) { add_peer(std::move(ep)); }

    // if we aren't connected to any peers but received peers we can connect to, it
    // means the update cycle (i.e. torrent) is not running, this may be the first
    // announce or we stoppped torrent as soon as we disconnected the last peer, in
    // either case, reinstate the update cycle (but only do this if the torrent is
    // not stopped, as it is possible to be in a stopped state by the time the response
    // arrives if torrent was gracefully stopped)
    if(!is_stopped() && m_peer_sessions.empty() && !m_available_peers.empty())
    {
        log(log_event::update, "starting torrent update cycle");
        update();
    }
}

inline void torrent::on_announce_error(tracker_entry& tracker,
    const std::error_code& error, const tracker_request::event_t event)
{
    if(error.category() == tracker_category())
    {
        const auto reason = error.message();
        log(log_event::tracker, "error contacting tracker: %s", reason.c_str());
        // if this tracker failed too much, we won't bother in the future, remove it
        if(++tracker.num_fails > 100)
        {
            m_trackers.erase(std::find_if(m_trackers.begin(), m_trackers.end(),
                [&tracker](const auto& t) { return &t == &tracker; }));
            if(m_trackers.empty() && m_peer_sessions.empty() && m_available_peers.empty())
            {
                stop();
                return;
            }
        }
        tracker.last_error = error;
        // this is a tracker specific error, so we can retry with a different tracker
        // (if there are no more trackers to try, it's handled by announce)
        announce(event);
    }
    else if(error)
    {
        const auto reason = error.message();
        log(log_event::tracker, "error contacting tracker: %s", reason.c_str());
        tracker.last_error = error;
        // TODO make this more granular: if we have no inet, it's not tracker's fault,
        // whereas if host is unreachable or somesuch, it is
        ++tracker.num_fails;
        // this is a general system error, so there is a larger underlying problem
        stop();
    }
}

inline void torrent::add_peer(tcp::endpoint peer)
{
    if(m_endpoint_filter.is_allowed(peer))
    {
        // only add peer if it's not already connected
        auto psit = std::find_if(m_peer_sessions.begin(), m_peer_sessions.end(),
            [&peer](const auto& session) { return session->remote_endpoint() == peer; });
        auto apit = std::find(m_available_peers.begin(), m_available_peers.end(), peer);
        if((psit == m_peer_sessions.end()) && (apit == m_available_peers.end()))
        {
            const auto address = peer.address().to_string();
            log(log_event::update, "adding peer(%s:%i)", address.c_str(), peer.port());
            m_available_peers.emplace_back(std::move(peer));
        }
    }
}

void torrent::update(const std::error_code& error)
{
    if(m_is_stopped || m_is_aborted || (error == asio::error::operation_aborted))
    {
        return;
    }
    else if(error)
    {
        // TODO log, alert, stop torrent
        log(log_event::update, "error in update cycle: %s", error.message().c_str());
        return;
    }

    remove_finished_peer_sessions();
    if(m_info->num_disk_io_failures > 300)
    {
        stop();
        return;
    }
    // if we don't have active sessions left it makes no sense to continue updating,
    // try to get some peers by announcing, which will reinstate the update cycle
    if(m_peer_sessions.empty() && m_available_peers.empty())
    {
        announce();
        return;
    }

    if(should_connect_peers()) { connect_peers(); }
    if(needs_peers()) { announce(); }
    if(cached_clock::now() - m_info->last_unchoke_time >= seconds(10)) { unchoke(); }

    // in the rare circumstance when we have as many peers as upload slots, the freshly
    // connected ones may not be unchokable, but waiting 10s for the next unchoke round
    // would be too much, so we check every second whether there are peers we can unchoke
    // TODO this feels ugly
    if(m_info->num_unchoked_peers < m_info->settings.max_upload_slots
       && m_peer_sessions.size() > m_info->settings.max_upload_slots)
    {
        fill_free_upload_slots();
    }

    // TODO send stats event
    // m_event_queue.emplace<torrent_stats_event>(*m_info);

    start_timer(m_update_timer, seconds(1),
        [SHARED_THIS](const std::error_code& error) { update(error); });
}

inline bool torrent::should_connect_peers() const noexcept
{
    // TODO take into consideration the number of connecting sessions -- we don't want
    // to have too many of those
    // we're only actively trying to connect to new peers if we fall below 30
    return m_peer_sessions.size() < (std::min)(m_info->settings.max_connections, 30)
        && !m_available_peers.empty();
}

inline bool torrent::needs_peers() const noexcept
{
    // we should be able to connect at least 30 (or max_connections number) of peers
    const int total_peers = m_peer_sessions.size() + m_available_peers.size();
    // TODO only for now
    return total_peers == 0;
    // TODO introduce some sort of threshold because if we have say 26 connectable and
    // connected peers, that's still plenty good
    return total_peers < (std::min)(m_info->settings.max_connections, 30);
}

void torrent::connect_peers()
{
    const int num_to_connect = std::min(
        m_info->settings.max_connections - m_peer_sessions.size(),
        m_available_peers.size());
    // this function shouldn't be called if we can't connect
    assert(num_to_connect > 0);
    log(log_event::update, "connecting %i peer%c", num_to_connect,
        num_to_connect == 1 ? 0 : 's');
    for(auto i = 0; i < num_to_connect; ++i)
    {
        connect_peer(m_available_peers[i]);
    }
    // erase the peers from the available peers list to which we've connected
    m_available_peers.erase(m_available_peers.begin(),
        m_available_peers.begin() + num_to_connect);
}

inline void torrent::connect_peer(tcp::endpoint& peer)
{
    const auto address = peer.address().to_string();
    log(log_event::update, "connecting peer(%s:%i)", address.c_str(), peer.port());
    peer_session::torrent_specific_args args;
    args.piece_picker = m_piece_picker;
    args.shared_downloads = m_downloads;
    args.torrent_info = m_info;
    args.disk_io = torrent_disk_io_frontend(*this);
    m_peer_sessions.emplace_back(std::make_shared<peer_session>(m_ios, std::move(peer),
        m_bandwidth_controller, m_global_settings, std::move(args)));
    m_peer_sessions.back()->start();
}

inline void torrent::remove_finished_peer_sessions()
{
    // save looping through all sessions if none are disconnected
    if(m_info->num_lingering_disconnected_sessions == 0) { return; }

    int num_removed = 0;
    for(auto i = 0; i < m_peer_sessions.size(); ++i)
    {
        if(m_peer_sessions[i]->is_stopped())
        {
            on_peer_session_finished(*m_peer_sessions[i]);
            m_peer_sessions.erase(m_peer_sessions.begin() + i);
            ++num_removed, --i;
            if(num_removed == m_info->num_lingering_disconnected_sessions) { break; }
        }
    }
    assert(num_removed == m_info->num_lingering_disconnected_sessions);
    m_info->num_lingering_disconnected_sessions = 0;
    log(log_event::update, "removing %i peer session%c", num_removed,
        num_removed == 1 ? 0 : 's');
}

void torrent::on_peer_session_finished(peer_session& session)
{
    assert(session.is_stopped());
    const auto address = session.remote_endpoint().address().to_string();
    log(log_event::update, "session(%s:%i, %s, %lis) finished", address.c_str(),
        session.remote_endpoint().port(), session.is_peer_seed() ? "seed" : "leech",
        session.connection_duration().count());

    if(!session.is_peer_choked())
    {
        --m_info->num_unchoked_peers;
    }

    if(session.is_peer_seed())
    {
        --m_info->num_seeders;
    }
    else
    {
        --m_info->num_leechers;
    }
}

void torrent::unchoke()
{
    const bool unchoke_optimistically = m_info->num_choke_cycles % 3 == 0;
    const int num_to_unchoke = [this, unchoke_optimistically]() -> int
    {
        int n = std::min(m_info->settings.max_upload_slots, int(m_peer_sessions.size()));
        // if we're optimistically unchoking, we need to normal unchoke one fewer peer
        // as we're going to unchoke an additional peer and we must still observe 
        // settings.max_upload_slots
        if(unchoke_optimistically) { --n; }
        return std::max(0, n);
    }();

    m_info->last_unchoke_time = cached_clock::now();
    ++m_info->num_choke_cycles;

    // we don't have free upload slots and no one is choked, so save the trouble
    if((num_to_unchoke == 0) && (m_info->num_unchoked_peers == 0)) { return; }

    // put the unchoke candidates at the beginning of the peer list
    std::partial_sort(m_peer_sessions.begin(), m_peer_sessions.begin() + num_to_unchoke,
        m_peer_sessions.end(), [this](const auto& a, const auto& b)
        { return m_unchoke_comparator(*a, *b); });
    // now go through all the peers and unchoke the first num_to_unchoke ones and
    // choke the rest if they aren't already
    m_info->num_unchoked_peers = 0;
    for(auto& session : m_peer_sessions)
    {
        if(m_info->num_unchoked_peers < num_to_unchoke)
        {
            if(session->is_peer_choked() && session->is_peer_interested())
            {
                session->unchoke_peer();
                const auto address = session->remote_endpoint().address().to_string();
                log(log_event::choke, "unchoking peer(%s:%i)", address.c_str(),
                    session->remote_endpoint().port());
            }
            // even if peer is already unchoked, we count it so that we don't unchoke
            // more than we should
            // we may not have been successful at unchoking peer (e.g. if connection has
            // not been established yet), so need to check
            if(!session->is_peer_choked())
            {
                ++m_info->num_unchoked_peers;
            }
        }
        else
        {
            if(!session->is_peer_choked())
            {
                session->choke_peer();
            }
        }
    }
    if(unchoke_optimistically)
    {
        //optimistic_unchoke();
    }
}

void torrent::optimistic_unchoke()
{
    if(m_peer_sessions.size() == m_info->num_unchoked_peers) { return; }

    const auto for_each_candidate = [this](const auto& f)
    {
        for(auto& session : m_peer_sessions)
        {
            if(session->is_connected()
               && session->is_peer_choked()
               && session->is_peer_interested())
            {
                f(session.get());
            }
        }
    };
    int num_candidates = 0;
    for_each_candidate([&num_candidates](const auto& _) { ++num_candidates; });
    std::vector<peer_session*> candidates;
    candidates.reserve(num_candidates);
    for_each_candidate([&candidates](const auto& c) { candidates.emplace_back(c); });
    if(!candidates.empty())
    {
        std::sort(candidates.begin(), candidates.end(), [](const auto& a, const auto& b)
            { return a->connection_established_time()
              < b->connection_established_time(); });
        // pick peer by generating a random number skewed towards the lower end
        const int peer_index = std::floor(candidates.size()
            * std::pow(util::random_real(), 2));
        candidates[peer_index]->unchoke_peer();
        // candidates must have eligible peers only
        assert(!candidates[peer_index]->is_peer_choked());
    }
    m_info->last_optimistic_unchoke_time = cached_clock::now();
}

inline void torrent::fill_free_upload_slots()
{
    const int num_to_unchoke = std::min(
        m_info->settings.max_upload_slots - m_info->num_unchoked_peers,
        int(m_peer_sessions.size()) - m_info->num_unchoked_peers);
    if(num_to_unchoke <= 0) { return; }

    int num_unchoked = 0;
    for(auto it = m_peer_sessions.begin() + m_info->num_unchoked_peers,
        end = m_peer_sessions.end(); it != end; ++it)
    {
        auto& session = *it;
        if(session->is_connected())
        {
            session->unchoke_peer();
            if(!session->is_peer_choked()) { ++num_unchoked; }
        }
    }
    m_info->num_unchoked_peers += num_unchoked;
}

bool torrent::choke_ranker::upload_rate_based(
    const peer_session& a, const peer_session& b) noexcept
{
    // instead of using weighed upload rate averages for determining a peer's bandwidth
    // between unchoke rounds, we instead count the number of bytes that were sent
    // during this period, and disregard past performance
    // note to self: function is called upload based but we query downloaded bytes;
    // function name refers to peer's upload capacity, while the query functions are
    // from our perspective TODO perhaps change this
    const auto down1 = a.num_bytes_downloaded_this_round();
    const auto down2 = b.num_bytes_downloaded_this_round();
    if(down1 != down2)
    {
        return down1 > down2;
    }
    return download_rate_based(a, b);
}

bool torrent::choke_ranker::download_rate_based(
    const peer_session& a, const peer_session& b) noexcept
{
    const auto up1 = a.num_bytes_uploaded_this_round();
    const auto up2 = b.num_bytes_uploaded_this_round();
    if(up1 != up2)
    {
        return up1 > up2;
    }
    // if both peers perform equally well, prioritize the one that has been
    // waiting to be unchoked longer
    return a.last_outgoing_unchoke_time() < b.last_outgoing_unchoke_time();
}

void torrent::on_new_piece(piece_download& download, const bool is_valid)
{
    log(log_event::update, "received new piece(%i, %s)", download.piece_index(),
        is_valid ? "valid" : "corrupt");
    // let the peer_sessions that participated in the download know of the piece's
    // hash result
    download.post_hash_result(is_valid);
    if(is_valid)
    {
        handle_valid_piece(download);
    }
    else
    {
        handle_corrupt_piece(download);
    }
    assert(m_downloads);
    auto it = std::find_if(m_downloads->begin(), m_downloads->end(),
        [&download](const auto& d) { return d->piece_index() == download.piece_index(); });
    // if we could not find this piece download it means that it was a parole/unique
    // download, i.e. peer_session didn't put it in m_downloads because it wanted
    // to test whether peer was the one sending corrupt data, and for this the piece
    // download was not shared among other peer_sessions
    if(it != m_downloads->end())
    {
        m_downloads->erase(it);
    }
}

inline void torrent::handle_valid_piece(piece_download& download)
{
    // notify piece piecker that this piece was downloaded
    const piece_index_t piece_index = download.piece_index();
    m_piece_picker->got(piece_index);
    // notify each peer of our new piece so that they can request it
    for(auto& session : m_peer_sessions)
    {
        assert(session);
        session->announce_new_piece(piece_index);
    }
    // update stats
    const int piece_length = get_piece_length(*m_info, piece_index);
    m_info->total_verified_piece_bytes += piece_length;
    ++m_info->num_downloaded_pieces;
    // update file progress
    const interval files = m_storage.files_containing_piece(piece_index);
    assert(!files.is_empty());
    for(auto i = files.begin; i < files.end; ++i)
    {
        const auto slice = m_storage.get_file_slice(
            file_index_t(i), block_info(piece_index, 0, piece_length));
        const double fraction = double(slice.length) / m_info->files[i].length;
        m_info->files[i].completion += fraction;
    }
    if(is_leech() && (m_info->num_downloaded_pieces == m_info->num_wanted_pieces))
    {
        on_download_complete();
    }
    m_is_state_changed = true;
}

inline void torrent::handle_corrupt_piece(piece_download& download)
{
    m_piece_picker->unreserve(download.piece_index());
    const int piece_length = get_piece_length(*m_info, download.piece_index());
    // we failed to download piece, free it for others to redownload
    m_info->total_wasted_bytes += piece_length;
    m_info->total_failed_piece_bytes += piece_length;
    ++m_info->num_hash_fails;
    // if we downloaded this piece from a single peer only, we know it's the culprit,
    // which will cause the corresponding peer_session to trigger a disconnect, so
    // remove that peer_session here
    if(download.is_exclusive() && (download.num_participants() == 1))
    {
        // if there is only a single uploader and we're still connected to peer,
        // find its matching peer_session and if it's disconnected because of the
        // bad piece, erase it
        auto it = std::find_if(m_peer_sessions.begin(), m_peer_sessions.end(),
            [peer_id = download.peers()[0]](const auto& session)
            { return session->peer_id() == peer.id; });
        assert(it != m_peer_sessions.end());
        auto& session = *it;
        if(session->is_stopped())
        {
            on_peer_session_finished(*session);
            m_peer_sessions.erase(it);
        }
    }
    // TODO verify whether to make this dependent on more granular conditions
    m_is_state_changed = true;
}

inline void torrent::on_download_complete()
{
    log(log_event::update, "download complete in %i seconds",
        total_seconds(cached_clock::now() - m_info->download_started_time));
    m_info->state[torrent_info::seeding] = true;
    m_info->download_finished_time = cached_clock::now();
    // now that we're seeders we want to compare the upload rate of peers to rank them
    // TODO once we support more algorithms we have to make this a conditional
    // or just make one a unified rate_based choker that uses download in leech mode
    // and upload rate in seed mode
    m_unchoke_comparator = &torrent::choke_ranker::upload_rate_based;
    // if we downloaded every piece in torrent we can announce to tracker that we have
    // become a seeder (otherwise we wouldn't qualify as a seeder in the strict sense,
    // I think but TODO maybe this is not true)
    if(m_info->num_downloaded_pieces == m_info->num_pieces)
    {
        announce(tracker_request::completed);
    }
    // since we have become a seeder, and if any of our peers were seeders, they were
    // disconnected, so clean up those finished sessions
    if(m_info->num_seeders > 1)
    {
        remove_finished_peer_sessions();
    }
    // TODO send event::alert that we've become seeders
}

template<typename... Args>
void torrent::log(const log_event event, const char* format, Args&&... args) const
{
    std::cerr << "[torrent#" << m_info->id << '|';
    switch(event)
    {
    case log_event::update: std::cerr << "UPDATE"; break;
    case log_event::disk: std::cerr << "DISK"; break;
    case log_event::tracker: std::cerr << "TRACKER"; break;
    case log_event::choke: std::cerr << "CHOKE"; break;
    }
    std::cerr << "] - " << util::format(format, std::forward<Args>(args)...) << '\n';
}

#undef SHARED_THIS

} // namespace tide
