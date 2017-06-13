#include "bandwidth_controller.hpp"
#include "endpoint_filter.hpp"
#include "piece_download.hpp"
#include "event_channel.hpp"
#include "piece_picker.hpp"
#include "sha1_hasher.hpp"
#include "settings.hpp"
#include "disk_io.hpp"
#include "torrent.hpp"
#include "tracker.hpp"
#include "view.hpp"

#include <algorithm>

namespace tide {

// torrent needs to be kept alive until all async ops complete, so we bind a
// shared_ptr to `this` to each async op's handler along with `this`
#define SHARED_THIS this, self(shared_from_this())

torrent::torrent(
    torrent_id_t id,
    asio::io_service& ios,
    disk_io& disk_io,
    bandwidth_controller& bandwidth_controller,
    torrent_settings& global_settings,
    std::vector<tracker_entry> trackers,
    endpoint_filter& endpoint_filter,
    event_channel& event_channel,
    torrent_args args
)
    : m_ios(ios)
    , m_disk_io(disk_io)
    , m_bandwidth_controller(bandwidth_controller)
    , m_global_settings(global_settings)
    , m_endpoint_filter(endpoint_filter)
    , m_event_channel(event_channel)
    , m_trackers(std::move(trackers))
    , m_info(std::make_shared<torrent_info>())
    , m_piece_picker(std::make_shared<piece_picker>(args.metainfo.num_pieces))
    , m_downloads(std::make_shared<std::vector<std::shared_ptr<piece_download>>>())
    , m_unchoke_comparator(&torrent::choke_ranker::download_rate_based)
    , m_metainfo(std::move(args.metainfo.source))
    , m_piece_hashes(args.metainfo.piece_hashes)
{
    // make sure engine gave us valid trackers
    for(const auto& e : m_trackers) assert(e.tracker);
    initialize_torrent_info(id, args);
    m_info.state[torrent_info::allocating] = true;
    // TODO setup trackers
    announce_to_tracker(tracker_request::event_t::started);
    m_disk_io.allocate_torrent(m_info, m_piece_hashes,
        [SHARED_THIS](const std::error_code& error, torrent_storage_handle storage)
        { on_torrent_allocated(error, storage); });
}

void torrent::initialize_torrent_info(const torrent_id_t id, torrent_args& args)
{
    m_info->id = id;
    // TODO how expensive is this?
    m_info->info_hash = create_sha1_digest(m_metainfo.find_bmap("info").encode());
    m_info->save_path = std::move(args.save_path);
    m_info->num_pieces = m_metainfo.num_pieces;
    m_info->size = args.metainfo.total_length;
    m_info->piece_length = args.metainfo.piece_length;
    m_info->last_piece_length =
        m_info->total_length - (m_info->num_pieces - 1) * m_info->piece_length;
    m_info->settings = std::move(args.settings);
    m_info->files = std::move(args.files);
    if(args.name.empty())
    {
        info_map.try_find_string("name", m_info->name);
    }
    else
    {
        m_info->name = std::move(args.name);
    }
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
        m_disk_io.allocate_torrent(m_info, m_piece_hashes,
            [SHARED_THIS](const std::error_code& error, torrent_storage_handle storage)
            { on_torrent_allocated(error, storage); });
        return;
    }
    m_storage = storage;
    m_info.state[torrent_info::allocating] = false;
    for(const auto file : args.file_priorities)
    {
        m_piece_picker.make_priority(m_storage.pieces_in_file(file));
    }
}

void torrent::pause()
{
    if(m_is_paused || m_is_aborted || !is_running()) { return; }

    announce_to_tracker(tracker_request::event_t::stopped);
    for(auto& session : m_peer_sessions)
    {
        if(session.is_stopped()) { continue; }
        // choke all peers to prevent responding to new requests (this is necessary,
        // since we're gracefully disconnecting peers, they may be around for a while
        // till all async ops finish, during which peers may send us requests)
        session.choke_peer();
        session.stop(peer_session::stop_mode_t::gracious);
        // TODO when last peer is disconnected, we have to send an alert
    }
}

void torrent::abort()
{
    if(m_is_paused || m_is_aborted || !is_running()) { return; }
    // TODO if we're being paused gracefully, we might want to switch from graceful to
    // abort instead of returning

    m_update_timer.cancel();
    m_announce_timer.cancel();

    // TODO

    disconnect_peers();
    m_info.state[torrent_info::stopped] = true;
}

void torrent::resume()
{

}

inline torrent::disconnect_peers(const torrent_errc reason)
{
    for(auto& session : m_peer_sessions)
    {
        if(!session->is_disconnected())
        {
            session->stop(reason);
        }
    }
}

void torrent::announce_to_tracker(tracker_request::event_t event, const bool force)
{
    if(m_trackers.empty())
    {
        log(log_event::tracker, "cannot announce: no trackers");
        return;
    }
    else if(is_paused())
    {
        // TODO we should allow announce's when we're in graceful pause mode
        log(log_event::tracker, "cannot announce: torrent paused");
        return;
    }
    m_info.state[torrent_info::announcing] = true;
    tracker_request request = create_tracker_request(event);

    // if the event is stopped or completed, we need to send it to all trackers to which
    // we have announced in the past, otherwise just pick the most suitable tracker, as
    // otherwise we're just requesting more peers
    if(event == tracker_request::event_t::stopped
        || event == tracker_request::event_t::completed)
    {
        for(auto& t : m_trackers)
        {
            // don't send the 'stopped' and 'completed' more than once
            // TODO if we download the torrent twice (i.e. got deleted so is downloaded
            // again), then this is wrong FIXME
            if((t.has_sent_completed && (event == tracker_request::event_t::completion))
               || (t.has_sent_stopped && (event == tracker_request::event_t::stopped)))
            {
                continue;
            }
            else if(t.has_sent_started)
            {
                t.tracker->announce(request,
                    [SHARED_THIS, &t](const std::error_code& ec, tracker_response r)
                    { on_announce_response(t, ec, std::move(r)); });
            }
        }
    }
    else
    {
        tracker_entry& entry = pick_tracker(force);
        //entry.is_busy = true;
        entry.tracker->announce(std::move(request),
            [SHARED_THIS, &entry](const std::error_code& ec, tracker_response r)
            { on_announce_response(entry, ec, std::move(r)); });
    }
    log(log_event::tracker, "sending announce");
}

inline tracker_request torrent::create_tracker_request(
    tracker_request::event_t event) const noexcept
{
    tracker_request request;
    request.info_hash = m_info->info_hash;
    request.peer_id = m_settings.client_id;
    request.downloaded = m_info->total_downloaded_piece_bytes;
    request.uploaded = m_info->total_uploaded_piece_bytes;
    request.left = m_info->size - m_info->downloaded_size;
    request.port = m_global_settings.listener_port;
    request.event = event;
    request.compact = true; // I think?
    request.num_want = event == tracker_request::event_t::started
                    || event == tracker_request::event_t::none
                       ? calculate_num_want()
                       : 0;
    return request;
}

inline tracker_entry& torrent::pick_tracker(const bool force)
{
    assert(!m_trackers.empty());
    // TODO probably revise this
    for(const auto& t : m_trackers)
    {
        if(can_announce_to(t))
            return t;
    }
    // if we couldn't find a tracker satisfying all criteria, lower criteria standards
    // and fall back
    for(const auto& t : m_trackers)
    {
        if(force && t.tracker->is_reachable() && !t.tracker->had_protocol_error())
            return t;
    }
    for(const auto& t : m_trackers)
    {
        if(t.tracker->is_reachable())
            return t;
    }
    for(const auto& t : m_trackers)
    {
        if(!t.tracker->had_protocol_error())
            return t;
    }
    // at this point nothing matters anymore
    return m_trackers.front();
}

inline bool torrent::can_announce_to(const tracker_entry& t) const noexcept
{
    return is_seed()
        || (t.tracker->is_reachable()
            && !t.tracker->had_protocol_error()
            && cached_clock::now() - t.last_announce_time >= t.interval);
/*|| is_shutting_down() */
/*&& !t.is_busy*/
}

void torrent::on_announce_response(tracker_entry& tracker,
    const std::error_code& error, tracker_response response)
{
    m_info.state[torrent_info::announcing] = false;
    // TODO merge the two
    if(error == tracker_errc::timed_out)
    {
        tracker.last_error = error;
        log(log_event::tracker, "timeout");
        return;
    }
    else if(error == tracker_errc::invalid_response
            || error == tracker_errc::response_too_small
            || error == tracker_errc::wrong_response_type
            || error == tracker_errc::invalid_transaction_id)
    {
        tracker.last_error = error;
        log(log_event::tracker, "invalid announce response");
        return;
    }
    else if(error)
    {
        tracker.last_error = error;
        // this is a general system error
        // TODO depending on the error (i.e. no internet) shutdown torrent
        return;
    }
    log(log_event::tracker, "received announce response");

    const auto now = cached_clock::now();
    m_info.last_announce_time = now;
    tracker.last_announce_time = now; 
    //entry.is_busy = false;

    if(!response.warning_message.empty())
    {
        // TODO send alert if appropriate
        log(log_event::tracker, "WARNING: %s", response.warning_message.c_str());
        tracker.warning_message = std::move(response.warning_message);
    }

    m_available_peers.reserve(m_available_peers.size()
        + response.ipv4_peers.size() + response.ipv6_peers.size());
    for(auto& ep : response.ipv4_peers)
    {
        add_peer(std::move(ep));
    }
    for(auto& ep : response.ipv6_peers)
    {
        add_peer(std::move(ep));
    }

    // if we aren't connected to any peers but received peers we can connect to, it
    // means the update cycle (i.e. torrent) is not running, this may be the first
    // announce or we stoppped torrent as soon as we disconnected the last peer, in
    // either case, reinstate the update cycle (but only do this if the torrent is
    // not paused, as it is possible to be in a paused state by the time the response
    // arrives if torrent was gracefully paused)
    // TODO create a function called is_update_cycle_running()
    if(!is_paused() && m_peer_sessions.empty() && !m_available_peers.empty())
    {
        update();
    }
}

inline void torrent::add_peer(tcp::endpoint peer)
{
    if(m_endpoint_filter.is_allowed(ep))
    {
        // only add peer if it's not already connected
        auto psit = std::find_if(m_peer_sessions.begin(), m_peer_sessions.end(),
            [&peer](const auto& session) { return session->remote_endpoint() == peer; });
        auto apit = std::find_if(m_available_peers.begin(),
            m_available_peers.end(), peer);
        if((psit == m_peer_sessions.end()) && (apit == m_available_peers.end())
        {
            m_available_peers.emplace_back(std::move(ep));
        }
    }
}

void torrent::update(const std::error_code& error)
{
    if(m_is_paused || m_is_aborted || (error == asio::error::operation_aborted))
    {
        return;
    }
    else if(error)
    {
        // TODO log, alert, pause torrent
        return;
    }

    remove_finished_peer_sessions();
    // TODO check if we should get more peers from tracker
    if(m_peer_sessions.size() < m_info.settings.max_connections)
    {
        connect_peers();
    }

    if(cached_clock::now() - m_info.last_choke_time >= seconds(10))
    {
        if(m_info.num_choke_cycles % 3 == 0)
            optimistic_unchoke();
        else
            unchoke();
        ++m_info.num_choke_cycles;
    }

    start_timer(m_update_timer, seconds(1),
        [SHARED_THIS](const std::error_code& error) { update(error); });
}

void torrent::connect_peers()
{
    const int num_to_connect = std::min(
        m_info.settings.max_connections - m_peer_sessions.size(),
        m_available_peers.size()
    );
    assert(num_to_connect > 0);
    // iterate from the back to connect to the most recently received peers as they are
    // most likely to be still active
    for(auto i = num_to_connect; i >= 0; --i)
    {
        connect_peer(m_available_peers[i]);
    }
    // erase the peers to which we've connected
    m_available_peers.erase(
        m_available_peers.begin() + m_available_peers.size() - num_to_connect,
        m_available_peers.end());
}

inline void torrent::connect_peer(tcp::endpoint& peer)
{
    assert(m_peer_sessions.size() < m_info.settings.max_connections);
    peer_session::torrent_specific_args args;
    args.piece_picker = m_piece_picker;
    args.shared_downloads = m_downloads;
    args.torrent_info = m_info;
    args.piece_completion_handler =
        [SHARED_THIS](piece_download& download, bool is_piece_good)
        { on_new_piece(download, is_piece_good); };
    m_peer_sessions.emplace_back(std::make_shared<peer_session>(
        std::make_unique<tcp::socket>(m_ios), std::move(peer), m_disk_io,
        m_bandwidth_controller, static_cast<peer_session_settings&>(m_settings),
        std::move(args)));
}

inline void torrent::remove_finished_peer_sessions()
{
    if(m_peer_sessions.empty())
    {
        return;
    }
    auto first_removed = std::remove_if(m_peer_sessions.begin(), m_peer_sessions.end(),
        [](const auto& session) { return session->is_disconnected(); });
    std::for_each(first_removed, m_peer_sessions.end(),
        [this](const auto& session) { on_peer_session_finished(session); });
    m_peer_sessions.erase(first_removed, m_peer_sessions.end());
}

inline void torrent::on_peer_session_finished(peer_session& session)
{
    assert(session.is_disconnected());

    if(!session.is_peer_choked())
    {
        --m_info.num_unchoked_peers;
        // TODO we shouldn't call unchoke so often, try to accumulate these calls and
        // execute them in one
        unchoke();
    }

    if(session.is_peer_seed())
    {
        --m_info.num_seeders;
    }
    else
    {
        --m_info.num_leechers;
    }
}

void torrent::unchoke()
{
    const int num_to_unchoke = std::min(
        m_info.settings.max_upload_slots, m_peer_sessions.size());
    // put the unchoke candidates at the beginning of the peer list
    std::partial_sort(m_peer_sessions.begin(), m_peer_sessions.begin() + num_to_unchoke,
        m_peer_sessions.end(), m_unchoke_comparator);
    // now go through all the peers and unchoke the first num_to_unchoke ones and
    // choke the rest
    int num_unchoked = 0;
    for(auto& session : m_peer_sessions)
    {
        if(num_unchoked < num_to_unchoke)
        {
            if(session->is_peer_choked() && session->is_peer_interested())
            {
                session->unchoke_peer();
            }
            // even if peer is already unchoked, we count it so that we don't unchoke
            // more than we should
            // TODO maybe consider not unchoking peers that are choking us
            // also maybe we should take into consideration the peers that are 
            // interested, e.g. if both peers are choking us and have roughly the
            // same performance, pick the one that is interested
            // though of course if one is not choking us and we're interested in them,
            // that one should be preferred

            // we may not have been successful at unchoking peer, so need to check
            if(!session->is_peer_choked())
            {
                ++num_unchoked;
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
    m_info->last_choke_time = cached_clock::now();
}

void torrent::optimistic_unchoke()
{
    const time_point now = cached_clock::now();
    // TODO
}

bool torrent::choke_ranker::upload_rate_based(
    const peer_session& a, const peer_session& b) noexcept
{
    const auto down1 = a.download_rate();
    const auto down2 = b.download_rate();
    if(down1 != down2)
    {
        return down1 > down2;
    }
    return compare_download_rate(a, b);
}

bool torrent::choke_ranker::download_rate_based(
    const peer_session& a, const peer_session& b) noexcept
{
    const auto up1 = a.upload_rate();
    const auto up2 = b.upload_rate();
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
    if(is_valid)
    {
        handle_valid_piece(download);
    }
    else
    {
        handle_corrupt_piece(download);
    }
    // let the peer_sessions that participated in the download know of the piece's
    // hash result
    download.post_hash_result(is_valid);
    assert(m_downloads);
    it = std::find_if(m_downloads->begin(), m_downloads->end(),
        [&download](const auto& p) { return p->piece_index() == download.piece_index(); });
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
    const piece_index_t index = download.piece_index();
    m_piece_picker->got(index);
    // notify each peer of our new piece so that they can request it
    for(auto& peer : m_peer_sessions)
    {
        peer->announce_new_piece(index);
    }
    // update stats
    const int piece_length = get_piece_length(*m_info, index);
    m_info->total_verified_piece_bytes += piece_length;
    ++m_info->num_downloaded_pieces;
    // update file progress
    const interval files = m_storage.files_containing_piece(index);
    assert(!files.is_empty());
    for(auto file = files.begin; file < files.end; ++file)
    {
        const auto slice = m_storage.get_file_slice(
            file, block_info(index, 0, piece_length));
        const double fraction = double(slice.length) / m_info.files[i].length;
        m_info.files[i].completion += fraction;
    }
    // if we were leeching up to this point but this piece completed the download
    if(is_leech() && (m_info.num_downloaded_pieces == m_info.num_wanted_pieces))
    {
        on_download_complete();
    }
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
            { return peer_id == session->peer_id() });
        assert(it != m_peer_sessions.end());
        auto& session = *it;
        if(session->is_disconnected())
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
    m_info.state[torrent_info::seeding] = true;
    m_info.download_finished_time = cached_clock::now();
    // now that we're seeders we want to compare the upload rate of peers to rank them
    // TODO once we support more algorithms we have to make this a conditional
    // or just make one rate_based choker that uses download in leech mode and upload
    // rate in seed mode
    m_unchoke_comparator = &torrent::choke_ranker::upload_rate_based;
    // if we downloaded every piece in torrent we can announce to tracker that we have
    // become a seeder (otherwise we wouldn't qualify as a seeder in the strict sense,
    // I think but TODO maybe this is not true)
    if(m_info->num_downloaded_pieces == m_info->num_pieces)
    {
        announce_to_tracker(tracker_request::event_t::completed);
    }
    // since we have become a seeder, and if any of our peers were seeders, they were
    // disconnected, so clean up those finished sessions
    if(m_info.num_seeders > 1)
    {
        remove_finished_peer_sessions();
    }
    // TODO send event::alert that we've become seeders
}

} // namespace tide
