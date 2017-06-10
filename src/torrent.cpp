#include "bandwidth_controller.hpp"
#include "endpoint_filter.hpp"
#include "piece_picker.hpp"
#include "sha1_hasher.hpp"
#include "settings.hpp"
#include "disk_io.hpp"
#include "torrent.hpp"
#include "tracker.hpp"
#include "view.hpp"

#include <algorithm>

namespace tide {

torrent::torrent(
    torrent_id_t id,
    asio::io_service& ios,
    disk_io& disk_io,
    bandwidth_controller& bandwidth_controller,
    torrent_settings& global_settings,
    torrent_args args
)
    : m_ios(ios)
    , m_disk_io(disk_io)
    , m_bandwidth_controller(bandwidth_controller)
    , m_global_settings(global_settings)
    , m_info(std::make_shared<torrent_info>())
    , m_piece_picker(std::make_shared<piece_picker>(args.metainfo.num_pieces))
    , m_piece_downloads(std::make_shared<std::vector<std::shared_ptr<piece_download>>>())
    , m_unchoke_comparator(&torrent::upload_rate_based)
    , m_metainfo(std::move(args.metainfo.source))
    , m_piece_hashes(args.metainfo.piece_hashes)
{
    initialize_torrent_info(args);
    m_info.state[torrent_info::state_t::allocating] = true;
    // TODO setup trackers
    announce_to_tracker();
    m_disk_io.allocate_torrent(
        m_info,
        m_piece_hashes,
        [this](const std::error_code& error)
        {
            on_torrent_allocated(error);
        }
    );
}

void torrent::initialize_torrent_info(torrent_args& args)
{
    m_info->id = id;
    // TODO perhaps do the hashing in a separate disk thread? how slow is this in the
    // worst case?
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
    const std::error_code& error, torrent_storage_handle handle)
{
    if(error || !handle)
    {
        log(log_event::disk, "ERROR allocating disk storage");
        // TODO send alert
        // TODO what to do when we couldn't allocate file? could this even occur?
        // what are the possible errors? no save path? shouldn't that be checked
        // at a higher level?
        m_disk_io.allocate_torrent(
            m_info,
            m_piece_hashes,
            [this](const std::error_code& error, torrent_storage_handle handle)
            {
                on_torrent_allocated(error, handle);
            }
        );
        return;
    }
    m_storage = handle;
    m_info.state[torrent_info::state_t::allocating] = false;
    for(const auto file : args.file_priorities)
    {
        m_piece_picker.make_priority(m_storage.pieces_in_file(file));
    }
}

void torrent::pause()
{
    if(m_is_paused || m_is_aborted || !is_running()) return;
}

void torrent::abort()
{
    if(m_is_aborted || !is_running()) return;

    m_update_timer.cancel();
    m_announce_timer.cancel();

    disconnect_peers();
    m_info.state[torrent_info::state_t::stopped] = true;
}

void torrent::resume()
{

}

inline torrent::disconnect_peers(const torrent_errc reason)
{
    for(auto& session : m_peer_sessions)
    {
        if(!session->is_disconnecting() && !session->is_finished())
            session->disconnect(reason);
    }
}

torrent_handle torrent::get_handle()
{
    return torrent_handle(this);
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
        log(log_event::tracker, "cannot announce: torrent paused");
        return;
    }

    tracker_request request;
    request.info_hash = m_info->info_hash;
    request.peer_id = m_settings.client_id;
    request.downloaded = m_info->total_downloaded_piece_bytes;
    request.uploaded = m_info->total_uploaded_piece_bytes;
    request.left = m_info->size - m_info->downloaded_size;
    request.port = m_global_settings.listener_port;
    request.event = event;
    request.compact = true; // I think?
    request.num_want(
        event == tracker_request::event_t::stopped ? 0 : calculate_num_want()
    );

    m_info.state[torrent_info::state_t::announcing] = true;
    pick_tracker().announce(
        std::move(request),
        [this](const std::error_code& error, tracker_response response)
        {
            on_announce_response(error, std::move(response));
        }
    );
    log(log_event::tracker, "sending announce");
}

inline tracker& torrent::pick_tracker()
{
    assert(!m_trackers.empty());
    for(const auto& t : m_trackers)
    {
        if(t->can_announce() && t->is_reachable() && !t->had_protocol_error())
            return *t;
    }
    // if we couldn't find a tracker satisfying all criteria, lower criteria standards
    // and fall back
    for(const auto& t : m_trackers)
    {
        if(t->is_reachable())
            return *t;
    }
    for(const auto& t : m_trackers)
    {
        if(!t->had_protocol_error())
            return *t;
    }
    // at this point nothing matters anymore
    return *m_trackers.front();
}

void torrent::on_announce_response(
    tracker& tracker, const std::error_code& error, tracker_response response)
{
    m_info.state.unset(torrent_info::state_t::announcing);
    if(error == tracker_errc::timed_out)
    {
        log(log_event::tracker, "timeout");
        return;
    }
    else if(error == tracker_errc::invalid_response
            || error == tracker_errc::response_too_small
            || error == tracker_errc::wrong_response_type
            || error == tracker_errc::invalid_transaction_id)
    {
        log(log_event::tracker, "invalid announce response");
        return;
    }
    else if(error)
    {
        // this is a general system error
        // TODO depending on the error (i.e. no internet) shutdown torrent
        return;
    }
    log(log_event::tracker, "received announce response");
    m_info.last_announce_time = cached_clock::now();

    if(!response.warning_message.empty())
    {
        // TODO send alert if appropriate
        log(log_event::tracker, "WARNING: %s", response.warning_message.c_str());
    }

    const bool was_peer_sessions_empty = m_peer_sessions.empty();

    m_available_peers.reserve(
        m_available_peers.size() + response.ipv4_peers.size() + response.ipv6_peers.size()
    );
    for(auto& ep : response.ipv4_peers)
    {
        add_peer(std::move(ep));
    }
    for(auto& ep : response.ipv6_peers)
    {
        add_peer(std::move(ep));
    }

    // If we hadn't been connected to any peers (may be the first announce or just ran
    // dry), but connnected to some after receiving peers from tracker, it means that
    // the update cycle is not running, because it was stopped as soon as the last peer
    // connection was torn now. Thus it needs to be restarted here.
    // TODO create a function called is_update_cycle_running()
    if(is_running() && was_peer_sessions_empty && !m_peer_sessions.empty())
    {
        update({});
    }
}

inline void torrent::add_peer(tcp::endpoint peer)
{
    if(!m_endpoint_filter(ep))
    {
        // only add peer if it's not already added
        auto psit = std::find_if(
            m_peer_sessions.begin(),
            m_peer_sessions.end(),
            [&endpoint](const auto& session)
            {
                return session->remote_endpoint() == endpoint;
            }
        );
        auto apit = std::find_if(
            m_available_peers.begin(),
            m_available_peers.end(),
            peer
        );
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
        // TODO
        return;
    }

    remove_finished_peer_sessions();

    if(m_peer_sessions.size() < m_info.settings.max_connections)
    {
        connect_peers();
    }

    if(cached_clock::now() - m_info.last_choke_time >= seconds(10))
    {
        if(m_info.num_choke_cycles % 3 == 0)
        {
            optimistic_unchoke();
        }
        else
        {
            unchoke();
        }
        ++m_info.num_choke_cycles;
    }

    start_timer(
        m_update_timer,
        seconds(1),
        [this](const std::error_code& error) { update(error); }
    );
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
        m_available_peers.end()
    );
}

inline void torrent::connect_peer(const tcp::endpoint& peer)
{
    assert(m_peer_sessions.size() < m_info.settings.max_connections);
    peer_session::torrent_specific_args args;
    args.picker = m_piece_picker;
    args.shared_downloads = m_piece_downloads;
    args.info = m_info;
    args.piece_completion_handler = [this](piece_download& download, bool is_piece_good)
    {
        on_new_piece(download, is_piece_good);
    };
    m_peer_sessions.emplace_back(
        std::make_unique<tcp::socket>(m_ios),
        peer,
        m_disk_io,
        m_bandwidth_controller,
        static_cast<peer_session_settings&>(m_settings),
        std::move(args)
    );
}

inline void torrent::remove_finished_peer_sessions()
{
    if(m_peer_sessions.empty())
    {
        return;
    }
    auto first_removed = std::remove_if(
        m_peer_sessions.begin(),
        m_peer_sessions.end(),
        [](const auto& session) { return session->is_finished(); }
    );
    std::for_each(
        first_removed,
        m_peer_sessions.end(),
        [this](const auto& session) { on_peer_session_finished(session); }
    );
    m_peer_sessions.erase(first_removed, m_peer_sessions.end());
}

inline void torrent::on_peer_session_finished(peer_session& session)
{
    assert(session.is_finished());

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
        m_info.settings.max_upload_slots, m_peer_sessions.size()
    );
    // put the unchoke candidates at the beginning of the peer list
    std::partial_sort(
        m_peer_sessions.begin(),
        m_peer_sessions.begin() + num_to_unchoke,
        m_peer_sessions.end(),
        m_unchoke_comparator
    );
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
}

bool torrent::compare_upload_rate(const peer_session& a, const peer_session& b) noexcept
{
    const auto down1 = a.download_rate();
    const auto down2 = b.download_rate();
    if(down1 != down2)
    {
        return down1 > down2;
    }
    return compare_download_rate(a, b);
}

bool torrent::compare_download_rate(const peer_session& a, const peer_session& b) noexcept
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
    assert(m_piece_downloads);
    it = std::find_if(
        m_piece_downloads->begin(),
        m_piece_downloads->end(),
        [&download](const auto& p)
        {
            return p->piece_index() == download.piece_index();
        }
    );
    // if we could not find this piece download it means that it was a parole/unique
    // download, i.e. peer_session didn't put it in m_piece_downloads because it wanted
    // to test whether peer was the one sending corrupt data, and for this the piece
    // download was not shared among other peer_sessions
    if(it != m_piece_downloads->end())
    {
        m_piece_downloads->erase(it);
    }
    // if piece passed the hash test and we've become a seeder with this new piece, we
    // may have disconnected peers that were also seeders; or if piece is corrupt but
    // we managed to find the culprit and disconnect it -- in either case, clean up
    if(is_seeder() || !is_valid)
    {
        remove_finished_peer_sessions();
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
            file, block_info(index, 0, piece_length)
        );
        const double fraction = double(slice.length) / m_info.files[i].length;
        m_info.files[i].completion += fraction;
    }
    // if we were leeching up to this point but this piece completed the download
    if(is_leecher() && (m_info.num_downloaded_pieces == m_info.num_wanted_pieces))
    {
        on_download_finished();
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
}

inline void torrent::on_download_finished()
{
    m_info.state.set[torrent_info::state_t::seeding];
    m_info.download_finished_time = cached_clock::now();
    // TODO send event::alert that we've become seeders
    // tell tracker that we completed the downlaod
    // TODO should we announce this even if are not downloading all the files?
}

} // namespace tide
