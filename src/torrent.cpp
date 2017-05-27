#include "sha1_hasher.hpp"
#include "torrent.hpp"
#include "tracker.hpp"
#include "view.hpp"

#include <algorithm>

torrent::torrent(
    torrent_id_t id,
    disk_io& disk_io,
    bandwidth_controller& bandwidth_controller,
    torrent_settings& global_settings,
    torrent_args args
)
    : m_disk_io(disk_io)
    , m_bandwidth_controller(bandwidth_controller)
    , m_global_settings(global_settings)
    , m_info(std::make_shared<torrent_info>())
    , m_piece_picker(std::make_shared<piece_picker>(args.metainfo.num_pieces))
    , m_piece_downloads(std::make_shared<piece_download_locator>())
    , m_unchoke_comparator(&torrent::upload_rate_based)
    , m_metainfo(std::move(args.metainfo.source))
{
    initialize_torrent_info(args);
    m_disk_io.allocate_torrent(
        m_info,
        args.metainfo.piece_hashes,
        [this](const std::error_code& error)
        {
            on_torrent_allocated(error);
        }
    );
    // TODO setup trackers
    make_tracker_announcement();
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

    m_info->files.reserve(args.files.size());
    int64_t file_offset = 0;
    for(file_info& f : args.files)
    {
        internal_file_info i_f;
        i_f.path = std::move(f.path);
        i_f.length = f.length;
        i_f.is_wanted = f.is_wanted;
        i_f.first_piece = file_offset / m_info->piece_length;
        // move file_offset to the next file's beginning / current file's end
        file_offset += info.length;
        i_f.last_piece = file_offset / m_info->piece_length;

        m_info.files.emplace_back(std::move(i_f));
    }

    if(args.name.empty())
    {
        info_map.try_find_string("name", m_info->name);
    }
    else
    {
        m_info->name = std::move(args.name);
    }
}

void torrent::on_torrent_allocated(const std::error_code& error)
{
    if(error)
    {
        // TODO what to do when we couldn't allocate file? could this even occur?
        // what are the possible errors? no save path? shouldn't that be checked
        // at a higher level?
        pause();
        return;
    }
    // TODO enforce file priorities!
    for(const auto file_index : args.file_priorities)
    {
        m_piece_picker.make_priority(pieces_in_file(file_index));
    }
}

inline interval torrent::pieces_in_file(const int file_index) const noexcept
{
    assert(file_index > 0 && file_index < m_file_indexs.size()); 
    return interval(
        m_info->files[file_index].first_piece,
        m_info->files[file_index].last_piece + 1
    );
}

torrent_handle torrent::get_handle()
{
    return torrent_handle(this);
}

void torrent::make_tracker_announcement(tracker_request::event_t event)
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
    request
        .info_hash(m_info->info_hash)
        .peer_id(m_settings.client_id)
        .downloaded(m_info->total_downloaded_piece_bytes)
        .uploaded(m_info->total_uploaded_piece_bytes)
        .left(m_info->size - m_info->downloaded_size)
        .event(event);

    request.num_want(
        event == tracker_request::event_t::stopped ? 0 : calculate_num_want()
    );

    m_last_tracker_announcement_time = cached_clock::now();
}

void torrent::on_tracker_response(
    const std::error_code& error, tracker_response response)
{
    // TODO here we connect to new peers   
}

void torrent::handle_tracker_error(
    const std::error_code& error, tracker_response resposne)
{
}

void torrent::remove_finished_sessions()
{
    auto first_removed = std::remove_if(
        m_peer_sessions.begin(),
        m_peer_sessions.end(),
        [](const std::unique_ptr<peer_session>& session)
        {
            return session->is_finished();
        }
    );
    m_peer_sessions.erase(first_removed, m_peer_sessions.end());
}

void torrent::choke()
{
    remove_finished_sessions();

    const int num_to_unchoke = std::min(
        m_info.settings.max_upload_slots, m_peer_sessions.size()
    );
    // put the unchoke candidates at the beginning of the peer list
    std::partial_sort(
        m_peer_sessions.begin(),
        m_peer_sessions.begin() + num_to_unchoke,
        m_peer_sessions.end(),
        [this](const auto& a, const auto& b)
        {
            return m_unchoke_comparator(*a, *b);
        }
    );

    // now go through all the peers and unchoke the first num_to_unchoke ones and
    // choke the rest
    int num_unchoked = 0;
    for(auto& session : m_peer_sessions)
    {
        if(num_unchoked < num_to_unchoke)
        {
            if(!session->is_peer_choked())
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
            ++num_unchoked;
        }
        else
        {
            if(session->is_peer_choked())
            {
                session->choke_peer();
            }
        }
    }

    // choke runs every 10 seconds, while optimistic unchoke runs every 30 seconds
    if(++m_num_chokes % 3 == 0)
    {
        optimistic_unchoke();
    }
}

void torrent::optimistic_unchoke()
{
    const time_point now = cached_clock::now();
}

bool torrent::compare_upload_rate(
    const peer_session& a, const peer_session& b) noexcept
{
    const auto down1 = a.num_bytes_downloaded_in_last_round();
    const auto down2 = b.num_bytes_downloaded_in_last_round();
    if(down1 != down2)
    {
        return down1 > down2;
    }
    return download_rate_based(a, b);
}

bool torrent::compare_download_rate(
    const peer_session& a, const peer_session& b) noexcept
{
    const auto up1 = a.num_bytes_uploaded_in_last_round();
    const auto up2 = b.num_bytes_uploaded_in_last_round();
    if(up1 != up2)
    {
        return up1 > up2;
    }
    // if both peers perform equally well, prioritize the one that has been
    // waiting to be unchoked longer
    return a.last_outgoing_unchoke_time() < b.last_outgoing_unchoke_time();
}

void torrent::on_new_piece(const piece_index_t piece, const bool is_valid)
{
    if(is_valid)
    {
        // notify piece piecker that this piece was downloaded
        m_piece_picker->got(piece);
        // notify each peer of our new piece so that they can request it
        for(auto& peer : m_peer_sessions)
        {
            peer->announce_new_piece(piece);
        }
    }
    else
    {
        // we failed to download piece, free it for others to redownload
        m_piece_picker->unreserve(piece);
        // TODO if only a single peer downloaded this piece, it has disconnected
        // itself, so remove it from m_peer_sessions immediately as opposed to waiting
        // for the next choke round
    }
    m_piece_downloads->erase(piece);
}
