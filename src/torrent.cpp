#include "endpoint_filter.hpp"
#include "piece_download.hpp"
#include "string_utils.hpp"
#include "piece_picker.hpp"
#include "alert_queue.hpp"
#include "sha1_hasher.hpp"
#include "engine_info.hpp"
#include "settings.hpp"
#include "disk_io.hpp"
#include "torrent.hpp"
#include "random.hpp"
#include "view.hpp"

#include <algorithm>
#include <cmath> // floor, min, max, pow

namespace tide {

// `torrent` needs to be kept alive until all async ops complete, so we bind a
// `std::shared_ptr` to the instance to each async op's handler along with `this`.
#define SHARED_THIS this, self(shared_from_this())

// Common constructor.
torrent::torrent(
    torrent_id_t id,
    const int num_pieces,
    asio::io_service& ios,
    disk_io& disk_io,
    rate_limiter& global_rate_limiter,
    const settings& global_settings,
    engine_info& engine_info,
    std::vector<tracker_entry> trackers,
    endpoint_filter& endpoint_filter,
    alert_queue& alert_queue
)
    : ios_(ios)
    , disk_io_(disk_io)
    , global_rate_limiter_(global_rate_limiter)
    , local_rate_limiter_(global_rate_limiter_)
    , global_settings_(global_settings)
    , engine_info_(engine_info_)
    , endpoint_filter_(endpoint_filter)
    , alert_queue_(alert_queue)
    , trackers_(std::move(trackers))
    , piece_picker_(num_pieces)
    , update_timer_(ios)
    , announce_timer_(ios)
    , unchoke_comparator_(&torrent::choke_ranker::download_rate_based)
{
    // make sure `engine` gave us valid trackers
    for(const auto& e : trackers_) assert(e.tracker);
    info_.id = id;
}

// For new torrents.
torrent::torrent(
    torrent_id_t id,
    asio::io_service& ios,
    disk_io& disk_io,
    rate_limiter& global_rate_limiter,
    const settings& global_settings,
    engine_info& engine_info,
    std::vector<tracker_entry> trackers,
    endpoint_filter& endpoint_filter,
    alert_queue& alert_queue,
    torrent_args args
)
    : torrent(id, args.metainfo.num_pieces, ios, disk_io, global_rate_limiter,
        global_settings, engine_info, std::move(trackers), endpoint_filter, alert_queue) 
{
    apply_torrent_args(args);
    if(!info_.settings.download_sequentially && piece_picker_.num_have_pieces() < 4)
    {
        piece_picker_.set_strategy(piece_picker::strategy::random);
    }
}

// For resumed torrents.
// TODO
torrent::torrent(
    torrent_id_t id,
    asio::io_service& ios,
    disk_io& disk_io,
    rate_limiter& global_rate_limiter,
    const settings& global_settings,
    engine_info& engine_info,
    std::vector<tracker_entry> trackers,
    endpoint_filter& endpoint_filter,
    alert_queue& alert_queue,
    bmap resume_data
)
    : torrent(id, resume_data.find_number("num_pieces"), ios, disk_io, 
        global_rate_limiter, global_settings, engine_info, std::move(trackers),
        endpoint_filter, alert_queue) 
{
    restore_resume_data(resume_data);
    if(!info_.settings.download_sequentially)
    {
        piece_picker_.set_strategy(piece_picker::strategy::random);
    }
}

void torrent::apply_torrent_args(torrent_args& args)
{
    piece_hashes_ = args.metainfo.piece_hashes;

    info_.info_hash = create_sha1_digest(
        args.metainfo.source.find_bmap("info").encode());
    info_.save_path = std::move(args.save_path);

    info_.num_pieces = args.metainfo.num_pieces;
    info_.num_wanted_pieces = args.metainfo.num_pieces;
    info_.size = args.metainfo.total_length;
    info_.piece_length = args.metainfo.piece_length;
    info_.last_piece_length =
        info_.size - (info_.num_pieces - 1) * info_.piece_length;
    info_.num_blocks = (info_.num_pieces)
        * util::ceil_division(info_.piece_length, 0x4000)
        + util::ceil_division(info_.last_piece_length, 0x4000);

    info_.settings = std::move(args.settings);
    info_.files = std::move(args.metainfo.files);
    // We'll actually apply file priorities once storage is allocated.
    info_.priority_files = std::move(args.priority_files);

    info_.wanted_size = 0;
    for(const auto& f : info_.files)
    {
        if(f.is_wanted) { info_.wanted_size += f.length; }
    }
    // FIXME num_wanted_piece calculation is a bit more involved, unfortunately, because
    // we also need to count the pieces that overlap into unwanted files, which the
    // above calculation does not take into consideration

    if(args.name.empty())
        args.metainfo.source.try_find_string("name", info_.name);
    else
        info_.name = std::move(args.name);

    // Initialize the thread-safe torrent_info copy with these variables as well.
    ts_info_ = info_;
}

void torrent::start()
{
    if(info_.state[torrent_info::active]) { return; }

    log(log_event::update, "starting torrent");
    info_.state[torrent_info::active] = true;

    if(!storage_)
    {
        log(log_event::disk, "allocating torrent storage");
        info_.state[torrent_info::allocating] = true;
        std::error_code error;
        auto handle = disk_io_.allocate_torrent(info_, piece_hashes_, error);
        // For now, allocation is done synchronously.
        on_torrent_allocated(error, handle);
    }

    announce(tracker_request::started);

    if(!peer_sessions_.empty())
    {
        log(log_event::update, "trying to reconnect %i peers", peer_sessions_.size());
        for(auto& session : peer_sessions_) { session->start(); }
        update();
    }

    // Highly unlikely that this will be run exactly at the Unix epoch, so this should
    // be good enough.
    if((info_.download_started_time == time_point()) && !is_seed())
    {
        info_.download_started_time = cached_clock::now();
    }

    alert_queue_.emplace<torrent_stopped_alert>(get_handle());
}

void torrent::stop()
{
    if(!info_.state[torrent_info::active]) { return; }

    log(log_event::update, "stopping torrent");

    // TODO should we stop these when the last peer disconnected?
    update_timer_.cancel();
    announce_timer_.cancel();

    announce(tracker_request::stopped);
    for(auto& session : peer_sessions_)
    {
        if(!session->is_stopped())
        {
            // Choke all peers to prevent responding to new requests (this is necessary,
            // since we're gracefully disconnecting peers, so they may be around for a 
            // while till all async ops finish, during which peers may send us requests).
            session->choke_peer();
            session->stop();
        }
    }
}

void torrent::force_tracker_announce(string_view url)
{
    auto entry = std::find_if(trackers_.begin(), trackers_.end(),
        [&url](const auto& t) { return t.tracker->url() == url; });
    if(entry != trackers_.end())
    {
        log(log_event::tracker, log::priority::high,
            "sending event(none) to tracker(%s)", url.data());
        entry->tracker->announce(prepare_tracker_request(tracker_request::none),
            [SHARED_THIS, entry] (const std::error_code& ec, tracker_response r)
            { on_announce_response(*entry, ec, std::move(r), tracker_request::none); });
        // TODO verify that iterator to tracker (`entry`) is not invalidated
    }
}

void torrent::on_peer_session_gracefully_stopped(peer_session& session)
{
    on_peer_session_finished(session);
    if(num_connected_peers() == 0)
    {
        info_.state[torrent_info::active] = false;
        assert(info_.num_seeders == 0);
        assert(info_.num_leechers == 0);
        assert(info_.num_unchoked_peers == 0);
        save_resume_data();

        alert_queue_.emplace<torrent_stopped_alert>(get_handle());
    }
}

void torrent::abort()
{
    // TODO if we're being stopped gracefully, we might want to switch from graceful to
    // abort instead of returning
    if(!info_.state[torrent_info::active]) { return; }

    log(log_event::update, "aborting torrent");

    update_timer_.cancel();
    announce_timer_.cancel();

    for(auto& session : peer_sessions_)
    {
        if(!session->is_disconnected()) { session->abort(); }
    }
    info_.state[torrent_info::active] = false;
    info_.num_seeders = 0;
    info_.num_leechers = 0;
    info_.num_unchoked_peers = 0;
    save_resume_data();

    alert_queue_.emplace<torrent_stopped_alert>(get_handle());
}

void torrent::attach_peer_session(std::shared_ptr<peer_session> session)
{
    if(!session) { return; }
    if(info_.settings.max_connections != values::unlimited
       && peer_sessions_.size() < info_.settings.max_connections)
    {
        // TODO
        peer_sessions_.emplace_back(std::move(session));
    }
    else
    {
#ifdef TIDE_ENABLE_LOGGING
        const auto& ep = session->remote_endpoint();
        const auto& ip = ep.address().to_string();
        log(log_event::peer, "connection limit reached, can't connect to %s:%i",
            ip.c_str(), ep.port());
#endif // TIDE_ENABLE_LOGGING
        //alert_queue_.emplace<torrent_connection_limit_reached_alert>(get_handle());
    }
}

void torrent::make_file_top_priority(const int file_index)
{
    const interval pieces = storage_.pieces_in_file(file_index);
    if(!pieces.empty()) { piece_picker_.make_top_priority(pieces); }
}

void torrent::prioritize_file(const int file_index)
{
    const interval pieces = storage_.pieces_in_file(file_index);
    if(!pieces.empty()) { piece_picker_.make_priority(pieces); }
}

void torrent::deprioritize_file(const int file_index)
{
    const interval pieces = storage_.pieces_in_file(file_index);
    if(!pieces.empty()) { piece_picker_.clear_priority(pieces); }
}

void torrent::prioritize_piece(const piece_index_t piece)
{
    piece_picker_.make_priority(interval{piece, piece + 1});
}

void torrent::deprioritize_piece(const piece_index_t piece)
{
    piece_picker_.clear_priority(interval{piece, piece + 1});
}

void torrent::auto_manage() noexcept
{
    info_.is_auto_managed = true;
    info_.settings.max_upload_slots = values::none;
    info_.settings.max_connections = values::none;
    info_.settings.max_download_rate = values::none;
    info_.settings.max_upload_rate = values::none;
    local_rate_limiter_.attach_to_global_rate_limiter();
}

void torrent::apply_settings(const torrent_settings& s)
{
    switch(s.choke_algorithm) {
    case torrent_settings::choke_algorithm::rate_based:
    {
        if(is_seed())
            unchoke_comparator_ = choke_ranker::upload_rate_based;
        else
            unchoke_comparator_ = choke_ranker::download_rate_based;
        break;
    }
    }

    // If we've been seeding so far but suddenly got this setting changed, stop torrent.
    if(is_seed() && s.stop_when_downloaded) { stop(); }
    if(!info_.settings.download_sequentially && s.download_sequentially)
        piece_picker_.set_strategy(piece_picker::strategy::sequential);

    set_max_upload_slots(s.max_upload_slots);
    set_max_connections(s.max_connections);
    set_max_download_rate(s.max_download_rate);
    set_max_upload_rate(s.max_upload_rate);

    info_.settings = s;
    // Torrent has its own settings now, so we'll no longer default to the global ones.
    info_.is_auto_managed = false;
}

void torrent::set_max_upload_slots(const int max_upload_slots)
{
#ifdef TIDE_ENABLE_EXPENSIVE_ASSERTS
    // The unchoked peers must always be at the beginning of `peer_sessions_`.
    for(auto i = 0; i < info_.num_unchoked_peers; ++i)
        assert(!peer_sessions_[i]->is_peer_choked());
#endif
    // If the number of upload slots was decreased, choke some peers. Otherwise the next
    // unchoke round will unchoke peers.
    assert(info_.num_unchoked_peers <= peer_sessions_.size());
    for(auto i = max_upload_slots, n = info_.num_unchoked_peers; i < n; ++i)
    {
        peer_sessions_[i]->choke_peer();
        --info_.num_unchoked_peers;
    }
    info_.settings.max_upload_slots = max_upload_slots;
}

void torrent::set_max_download_rate(const int n)
{
    local_rate_limiter_.set_max_download_rate(n);
    local_rate_limiter_.detach_from_global_rate_limiter();
}

void torrent::set_max_upload_rate(const int n)
{
    local_rate_limiter_.set_max_upload_rate(n);
    local_rate_limiter_.detach_from_global_rate_limiter();
}

void torrent::set_max_connections(const int max_connections)
{
    // Some connections may need to be closed if `max_connections` is lower than the
    // current setting.
    for(auto i = max_connections; i < peer_sessions_.size(); ++i)
    {
        // This will asynchronously stop the session, which will invoke
        // `on_peer_session_gracefully_stopped`, so no further action is necessary.
        // If the session is already stopped but hasn't yet been removed from
        // `peer_sessions_`, it will be in the next call to `update`.
        peer_sessions_[i]->stop();
    }
    info_.settings.max_connections = max_connections;
}

int torrent::close_n_connections(const int n)
{
    int num_closed = 0;
    for(auto rit = peer_sessions_.rbegin(), rend = peer_sessions_.rend();
        (rit != rend) && (num_closed < n); ++rit)
    {
        auto& session = *rit;
        if(!session->is_stopped())
        {
            session->stop();
            ++num_closed;
        }
    }
    return num_closed;
}

inline void torrent::on_torrent_allocated(
    const std::error_code& error, torrent_storage_handle storage)
{
    if(error || !storage)
    {
        log(log_event::disk, log::priority::high, "ERROR allocating disk storage");
        // TODO send alert
        // TODO what to do when we couldn't allocate file? could this even occur?
        // what are the possible errors? no save path? shouldn't that be checked
        // at a higher level?
        ++info_.num_disk_io_failures;
        if(info_.num_disk_io_failures < 100)
        {
            // TODO allocation is no longer async
            //disk_io_.allocate_torrent(info_, piece_hashes_,
                //[SHARED_THIS](const std::error_code& ec, torrent_storage_handle storage)
                //{ on_torrent_allocated(ec, storage); });
        }
        return;
    }
    log(log_event::disk, "torrent allocated");
    storage_ = storage;
    info_.state[torrent_info::allocating] = false;
#ifdef TIDE_ENABLE_EXPENSIVE_ASSERTS
    for(auto i = 0; i < info_.num_pieces; ++i)
    {
        assert(!storage_.files_containing_piece(i).empty());
    }
#endif // TIDE_ENABLE_EXPENSIVE_ASSERTS
    for(const file_index_t file : info_.priority_files)
    {
        // At this point each entry must be sanitized.
        log(log_event::disk, "making file (%s) priority",
            info_.files[file].path.c_str());
        piece_picker_.make_priority(storage_.pieces_in_file(file));
    }
}

inline bool torrent::should_save_resume_data() const noexcept
{
    return has_state_changed_
        && info_.last_resume_data_save_time - cached_clock::now() >= seconds(30);
}

inline void torrent::save_resume_data()
{
    if(!has_state_changed_) { return; }
    log(log_event::disk, "saving torrent resume data");
    disk_io_.save_torrent_resume_data(id(), create_resume_data(),
        [SHARED_THIS](const std::error_code& error) { on_resume_data_saved(error); });
    has_state_changed_ = false;
    info_.state[torrent_info::saving_state] = true;
    info_.last_resume_data_save_time = cached_clock::now();
}

void torrent::on_resume_data_saved(const std::error_code& error)
{
    info_.state[torrent_info::saving_state] = false;
    if(error)
    {
        const auto reason = error.message();
        log(log_event::disk, log::priority::high,
            "failed to save torrent resume data: %s", reason.c_str());
        has_state_changed_ = true;
        if(should_save_resume_data()) { save_resume_data(); }
    }
    else
    {
        log(log_event::disk, "torrent resume data saved");
    }
}

bmap_encoder torrent::create_resume_data() const
{
    bmap_encoder resume_data;

    // info
    resume_data["info_hash"] = std::string(
        info_.info_hash.begin(), info_.info_hash.end());
    resume_data["bitfield"] = is_seed() ? "have_all"
                                        : piece_picker_.my_bitfield().to_string();
    resume_data["save_path"] = info_.save_path.c_str();
    resume_data["name"] = info_.name;
    // TODO maybe deduce these by adding together the file lengths when we read them back
    resume_data["size"] = info_.size;
    resume_data["wanted_size"] = info_.wanted_size;
    resume_data["num_pieces"] = info_.num_pieces;
    resume_data["num_wanted_pieces"] = info_.num_wanted_pieces;
    resume_data["num_downloaded_pieces"] = info_.num_downloaded_pieces;
    resume_data["num_pending_pieces"] = info_.num_pending_pieces;
    resume_data["piece_hashes"] = piece_hashes_.data();
    resume_data["files"] = [this]
    {
        blist_encoder files_list;
        for(const auto& f : info_.files)
        {
            bmap_encoder file_map;
            file_map["path"] = f.path.c_str();
            file_map["length"] = f.length;
            file_map["downloaded_length"] = f.downloaded_length;
            file_map["is_wanted"] = f.is_wanted ? 1 : 0;
            files_list.push_back(file_map);
        }
        return files_list;
    }();
    resume_data["priority_files"] = [this]
    {
        blist_encoder priority_files;
        for(const auto& f : info_.priority_files)
        {
            priority_files.push_back(f);
        }
        return priority_files;
    }();
    resume_data["partial_pieces"] = [this]
    {
        blist_encoder partial_pieces;
        for(const auto& d : downloads_)
        {
            bmap_encoder piece;
            piece["index"] = d->piece_index();
            blist_encoder blocks;
            int i = 0;
            for(const piece_download::block block : d->blocks())
            {
                if(block.status == piece_download::block::status::received)
                {
                    // Save the block indices, they are at 0x4000 offsets.
                    blocks.push_back(i);
                }
                ++i;
            }
            piece["blocks"] = blocks;
            partial_pieces.push_back(piece);
        }
        return partial_pieces;
    }();

    // settings
    resume_data["download_sequentially"] = info_.settings.download_sequentially;
    resume_data["stop_when_downloaded"] = info_.settings.stop_when_downloaded;
    resume_data["max_upload_slots"] = info_.settings.max_upload_slots;
    resume_data["max_connections"] = info_.settings.max_connections;
    resume_data["max_upload_rate"] = info_.settings.max_upload_rate;
    resume_data["max_download_rate"] = info_.settings.max_download_rate;

    // stats
    resume_data["total_seed_time"] = to_int<seconds>(info_.total_seed_time);
    resume_data["total_leech_time"] = to_int<seconds>(info_.total_leech_time);
    resume_data["download_started_time"] = to_int<seconds>(
        info_.download_started_time.time_since_epoch());
    resume_data["download_finished_time"] = to_int<seconds>(
        info_.download_finished_time.time_since_epoch());
    resume_data["total_downloaded_piece_bytes"] = info_.total_downloaded_piece_bytes;
    resume_data["total_uploaded_piece_bytes"] = info_.total_uploaded_piece_bytes;
    resume_data["total_downloaded_bytes"] = info_.total_downloaded_bytes;
    resume_data["total_uploaded_bytes"] = info_.total_uploaded_bytes;
    resume_data["total_verified_piece_bytes"] = info_.total_verified_piece_bytes;
    resume_data["total_failed_piece_bytes"] = info_.total_failed_piece_bytes;
    resume_data["total_wasted_bytes"] = info_.total_wasted_bytes;
    resume_data["total_bytes_written_to_disk"] = info_.total_bytes_written_to_disk;
    resume_data["total_bytes_read_from_disk"] = info_.total_bytes_read_from_disk;
    resume_data["num_hash_fails"] = info_.num_hash_fails;
    resume_data["num_illicit_requests"] = info_.num_illicit_requests;
    resume_data["num_unwanted_blocks"] = info_.num_unwanted_blocks;
    resume_data["num_disk_io_failures"] = info_.num_disk_io_failures;
    resume_data["num_timed_out_requests"] = info_.num_timed_out_requests;

    return resume_data;
}

void torrent::restore_resume_data(const bmap& resume_data)
{
    // TODO how to handle an invalid resume_data? should this be checked on an upper
    // level or should we throw here (this method is called from the constructor)?

    // info
    const auto info_hash = resume_data.find_string_view("info_hash");
    std::copy(info_hash.begin(), info_hash.end(), info_.info_hash.begin());

    // info
    string_view bitfield;
    resume_data.try_find_string_view("bitfield", bitfield);
    if(bitfield == "have_all")
    {
        piece_picker_ = piece_picker(tide::bitfield(info_.num_pieces));
    }
    else
    {
        tide::bitfield pieces(info_.num_pieces);
        for(auto i = 0; i < info_.num_pieces; ++i)
        {
            if(bitfield[i] == '1')
            {
                pieces[i] = true;
            }
        }
        piece_picker_ = piece_picker(std::move(pieces));
    }
    std::string save_path;
    resume_data.try_find_string("save_path", save_path);
    info_.save_path = std::move(save_path);
    resume_data.try_find_string("name", info_.name);
    resume_data.try_find_number("size", info_.size);
    resume_data.try_find_number("wanted_size", info_.wanted_size);
    resume_data.try_find_number("num_pieces", info_.num_pieces);
    resume_data.try_find_number("num_wanted_pieces", info_.num_wanted_pieces);
    resume_data.try_find_number("num_downloaded_pieces", info_.num_downloaded_pieces);
    resume_data.try_find_number("num_pending_pieces", info_.num_pending_pieces);
    resume_data.try_find_string("piece_hashes", piece_hashes_);

    blist files;
    resume_data.try_find_blist("files", files);
    info_.files.reserve(files.size());
    for(const bmap file_map : files.all_bmaps())
    {
        file_info f;
        std::string path;
        file_map.try_find_string("path", path);
        f.path = std::move(path);
        file_map.try_find_number("length", f.length);
        file_map.try_find_number("downloaded_length", f.downloaded_length);
        file_map.try_find_number("is_wanted", f.is_wanted);
        info_.files.emplace_back(std::move(f));
    }

    blist priority_files;
    resume_data.try_find_blist("priority_files", priority_files);
    info_.priority_files.reserve(priority_files.size());
    for(const auto file_index : priority_files.all_numbers())
    {
        info_.priority_files.push_back(file_index);
    }

    /*
    // TODO
    // Partial pieces are not supported for now as we need to let `disk_io` know that we
    // have these partial pieces on disk, which for now is too difficult to do, so
    // we'll just redownload these blocks.
    blist partial_pieces;
    resume_data.try_find_blist("partial_pieces", partial_pieces);
    for(const bmap piece : partial_pieces)
    {
        piece_index_t index = invalid_piece_index;
        piece.try_find_number("index", index);
        if(index == invalid_piece_index) { continue; }
        auto download = std::make_shared<piece_download>(index);
        blist blocks;
        piece.try_find_blist("blocks", blocks);
        for(const int block_index : blocks)
        {
            download->have_block(block_index * 0x4000);
        }
    }
    */

    // settings
    resume_data.try_find_number("download_sequentially",
        info_.settings.download_sequentially);
    resume_data.try_find_number("stop_when_downloaded",
        info_.settings.stop_when_downloaded);
    resume_data.try_find_number("max_upload_slots", info_.settings.max_upload_slots);
    resume_data.try_find_number("max_connections", info_.settings.max_connections);
    resume_data.try_find_number("max_upload_rate", info_.settings.max_upload_rate);
    resume_data.try_find_number("max_download_rate", info_.settings.max_download_rate);

    // stats
    int int_buffer = 0;
    resume_data.try_find_number("total_seed_time", int_buffer);
    info_.total_seed_time = seconds(int_buffer);
    resume_data.try_find_number("total_leech_time", int_buffer);
    info_.total_leech_time = seconds(int_buffer);
    resume_data.try_find_number("download_started_time", int_buffer);
    info_.download_started_time = time_point(seconds(int_buffer));
    resume_data.try_find_number("download_finished_time", int_buffer);
    info_.download_finished_time = time_point(seconds(int_buffer));

    resume_data.try_find_number("total_downloaded_piece_bytes",
        info_.total_downloaded_piece_bytes);
    resume_data.try_find_number("total_uploaded_piece_bytes",
        info_.total_uploaded_piece_bytes);
    resume_data.try_find_number("total_downloaded_bytes",
        info_.total_downloaded_bytes);
    resume_data.try_find_number("total_uploaded_bytes",
        info_.total_uploaded_bytes);
    resume_data.try_find_number("total_verified_piece_bytes",
        info_.total_verified_piece_bytes);
    resume_data.try_find_number("total_failed_piece_bytes",
        info_.total_failed_piece_bytes);
    resume_data.try_find_number("total_wasted_bytes",
        info_.total_wasted_bytes);
    resume_data.try_find_number("total_bytes_written_to_disk",
        info_.total_bytes_written_to_disk);
    resume_data.try_find_number("total_bytes_read_from_disk",
        info_.total_bytes_read_from_disk);
    resume_data.try_find_number("num_hash_fails", info_.num_hash_fails);
    resume_data.try_find_number("num_illicit_requests", info_.num_illicit_requests);
    resume_data.try_find_number("num_unwanted_blocks", info_.num_unwanted_blocks);
    resume_data.try_find_number("num_disk_io_failures", info_.num_disk_io_failures);
    resume_data.try_find_number("num_timed_out_requests", info_.num_timed_out_requests);
}

void torrent::announce(const int event, const bool force)
{
    if(trackers_.empty())
    {
        log(log_event::tracker, "cannot announce: no trackers");
        return;
    }

    info_.state[torrent_info::announcing] = true;
    tracker_request request = prepare_tracker_request(event);

    // If the event is stopped or completed, we need to send it to all trackers to which
    // we have announced in the past, otherwise just pick the most suitable tracker, as
    // we're just requesting more peers.
    if((event == tracker_request::stopped) || (event == tracker_request::completed))
    {
        for(auto& entry : trackers_)
        {
            // Don't send the `stopped` and `completed` events more than once, or if we 
            // haven't contacted tracker at all (haven't sent a `started` event).
            if((entry.has_sent_completed && (event == tracker_request::completed))
               || (entry.has_sent_stopped && (event == tracker_request::stopped)))
            {
                continue;
            }
            else if(entry.has_sent_started && entry.tracker->is_reachable())
            {
                log(log_event::tracker, log::priority::high,
                    "sending event(%s) to tracker(%s)",
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
        // TODO verify that this is correct
        if(!t)
        {
            if(trackers_.empty() && peer_sessions_.empty() && available_peers_.empty())
            {
                log(log_event::tracker, log::priority::high,
                    "couldn't find tracker to announce to and we don't have any peers,"
                    " stopping torrent");
                stop();
            }
            log(log_event::tracker, "cannot announce, no suitable tracker");
            return;
        }
        tracker_entry& entry = *t;
        // If we haven't sent the `started` event before, this is the first time
        // contacting tracker, in which case we must send a `started` event.
        if(!entry.has_sent_started)
        {
            request.event = tracker_request::started;
        }
        log(log_event::tracker, log::priority::high,
            "sending event(%s) to tracker(%s)",
            request.event == tracker_request::started ? "started" : "none",
            entry.tracker->url().c_str());
        entry.tracker->announce(std::move(request),
            [SHARED_THIS, &entry, event = request.event]
            (const std::error_code& ec, tracker_response r)
            { on_announce_response(entry, ec, std::move(r), event); });
    }
}

inline tracker_request torrent::prepare_tracker_request(const int event) const noexcept
{
    tracker_request request;
    request.info_hash = info_.info_hash;
    request.peer_id = global_settings_.peer_session.client_id;
    request.downloaded = info_.total_downloaded_piece_bytes;
    request.uploaded = info_.total_uploaded_piece_bytes;
    request.left = info_.size - info_.wanted_size;
    request.port = global_settings_.listener_port;
    request.event = event;
    request.compact = true;
    request.num_want = event == tracker_request::started
                    || event == tracker_request::none
                       ? calculate_num_want()
                       : 0;
    return request;
}

inline int torrent::calculate_num_want() const noexcept
{
    const int available = global_settings_.max_connections - engine_info_.num_connections;
    if(available == 0) { return 0; }
    const int num_desired = info_.settings.max_connections
        - peer_sessions_.size() - available_peers_.size();
    // TODO maybe we should get more in case we can connect to more peers.
    return std::min(available, num_desired);
}

inline tracker_entry* torrent::pick_tracker(const bool force)
{
    // Even if we're forcing the reannounce, first try to see if we can find a tracker
    // to which we can announce without forcing some other tracker.
    for(auto& t : trackers_)
    {
        if(can_announce_to(t)) { return &t; }
    }
    // If we're forcing a reannounce, we don't have to check whether the wait interval
    // is up, we need only know that we can reach tracker.
    if(force)
    {
        for(auto& t : trackers_)
        {
            if(can_force_announce_to(t))
            {
                t.last_force_time = cached_clock::now();
                return &t;
            }
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

inline bool torrent::can_force_announce_to(const tracker_entry& t) const noexcept
{
    return t.tracker->is_reachable()
        && !t.tracker->had_protocol_error()
        && cached_clock::now() - t.last_force_time >= seconds(10);
}

void torrent::on_announce_response(tracker_entry& tracker, const std::error_code& error,
    tracker_response response, const int event)
{
    info_.state[torrent_info::announcing] = false;
    if(error)
    {
        on_announce_error(tracker, error, event);
        return;
    }

    log(log_event::tracker, log::priority::high,
        "received announce response from %s (peers: %i; "
        "interval: %i; seeders: %i; leechers: %i; tracker_id: %s)",
        tracker.tracker->url().c_str(), response.peers.size()
        + response.ipv4_peers.size() + response.ipv6_peers.size(), response.interval,
        response.num_seeders, response.num_leechers, response.tracker_id.c_str());
    //alert_queue_.emplace<announce_response_alert>(tracker.tracker.url(),
        //response.interval, response.num_seeders, response.num_leechers);

    const auto now = cached_clock::now();
    info_.last_announce_time = now;
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

    available_peers_.reserve(available_peers_.size()
        + response.ipv4_peers.size() + response.ipv6_peers.size());
    for(auto& ep : response.ipv4_peers) { add_peer(std::move(ep)); }
    for(auto& ep : response.ipv6_peers) { add_peer(std::move(ep)); }

    // If we aren't connected to any peers but received peers we can connect to, it
    // means the update cycle (i.e. torrent) is not running. This may be the first
    // announce or we stoppped torrent as soon as we disconnected the last peer. In
    // either case, reinstate the update cycle (but only do this if the torrent is not
    // stopped, as it is possible to be in a stopped state by the time the response
    // arrives if torrent was gracefully stopped).
    if(!is_stopped() && peer_sessions_.empty() && !available_peers_.empty())
    {
        log(log_event::update, log::priority::high, "starting torrent update cycle");
        update();
    }
}

inline void torrent::on_announce_error(tracker_entry& tracker,
    const std::error_code& error, const int event)
{
    // TODO is this correct?
    if(error == asio::error::network_down)
    {
        log(log_event::tracker, "network down, can't reach tracker, stopping torrent");
        stop();
    }
    else
    {
        const auto reason = error.message();
        log(log_event::tracker, "error contacting tracker: %s", reason.c_str());
        // If this tracker failed too much, we won't bother in the future, remove it.
        if(++tracker.num_fails > 100)
        {
            trackers_.erase(std::find_if(trackers_.begin(), trackers_.end(),
                [&tracker](const auto& t) { return &t == &tracker; }));
            if(trackers_.empty() && peer_sessions_.empty() && available_peers_.empty())
            {
                stop();
                return;
            }
        }
        tracker.last_error = error;
        // Retry.
        announce(event);
    }
}

inline void torrent::add_peer(tcp::endpoint peer)
{
    if(endpoint_filter_.is_allowed(peer))
    {
        // Only add peer if it's not already connected or is in `available_peers_`.
        auto psit = std::find_if(peer_sessions_.begin(), peer_sessions_.end(),
            [&peer](const auto& session) { return session->remote_endpoint() == peer; });
        auto apit = std::find(available_peers_.begin(), available_peers_.end(), peer);
        if((psit == peer_sessions_.end()) && (apit == available_peers_.end()))
        {
            const auto address = peer.address().to_string();
            log(log_event::update, "adding peer(%s:%i)", address.c_str(), peer.port());
            available_peers_.emplace_back(std::move(peer));
        }
    }
}

void torrent::update(const std::error_code& error)
{
    if(error)
    {
        // TODO log, alert, stop torrent
        log(log_event::update, "error in update cycle: %s", error.message().c_str());
        return;
    }

    log(log_event::update, "upload rate: %i bytes/s; download rate: %i bytes/s",
        info_.upload_rate.rate(), info_.download_rate.rate());

    if(local_rate_limiter_.is_detached_from_global_rate_limiter())
    {
        assert(!is_auto_managed());
        assert(info_.settings.max_download_rate == values::unlimited
               || info_.settings.max_download_rate > 0);
        assert(info_.settings.max_upload_rate == values::unlimited
               || info_.settings.max_upload_rate > 0);
        local_rate_limiter_.add_download_quota(info_.settings.max_download_rate);
        local_rate_limiter_.add_upload_quota(info_.settings.max_upload_rate);
    }

    remove_finished_peer_sessions();
    if(info_.num_disk_io_failures >= 300)
    {
        log(log_event::disk, log::priority::high,
            "too many (%i) disk failures, stopping torrent",
            info_.num_disk_io_failures);
        stop();
        return;
    }

    if(should_connect_peers()) { connect_peers(); }
    if(needs_peers())
    {
        const bool has_no_peers = peer_sessions_.empty() && available_peers_.empty();
        announce(tracker_request::none, has_no_peers);
        // If we don't have active sessions left it makes no sense to continue updating.
        // Try to get some peers by announcing, which will reinstate the update cycle.
        if(has_no_peers)
        {
            log(log_event::update, "no peer sessions or available peers, announcing");
            return;
        }
    }

    // Only run the unchoke procedure every 10 seconds.
    if(cached_clock::now() - info_.last_unchoke_time >= seconds(10)) { unchoke(); }

    // FIXME this is wrong because this update function may not be invoked if we don't
    // have any seeds, in which case these counters still need incrementing
    if(is_seed())
    {
        info_.total_seed_time += seconds(1);
        // Check whether we need to stop due to reaching the designated seed-ratios
        // (only if any of these settings are enabled).
        if(has_reached_share_ratio_limit()
           || has_reached_seed_time_limit()
           || has_reached_share_time_ratio_limit()) { stop(); }
    }
    else
    {
        info_.total_leech_time += seconds(1);
    }

    update_thread_safe_info();

    //if(should_save_resume_data()) { save_resume_data(); }

    alert_queue_.emplace<torrent_stats_alert>(get_handle());

    start_timer(update_timer_, seconds(1),
        [SHARED_THIS](const std::error_code& error) { update(error); });
}

inline bool torrent::should_connect_peers() const noexcept
{
    // TODO take into consideration the number of connecting sessions -- we don't want
    // to have too many of those
    // We're only actively trying to connect to new peers if we fall below 30.
    return !available_peers_.empty()
        && peer_sessions_.size() < (std::min)(info_.settings.max_connections, 30);
}

inline bool torrent::needs_peers() const noexcept
{
    // We should be able to connect at least 30 (or max_connections number) of peers.
    const int total_peers = peer_sessions_.size() + available_peers_.size();
    // TODO verify
    return total_peers < (std::min)(info_.settings.max_connections, 20);
}

void torrent::connect_peers()
{
    const int num_to_connect = std::min({int(available_peers_.size()),
        info_.settings.max_connections - int(peer_sessions_.size()),
        global_settings_.max_connections - engine_info_.num_connections});
    // This function shouldn't be called if we can't connect.
    assert(num_to_connect > 0);
    log(log_event::update, "connecting %i peer%c", num_to_connect,
        num_to_connect == 1 ? 0 : 's');
    for(auto i = 0; i < num_to_connect; ++i) { connect_peer(available_peers_[i]); }
    // Erase the peers from the available peers list to which we've connected.
    available_peers_.erase(available_peers_.begin(),
        available_peers_.begin() + num_to_connect);
}

inline void torrent::connect_peer(tcp::endpoint& peer)
{
    const auto address = peer.address().to_string();
    log(log_event::update, "connecting peer(%s:%i)", address.c_str(), peer.port());
    peer_sessions_.emplace_back(std::make_shared<peer_session>(ios_,
        std::move(peer), local_rate_limiter_, global_settings_.peer_session,
        torrent_frontend(*this)));
    peer_sessions_.back()->start();
    // FIXME TODO we need to know how many seeds and leeches we have in the swarm.
    // should we periodically loop through all peers in session to find out?
}

inline void torrent::remove_finished_peer_sessions()
{
    // Save looping through all sessions if none are disconnected.
    //if(info_.num_lingering_disconnected_sessions == 0) { return; }
    int num_removed = 0;
    for(auto i = 0; i < peer_sessions_.size(); ++i)
    {
        if(peer_sessions_[i]->is_stopped())
        {
            on_peer_session_finished(*peer_sessions_[i]);
            peer_sessions_.erase(peer_sessions_.begin() + i);
            ++num_removed, --i;
            //if(num_removed == info_.num_lingering_disconnected_sessions) { break; }
        }
    }
    if(num_removed > 0)
    {
        //info_.num_lingering_disconnected_sessions -= num_removed;
        log(log_event::update, "removing %i peer session%c", num_removed,
            num_removed == 1 ? 0 : 's');
    }
}

void torrent::on_peer_session_finished(peer_session& session)
{
    assert(session.is_stopped());
    const auto address = session.remote_endpoint().address().to_string();
    log(log_event::update, "session(%s:%i, %s, %lis) finished", address.c_str(),
        session.remote_endpoint().port(), session.is_peer_seed() ? "seed" : "leech",
        session.connection_duration().count());

    if(!session.is_peer_choked())
        --info_.num_unchoked_peers;

    if(session.is_peer_seed())
        --info_.num_seeders;
    else
        --info_.num_leechers;
}

inline void torrent::update_thread_safe_info()
{
    std::unique_lock<std::mutex> l(ts_info_mutex_);
    // Only update the fields that are expected to have changed. Specific fields which
    // are also more expensive to update, such as priority_files, are updated when that
    // change occurs. Fields like info_hash never change.
    ts_info_.num_pieces = info_.num_pieces;
    ts_info_.num_wanted_pieces = info_.num_wanted_pieces;
    ts_info_.num_downloaded_pieces = info_.num_downloaded_pieces;
    ts_info_.num_pending_pieces = info_.num_pending_pieces;
    ts_info_.num_blocks = info_.num_blocks;
    ts_info_.num_pending_blocks = info_.num_pending_blocks;
    ts_info_.num_seeders = info_.num_seeders;
    ts_info_.num_leechers = info_.num_leechers;
    ts_info_.num_unchoked_peers = info_.num_unchoked_peers;
    ts_info_.num_connecting_sessions = info_.num_connecting_sessions;
    ts_info_.num_lingering_disconnected_sessions =
        info_.num_lingering_disconnected_sessions;
    ts_info_.num_choke_cycles = info_.num_choke_cycles;
    ts_info_.total_seed_time = info_.total_seed_time;
    ts_info_.total_leech_time = info_.total_leech_time;
    ts_info_.download_started_time = info_.download_started_time;
    ts_info_.download_finished_time = info_.download_finished_time;
    ts_info_.last_announce_time = info_.last_announce_time;
    ts_info_.last_unchoke_time = info_.last_unchoke_time;
    ts_info_.last_optimistic_unchoke_time = info_.last_optimistic_unchoke_time;
    ts_info_.last_resume_data_save_time = info_.last_optimistic_unchoke_time;
    ts_info_.settings = info_.settings;
    ts_info_.state = info_.state;
};

inline void torrent::sort_unchoke_candidates(const int n)
{
    assert(n <= peer_sessions_.size());
    std::partial_sort(peer_sessions_.begin(), peer_sessions_.begin() + n,
        peer_sessions_.end(), [this](const auto& a, const auto& b)
        { return unchoke_comparator_(*a, *b); });
}

inline int torrent::num_to_unchoke(const bool unchoke_optimistically) const noexcept
{
    int n = std::min(info_.settings.max_upload_slots, int(peer_sessions_.size()));
    // If we're optimistically unchoking, we need to normal unchoke one fewer peer
    // as we're going to unchoke an additional peer and we must still observe 
    // settings.max_upload_slots.
    if(unchoke_optimistically) { --n; }
    return std::max(0, n);
}

void torrent::unchoke()
{
    const bool unchoke_optimistically = info_.num_choke_cycles % 3 == 0;
    const int num_to_unchoke = this->num_to_unchoke(unchoke_optimistically);

    info_.last_unchoke_time = cached_clock::now();
    ++info_.num_choke_cycles;

    // We don't have free upload slots and no one is choked, so save the trouble.
    if((num_to_unchoke == 0) && (info_.num_unchoked_peers == 0)) { return; }

    // Put the unchoke candidates at the beginning of the peer list.
    sort_unchoke_candidates(num_to_unchoke);
    // Now go through all the peers and unchoke the first num_to_unchoke ones and
    // choke the rest if they aren't already.
    info_.num_unchoked_peers = 0;
    for(auto& session : peer_sessions_)
    {
        if(info_.num_unchoked_peers < num_to_unchoke)
        {
            if(session->is_peer_choked() && session->is_peer_interested())
            {
                session->unchoke_peer();
#ifdef TIDE_ENABLE_LOGGING
                const auto address = session->remote_endpoint().address().to_string();
                log(log_event::choke, "unchoking peer(%s:%i)", address.c_str(),
                    session->remote_endpoint().port());
#endif // TIDE_ENABLE_LOGGING
            }
            // Even if peer is already unchoked, we count it so that we don't end up
            // with more unchoked peers than we should. We may not have been successful
            // at unchoking peer (e.g. if connection has not been established yet), so
            // need to check.
            if(!session->is_peer_choked()) { ++info_.num_unchoked_peers; }
        }
        else
        {
            if(!session->is_peer_choked()) { session->choke_peer(); }
        }
    }
    if(unchoke_optimistically) { /*optimistic_unchoke();*/ }
}

void torrent::optimistic_unchoke()
{
    if(peer_sessions_.size() == info_.num_unchoked_peers) { return; }

    const auto for_each_candidate = [this](const auto& f)
    {
        for(auto& session : peer_sessions_)
        {
            if(session->is_connected()
               && !session->is_peer_seed()
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
        std::sort(candidates.begin(), candidates.end(),
            [](const auto& a, const auto& b)
            {
                return a->connection_established_time()
                     < b->connection_established_time();
            });
        // Pick peer by generating a random number skewed towards the lower end, thereby
        // giving newer peers a better chance at being picked.
        const int peer_index = std::floor(candidates.size()
            * std::pow(util::random_real(), 2));
        candidates[peer_index]->unchoke_peer();
        // Candidates must have eligible peers only.
        assert(!candidates[peer_index]->is_peer_choked());
    }
    info_.last_optimistic_unchoke_time = cached_clock::now();
}

bool torrent::choke_ranker::upload_rate_based(
    const peer_session& a, const peer_session& b) noexcept
{
    // Instead of using weighed upload rate averages for determining a peer's bandwidth
    // between unchoke rounds, we instead count the number of bytes that were sent
    // during this period, and disregard past performance.
    // Note to self: function is called upload based but we query downloaded bytes;
    // function name refers to peer's upload capacity, while the query functions are
    // from our perspective TODO perhaps change this to be less confusing.
    const auto down1 = a.num_bytes_downloaded_this_round();
    const auto down2 = b.num_bytes_downloaded_this_round();
    if(down1 != down2) { return down1 > down2; }
    return download_rate_based(a, b);
}

bool torrent::choke_ranker::download_rate_based(
    const peer_session& a, const peer_session& b) noexcept
{
    const auto up1 = a.num_bytes_uploaded_this_round();
    const auto up2 = b.num_bytes_uploaded_this_round();
    if(up1 != up2) { return up1 > up2; }
    // If both peers perform equally well, prioritize the one that has been
    // waiting to be unchoked longer.
    return a.last_outgoing_unchoke_time() < b.last_outgoing_unchoke_time();
}

void torrent::on_new_piece(piece_download& download, const bool is_valid)
{
    // Let know the `peer_session`s that participated in the download of the piece's
    // hash result (note: call this before everything else).
    download.post_hash_result(is_valid);
    --info_.num_pending_pieces;

    if(is_valid)
        handle_valid_piece(download);
    else
        handle_corrupt_piece(download);

    log(log_event::download, log::priority::high, "received new piece(%i, %s) (%i/%i)",
        download.piece_index(), is_valid ? "valid" : "corrupt",
        piece_picker_.num_have_pieces(), info_.num_pieces);

    const auto it = std::find_if(downloads_.begin(), downloads_.end(),
        [&download](const auto& d) { return d->piece_index() == download.piece_index(); });
    // If we could not find this piece download it means that it was a parole/unique
    // download, i.e. `peer_session` didn't put it in downloads_ because it wanted
    // to test whether peer was the one sending corrupt data, and for this the piece
    // download was not shared among other `peer_session`s.
    if(it != downloads_.end()) { downloads_.erase(it); }

#ifdef TIDE_ENABLE_DEBUGGING
    std::string s;
    for(const auto& d : downloads_)
    {
        const int num_blocks = d->num_blocks();
        const int num_have_blocks = d->num_received_blocks();
        s += std::to_string(d->piece_index()) + "-(" + std::to_string(num_have_blocks)
          + '/' + std::to_string(num_blocks) + "|" + std::to_string(d->peers().size())
          + ") ";
    }
    if(!s.empty()) log(log_event::download, log::priority::high,
        "active piece downloads: %s", s.c_str());
#endif // TIDE_ENABLE_DEBUGGING
}

inline void torrent::handle_valid_piece(piece_download& download)
{
    ++info_.num_downloaded_pieces;

    // Notify piece piecker that this piece was downloaded.
    piece_picker_.got(download.piece_index());

    // Notify each peer of our new piece so that they can request it.
    for(auto& session : peer_sessions_)
    {
        assert(session);
        session->announce_new_piece(download.piece_index());
    }

    // Update stats.
    const int piece_length = get_piece_length(info_, download.piece_index());
    info_.total_verified_piece_bytes += piece_length;
    ++info_.num_downloaded_pieces;

    // Update file progress.
    const interval files = storage_.files_containing_piece(download.piece_index());
    assert(!files.empty());
    for(file_index_t i = files.begin; i < files.end; ++i)
    {
        const auto slice = storage_.get_file_slice(i,
            block_info(download.piece_index(), 0, piece_length));
        info_.files[i].downloaded_length += slice.length;
        if(info_.files[i].downloaded_length == info_.files[i].length)
        {
            alert_queue_.emplace<file_complete_alert>(get_handle(), i);
        }
    }

    if(piece_picker_.num_pieces_left() == 0)
    {
        on_download_complete();
    }
    else if(!info_.settings.download_sequentially
            && piece_picker_.num_have_pieces() > 4
            && piece_picker_.strategy() != piece_picker::strategy::rarest_first)
    {
        piece_picker_.set_strategy(piece_picker::strategy::rarest_first);
        log(log_event::download, "leaving quick-start download strategy");
    }

    has_state_changed_ = true;
}

inline void torrent::handle_corrupt_piece(piece_download& download)
{
    piece_picker_.unreserve(download.piece_index());
    const int piece_length = get_piece_length(info_, download.piece_index());
    // We failed to download piece, free it for others to redownload.
    info_.total_wasted_bytes += piece_length;
    info_.total_failed_piece_bytes += piece_length;
    ++info_.num_hash_fails;
    // If we downloaded this piece from a single peer only, we know it's the culprit,
    // which will cause the corresponding `peer_session` to trigger a disconnect, so
    // remove that `peer_session` here.
    if(download.is_exclusive() && (download.peers().size() == 1))
    {
        // If there is only a single uploader and we're still connected to peer,
        // find its matching `peer_session` and if it's disconnected because of the
        // bad piece, erase it.
        auto it = std::find_if(peer_sessions_.begin(), peer_sessions_.end(),
            [peer_id = download.peers()[0].id](const auto& session)
            { return session->remote_endpoint() == peer_id; });
        assert(it != peer_sessions_.end());
        auto& session = *it;
        // `session` may not be stopped as it may be exempt from the usual parole rules.
        if(session->is_stopped())
        {
            on_peer_session_finished(*session);
            peer_sessions_.erase(it);
        }
    }
    // TODO verify whether to make this dependent on more granular conditions
    has_state_changed_ = true;
}

inline void torrent::on_download_complete()
{
    info_.state[torrent_info::seeding] = true;
    info_.state[torrent_info::end_game] = false;
    info_.download_finished_time = cached_clock::now();
    log(log_event::download, log::priority::high, "download complete in %lli seconds",
        to_int<seconds>(info_.download_finished_time - info_.download_started_time));
    // Now that we're seeders we want to compare the upload rate of peers to rank them.
    // TODO once we support more algorithms we have to make this a conditional
    unchoke_comparator_ = &torrent::choke_ranker::upload_rate_based;
    // If we downloaded every piece in torrent we can announce to tracker that we have
    // become a seeder (otherwise we wouldn't qualify as a seeder in the strict sense,
    // I think but TODO maybe this is not true).
    if(info_.num_downloaded_pieces == info_.num_pieces)
    {
        announce(tracker_request::completed);
    }
    // Since we have become a seeder, and if any of our peers were seeders, they were
    // disconnected, so clean up those finished sessions.
    if(info_.num_seeders > 1) { remove_finished_peer_sessions(); }
    alert_queue_.emplace<download_complete_alert>(get_handle());
    if(info_.settings.stop_when_downloaded)
    {
        log(log_event::download, log::priority::high,
            "stopping download due to completion");
        stop();
    }
}

template<typename... Args>
void torrent::log(const log_event event, const char* format, Args&&... args) const
{
    log(event, log::priority::normal, format, std::forward<Args>(args)...);
}

template<typename... Args>
void torrent::log(const log_event event, const log::priority priority,
    const char* format, Args&&... args) const
{
#ifdef TIDE_ENABLE_LOGGING
    const auto header = [event]() -> std::string
    {
        switch(event)
        {
        case log_event::update: return "UPDATE";
        case log_event::download: return "DOWNLOAD";
        case log_event::upload: return "UPLOAD";
        case log_event::disk: return "DISK";
        case log_event::tracker: return "TRACKER";
        case log_event::choke: return "CHOKE";
        case log_event::peer: return "PEER";
        default: return "";
        }
    }();
    log::log_torrent(id(), std::move(header),
        util::format(format, std::forward<Args>(args)...), priority);
#endif // TIDE_ENABLE_LOGGING
}

#undef SHARED_THIS

} // namespace tide
