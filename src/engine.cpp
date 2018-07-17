#include "string_utils.hpp"
#include "engine.hpp"
#include "system.hpp"

#include <algorithm>
#include <stdexcept>
#include <cassert>

#include <asio/post.hpp>

#include <iostream>

// Functions that have this in their signature are executed on the network thread, which
// means functions called by user must call them via `network_ios_`.
#define TIDE_NETWORK_THREAD

namespace tide {

engine::engine(settings s)
    : disk_io_(network_ios_, settings_.disk_io)
    , work_(network_ios_)
    , acceptor_(network_ios_)
    , update_timer_(network_ios_)
{
    network_thread_ = std::thread([this]
    {
        update();
        network_ios_.run();
    });
    apply_settings(std::move(s));
}

engine::~engine()
{
    if(network_thread_.joinable()) { network_thread_.join(); }
}

TIDE_NETWORK_THREAD
inline void engine::move_torrent_to_position(
        std::vector<std::shared_ptr<torrent>>& torrents, int curr_pos, const int pos)
{
    if((curr_pos == pos) || (pos < 0) || (pos >= torrents.size())) { return; }
    using std::swap;
    if(curr_pos < pos)
    {
        // Bubble up torrent to pos.
        while(curr_pos < pos)
        {
            swap(torrents[curr_pos], torrents[curr_pos+1]);
            ++curr_pos;
        }
    }
    else if(curr_pos > pos)
    {
        // Bubble down torrent to pos.
        while(curr_pos > pos)
        {
            swap(torrents[curr_pos], torrents[curr_pos-1]);
            --curr_pos;
        }
    }
}

TIDE_NETWORK_THREAD
template<typename Function>
void engine::find_torrent_and_execute(const torrent_handle& torrent, Function fn)
{
    auto it = std::find_if(leeches_.begin(), leeches_.end(),
        [&torrent](const auto& t) { return *t == torrent; });
    if(it != leeches_.end())
    {
        fn(leeches_, it);
    }
    else
    {
        it = std::find_if(seeds_.begin(), seeds_.end(),
            [&torrent](const auto& t) { return *t == torrent; });
        if(it != seeds_.end()) { fn(seeds_, it); }
    }
}

void engine::set_torrent_queue_position(const torrent_handle& torrent, const int pos)
{
    if(pos < 0) { throw std::invalid_argument("pos must be larger than 0"); }
    asio::post(network_ios_, [this, torrent, pos]
    {
        find_torrent_and_execute(torrent, [this, pos](auto& torrents, auto it)
            { move_torrent_to_position(torrents, it - torrents.begin(), pos); });
    });
}

void engine::increment_torrent_queue_position(const torrent_handle& torrent)
{
    asio::post(network_ios_, [this, torrent]
    {
        find_torrent_and_execute(torrent,
            [this](auto& torrents, auto it)
            {
                const int curr_pos = it - torrents.begin();
                move_torrent_to_position(torrents, curr_pos, curr_pos + 1);
            });
    });
}

void engine::decrement_torrent_queue_position(const torrent_handle& torrent)
{
    asio::post(network_ios_, [this, torrent]
    {
        find_torrent_and_execute(torrent,
            [this](auto& torrents, auto it)
            {
                const int curr_pos = it - torrents.begin();
                move_torrent_to_position(torrents, curr_pos, curr_pos - 1);
            });
    });
}

void engine::move_torrent_to_queue_top(const torrent_handle& torrent)
{
    asio::post(network_ios_, [this, torrent]
    {
        find_torrent_and_execute(torrent, [this](auto& torrents, auto it)
            { move_torrent_to_position(torrents, it - torrents.begin(), 0); });
    });
}

void engine::move_torrent_to_queue_bottom(const torrent_handle& torrent)
{
    asio::post(network_ios_, [this, torrent]
    {
        find_torrent_and_execute(torrent,
            [this](auto& torrents, auto it)
            {
                move_torrent_to_position(torrents,
                    it - torrents.begin(), torrents.size() - 1);
            });
    });
}

template<typename T, typename String>
void throw_if_below(const T& v, const T& min, const String& msg)
{
    if((v != values::none) && (v < min)) throw std::invalid_argument(msg);
}

template<typename T, typename String>
void throw_if_below_allow_unlimited(const T& v, const T& min, const String& msg)
{
    if((v != values::unlimited) && (v != values::none) && (v < min))
        throw std::invalid_argument(msg);
}

void engine::verify(const settings& s) const
{
    verify(s.disk_io);
    verify(s.torrent);
    verify(s.peer_session);

    throw_if_below(s.listener_port, uint16_t(1024),
        "settings::listener_port must be between 1024 and 65535 or none");
    throw_if_below(s.max_udp_tracker_timeout_retries, 0,
        "settings::max_udp_tracker_timeout_retries must be none, 0 or more");
    throw_if_below(s.slow_torrent_download_rate_threshold, 0,
        "settings::max_http_tracker_timeout_retries must be none, 0 or more");
    throw_if_below(s.slow_torrent_upload_rate_threshold, 0,
        "settings::slow_torrent_upload_rate_threshold must be none, 0 or more");
    throw_if_below(s.min_num_peers, 0,
        "settings::min_num_peers must be none, 0 or more");
    throw_if_below(s.max_active_leeches, 1,
        "settings::max_active_leeches must be none or above 0");
    throw_if_below(s.max_active_seeds, 1,
        "settings::max_active_seeds must be none or above 0");
    throw_if_below(s.max_upload_slots, 1,
        "settings::max_upload_slots must be none or above 0");
    throw_if_below(s.max_connections, 1,
        "settings::max_connections must be none or above 0");
    throw_if_below_allow_unlimited(s.max_download_rate, 1,
        "settings::max_download_rate must be unlimited, none or above 0");
    throw_if_below_allow_unlimited(s.max_upload_rate, 1,
        "settings::max_upload_rate must be unlimited, none or above 0");
    throw_if_below_allow_unlimited(s.share_ratio_limit, 1,
        "settings::share_ratio_limit must be unlimited, none or above 0");
    throw_if_below_allow_unlimited(s.share_time_ratio_limit, 1,
        "settings::share_time_ratio_limit must be unlimited, none or above 0");
}

void engine::verify(const disk_io_settings& s) const
{
    throw_if_below(s.concurrency, 1, "disk_io_settings::concurrency must be at least 1");
    throw_if_below(s.max_buffered_blocks, 0,
        "disk_io_settings::max_buffered_blocks must be at least 0");
    throw_if_below(s.read_cache_capacity, 0,
        "disk_io_settings::read_cache_capacity must be at least 0");
    throw_if_below(s.read_cache_line_size, 0,
        "disk_io_settings::read_cache_line_size must be at least 0");
    throw_if_below(s.write_cache_line_size, 0,
        "disk_io_settings::write_cache_line_size must be at least 0");
    if(s.resume_data_path.empty()) throw std::invalid_argument(
        "disk_io_settings::resume_data_path must not be empty");
}

void engine::verify(const torrent_settings& s) const
{
    throw_if_below(s.max_upload_slots, 1,
        "torrent_settings::max_upload_slots must be none or above 0");
    throw_if_below(s.max_connections, 1,
        "torrent_settings::max_connections must be none or above 0");
    throw_if_below_allow_unlimited(s.max_download_rate, 1,
        "torrent_settings::max_download_rate must be unlimited, none or above 0");
    throw_if_below_allow_unlimited(s.max_upload_rate, 1,
        "torrent_settings::max_upload_rate must be unlimited, none or above 0");
}

void engine::verify(const peer_session_settings& s, const int write_cache_line_size) const
{
    throw_if_below_allow_unlimited(s.max_incoming_request_queue_size, 10,
        "peer_session_settings::max_incoming_request_queue_size must be unlimited,"
        " none or above 10");
    throw_if_below(s.min_outgoing_request_queue_size, 0,
        "peer_session_settings::min_outgoing_request_queue_size must be 0 or above");
    // FIXME for some reason the values of max_outgoing_request_queue_size and
    // min_outgoing_request_queue_size get switched up
    throw_if_below(s.max_outgoing_request_queue_size, s.min_outgoing_request_queue_size,
        "peer_session_settings::max_outgoing_request_queue_size must be above"
        " peer_session_settings::min_outgoing_request_queue_size");
    throw_if_below(s.max_connection_attempts, 1,
        "peer_session_settings::max_connection_attempts must be above 0");
    throw_if_below(s.max_receive_buffer_size, 0x4000 * std::max(1, write_cache_line_size),
        "peer_session_settings::max_connection_attempts must be above"
        " disk_io_settings::write_cache_line_size * 16KiB (0x4000 bytes)");
    throw_if_below(s.max_send_buffer_size, 0x4000,
        "peer_session_settings::max_send_buffer_size must be at least 16KiB"
        " (0x4000 bytes)");
    // TODO check the minimum value for this
    throw_if_below(s.allowed_fast_set_size, 1,
        "peer_session_settings::allowed_fast_set_size must be at least 1");
    // TODO verify duration settings
}

void engine::fill_in_defaults(settings& s)
{
    fill_in_defaults(s.disk_io);

    using values::none;
    using values::unlimited;

    auto set_if_none = [](auto& setting, auto val) { if(setting == none) setting = val; };

    set_if_none(s.listener_port, 6666); // TODO

    set_if_none(s.max_udp_tracker_timeout_retries, 3);
    set_if_none(s.max_http_tracker_timeout_retries, 3);
    set_if_none(s.min_num_peers, 10);

    static const int default_slow_threshold = 0x4000;
    set_if_none(s.slow_torrent_download_rate_threshold, default_slow_threshold);
    set_if_none(s.slow_torrent_upload_rate_threshold, default_slow_threshold);

    set_if_none(s.max_active_leeches, 4);
    set_if_none(s.max_active_seeds, 4);
    set_if_none(s.max_upload_slots, 4);
    set_if_none(s.max_connections, 200);

    set_if_none(s.max_download_rate, unlimited);
    set_if_none(s.max_upload_rate, unlimited);

    set_if_none(s.share_ratio_limit, unlimited);
    set_if_none(s.share_time_ratio_limit, unlimited);
}

/** Attempts to query the system for RAM info and if it fails it returns an estimate. */
inline system::ram ram_status()
{
    std::error_code error;
    auto ram = system::ram_status(error);
    if(error)
    {
        // Since we weren't successful in determining the RAM size, we'll proceed
        // with sensible default values here (on the lower end, to err on the side
        // of caution).
        ram.physical_size = 1 * 1024 * 1024; // 1GiB.
        ram.physical_free_space = 0.3 * 1024 * 1024; // 0.3GiB.
    }
    return ram;
}

void engine::fill_in_defaults(disk_io_settings& s)
{
    if(s.concurrency <= 0)
        s.concurrency = 2 * std::thread::hardware_concurrency();

    system::ram ram = ram_status();
    // Make sure the value set by user does not exceed available physical RAM.
    if(s.max_buffered_blocks <= 0
       || s.max_buffered_blocks * 0x4000 >= ram.physical_size)
    {
        // Use up 10% of the available memory, or less.
        s.max_buffered_blocks = std::min(
            ram.physical_size / 10 / 0x4000,
            ram.physical_free_space / 2);
    }
    if(s.read_cache_capacity <= 0)
    {
        // Also use up 10% of the available memory for the read cache.
        s.read_cache_capacity = std::min(
            ram.physical_size / 10 / 0x4000,
            ram.physical_free_space / 2);
    }
    assert(s.read_cache_capacity > 0);

    // TODO choose better values, these are placeholders.
    if(s.read_cache_line_size < 0)
        s.read_cache_line_size = 8;
    if(s.write_cache_line_size < 0)
        s.write_cache_line_size = 8;

    // Only do this step if receive buffer has already been set.
    if(settings_.peer_session.max_receive_buffer_size > 0)
    {
        // Find a suitable value for `write_buffer_capacity`, which acts as an upper bound
        // for a piece's write cache (i.e the number of blocks buffered before flushed to
        // disk).
        const auto receive_buffer_size_in_blocks =
            settings_.peer_session.max_receive_buffer_size / 0x4000;
        s.write_buffer_capacity = util::clamp(10, s.write_cache_line_size,
            receive_buffer_size_in_blocks);
        // Try to leave as much space between the minimum value (`write_cache_line_size`)
        // and the upper bound (`write_buffer_capacity`), but don't approach the maximum
        // value (`receive_buffer_size`) too closely, lest it impair download throughput.
        // i.e.:
        // write_cache_line_size <= write_buffer_capacity < receive_buffer_size_in_blocks
        while(receive_buffer_size_in_blocks - s.write_buffer_capacity > 2)
            ++s.write_buffer_capacity;
    }

    if((s.write_buffer_expiry_timeout == seconds(0)) && (s.write_cache_line_size > 0))
        s.write_buffer_expiry_timeout = minutes(5);
}

void engine::fill_in_defaults(torrent_args& args)
{
}

void engine::apply_settings(settings s)
{
    verify(s);
    fill_in_defaults(s);
    asio::post(network_ios_, [this, s = std::move(s)]() mutable
    {
        apply_disk_io_settings_impl(std::move(s.disk_io));
        apply_torrent_settings_impl(std::move(s.torrent));
        apply_peer_session_settings_impl(std::move(s.peer_session));
        // We don't want to just assign `s` to `settings_` as the specializations of
        // `apply_settings_*` copy their respective settings, so we'd copy twice, some
        // of them potentially expensive (heap alloc).
#define COPY_FIELD(f) do { settings_.f = s.f; } while(0)
        // TODO find a less error-prone way to copy the rest of the settings
        COPY_FIELD(enqueue_new_torrents_at_top);
        if(settings_.slow_torrent_download_rate_threshold
           != s.slow_torrent_download_rate_threshold) { update_leeches(); }
        if(settings_.slow_torrent_upload_rate_threshold
           != s.slow_torrent_upload_rate_threshold) { update_seeds(); }
        COPY_FIELD(discard_piece_picker_on_completion);
        COPY_FIELD(prefer_udp_trackers);
        COPY_FIELD(max_udp_tracker_timeout_retries);
        COPY_FIELD(slow_torrent_download_rate_threshold);
        COPY_FIELD(slow_torrent_upload_rate_threshold);

        apply_max_connections_setting(s.max_connections);
        apply_max_active_leeches_setting(s.max_active_leeches);
        apply_max_active_seeds_setting(s.max_active_seeds);
        apply_max_upload_slots_setting(s.max_upload_slots);

        // At this point these values should be verified.
        assert(s.max_download_rate > 0
               || s.max_download_rate == values::none
               || s.max_download_rate == values::unlimited);
        assert(s.max_upload_rate > 0
               || s.max_upload_rate == values::none
               || s.max_upload_rate == values::unlimited);
        COPY_FIELD(max_download_rate);
        rate_limiter_.set_max_download_rate(s.max_download_rate);
        COPY_FIELD(max_upload_rate);
        rate_limiter_.set_max_upload_rate(s.max_upload_rate);

        // If any of these new values have caused some torrents to stop, the effects
        // will be enforced in the next call to `update`.
        COPY_FIELD(share_ratio_limit);
        COPY_FIELD(share_time_ratio_limit);
        COPY_FIELD(seed_time_limit);

        COPY_FIELD(tracker_timeout);
        COPY_FIELD(stats_aggregation_interval);
        if(settings_.stats_aggregation_interval == seconds(0))
            settings_.stats_aggregation_interval = seconds(1);
#undef COPY_FIELD
    });
}

TIDE_NETWORK_THREAD
void engine::apply_max_connections_setting(const int max_connections)
{
    assert(max_connections >= 0);
    int num_connections = 0;
    for(const auto& torrent : leeches_)
        num_connections += torrent->num_connected_peers();
    for(const auto& torrent : seeds_)
        num_connections += torrent->num_connected_peers();
    const int num_to_close = num_connections - max_connections;
    if(num_to_close > 0)
    {
        // We need to close some connections to conform to the new uppper bound. Start
        // by closing connections on the torrent with the smallest priority, i.e. the
        // last active torrent, and start by removing seed connections as we prioritize
        // downloads.
        for(int i = info_.num_active_seeds - 1; i >= 0; --i)
        {
            if(num_connections <= max_connections) { break; }
            assert(i < seeds_.size());
            num_connections -= seeds_[i]->close_n_connections(num_to_close);
        }
        for(int i = info_.num_active_leeches - 1; i >= 0; --i)
        {
            if(num_connections <= max_connections) { break; }
            assert(i < leeches_.size());
            num_connections -= leeches_[i]->close_n_connections(num_to_close);
        }
    }
    settings_.max_connections = max_connections;
}

TIDE_NETWORK_THREAD
void engine::apply_max_active_leeches_setting(const int max_active_leeches)
{
    info_.num_active_leeches = apply_max_active_torrents_setting(leeches_,
            info_.num_active_leeches, max_active_leeches);
    settings_.max_active_leeches = max_active_leeches;
}

TIDE_NETWORK_THREAD
void engine::apply_max_active_seeds_setting(const int max_active_seeds)
{
    info_.num_active_seeds = apply_max_active_torrents_setting(seeds_,
            info_.num_active_seeds, max_active_seeds);
    settings_.max_active_seeds = max_active_seeds;
}

TIDE_NETWORK_THREAD
int engine::apply_max_active_torrents_setting(
        std::vector<std::shared_ptr<torrent>>& torrents,
        int num_active, const int max_active)
{
    if(num_active > max_active)
    {
        // New setting does not allow as many active torrents as we currently have.
        assert(num_active <= torrents.size());
        for(auto i = max_active, n = num_active; i < n; ++i)
        {
            torrents[i]->stop();
            --num_active;
        }
    }
    else if((num_active < max_active) && (num_active < torrents.size()))
    {
        // We now can have more active torrents than we currently do.
        assert(max_active <= torrents.size());
        for(auto i = num_active, n = max_active; i < n; ++i)
        {
            torrents[i]->start();
            ++num_active;
        }
    }
    return num_active;
}

TIDE_NETWORK_THREAD
void engine::apply_max_upload_slots_setting(const int max_upload_slots)
{
    // TODO how to distribute upload slots? prefer priority torrents (those at the front
    // of leeches_), or distribute equally?
}

void engine::apply_disk_io_settings(disk_io_settings s)
{
    verify(s);
    fill_in_defaults(s);
    asio::post(network_ios_, [this, s = std::move(s)]
        { apply_disk_io_settings_impl(std::move(s)); });
}

TIDE_NETWORK_THREAD
inline void engine::apply_disk_io_settings_impl(disk_io_settings s)
{
    assert(!s.resume_data_path.empty());
    disk_io_.set_concurrency(s.concurrency);
    disk_io_.set_read_cache_capacity(s.read_cache_capacity);
    disk_io_.set_resume_data_path(s.resume_data_path);
    settings_.disk_io = std::move(s);
}

void engine::apply_torrent_settings(torrent_settings s)
{
    verify(s);
    asio::post(network_ios_, [this, s = std::move(s)]
        { apply_torrent_settings_impl(std::move(s)); });
}

TIDE_NETWORK_THREAD
inline void engine::apply_torrent_settings_impl(torrent_settings s)
{
    for_each_torrent([&s](auto& t) { t.apply_settings(s); });
    settings_.torrent = s;
}

void engine::apply_peer_session_settings(peer_session_settings s)
{
    verify(s);
    asio::post(network_ios_, [this, s = std::move(s)]
        { apply_peer_session_settings_impl(std::move(s)); });
}

TIDE_NETWORK_THREAD
inline void engine::apply_peer_session_settings_impl(peer_session_settings s)
{
    settings_.peer_session = std::move(s);
    int receive_buffer_size_in_blocks =
        settings_.peer_session.max_receive_buffer_size / 0x4000;
    if(receive_buffer_size_in_blocks == 0)
    {
        // We must be able to receive at least one full block.
        receive_buffer_size_in_blocks = 1;
        settings_.peer_session.max_receive_buffer_size = 0x4000;
    }
    if(settings_.disk_io.write_cache_line_size > receive_buffer_size_in_blocks)
    {
        // `disk_io_settings::write_cache_line_size` must not be larger than
        // `peer_session::max_receive_buffer_size`, as otherwise downloads would stall
        // (see comment in settings.hpp.). So we must shrink the write cache line.
        settings_.disk_io.write_cache_line_size = receive_buffer_size_in_blocks - 1;
    }
    if(settings_.disk_io.write_buffer_capacity - 2 <= receive_buffer_size_in_blocks)
    {
        // We need to adjust `write_buffer_capacity` to exceed `max_receive_buffer_size`.
        settings_.disk_io.write_buffer_capacity = receive_buffer_size_in_blocks + 2;
    }
}

TIDE_NETWORK_THREAD
void engine::update(const std::error_code& error)
{
    if(error)
    {
        // TODO not much we can do about these sorts of errors, can we? log, continue
    }

    // Only run the main update procedure every second, while update is invoked every
    // tenth second.
    if(++info_.update_counter % 10)
    {
        // Refill our bandwidth quota (even if it's unlimited, `rate_limiter_`
        // handles this).
        rate_limiter_.add_download_quota(settings_.max_download_rate);
        rate_limiter_.add_upload_quota(settings_.max_upload_rate);

        relocate_new_seeds();
        update_leeches();
        update_seeds();

        // TODO post engine_info stats if required.
    }

    cached_clock::update();
    ts_cached_clock::set(cached_clock::now());
    start_timer(update_timer_, milliseconds(100),
        [this](const std::error_code& error) { update(error); });
}

TIDE_NETWORK_THREAD
void engine::relocate_new_seeds()
{
    for(auto i = 0; i < leeches_.size();)
    {
        auto& torrent = leeches_[i];
        if(torrent->is_seed())
        {
            seeds_.emplace_back(std::move(torrent));
            using std::swap;
            swap(leeches_[i], leeches_[leeches_.size()-1]);
            leeches_.erase(--leeches_.end());
        }
        else ++i;
    }
}

TIDE_NETWORK_THREAD
void engine::update_leeches()
{
    int num_active_slots = settings_.max_active_leeches;
    info_.num_active_leeches = info_.num_slow_leeches = 0;
    for(auto& torrent : leeches_)
    {
        assert(torrent->is_leech());
        if(num_active_slots == 0)
        {
            // No more active slots left, stop torrents beyond this point, unless their
            // transfer rate is below the negligible threshold.
            if(torrent->is_running())
            {
                if(is_leech_slow(*torrent))
                {
                    ++info_.num_slow_leeches;
                    ++info_.num_active_leeches;
                }
                else
                {
                    torrent->stop();
                }
            }
        }
        else
        {
            if(torrent->is_stopped()) { torrent->start(); }
            // Only decrease the number of available slots if the torrent is not "slow".
            if(is_leech_slow(*torrent))
                ++info_.num_slow_leeches;
            else
                --num_active_slots;
            ++info_.num_active_leeches;
        }
    }
}

TIDE_NETWORK_THREAD
void engine::update_seeds()
{
    int num_active_slots = settings_.max_active_seeds;
    info_.num_active_seeds = info_.num_slow_seeds = 0;
    for(auto& torrent : seeds_)
    {
        assert(torrent->is_seed());
        if(num_active_slots == 0)
        {
            // No more active slots left, stop torrents beyond this point, unless their
            // transfer rate is below the negligible threshold.
            if(torrent->is_running())
            {
                if(is_seed_slow(*torrent))
                {
                    ++info_.num_slow_seeds;
                    ++info_.num_active_seeds;
                }
                else
                {
                    torrent->stop();
                }
            }
        }
        else
        {
            if(torrent->is_stopped()) { torrent->start(); }
            // Only decrease the number of available slots if the torrent is not "slow".
            if(is_seed_slow(*torrent))
                ++info_.num_slow_seeds;
            else
                --num_active_slots;
            ++info_.num_active_seeds;
        }
    }
}

TIDE_NETWORK_THREAD
inline bool engine::is_torrent_slow(const torrent& t) const noexcept
{
    if(t.is_seed())
        return is_seed_slow(t);
    else
        return is_leech_slow(t);
}

TIDE_NETWORK_THREAD
inline bool engine::is_leech_slow(const torrent& t) const noexcept
{
    return settings_.slow_torrent_download_rate_threshold != values::none
        && t.download_rate() <= settings_.slow_torrent_download_rate_threshold;
}

TIDE_NETWORK_THREAD
inline bool engine::is_seed_slow(const torrent& t) const noexcept
{
    return settings_.slow_torrent_upload_rate_threshold != values::none
        && t.upload_rate() <= settings_.slow_torrent_upload_rate_threshold;
}

template<typename Function>
void engine::for_each_torrent(Function fn)
{
    for(auto& t : leeches_) { fn(*t); }
    for(auto& t : seeds_) { fn(*t); }
}

void engine::pause()
{
    asio::post(network_ios_, [this] { for_each_torrent([](torrent& t) { t.stop(); }); });
}

void engine::resume()
{
    asio::post(network_ios_, [this] { for_each_torrent([](torrent& t) { t.start(); }); });
}

std::deque<std::unique_ptr<alert>> engine::alerts()
{
    return alert_queue_.extract_alerts();
}

void engine::parse_metainfo(const path& path)
{
    asio::post(network_ios_, [this, path]
    {
        disk_io_.read_metainfo(path,
            [this](const std::error_code& error, metainfo m)
            {
                if(error)
                    alert_queue_.emplace<error_alert>(error);
                else
                    alert_queue_.emplace<metainfo_parsed_alert>(std::move(m));
            });
    });
}

void engine::add_torrent(torrent_args args)
{
    verify(args);
    fill_in_defaults(args);
    asio::post(network_ios_, [this, args = std::move(args)]
    {
        const bool start_in_paused = args.start_in_paused;
        const torrent_id_t torrent_id = next_torrent_id();
        // `torrent` calls `disk_io::allocate_torrent` so we don't have to here.
        auto torrent = std::make_shared<tide::torrent>(torrent_id, network_ios_,
            disk_io_, rate_limiter_, settings_, info_, get_trackers(args.metainfo),
            endpoint_filter_, alert_queue_, std::move(args));
        if(settings_.enqueue_new_torrents_at_top)
        {
            leeches_.insert(leeches_.begin(), torrent);
            if(!start_in_paused) { torrent->start(); }
        }
        else
        {
            leeches_.emplace_back(torrent);
        }
        alert_queue_.emplace<torrent_added_alert>(torrent->get_handle());
        // Adding a new torrent might have increased the number of active leeches beyond
        // the limit, so we'll need to update `leeches_`.
        update_leeches();
    });
}

void engine::verify(torrent_args& args) const
{
    // TODO this is mostly a rough outline just to have something for the time being
    if(args.metainfo.source.empty())
        throw std::invalid_argument("torrent_args::metainfo must not be empty");
    if(args.save_path.empty())
        throw std::invalid_argument("torrent_args::path must not be empty");

    // FIXME this doesn't work for some reason
    const auto is_tracker_url_valid = [](const auto& url)
    {
        return util::starts_with(url, "udp://")
            || util::starts_with(url, "http://")
            || util::starts_with(url, "https://");
        // TODO the full url needs to be tested
    };

    for(const auto& tracker : args.metainfo.announce_list)
    {
        if(!is_tracker_url_valid(tracker.url)) throw std::invalid_argument(
            "metainfo::announce_list[i] url must be valid");
    }

    if((args.metainfo.announce_list.empty() && args.metainfo.announce.empty())
       || !is_tracker_url_valid(args.metainfo.announce))
    {
        assert(util::starts_with("http://a.com", "http://"));
        std::cout << "invalid metainfo: "
            << std::string(args.metainfo.announce.begin(), args.metainfo.announce.end())
            << '\n';
        throw std::invalid_argument("no valid announce url in metainfo");
    }

    if(args.save_path.empty() || !system::exists(args.save_path)) // `exists` throws
        throw std::invalid_argument("torrent_args::save_path must be valid");
}

TIDE_NETWORK_THREAD
inline torrent_id_t engine::next_torrent_id() noexcept
{
    static torrent_id_t s_id = 0;
    return s_id++;
}

TIDE_NETWORK_THREAD
std::vector<tracker_entry> engine::get_trackers(const metainfo& metainfo)
{
    // Announce may be the same as one of the entries in announce-list, so check.
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
            // At this point tracker urls must be valid.
            if(util::is_udp_tracker(tracker.url))
            {
                entry.tracker = std::make_shared<udp_tracker>(
                    network_ios_, tracker.url, settings_);
                trackers.emplace_back(std::move(entry));
            }
            else if(util::is_http_tracker(tracker.url))
            {
                entry.tracker = std::make_shared<http_tracker>(
                    network_ios_, tracker.url, settings_);
                trackers.emplace_back(std::move(entry));
            }
            // Add new tracker to the engine's tracker collection as well.
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
