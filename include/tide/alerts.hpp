#ifndef TIDE_ALERTS_HEADER
#define TIDE_ALERTS_HEADER

#include "time.hpp"
#include "types.hpp"
#include "metainfo.hpp"
#include "disk_io.hpp"
#include "torrent_info.hpp"
#include "torrent_handle.hpp"
#include "peer_session.hpp"

#include <type_traits>

namespace tide {

/** This is the interface all alerts must implement. */
struct alert
{
    enum category
    {
        error = 1,
        warning = 2,
        // Many operations user requests run asynchronously (e.g. allocating a torrent)
        // but invoking a user provided handler is not feasible due to engine running on
        // a different thread, so all such results are passed as an alert.
        async_result = 4,
        storage = 8,
        torrent = 16,
        tracker = 32,
        peer = 64,
        dht = 128,
        progress = 256,
        stats = 512,
        performance = 1024,
    };

    // The time this alert was posted.
    time_point time;

    alert() : time(cached_clock::now()) {}
    alert(const alert&) = default;
    alert& operator=(const alert&) = default;
    alert(alert&&) = default;
    alert& operator=(alert&&) = default;
    virtual ~alert() {}

    virtual int category() const noexcept = 0;
};

/** Generic alert to report errors of asynchronous operations. */
struct error_alert : public alert
{
    std::error_code error;
    explicit error_alert(std::error_code ec) : error(ec) {}
    int category() const noexcept override { return category::error; }
};

// -- individual torrent related alerts --

/** Base class for all torrent related alerts. */
struct torrent_alert : public alert
{
    torrent_handle handle;
    explicit torrent_alert(torrent_handle h) : handle(h) {}
    int category() const noexcept override { return torrent; }
};

struct torrent_added_alert final : public torrent_alert
{
    explicit torrent_added_alert(torrent_handle h) : torrent_alert(h) {}
};

struct torrent_removed_alert final : public torrent_alert
{
    explicit torrent_removed_alert(torrent_handle h) : torrent_alert(h) {}
};

struct torrent_stopped_alert final : public torrent_alert
{
    explicit torrent_stopped_alert(torrent_handle h) : torrent_alert(h) {}
};

struct torrent_started_alert final : public torrent_alert
{
    explicit torrent_started_alert(torrent_handle h) : torrent_alert(h) {}
};

struct torrent_stats_alert final : public torrent_alert
{
    explicit torrent_stats_alert(torrent_handle h) : torrent_alert(h) {}
    int category() const noexcept override
    { return torrent_alert::category() | category::stats; }
};

struct download_complete_alert final : public torrent_alert
{
    explicit download_complete_alert(torrent_handle h) : torrent_alert(h) {}
};

struct torrent_seed_ratio_reached_alert final : public torrent_alert
{
    explicit torrent_seed_ratio_reached_alert(torrent_handle h) : torrent_alert(h) {}
};

struct file_complete_alert final : public torrent_alert
{
    file_index_t file_index;
    explicit file_complete_alert(torrent_handle h, file_index_t f)
        : torrent_alert(h)
        , file_index(f)
    {}
};

// -- tracker related alerts --

struct tracker_alert : public alert
{

};

// -- individual peer related alerts --

/** Base class for peer related alerts. */
struct peer_alert : public alert
{
    tcp::endpoint endpoint;
    peer_id_t peer_id;
    peer_alert(tcp::endpoint ep, peer_id_t pid) : endpoint(std::move(ep)), peer_id(pid) {}
    int category() const noexcept override { return peer; }
};

struct peer_stats_alert final : public peer_alert
{
    //peer_stats stats;
    peer_stats_alert(tcp::endpoint ep, peer_id_t pid/*, peer_stats s*/)
        : peer_alert(std::move(ep), pid)
        //, stats(std::move(s))
    {}

    int category() const noexcept override
    { return peer_alert::category() | category::stats; }
};

// -- storage related alerts --

/** Base class for storage related alerts. */
struct storage_alert : public alert
{
    int category() const noexcept override { return storage; }
};

/*
struct disk_io_failure_alert : public storage_alert, public error_alert
{
    int category() const noexcept override
    { return storage_alert::category() | error_alert::category(); }
};

struct too_many_disk_io_failures_alert : public disk_io_failure_alert {};
*/

/*
struct disk_io_stats final : public stats_alert
{
    disk_io::stats stats;
    disk_io_stats(disk_io::stats s) : stats(std::move(s)) {}
};
*/

struct metainfo_parsed_alert final : public alert
{
    class metainfo metainfo;
    metainfo_parsed_alert(class metainfo m) : metainfo(std::move(m)) {}
    int category() const noexcept { return async_result; }
};

/** Convenience method to cast an alert to the specified one. */
template<typename T>
T* alert_cast(alert* a)
{
    static_assert(std::is_base_of<alert, T>::value,
        "alert_cast may only be used with types inheriting from alert");

    if(a && dynamic_cast<T*>(a)) { return dynamic_cast<T*>(a); }
    return nullptr;
}

} // tide

#endif // TIDE_ALERTS_HEADER
