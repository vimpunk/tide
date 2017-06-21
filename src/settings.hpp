#ifndef TORRENT_GLOBAL_SETTINGS_HEADER
#define TORRENT_GLOBAL_SETTINGS_HEADER

#include "units.hpp"
#include "time.hpp"
#include "path.hpp"

#include <array>

namespace tide {

// all settings below, save for torrent's are universal, i.e. they apply to all
// instances rather than for each individual class. TODO make this more obvious
// using better structure. perhaps a single class for all settings should suffice
// with a separate torrent_settings class?

struct engine_settings
{
    // Setting this option will tell engine to give new torrents higher priority, i.e.
    // put them first in the torrent priority queue.
    bool enqueue_new_torrents_at_top = true;

    // Torrents without any piece transfers (protocol overhead is not counted as it's
    // negligible) are not considered when enforcing the maximum number of downloads and
    // uploads. The default is not counting these torrents as it leads to performance
    // improvements.
    bool count_slow_torrents = false;

    // If this option is enabled, the piece picker that tracks piece availability in a
    // torrent swarm and decides which pieces to download next is released once a torrent
    // beocmes a seeder. It has a drawback, though it may be considered an edge case: 
    // if the downloaded files are corrupted, and if user wants to download the torrent
    // again, the availability of all pieces has to be collected again.
    // TODO currently not implemented
    bool discard_piece_picker_on_completion = true;

    // TODO desc.
    // TODO maybe this is a per torrent setting?
    bool prefer_udp_trackers = true;

    // The initial port to which the torrent engine will attempt to bind. If met with
    // failure or no port is specified, it falls back to the OS provided random port.
    uint16_t listener_port;

    // These are the values (in bytes/s) that are used to determine slow torrents if the
    // count_slow_torrents setting is turned off.
    int slow_torrent_download_rate_threshold;
    int slow_torrent_upload_rate_threshold;

    // The total number of active peer connections in all torrents.
    int max_all_torrent_connections = 200;

    // The total number of torrents that are allowed to download.
    int max_downloads = 8;

    // The total number of torrents that are allowed to upload.
    int max_uploads = 4;

    // The maximum upload and download speeds of all torrents combined. Setting it to -1
    // means unlimited, which is the default.
    int max_upload_rate = -1;
    int max_download_rate = -1;

    // If a torrent reaches either of these values (number of seconds spent seeding,
    // upload / download ratio, time spent seeding / time spent downloading,
    // respectively), it is stopped (but not removed).
    int share_ratio_limit;
    int seed_time_ratio_limit;
    seconds seed_time_limit;

    // The number of seconds following the tracker announce after which the tracker is
    // considered to have timed out and the connection is dropped.
    seconds tracker_timeout;

    // This is the granularity at which statistics of a torrent are sent to the user.
    // Note that user may manually request statistics of a certain torrent or even
    // peer_session at arbitrary intervals.
    // Note that this value should ideally not go below 500ms as it would be prohibitive
    // in the face of many torrents.
    milliseconds stats_aggregation_interval;

    // This is the amount of time between the torrent engine's event loop which, among
    // other things, is responsible for meting out bandwidth quota to peers. A lower
    // value results in more accurate quota distribution, while a higher value will likely
    // perform better on slower machines.
    // Should be between 100 and 1000.
    milliseconds bandwidth_distribution_interval;

    // TODO add choking algorithm choices
    enum class choking_algorithm_t
    {
        // In leech mode, it chooses the peers that had the best upload rate in the
        // past 20 seconds (or according to some weighed running average), while in
        // seed mode peers with the best download rates are preferred, which helps
        // fast file distribution.
        rate_based
    };

    choking_algorithm_t choking_algorithm;

    engine_settings()
        : tracker_timeout(60)
        , stats_aggregation_interval(2000)
        , bandwidth_distribution_interval(150)
    {}
};

struct disk_io_settings
{
    // The number of hardware threads to use for disk io related operations. The default
    // is the number of cores or some number derived from it.
    int max_disk_io_threads;

    // The upper bound of the piece cache in number of 16KiB blocks. The write buffer
    // (which is basically a write cache, deferring writes as much as possible) is
    // counted here as well.
    int cache_capacity;

    // This specifies how many blocks in a piece should be bufferred before writing
    // them to disk.
    int read_cache_line_size;

    // All metadata of the application (torrent states, preferences etc) are saved here.
    // This must be specified.
    path resume_data_path;
};

/** These are the (global) default settings, but each torrent may specialize this. */
struct torrent_settings
{
    // If set to true the torrent will download pieces in order. This can be useful when
    // downloading serial media, but may result in slower overall performance.
    bool download_sequentially = false;

    // This stops the torrent (though does not remove it) when all files have been
    // fully downloaded. Take everything, give nothing back?
    bool stop_when_downloaded = false;

    // Pick UDP trackers over HTTP trackers, even if HTTP trackers have a higher
    // priority in metainfo's announce-list.
    bool prefer_udp_trackers = false;

    // The number of peers to which we upload pieces. This should probably be left at
    // the default value (4) for better performance.
    int max_upload_slots = 4;

    // The maximum number of open peer connections we'll have at any given time. Any
    // further connection attempts from peers will be dismissed after we've reached this
    // threshold.
    int max_connections = 50;

    // Leaving these at -1 means it's unlimited. Specified as the maximum number of
    // bytes that should be transferred in a second.
    int max_upload_rate = -1;
    int max_download_rate = -1;
};

/** These are settings for every peer connection. */
struct peer_session_settings
{
    // The client's name and version should come here. This will be used when contacting
    // trackers and when interacting with peers that support the extension.
    // It is 20 bytes long.
    peer_id_t client_id;

    // The number of seconds we should wait for a peer (regardless of the last sent
    // message type) before concluding it to have timed out and closing the connection.
    // The default is 2 minutes.
    // TODO rework
    seconds peer_timeout;

    // This is the number of seconds we wait for establishing a connection with a peer.
    // This should be lower than peer_timeout_sec, because until this peer is not
    // connected it takes up space from other potential candidates.
    seconds peer_connect_timeout;

    // The roundtrip time threshold in seconds under which we attempt to request whole
    // pieces instead of blocks.
    //int whole_piece_rtt_threshold_s;

    // The number of outstanding block requests peer is allowed to have at any given
    // time. If peer exceeds this number, all subsequent requests are rejected until the
    // number of outstanding requests drops below this limit.
    int max_incoming_request_queue_size;

    // This is the number of outstanding block requests to peer we are allowed to have.
    int max_outgoing_request_queue_size;

    // The number of attempts we are allowed to make when connecting to a peer.
    int max_connection_attempts;

    // Upper bounds for the send and receive buffers. It should be set large if memory
    // can be spared for better performance (at least 3 blocks (16KiB)), though note
    // that the receive buffer cannot be less than the block size (16KiB) as we wouldn't
    // be able to receive blocks then. A value of -1 means that these are auto managed.
    int max_receive_buffer_size = -1;
    int max_send_buffer_size = -1;

    // Normally the TCP/IP overhead is not included when limiting torrent bandwidth. With
    // this set, an esimate of the overhead is added to the traffic.
    bool include_ip_overhead = false;

    enum class encryption_policy_t
    {
        // TODO add encryption
        // Only encrypted connections are made, incoming non-encrypted connections are
        // not allowed.
        //encryption_only,

        // Both encrypted and plaintext connections are allowed. If an encrypted
        // connection fails, a plaintext one is attempted.
        //mixed,

        // Only non-encrypted connections are allowed.
        no_encryption
    };

    encryption_policy_t encryption_policy = encryption_policy_t::no_encryption;

    peer_session_settings()
        : peer_timeout(60)
        , peer_connect_timeout(120)
    {}
};

/**
 * Classes should only refer to their settings through their corresponding settings
 * struct (i.e. disk_io should only operate on disk_io_settings), but engine will
 * nonetheless hold onto a single settings instance for convenience.
 */
struct settings
    : public engine_settings
    , public disk_io_settings
    , public torrent_settings
    , public peer_session_settings
{};

} // namespace tide

#endif // TORRENT_GLOBAL_SETTINGS_HEADER
