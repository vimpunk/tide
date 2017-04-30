#ifndef TORRENT_GLOBAL_SETTINGS_HEADER
#define TORRENT_GLOBAL_SETTINGS_HEADER

#include <string>
#include <array>

struct torrent_engine_settings
{
    // The client's name and version should come here. This will be used when contacting
    // trackers and when interacting with peers that support the extension.
    // It must be 20 bytes long.
    std::array<char, 20> client_id;

    // This is the ip address that will be used when contacting trackers. Omitted if
    // not specified.
    std::string announce_ip;

    // Normally the TCP/IP overhead is not included when limiting torrent bandwidth. With
    // this set, an esimate of the overhead is added to the traffic.
    bool should_include_ip_overhead = false;

    // Torrents without any piece transfers (protocol overhead is not counted as it's
    // negligible) are not considered when enforcing the maximum number of downloads and
    // uploads. The default is not counting these torrents as it leads to performance
    // improvements.
    bool should_count_slow_torrents = false;

    // These are the values (in bytes/s) that are used to determine slow torrents if the
    // should_count_slow_torrents setting is turned off.
    int inactive_torrent_down_threshold;
    int inactive_torrent_up_threshold;

    // The number of seconds following the tracker announce after which the tracker is
    // considered to have timed out and the connection is dropped.
    int tracker_timeout_s = 60;

    // The initial port to which the torrent engine will attempt to bind. If met with
    // failure, it falls back to the OS provided random port.
    int listener_port;

    // The total number of active peer connections.
    int max_connections = 200;

    // The total number of torrents that are allowed to download.
    int max_downloads = 8;

    // The total number of torrents that are allowed to upload.
    int max_uploads = 4;

    // The maximum upload and download speeds of all torrents combined. Setting it to -1
    // means unlimited, which is the default.
    int max_up_speed = -1;
    int max_down_speed = -1;

    // If a torrent reaches either of these values (number of seconds spent seeding,
    // upload / download ratio, time spent seeding / time spent downloadint,
    // respectively), it is stopped.
    int seed_time_limit_s;
    int share_ratio_limit;
    int seed_time_ratio_limit;

    // This is the amount of time between the torrent engine's event loop which, among
    // other things, is responsible for meting out bandwidth quota to peers. A lower
    // value results in more accurate quota distribution, while a higher value will likely
    // perform better on slower machines.
    // Should be between 100 and 1000.
    int bandwidth_distribution_interval_ms = 150;

    // TODO choking algorithm choice
};

struct disk_io_settings
{
    // The number of hardware threads to use for disk io related operations. The default
    // is the number of cores or some number derived from it.
    int max_disk_io_threads;

    // The upper bound of the piece cache in bytes.
    int64_t cache_capacity;

    // This is the path all torrents will be saved by default.
    std::string default_save_path;

    // All metadata of the application (resume states, preferences etc) are saved here.
    std::string app_metadata_path;
};

struct torrent_settings
{
    // If set to true the torrent will download pieces in order. This can be useful when
    // downloading media, but will almost certainly result in poorer performance.
    bool should_download_sequentially = false;
};

struct peer_session_settings
{
    // The number of seconds we should wait for a peer (regardless of the last sent
    // message type) before concluding it to have timed out and closing the connection.
    // The default is 2 minutes.
    int peer_timeout_s = 120;

    // This is the number of seconds we wait for establishing a connection with a peer.
    // This should be lower than peer_timeout_sec, because until this peer is not
    // connected it takes up space from other potential candidates.
    int peer_connect_timeout_s = 60;

    // The roundtrip time threshold in seconds under which we attempt to request whole
    // pieces instead of blocks.
    //int whole_piece_rtt_threshold_s;

    // The number of outstanding block requests peer is allowed to have at any given time.
    // If peer exceeds this number, all subsequent requests are rejected until the the
    // number of outstanding requests drops below the limit.
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
};

struct settings
    : public torrent_engine_settings
    , public torrent_settings
    , public disk_io_settings
    , public peer_session_settings
{};

#endif // TORRENT_GLOBAL_SETTINGS_HEADER
