#ifndef TIDE_GLOBAL_SETTINGS_HEADER
#define TIDE_GLOBAL_SETTINGS_HEADER

#include "extensions.hpp"
#include "types.hpp"
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

    // Pick UDP trackers over HTTP trackers, even if HTTP trackers have a higher
    // priority in the metainfo's announce-list.
    bool prefer_udp_trackers = false;

    // The initial port to which the torrent engine will attempt to bind. If met with
    // failure or no port is specified, it falls back to the OS provided random port.
    uint16_t listener_port;

    // Since UDP is an unreliable protocol, we have to guard against lost or corrupt
    // packets. Thus a number of retries is allowed for each announce and scrape request.
    // If a response is not received after 15 * 2 ^ n seconds, we retransmit the request,
    // where n starts at 0 and is increased up to this value, after every retransmission. 
    int max_udp_tracker_timeout_retries = 4;

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

    // The number of seconds following the second attempt (the first attempt is always
    // given 15 seconds to complete) of a tracker announce or scrape after which the
    // tracker is considered to have timed out and the connection is dropped.
    seconds tracker_timeout{60};

    // This is the granularity at which statistics of a torrent are sent to the user.
    // Note that user may manually request statistics of a certain torrent or even
    // peer_session at arbitrary intervals.
    // TODO should we support millisecond granularity?
    seconds stats_aggregation_interval{1};

    // This is the amount of time between the torrent engine's event loop which, among
    // other things, is responsible for meting out bandwidth quota to peers. A lower
    // value results in more accurate quota distribution, while a higher value will likely
    // perform better on slower machines.
    // Should be between 100 and 1000.
    milliseconds bandwidth_distribution_interval{150};

    enum class choking_algorithm
    {
        // In leech mode, it chooses the peers that had the best upload rate in the
        // past 20 seconds (or according to some weighed running average), while in
        // seed mode peers with the best download rates are preferred, which helps
        // fast file distribution.
        rate_based
    };

    choking_algorithm choking_algorithm;
};

struct disk_io_settings
{
    // The number of hardware threads to use for disk io related operations. The default
    // is the number of cores or some number derived from it.
    int max_disk_io_threads;

    // This is the upper bound on the number of blocks that disk_io will keep in memory
    // until it can be saved. This is for the contingency in which blocks cannot be
    // saved to disk due to some error, in which case they'll remain in memory. But to
    // not let this spiral out of control, this upper bound is enforced, after which
    // blocks are dropped (necessitating a re-download). The default is 156MiB.
    // If the value is 0 or below, the upper bound is not enforced.
    // TODO maybe combine this and read cache capacity as a single upper bound on the
    // total blocks in memory
    int max_buffered_blocks = 10'000;

    // The upper bound of the piece cache in number of 16KiB blocks. The write buffer
    // (which is basically a write cache, deferring writes as much as possible) is
    // counted here as well. A value of -1 means that this is automatically set by
    // tide based on the available memory in client's system.
    int read_cache_capacity = -1;

    // This determines how many blocks should be read ahead, including the originally
    // requested block. If it's 0, it disables read ahead and only one block will be
    // pulled in a time. This is not recommended, but might help to conserve memory.
    int read_cache_line_size = 4;

    // The number of contiguous 16KiB blocks that are buffered before written to disk.
    // If the piece is smaller than this, the number of blocks in piece replaces this
    // value.
    // If blocks in a piece's write buffer are not contiguous, their numbers might
    // exceed this value. To avoid memory inflation and other performance penalties,
    // disk_io will choose a suitable upper bound (usually betweeen this value and
    // receive_buffer_size) after which blocks are flushed to disk no matter what.
    //
    // NOTE: this value times 16KiB must never exceed receive_buffer_size, as the blocks
    // being written to disk are counted as part of peer_session's receive buffer, which
    // means that the write cache would never fill up as peer_session would not be able
    // to receive more blocks, effectively stalling the download. For this reason if
    // this condition is not met, it will be overwritten by a value deemed fit by engine.
    //
    // NOTE: write_buffer_capacity is included here for data organization purposes,
    // but any user set value is disregarded as engine calculates this as a function of
    // write_cache_line_size and receive_buffer_size.
    int write_cache_line_size = 4;
    int write_buffer_capacity;

    // This enforces an upper bound on how long blocks may stay in memory. This is to
    // avoid lingering blocks, which may occur if the client started downloading a piece
    // from the only peer that has it, then disconnected.
    seconds write_buffer_expiry_timeout{5 * 60};

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

    // The extensions this client wishes to support.
    extensions::flags extensions = {extensions::fast};

    // The number of seconds we should wait for a peer (regardless of the last sent
    // message type) before concluding it to have timed out and closing the connection.
    seconds peer_timeout{60};

    // This is the number of seconds we wait for establishing a connection with a peer.
    // This should be lower than peer_timeout_sec, because until this peer is not
    // connected it takes up space from other potential candidates.
    seconds peer_connect_timeout{60};

    // The number of outstanding block requests peer is allowed to have at any given
    // time. If peer exceeds this number, all subsequent requests are rejected until the
    // number of outstanding requests drops below this limit.
    int max_incoming_request_queue_size;

    // This is the number of outstanding block requests to peer we are allowed to have.
    int max_outgoing_request_queue_size = 50;
    int min_outgoing_request_queue_size = 4;

    // The number of attempts we are allowed to make when connecting to a peer.
    int max_connection_attempts = 5;

    // Upper bounds for the send and receive buffers. It should be set large if memory
    // can be spared for better performance (at least 3 blocks (16KiB)), though note
    // that the receive buffer cannot be less than the block size (16KiB) as we wouldn't
    // be able to receive blocks then. A value of -1 means that these are auto managed.
    //
    // NOTE: max_receive_buffer_size  must always be larger than write_cache_line_size
    // * 16KiB, see write_cache_line_size comment.
    int max_receive_buffer_size = -1;
    int max_send_buffer_size = -1;

    // If the Fast extension is enabled, a peer may receive a set of pieces, called
    // allowed fast set, that it may download even when it is choked. This is used to
    // boost peers in the incipient phase of their download where they don't have
    // any pieces.
    int allowed_fast_set_size = 10;

    // Normally the TCP/IP overhead is not included when limiting torrent bandwidth.
    // With this set, an esimate of the overhead is added to the traffic.
    bool include_ip_overhead = false;

    enum encryption_policy
    {
        // Only encrypted connections are made, incoming non-encrypted connections are
        // dropped.
        encryption_only,

        // Both encrypted and plaintext connections are allowed. If an encrypted
        // connection fails, a plaintext one is attempted.
        mixed,

        // Only non-encrypted connections are allowed.
        no_encryption
    };

    encryption_policy encryption_policy = no_encryption;
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

#endif // TIDE_GLOBAL_SETTINGS_HEADER
