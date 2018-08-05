#ifndef TIDE_SETTINGS_HEADER
#define TIDE_SETTINGS_HEADER

#include "extensions.hpp"
#include "path.hpp"
#include "time.hpp"
#include "types.hpp"

#include <array>

namespace tide {
namespace values {

constexpr int unlimited = -1;
constexpr int none = -2;

} // values

struct disk_io_settings
{
    // The number of hardware threads to use for disk io related operations. The
    // default is the number of cores or some number derived from it.
    int concurrency = values::none;

    // This is the upper bound on the number of blocks (16KiB each) that
    // `disk_io` will keep in memory until it can be saved. This is for the
    // contingency in which blocks cannot be saved to disk due to some error, in
    // which case they'll remain in memory.
    // But to not let this spiral out of control, this upper bound is enforced,
    // after which blocks are dropped (necessitating a re-download). The default
    // is 156MiB.  If it's 0, no blocks are buffered, however, this is really
    // NOT recommended.
    int max_buffered_blocks = values::none;

    // The upper bound of the piece cache in number of 16KiB blocks. Setting it
    // to `value::none` means that this is automatically determined by tide
    // based on the available memory in client's system. Setting it to
    // 0 effectively disables caching.
    int read_cache_capacity = values::none;

    // This determines how many blocks should be read ahead, including the
    // originally requested block. If it's 0, it disables read ahead and only
    // one block will be pulled in a time. This will drastically affect download
    // performance, but may be necessary in memory constrained systems.
    int read_cache_line_size = values::none;

    // The number of contiguous 16KiB blocks that are buffered before written to
    // disk.  If the piece is smaller than this, the number of blocks in piece
    // is used instead of this value.
    // If blocks in a piece's write buffer are not contiguous, their numbers
    // might exceed this value. To avoid memory inflation and other performance
    // penalties, the implementation will choose a suitable upper bound (usually
    // betweeen this value and `receive_buffer_size`) after which blocks are
    // flushed to disk.  If this or `max_buffered_blocks` are set to 0,
    // buffering is disabled.
    //
    // NOTE: this value times 16KiB must never exceed `peer_session_settings::
    // receive_buffer_size`, as the blocks being written to disk are counted as
    // part of `peer_session`'s receive buffer, which means that the write cache
    // would never fill up as `peer_session` would not be able to receive more
    // blocks, effectively stalling the download. For this reason if this
    // condition is not met, it will be overwritten by a value deemed fit by the
    // implementation.
    //
    // NOTE: `write_buffer_capacity` is included here for data organization
    // purposes, but any user set value is disregarded as engine calculates this
    // as a function of `write_cache_line_size` and `receive_buffer_size`.
    int write_cache_line_size = 4;
    int write_buffer_capacity = values::none;

    // This enforces an upper bound on how long blocks may stay in memory. This
    // is to avoid lingering blocks, which may occur if the client started
    // downloading a piece from the only peer that has it, then disconnected.
    seconds write_buffer_expiry_timeout{minutes{5}};

    // All metadata of the application (torrent states, preferences etc) are
    // saved here.
    // This must be specified.
    path resume_data_path;
};

/** Settings pertaining to a single torrent. */
struct torrent_settings
{
    enum class choke_algorithm
    {
        // In leech mode, it chooses the peers that had the best upload rate in
        // the past 20 seconds (or according to some weighed running average),
        // while in seed mode peers with the best download rates are preferred,
        // which helps fast file distribution.
        rate_based
    };

    choke_algorithm choke_algorithm;

    // If set to true the torrent will download pieces in order. This can be
    // useful when downloading serial media, but may result in slower overall
    // performance.
    bool download_sequentially = false;

    // This stops the torrent (though does not remove it) when all files have
    // been fully downloaded. Take everything, give nothing back, eh?
    bool stop_when_downloaded = false;

    // The following fields are set and managed by the implementation if values
    // are `values::none`.

    // The number of peers to which we upload pieces. This should not be a high
    // value for better performance, unless a lot of uplink bandwidth is
    // available.
    int max_upload_slots = values::none;

    // The maximum number of open peer connections we'll have at any given time.
    // Any further connection attempts from peers will be dismissed after we've
    // reached this threshold.
    int max_connections = values::none;

    // Specified as the maximum number of bytes that should be transferred in
    // a second.
    //
    // NOTE: if any of these fields are set to other than `values::none`, they
    // overwrite their counterpart in `settings`, meaning the global rate limits
    // won't include this torrent. This can be useful when a torrent is to be
    // urgently downloaded.
    int max_download_rate = values::none;
    int max_upload_rate = values::none;
};

#define TIDE_EARLY_ALPHA_CLIENT_ID                                                     \
    {                                                                                  \
        't', 'i', 'd', 'e', '-', 'e', 'a', 'r', 'l', 'y', '-', 'a', 'l', 'p', 'h', 'a' \
    }

/** These are settings for every peer connection. */
struct peer_session_settings
{
    // The client's name and version should come here. This will be used when
    // contacting trackers and when interacting with peers that support the
    // extension.  It is 20 bytes long.
    peer_id_t client_id = TIDE_EARLY_ALPHA_CLIENT_ID;

    // The extensions this client wishes to support. See tide/flag_set.hpp to
    // see how to set flags.
    extensions::flags extensions = {extensions::fast};

    // The number of seconds we should wait for a peer (regardless of the last
    // sent message type) before concluding it to have timed out and closing the
    // connection. This value must be at least 2 minutes, for 2 minutes is
    // BitTorrent's keep-alive timeout.
    seconds peer_timeout{minutes{2}};

    // This is the number of seconds we wait for establishing a connection with
    // a peer.  This should be lower than peer_timeout_sec, because until this
    // peer is not connected it takes up space from other potential candidates.
    seconds peer_connect_timeout{20};

    // The number of outstanding block requests peer is allowed to have at any
    // given time. If peer exceeds this number, all subsequent requests are
    // rejected until the number of outstanding requests drops below this limit.
    int max_incoming_request_queue_size = 200;

    // This is the number of outstanding block requests to peer we are allowed
    // to have.
    int min_outgoing_request_queue_size = 4;
    int max_outgoing_request_queue_size = 50;

    // The number of attempts we are allowed to make when connecting to a peer.
    int max_connection_attempts = 5;

    // Upper bounds for the send and receive buffers, specified in bytes. It
    // should be set to a large value if memory can be spared for better
    // performance (at least 3 blocks (3 * 16KiB)), though note that the receive
    // buffer cannot be less than the block size (16KiB) as we wouldn't be able
    // to receive blocks then. A value of `none` means that these are determined
    // by the implementation.
    //
    // NOTE: `max_receive_buffer_size`  must always be larger than
    // `disk_io_settings:: write_cache_line_size` * 16KiB, see
    // `disk_io_settings::write_cache_line_size` comment.
    int max_receive_buffer_size = values::none;
    int max_send_buffer_size = values::none;

    // If the Fast extension is enabled, a peer may receive a set of pieces,
    // called allowed fast set, that it may download even when it is choked.
    // This is used to boost peers in the incipient phase of their download
    // where they don't have any pieces.
    int allowed_fast_set_size = 10;

    // Normally the TCP/IP overhead is not included when limiting torrent
    // bandwidth.  With this set, an esimate of the overhead is added to the
    // traffic.
    bool include_ip_overhead = false;

    enum encryption_policy
    {
        // Only encrypted connections are made, incoming non-encrypted
        // connections are dropped.
        encryption_only,

        // Both encrypted and plaintext connections are allowed. If an encrypted
        // connection fails, a plaintext one is attempted.
        mixed,

        // Only non-encrypted connections are allowed.
        no_encryption
    };

    encryption_policy encryption_policy = no_encryption;
};

struct settings
{
    // Setting this option will tell engine to give new torrents higher
    // priority, i.e.  put them first in the torrent priority queue.
    bool enqueue_new_torrents_at_top = true;

    // If this option is enabled, the piece picker that tracks piece
    // availability in a torrent swarm and decides which pieces to download next
    // is released once a torrent beocmes a seeder. It has a drawback, though it
    // may be considered an edge case: if the downloaded files are corrupted,
    // and if user wants to download the torrent again, the availability of all
    // pieces has to be collected again.
    // TODO currently not implemented
    bool discard_piece_picker_on_completion = true;

    // Pick UDP trackers over HTTP trackers, even if HTTP trackers have a higher
    // priority in the metainfo's announce-list.
    bool prefer_udp_trackers = false;

    // The port number to which the tide's listener will attempt to bind. If met
    // with failure or no port is specified, it falls back to the OS provided
    // random port, which is then assigned to this field.
    //
    // NOTE: currently this field may only be set the first time, as changing it
    // once we're bound to it leads to some complications (e.g. letting know all
    // trackers).
    uint16_t listener_port = values::none;

    // Since UDP is an unreliable protocol, we have to guard against lost or
    // corrupt packets. Thus a number of retries is allowed for each announce
    // and scrape request.
    // If a response is not received after 15 * 2 ^ n seconds, we retransmit the
    // request, where n starts at 0 and is increased up to this value, after
    // every retransmission.
    int max_udp_tracker_timeout_retries = 4;
    int max_http_tracker_timeout_retries = 4;

    // The minimum number of peers we should always have (connected and
    // unconnected).  It may be 0 or `values::none`, in which case tide will
    // choose a suitable default value.
    // TODO is this needed?
    int min_num_peers = values::none;

    // Torrents that are below a certain threshold in their total transfer rate
    // are not counted as "active" and thus are not considered when enforcing
    // the maximum number of active torrents. This allows faster torrents to be
    // active, even when they're not at the front of the queue.
    //
    // If a torrent is below these values (in bytes/s) it is considered a slow
    // torrent (upload or download) and is not counted when enforcing the max
    // active limit. If a field is set to 0 slow torrents are also counted. If
    // it's `values::none`, this value is determined by tide.
    int slow_torrent_download_rate_threshold = values::none;
    int slow_torrent_upload_rate_threshold = values::none;

    // The total number of torrents that may download and upload.
    int max_active_leeches = 4;
    int max_active_seeds = 4;

    // The total number of connections that are allowed to upload.
    int max_upload_slots = 4;

    // The total number of active peer connections in all torrents.
    int max_connections = 200;

    // The maximum upload and download speeds of all torrents combined. These
    // may be overwritten by individual torrents. See comment above `torrent`
    // below.
    int max_download_rate = values::unlimited;
    int max_upload_rate = values::unlimited;

    // A torrent is stopped (but not removed) if it reaches either of the
    // following values:
    //
    // uploaded bytes / downloaded bytes;
    int share_ratio_limit = values::unlimited;
    // time spent seeding / time spent downloading;
    int share_time_ratio_limit = values::unlimited;
    // number of seconds spent seeding.
    seconds seed_time_limit{0};

    // The number of seconds following the second attempt (the first attempt is
    // always given 15 seconds to complete) of a tracker announce or scrape
    // after which the tracker is considered to have timed out and the
    // connection is dropped.
    seconds tracker_timeout{60};

    // This is the granularity at which statistics of a torrent are sent to the
    // user.  Note that user may manually request statistics of a certain
    // torrent or even peer_session at arbitrary intervals.
    seconds stats_aggregation_interval{1};

    disk_io_settings disk_io;
    // Global default settings for all torrents, but each individual torrent's
    // settings may be customized.
    // If `max_download_rate` and/or `max_upload_rate` are other than
    // `values::none`, the same fields in `settings` are disregarded, as each
    // torrent will then employ its own upload/download rate limits.
    torrent_settings torrent;
    // Global settings for all `peer_session` instances. It is not possible to
    // customize a torrent's peer_sessions' settings, all of them refer to this
    // instance.
    peer_session_settings peer_session;
};

} // tide

#endif // TIDE_SETTINGS_HEADER
