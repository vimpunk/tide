#ifndef TORRENT_PEER_SESSION_HEADER
#define TORRENT_PEER_SESSION_HEADER

#include "peer_session_error.hpp"
#include "block_disk_buffer.hpp"
#include "throughput_rate.hpp"
#include "sliding_average.hpp"
#include "message_parser.hpp"
#include "bt_bitfield.hpp"
#include "send_buffer.hpp"
#include "disk_buffer.hpp"
#include "block_info.hpp"
#include "flag_set.hpp"
#include "socket.hpp"
#include "units.hpp"
#include "time.hpp"

#include <system_error>
#include <vector>
#include <memory>

#include <asio/io_service.hpp>

namespace tide {

class peer_session_settings;
class bandwidth_controller;
class disk_read_buffer;
class piece_download;
class torrent_info;
class piece_picker;
class disk_io;

/**
 * NOTE: even though peer_session is only handled by its corresponding torrent (i.e.
 * unique_ptr semantics), it must be stored in a shared_ptr as it uses shared_from_this
 * in the handlers passed to async operations in order to prolong its lifetime until
 * the operations complete (otherwise the handlers would refer to invalid memory).
 */
class peer_session : protected std::enable_shared_from_this<peer_session>
{
public:

    /**
     * These are the fields that we get from torrent either through the constructor when
     * this is an outbound connection, or when we attach to a torrent after the peer
     * handshake when this is an inbound connection. To test whether we succesfully
     * attached to a torrent, torrent_info must not be nullptr (the others may be, as
     * optimizations may be employed, such as the omission of shared_downloads when
     * seeding, but torrent_info must be present).
     */
    struct torrent_specific_args
    {
        std::shared_ptr<class piece_picker> piece_picker;
        std::shared_ptr<std::vector<std::shared_ptr<piece_download>>> shared_downloads;
        std::shared_ptr<class torrent_info> torrent_info;
        std::function<void(piece_download&, bool)> piece_completion_handler;
    };

    /** At any given time, peer_session is in one of the below states. */
    enum class state_t
    {
        // This state indicates that peer_session is or has been disconnected, or never
        // started, so it's save to destruct it.
        disconnected,
        connecting,
        in_handshake,
        // This state is optional, it is used to verify that the bitfield exchange
        // occurrs after the handshake and not later. It is set once the handshake
        // is done and changed to connected as soon as we receive the bitfield or
        // the the first message that is not a bitfield. Any subsequent bitfield
        // messages are rejected and the connection is dropped.
        bitfield_exchange,
        // This is the state in which the session is when it is ready to send and
        // receive regular messages, i.e. when the up/download actually begins.
        connected,
        // If peer_session is gracefully disconnected, we wait for all pending async
        // operations to complete before closing the connection. Otherwise we don't for
        // async ops, we immediately transition to disconnected, skipping this one.
        disconnecting
    };

private:

    enum class op_t : uint8_t
    {
        // Whether we're currently reading to or writing from socket. Both operations
        // last until their handles are invoked. This is used to block access to the
        // socket to accumulate work to be done into batches in order to amortize
        // the costs of context switching required to do these operations.
        send,
        receive,
        disk_read,
        disk_write,
        // To keep up with the transport layer's slow start algorithm (which unlike
        // its name increases window size quite quickly), a peer_session starts out
        // in slow start as well, wherein m_info.best_request_queue_size is increased
        // by every time one of our requests got served.
        slow_start,
        max
    };

    flag_set<op_t, op_t::max> m_op_state;

    // For now socket is tcp only but this will be a generic stream socket (hence the 
    // pointer), which then may be tcp, udp, ssl<tcp>, socks5 etc
    std::unique_ptr<tcp::socket> m_socket;

    // We try to fill up the send buffer as much as possible before draining it to
    // socket to minimize the number of context switches (syscalls) by writing to the
    // socket.
    send_buffer m_send_buffer;

    // We receive from socket directly into message_parser's internal buffer.
    message_parser m_message_parser;

    // The disk thread used for async piece fetches and writes.
    disk_io& m_disk_io;

    // We may be rate limited so we must always request upload and download bandwidth
    // quota before proceeding to do either of those functions.
    bandwidth_controller& m_bandwidth_controller;

    // These are the tunable parameters that the user provides.
    const peer_session_settings& m_settings;

    // NOTE: if this starts as an incoming connection, we won't have this field until we
    // finished the handshake and attached ourselves to a torrent.
    std::shared_ptr<piece_picker> m_piece_picker;

    // We aggregate all peer's stats in a torrent wide torrent_info instance.
    //
    // NOTE: if this starts as an incoming connection, we won't have this field until we
    // finished the handshake and attached ourselves to a torrent.
    // It must never be null. If it is, disconnect immediately.
    std::shared_ptr<torrent_info> m_torrent_info;

    // This is where all current active piece downloads (from any peer in torrent)
    // can be accessed.
    //
    // NOTE: if this starts as an incoming connection, we won't have this field until we
    // finished the handshake and attached ourselves to a torrent. It's also null if
    // we're seeding (no point in having it when we're not downloading).
    std::shared_ptr<std::vector<std::shared_ptr<piece_download>>> m_shared_downloads;

    // These are the active piece downloads in which this peer_session is participating.
    std::vector<std::shared_ptr<piece_download>> m_downloads;

    // Our pending requests that we sent to peer. This is emptied if we are choked, as
    // in that case we don't expect outstanding requests to be served. If we receive a
    // block that is not in this list, we dump it as unexpected. If we receive a block
    // that is in the list, it is removed from the list.
    std::vector<pending_block> m_sent_requests;

    // The requests we got from peer which are are stored here as long as we can cancel
    // them, that is, until they are not sent (queued up in disk_io or elsewhere). If
    // the block is transmitted, it is removed from this list.
    std::vector<block_info> m_received_requests;

    // If peer is on parole, it may only download a single piece in which no other peer
    // may participate. This is because normally multiple blocks are downloaded from
    // multiple peers and if one turns out to be bad (and more peers helped to complete
    // it), we have no way of determining which peer misbehaved. So as a result all are
    // suspected and each is assigned a "parole piece" which only this peer downloads.
    // The result of this download determines the guilt of this peer.
    // If peer_session is destructed without having the chance to finish this piece,
    // the download is placed into m_downloads, letting others finish it. This has
    // the risk of putting another peer on parole if this one sent us corrupt pieces,
    // so we may want to discard the piece as is (TODO).
    std::unique_ptr<piece_download> m_parole_download;

    /**
     * This is used for internal bookkeeping information and statistics about a peer.
     * For external stats reporting see stats or detailed_stats.
     */
    struct info
    {
        // Peer's 20 byte BitTorrent id.
        peer_id_t peer_id;

        // A string representing the peer's software, if available (left empty if peer
        // could not be identified).
        std::string client;

        // These are the extensions peer supports.
        std::array<uint8_t, 8> extensions;

        // All pieces peer has.
        bt_bitfield available_pieces;

        tcp::endpoint local_endpoint;
        tcp::endpoint remote_endpoint;

        // The timepoints at which events necessary for business logic occur are
        // recorded. All of these values are only estimates, as they are updated from a 
        // central cached timepoint updated around every 100ms.

        time_point connection_started_time;
        time_point connection_established_time;

        time_point last_send_time;
        time_point last_receive_time;

        time_point last_outgoing_choke_time;
        time_point last_incoming_choke_time;

        time_point last_outgoing_unchoke_time;
        time_point last_incoming_unchoke_time;

        time_point last_outgoing_interest_time;
        time_point last_incoming_interest_time;

        time_point last_outgoing_uninterest_time;
        time_point last_incoming_uninterest_time;

        time_point last_outgoing_request_time;
        time_point last_incoming_request_time;

        time_point last_outgoing_block_time;
        time_point last_incoming_block_time;

        // TODO if more flags are added, consider using flag_set (the reason it's not
        // used now and neither are bitfields is because the initial values here are
        // important and might be error prone otherwise)
        bool am_choked = true;
        bool am_interested = false;
        bool is_peer_choked = true;
        bool is_peer_interested = false;

        // Peer is on parole if it participated in a download that resulted in a
        // corrupt piece. Unless the peer was the sole contributor to this piece;
        // the culprit cannot be determined, so each participant goes on parole;
        // which means that in the next download
        bool is_peer_on_parole = false;

        // If a peer does not manage to serve our request within the timeout limit;
        // it is marked and fewer requests are made subsequently.
        bool has_peer_timed_out = false;

        // If it's an outgoing connection, we initiated it, otherwise peer did.
        bool is_outbound;

        // Peer is seeding (whether we're a seeder is already recorded in
        // torrent_info).
        bool is_peer_seed;

        // peer_session may be restarted (reconnected to peer) an arbitrary number of
        // times, but apart from the first time, in which case peer_session may be
        // outbound or inbound, whenever we reconnect, the connection is always
        // outbound. This field is used to make sure that we don't accidentally start
        // the session as inbound when reconnecting.
        // TODO this is cludgey, find a nicer solution
        bool was_started_before = false;

        //bool is_rc4_encrypted;

        // The total number of piece bytes exchanged with this peer. Does not include
        // protocol overhead (both BitTorrent protocol and TCP/IP protocol).
        // Note that it also includes pieces that later turned out to be invalid and had
        // to be wasted. For the valid downloaded bytes, see total_verified_piece_bytes.
        int64_t total_downloaded_piece_bytes = 0;
        int64_t total_uploaded_piece_bytes = 0;

        // The total number of all bytes, excluding the underlying network protocol 
        // overhead, exchaned with this peer (i.e. total_piece_{up,down}loaded +
        // BitTorrent protocol overhead).
        int64_t total_downloaded_bytes = 0;
        int64_t total_uploaded_bytes = 0;

        // This field is only updated once the piece has been fully downloaded and its
        // verified. It should not be used as gauge download speed.
        int64_t total_verified_piece_bytes = 0;

        // If we receive a piece that we already have, this is incremented.
        int64_t total_wasted_bytes = 0;

        // The number of bytes this peer is allowed to send and receive until it is
        // allotted more or requests more if it runs out.
        int send_quota = 0;
        int receive_quota = 0;

        // The maximum number of bytes/s we are allowed to send to or receive from peer.
        // No limit is employed if the values are -1 (this is the default).
        int max_upload_rate = -1;
        int max_download_rate = -1;

        // The number of bad pieces in which this peer has participated.
        int num_hash_fails = 0;

        // If peer sends requests while it's choked this counter is increased. After 300
        // such requests, peer is disconnected.
        int num_illicit_requests = 0;

        // Record the number of unwanted blocks we receive from peer. After a few we
        // disconnect so as to avoid being flooded.
        int num_unwanted_blocks = 0;

        // After a certain number of subsequent disk read/write failures peer is
        // disconnected because it implies that there is a problem that could not be
        // fixed.
        int num_disk_io_failures = 0;

        // The request queue size (the number of blocks we requests from the peer in one
        // go, which saves us from the full round trip time between a request and a
        // block) is recalculated every time we receive a block in order to fully utilize 
        // the link, which is done by keeping approximately the bandwidth delay product 
        // number of bytes outstanding at any given time (and some more to account for
        // disk latency). Though during the start of the connection it is subject to slow 
        // start mode.
        int best_request_queue_size = 2;

        // If the number of unserved and currently served requests to peer exceeds this
        // number, further requests will be dropped. This is the same value found in
        // m_settings, unless peer' client is BitComet, in which case this is capped at
        // 50 (any further requests have been observed to be dropped by BC).
        int max_outgoing_request_queue_size;

        // The number of requests to which we haven't gotten any response.
        int num_timed_out_requests = 0;

        // The number of requests that peers hasn't served yet.
        //int download_queue_size = 0;
        // The number of requests from peer that haven't been answered yet.
        //int upload_queue_size = 0;

        int total_bytes_written_to_disk = 0;
        int total_bytes_read_from_disk = 0;

        // The number of bytes that written or are waiting to be written to and read
        // from disk.
        int num_pending_disk_write_bytes = 0;
        int num_pending_disk_read_bytes = 0;

        // The number of piece bytes we're expecting to receive from peer.
        int num_outstanding_bytes = 0;

        state_t state = state_t::disconnected;

        // The block currently being received is put here. This is used to determine
        // whether we can cancel a request, because if we're already receiving a block,
        // we can't send cancel it.
        // TODO this feels hacky
        block_info in_transit_block = invalid_block;
    };

    // Info and status regarding this peer. One instance persists throughout the session,
    // which is constantly updated but copies for stat aggregation are made on demand.
    info m_info;

    // These values are weighed running averages, the last 20 seconds having the largest
    // weight. These are strictly the throughput rates of piece byte transfers and are
    // used to compare a peer's performance agains another to determine which to unchoke.
    throughput_rate<20> m_upload_rate;
    throughput_rate<20> m_download_rate;

    // This is the average network round-trip-time (in milliseconds) between issuing a
    // request and receiving a block (note that it doesn't have to be the same block
    // since peers are not required to serve our requests in order, so this is more of
    // a general approximation).
    sliding_average<20> m_avg_request_rtt;

    // We measure the average time it takes (in milliseconds) to do disk jobs as this
    // affects the value that is picked for m_info.best_request_queue_size (counting
    // disk latency is part of a requests's full round trip time).
    sliding_average<20> m_avg_disk_write_time;

    // This is only used when connecting to the peer. If we couldn't connect by the time
    // this timer expires, the connection is aborted.
    deadline_timer m_connect_timeout_timer;

    // After expiring every few minutes (2 by default) this timer tests whether we've
    // sent any messages (m_last_send_time), and if not, sends a keep alive message
    // to keep the connection going.
    deadline_timer m_keep_alive_timer;

    // Started when we send block requests and stopped and restarted every time one of
    // the requests is served. If none is served before the timer expires, peer has
    // timed out and on_request_timeout is called. If all our requests have been
    // served in a timely manner, the timeout is not restarted after stopping it.
    deadline_timer m_request_timeout_timer;

    // If neither endpoint has become interested in the other in 10 minutes, the peer
    // is disconnected. This means that every time we are no longer interested and peer
    // is not interested, or the other way around, this timer has to be started, and
    // stopped if either side becomes interested.
    deadline_timer m_inactivity_timeout_timer;

    // This handler is given to us by torrent and is given to disk_io every time we
    // save a block. Once a piece is completed and it has been hashed and compared to 
    // the expected hash, the piece_download instance and the hash test result (true
    // meaning the piece passed) is passed to this handler for torrent to process the
    // new piece and let other peers know that we got a new piece (via 
    // announce_new_piece). It is crucial that nothing in peer_session (this) is passed
    // to disk_io as the piece completion handler, as a peer_session may be destructed
    // before the piece is completed, so torrent must be the one that invokes
    // piece_download::post_hash_result (and passing shared_from this to the handler
    // would unnecessarily prolong peer_session's lifetime).
    //
    //    [torrent]<---3:piece completion---[disk_io]
    //        |                                 A
    // 4:post hash result                       |
    // to participants                          |
    //        |                                 |
    //        V                                 |
    // [piece_download]<--.               2:save blocks
    //        |           |                     |
    //        |    1:register blocks &          |
    //        |    completion handler           |
    //        |           |                     |
    // 5:invoke handler   |                     |
    //        |           |                     |
    //        `---->[peer_session]--------------'
    //
    std::function<void(piece_download&, bool)> m_piece_completion_handler;

    // When this is an incoming connection, this peer_session must attach to a torrent
    // using this callback after peer's handshake has been received and a torrent info
    // hash could be extracted. It is not used otherwise.
    std::function<torrent_specific_args(const sha1_hash&)> m_torrent_attacher;

public:

    /**
     * Instantiate an outbound connection (when connections are made by torrent, i.e. the
     * torrent is known), but does NOT start the session or connect, that is done by
     * calling start.
     *
     * The socket must be initialized, but not opened, nor connected.
     */
    peer_session(std::unique_ptr<tcp::socket> socket,
        tcp::endpoint peer_endpoint, disk_io& disk_io,
        bandwidth_controller& bandwidth_controller,
        const peer_session_settings& settings,
        torrent_specific_args torrent_args);

    /**
     * Instantiate an inbound connection, that is, it is not known to which torrent this
     * peer belongs until the handshake is completed. The socket is already connected
     * to peer, but the session isn't formally started (because it needs to use
     * shared_from_this but that is not available in the ctor), so start has to be
     * called once the peer_session is constructed, after which the session is continued.
     *
     * The socket must be initialized, but not opened.
     *
     * The torrent_attacher handler is called after we receive peer's handshake. This is
     * used to locate the torrent to which this connection belongs. After this, we have
     * the torrent's info hash so we can send our handshake as well. If this succeeds,
     * the peer is fully connected, but if torrent_attacher doesn't return a valid
     * torrent_specific_args instance (its fields are nullptr), we know peer didn't send
     * the correct hash so the connection is closed and this peer_session may be removed.
     */
    peer_session(std::unique_ptr<tcp::socket> socket,
        tcp::endpoint peer_endpoint, disk_io& disk_io,
        bandwidth_controller& bandwidth_controller,
        const peer_session_settings& settings,
        std::function<torrent_specific_args(const sha1_hash&)> torrent_attacher);

    /**
     * NOTE: peer_session is not destructed until all outstanding asynchronous
     * operations have been cancelled or completed (depending on the stop mode), for
     * each async operation's handler owns a shared_ptr to `this`.
     */
    ~peer_session();

    /**
     * The constructor only sets up the session but does not start it, this has to be
     * done explicitly, or if the torrent has been paused (and thus all peer_sessions
     * were disconnected), this is used to attempt reconnecting to peer.
     */
    void start();

    enum class stop_mode_t
    {
        // If there are currently ongoing asynchronous operations, such as a socket send
        // or receive, we wait for them to complete. This is important when sending or
        // receiving a block, in which case no payload data is wasted. However, if
        // reading a block from disk returns after being stopped, it won't be sent. 
        // This is the recommended and default setting.
        graceful,
        // All pending network operations are aborted by calling cancel on the
        // IO objects, i.e. in transit data will be lost.
        abort
    };

    /** Disconnects peer in the specified mode. */
    void stop(const stop_mode_t stop_mode = stop_mode_t::graceful);

    /**
     * This is a light-weight representation of the most essential information about
     * a peer_session. This should be used where update of a peer's status is required
     * at constant, short intervals.
     */
    struct stats
    {
        // The unique torrent id to which this peer belongs.
        torrent_id_t torrent_id;

        // Peer's 20 byte BitTorrent id.
        peer_id_t peer_id;

        // A string representing the peer's software, if available (left empty if peer
        // could not be identified).
        std::string client;

        // This is the average network round-trip-time between issuing a request and
        // receiving a block, but it doesn't have to be the same block since peers are
        // not required to serve our requests in order, so this is more of a general
        // approximation. Also note that the timer used has a resolution of only ~100ms.
        milliseconds avg_request_rtt;

        // Latest payload (piece) upload and download rates in bytes/s.
        int upload_rate = 0;
        int download_rate = 0;

        // The highest upload and download rate recorded in this connection.
        int peak_upload_rate = 0;
        int peak_download_rate = 0;

        // The amount of actual message bytes in buffers and capacity.
        int used_send_buffer_size = 0;
        int total_send_buffer_size = 0;
        int used_receive_buffer_size = 0;
        int total_receive_buffer_size = 0;
    };

    /**
     * This practically includes every statistics collected about a peer, which means
     * it's expensive to request regularly, so it is advised to only request it when
     * user explicitly requests more info about a peer.
     TODO we inherit peer_id and client twice
     */
    struct detailed_stats : public info, public stats
    {
        // The pieces we're currently downloading from this peer (those that have been
        // fully downloaded but not yet been verified count as well).
        std::vector<piece_index_t> piece_downloads;
    };

    /**
     * When peer_session is stopped gracefully, it transitions from connected to
     * disconnecting, then finally to disconnected. If it's aborted, it transitions
     * from connected to disconnected. If one only wishes to know whether peer_session
     * is effectively finished (disconnecting or disconnected), use is_stopped.
     */
    bool is_connecting() const noexcept;
    bool is_disconnecting() const noexcept;
    bool is_disconnected() const noexcept;
    bool is_stopped() const noexcept;
    bool is_in_handshake() const noexcept;
    bool am_choked() const noexcept;
    bool am_interested() const noexcept;
    bool is_peer_choked() const noexcept;
    bool is_peer_interested() const noexcept;
    bool is_peer_on_parole() const noexcept;
    bool is_peer_seed() const noexcept;
    bool is_outbound() const noexcept;
    bool has_pending_disk_op() const noexcept;
    bool has_pending_async_op() const noexcept;

    state_t state() const noexcept;
    stats get_stats() const noexcept;
    void get_stats(stats& s) const noexcept;
    detailed_stats get_detailed_stats() const noexcept;
    void get_detailed_stats(detailed_stats& s) const noexcept;

    time_point last_outgoing_unchoke_time() const noexcept;
    time_point connection_established_time() const noexcept;

    const tcp::endpoint& local_endpoint() const noexcept;
    const tcp::endpoint& remote_endpoint() const noexcept;

    int64_t download_rate() const noexcept;
    int64_t upload_rate() const noexcept;

    /** Sends a choke message and drops serving all pending requests made by peer. */
    void choke_peer();
    void unchoke_peer();

    /**
     * This is called (by torrent) when a piece was successfully downloaded. It may
     * alter our interest in peer.
     */
    void announce_new_piece(const piece_index_t piece);

private:

    /** Initializes fields common to both constructors. */
    peer_session(std::unique_ptr<tcp::socket> socket,
        tcp::endpoint peer_endpoint, disk_io& disk_io,
        bandwidth_controller& bandwidth_controller,
        const peer_session_settings& settings);

    /** If our interest changes, sends the corresponding send_{un,}interested message. */
    void update_interest();
    bool am_seeder() const noexcept;

    /**
     * This must be called when we know that we're not going to receive previously
     * requested blocks, so that they may be requested from other peers.
     */
    void abort_our_requests();

    /**
     * Removes the handlers associated with this peer_session from all downloads in
     * which it participated, so that after destruction is complete no invalid handlers
     * remain lingering in piece_downloads.
     */
    void detach_downloads();

    // ----------------------
    // -- {dis,}connecting --
    // ----------------------

    void connect();
    void on_connected(const std::error_code& error = std::error_code());

    /** error indicates why peer was disconnected. */
    void disconnect(const std::error_code& error);

    /**
     * Just a convenience function that returns true if we are disconnecting or have
     * disconnected or if error is operation_aborted. This is used by handlers passed
     * to async operations to check if the connection has been or is being torn down. 
     * is_disconnected() alone is not sufficient here as peer_session may be gracefully 
     * disconnected, which means the connection won't be closed until all pending 
     * operations on it are run. This is ensured by giving each handler a shared_ptr to 
     * this, meaning the last handler to destruct will invoke peer_session's destructor 
     * where disconnect() is finally called.
     */
    bool should_abort(const std::error_code& error = std::error_code()) const noexcept;

    // -------------
    // -- sending --
    // -------------

    /**
     * This is the main async "cycle" for sending messages. Registers an async write
     * to socket to drain from m_send_buffer as much as our current quota allows.
     */
    void send();
    void request_upload_bandwidth();
    bool can_send() const noexcept;

    /**
     * This is the handler for send. Clears num_bytes_sent bytes from m_send_buffer,
     * handles errors, adjusts send quota and calls send to continue the cycle.
     */
    void on_sent(const std::error_code& error, size_t num_bytes_sent);
    void update_send_stats(const int num_bytes_sent) noexcept;

    // ---------------
    // -- receiving --
    // ---------------

    /**
     * Registers an asynchronous read operation on socket to read in as much as possible,
     * limited by our receive quota, into m_message_parser.
     */
    void receive();
    void request_download_bandwidth();
    bool can_receive() const noexcept;
    
    /**
     * If we don't expect piece payloads (in which case receive operations are
     * constrained by how fast we can write to disk, and resumed once disk writes
     * finished, in on_block_saved), we should always have enough space for protocol
     * chatter (non payload messages), otherwise the async receive cycle would stop,
     * i.e. there'd be noone reregistering the async receive calls.
     */
    void ensure_protocol_exchange();
    int get_num_to_receive() const noexcept;

    /**
     * Accounts for the bytes read, subtracts num_bytes_received from the send quota,
     * checks if the async_read_some operation read all available bytes and if not,
     * tries synchronously read the rest. Then it dispatches message handling.
     */
    void on_received(const std::error_code& error, size_t num_bytes_received);
    void update_receive_stats(const int num_bytes_received) noexcept;

    void adjust_receive_buffer(const bool was_choked);
    bool am_expecting_piece() const noexcept;

    /**
     * If the receive buffer is completely filled up in a receive operation, it may mean
     * that there are more bytes left in socket. This function attempts to synchronously
     * read them, if receive buffer capacity has not been reached. The number of bytes 
     * read is returned.
     */
    int flush_socket();

    // ----------------------
    // -- message handling --
    // ----------------------
    // Each message handler extracts the current message from the receive buffer,thus
    // advancing to the next message.

    /**
     * Parses messages and dispatches their handling. It also corks the socket from
     * writing until it's parsed all messages, after which the content of the send buffer
     * is flushed to socket in one.
     */
    void handle_messages();

    void handle_handshake();
    void handle_bitfield();
    void handle_keep_alive();
    void handle_choke();
    void handle_unchoke();
    void handle_interested();
    void handle_not_interested();
    void handle_have();
    void handle_request();
    void handle_cancel();
    void handle_block();

    /**
     * Depending on the request round trip time, marks peer as having timed out and
     * adjusts request queue size in accordance. If there are blocks to left to request,
     * restarts the timer otherwise cancels it.
     */
    void adjust_request_timeout();

    /**
     * Called after every block we receive, optimizes the number of blocks to request to
     * saturate the TCP downlink as best as possible.
     */
    void adjust_best_request_queue_size() noexcept;

    /**
     * Updates download rate and related statistics which affect how many requests we'll
     * issue in the future.
     */
    void update_download_stats(const int num_bytes);

    bool is_request_valid(const block_info& request) const noexcept;
    bool is_block_info_valid(const block_info& block) const noexcept;
    bool is_piece_index_valid(const piece_index_t index) const noexcept;
    bool should_accept_request(const block_info& block) const noexcept;

    /**
     * We expect blocks (i.e. this is not the same as handle_illicit_block()), but this
     * one was not in our m_sent_requests queue.
     */
    void handle_unexpected_block(const block_info& block, message msg);

    // These methods are called when the peer sends us messages that it is not allowed to
    // send (e.g. they're choked). Note: these handlers must NOT extract anything from
    // m_message_parser as that has already been done by their corresponding handle
    // functions from which they are called.

    /** If we get too many unrequested blocks, disconnect peer to avoid being flooded. */
    void handle_illicit_block();

    /**
     * This is called if the peer sends us requests even though it is choked. After a
     * few such occurences (currently 300), peer is disconnected. Every 10 requests peer
     * is choked again, because it may not have gotten our choke message.
     */
    void handle_illicit_request();

    /** Bitfield messages are only supposed to be exchanged when connecting. */
    void handle_illicit_bitfield();
    void handle_unknown_message();

    // ----------
    // -- disk --
    // ----------

    void save_block(const block_info& block_info,
        disk_buffer block_data, piece_download& piece_download);
    void on_block_saved(const std::error_code& error,
        const block_info& block, const time_point start_time);
    void on_block_read(const std::error_code& error, const block_source& block);

    /**
     * This is invoked by piece_download when the piece has been fully downloaded and
     * hashed by disk_io. This is where hash fails and parole mode is handled as well as
     * the piece_download corresponding to piece is removed from m_downloads.
     */
    void on_piece_hashed(const piece_download& download, const bool is_piece_good);

    /**
     * Once a piece has been downloaded and hashed, torrent processes it and calls the
     * handler corresponding to the hash result of each peer_session that participated
     * in the download.
     */
    void handle_valid_piece(const piece_download& download);
    void handle_corrupt_piece(const piece_download& download);

    // ---------------------
    // -- message sending --
    // ---------------------

    /**
     * This is used by public sender methods (choke_peer, announce_new_piece etc) to
     * see if we are in a state where we can send messages (not connecting or 
     * disconnected).
     */
    bool is_ready_to_send() const noexcept;

    /**
     * Each of the below methods appends its message to m_send_buffer and calls send
     * at the end, but the payload may be buffered for a while before it is written to
     * socket.
     * The first five senders simply send the message and record that they have done so.
     * Testing whether it is prudent to do so (e.g. don't send an interested message
     * if we're already interested) is done by other methods that use them.
     */
    void send_handshake();
    void send_bitfield();
    void send_keep_alive();
    void send_choke();
    void send_unchoke();
    void send_interested();
    void send_not_interested();
    void send_have(const piece_index_t piece);
    void send_request(const block_info& block);
    void send_requests();
    void send_block(const block_source& block);
    void send_cancel(const block_info& block);
    void send_port(const int port);

    /**
     * We can make requests if we're below the max number of outstanding requests
     * and we're not choked and we're interested.
     * TODO restrict requests if disk is overwhelmed
     */
    bool can_send_requests() const noexcept;

    /**
     * Either one of these is called by send_requests. Both merely add the request
     * message to the m_sent_request queue but don't send off the message. This is done
     * by send_requests, if any requests have been made in either of these functions.
     * New requests are placed in m_sent_requests.
     * The number of blocks that have been placed in the request queue are returned.
     */
    int make_requests_in_parole_mode();
    int make_requests_in_normal_mode();
    
    /**
     * Tries to pick blocks from downloads in which this peer participates.
     * New requests are placed in m_sent_requests.
     * The number of blocks that have been placed in the request queue are returned.
     */
    int continue_downloads();

    /**
     * Tries to join  piece download started by another peer, if there are any, and
     * pick blocks for those piece downloads.
     * New requests are placed in m_sent_requests.
     * The number of blocks that have been placed in the request queue are returned.
     */
    int join_download();
    std::shared_ptr<piece_download> find_shared_download();

    /**
     * Starts a new download and registers it in m_shared_downloads so that other
     * peers may join.
     * New requests are placed in m_sent_requests.
     * The number of blocks that have been placed in the request queue are returned.
     */
    int start_download();

    int num_to_request() const noexcept;

    // -------------------
    // -- timeout logic --
    // -------------------

    /**
     * The number of seconds after which we consider the request to have timed out.
     * This is always a number derived from the latest download metrics.
     */
    seconds request_timeout() const;

    /**
     * Finds the most suitable block to time out. This is usually the last block we
     * sent, since timing out the last block gives us the possibility of downloading it
     * from another peer and receiving it in time to cancel it with this peer, and by
     * the time the other blocks that were sent earlier (if any), will have a greater
     * chance of arriving, avoiding the need to time them out. However, if this is the
     * only peer that has the block, we must not time out the block.
     */
    void on_request_timeout(const std::error_code& error);
    void cancel_request_handler(const block_info& block);
    void on_connect_timeout(const std::error_code& error);
    void on_inactivity_timeout(const std::error_code& error);
    void on_keep_alive_timeout(const std::error_code& error);

    // -----------
    // -- utils --
    // -----------

    enum class log_event
    {
        connecting,
        disconnecting,
        incoming,
        outgoing,
        disk,
        invalid_message,
        parole,
        timeout,
        request
    };

    template<typename... Args>
    void log(const log_event event, const std::string& format, Args&&... args) const;

    /** Tries to detect client's software from its peer_id in its handshake. */
    void try_identify_client();

    /**
     * It guarantees to return a valid piece_download pointer, otherwise an assertion
     * is triggered.
     */
    piece_download* find_download(const piece_index_t piece) noexcept;

    class send_cork;
};

inline bool peer_session::is_ready_to_send() const noexcept
{
    return !is_disconnected() && !is_connecting();
}

inline bool peer_session::is_connecting() const noexcept
{
    return m_info.state == state_t::connecting;
}

inline bool peer_session::is_in_handshake() const noexcept
{
    return m_info.state == state_t::in_handshake;
}

inline bool peer_session::is_disconnecting() const noexcept
{
    return m_info.state == state_t::disconnecting;
}

inline bool peer_session::is_disconnected() const noexcept
{
    return m_info.state == state_t::disconnected;
}

inline bool peer_session::is_stopped() const noexcept
{
    return is_disconnecting() || is_disconnected();
}

inline bool peer_session::am_choked() const noexcept
{
    return m_info.am_choked;
}

inline bool peer_session::is_peer_choked() const noexcept
{
    return m_info.is_peer_choked;
}

inline bool peer_session::am_interested() const noexcept
{
    return m_info.am_interested;
}

inline bool peer_session::is_peer_interested() const noexcept
{
    return m_info.is_peer_interested;
}

inline bool peer_session::is_peer_on_parole() const noexcept
{
    return m_info.is_peer_on_parole;
}

inline bool peer_session::is_peer_seed() const noexcept
{
    return m_info.is_peer_seed;
}

inline bool peer_session::is_outbound() const noexcept
{
    return m_info.is_outbound;
}

inline bool peer_session::has_pending_disk_op() const noexcept
{
    return m_op_state[op_t::disk_read] || m_op_state[op_t::disk_write];
}

inline bool peer_session::has_pending_async_op() const noexcept
{
    return m_op_state[op_t::send]
        || m_op_state[op_t::receive]
        || m_op_state[op_t::disk_read]
        || m_op_state[op_t::disk_write];
}

inline peer_session::state_t peer_session::state() const noexcept
{
    return m_info.state;
}

inline time_point peer_session::last_outgoing_unchoke_time() const noexcept
{
    return m_info.last_outgoing_unchoke_time;
}

inline time_point peer_session::connection_established_time() const noexcept
{
    return m_info.connection_established_time;
}

inline const tcp::endpoint& peer_session::local_endpoint() const noexcept
{
    return m_info.local_endpoint;
}

inline const tcp::endpoint& peer_session::remote_endpoint() const noexcept
{
    return m_info.remote_endpoint;
}

inline int64_t peer_session::download_rate() const noexcept
{
    return m_download_rate.bytes_per_second();
}

inline int64_t peer_session::upload_rate() const noexcept
{
    return m_upload_rate.bytes_per_second();
}

} // namespace tide

#endif // TORRENT_PEER_SESSION_HEADER
