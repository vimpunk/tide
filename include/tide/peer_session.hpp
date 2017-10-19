#ifndef TIDE_PEER_SESSION_HEADER
#define TIDE_PEER_SESSION_HEADER

#include "peer_session_error.hpp"
#include "per_round_counter.hpp"
#include "torrent_frontend.hpp"
#include "throughput_rate.hpp"
#include "sliding_average.hpp"
#include "message_parser.hpp"
#include "block_source.hpp"
#include "send_buffer.hpp"
#include "disk_buffer.hpp"
#include "block_info.hpp"
#include "extensions.hpp"
#include "flag_set.hpp"
#include "bitfield.hpp"
#include "socket.hpp"
#include "types.hpp"
#include "stats.hpp"
#include "time.hpp"
#include "log.hpp"

#include <system_error>
#include <vector>
#include <memory>

namespace asio { class io_service; }

namespace tide {

class peer_session_settings;
class bandwidth_controller;
class disk_read_buffer;
class piece_download;
class torrent_info;
class piece_picker;

/** Used to represent requests we had sent out. */
struct pending_block : public block_info
{
    time_point request_time;
    bool has_timed_out;

    pending_block(block_info b) : block_info(std::move(b)) {}
    pending_block(piece_index_t index, int offset, int length)
        : block_info(index, offset, length)
    {}
};

/**
 * NOTE: even though peer_session is only handled by its corresponding torrent (i.e.
 * unique_ptr semantics), it must be stored in a shared_ptr as it uses shared_from_this
 * in the handlers passed to async operations in order to prolong its lifetime until
 * all such operations complete (otherwise the handlers could end up referring to
 * invalid memory).
 */
struct peer_session : public std::enable_shared_from_this<peer_session>
{
    /** At any given time, peer_session is in one of the below states. */
    enum class state
    {
        // This state indicates that peer_session is or has been disconnected, or never
        // started, so it's save to destruct it.
        disconnected,
        connecting,
        handshaking,
        // This state is optional, it is used to verify that the bitfield exchange
        // occurrs after the handshake and not later. It is set once the handshake
        // is done and changed to connected as soon as we receive the bitfield or
        // the the first message that is not a bitfield. Any subsequent bitfield
        // messages are rejected and the connection is dropped.
        // If both sides support the Fast extension, then this state is mandatory, but
        // the exchanged message may be a HAVE ALL or HAVE NONE.
        piece_availability_exchange,
        // This is the state in which the session is when it is ready to send and
        // receive regular messages, i.e. when the up/download actually begins.
        connected,
        // If peer_session is gracefully stopped, we wait for all pending async
        // operations (listed in op) to complete before closing the connection.
        // This means that each async operation's callback will check whether it's the
        // last outstanding operation, and if so, it will finally disconnect peer. Note
        // that only socket and disk read writes qualify, timers need not do this.
        disconnecting
    };

private:

    enum class op : uint8_t
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
        // in slow start as well, wherein info_.best_request_queue_size is increased
        // by every time one of our requests got served.
        slow_start,
        max
    };

    flag_set<op, op::max> op_state_;

    // We try to fill up the send buffer as much as possible before draining it to
    // socket to minimize the number of context switches (syscalls) by writing to the
    // socket.
    send_buffer send_buffer_;

    // We receive from socket directly into message_parser's internal buffer.
    message_parser message_parser_;

    // For now socket is tcp only but this will be a generic stream socket (hence the 
    // pointer), which then may be tcp, udp, ssl<tcp>, socks5 etc
    std::unique_ptr<tcp::socket> socket_;

    // We may be rate limited so we must always request upload and download bandwidth
    // quota before proceeding to do either of those functions.
    bandwidth_controller& bandwidth_controller_;

    // These are the tunable parameters that the user provides.
    const peer_session_settings& settings_;

    // This is a mediator between this peer_session and its associated torrent. Vital
    // elements such as the piece_picker, torrent_info, disk_io, and piece downloads
    // shared across all peers in torrent may be accessed via this object.
    // It holds a shared_ptr to torrent.
    //
    // NOTE: if this starts as an incoming connection, we won't have this field until we
    // finished the handshake and attached ourselves to a torrent.
    // It must never be invalid, if it is, disconnect immediately.
    torrent_frontend torrent_;

    // These are the active piece downloads in which this peer_session is participating.
    std::vector<std::shared_ptr<piece_download>> downloads_;

    // Our pending requests that we sent to peer. It represents the blocks that we are
    // expecting. Thus, if we receive a block that is not in this list, it is dropped.
    // If we receive a block whose request entry is in here, the request entry is
    // removed.
    // If the Fast extension is not enabled, this is emptied when we're choked, as in
    // that case we don't expect outstanding requests to be served.
    std::vector<pending_block> outgoing_requests_;

    // The requests we got from peer which are are stored here as long as we can cancel
    // them, that is, until they are not sent (queued up in disk_io or elsewhere). If
    // the block is transmitted, it is removed from this list.
    // TODO maybe instead remove blocks once the disk_io fetch has been issued?
    std::vector<block_info> incoming_requests_;

    // If both sides of the connection use the Fast extension, peer may send us requests
    // for pieces in this set even if it's choked and vice versa. These allowed pieces
    // are stored in these sets.
    //
    // NOTE: must not interpret allowed fast pieces to mean that the peer has this piece.
    // This allows for allowed fast set exchanges in the beginning of the connection.
    std::vector<piece_index_t> incoming_allowed_set_;
    std::vector<piece_index_t> outgoing_allowed_set_;

    /**
     * This is used for internal bookkeeping information and statistics about a peer.
     * For external stats reporting see stats or detailed_stats.
     */
    struct info : public stats
    {
        // Peer's 20 byte BitTorrent id.
        peer_id_t peer_id;

        // A string representing the peer's software, if available (left empty if peer
        // could not be identified).
        std::string client;

        // These are the extensions peer supports.
        extensions::flags extensions;

        // All pieces peer has.
        bitfield available_pieces;

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

        // Since there is no central update loop upon which we could rely to gauge the
        // per-second download performance of a session (which is necessary to accurately
        // adjust the request queue size), we have to check whether at least a second has 
        // elapsed since the last time the update queue has been updated.
        time_point last_request_queue_adjust_time;

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

        // The number of bytes this peer is allowed to send and receive until it is
        // allotted more or requests more if it runs out.
        int send_quota = 0;
        int receive_quota = 0;

        // The request queue size (the number of blocks we requests from the peer in one
        // go, which saves us from the full round trip time between a request and a
        // block) is recalculated every time we receive a block in order to fully utilize 
        // the link, which is done by keeping approximately the bandwidth delay product 
        // number of bytes outstanding at any given time (and some more to account for
        // disk latency). Though during the start of the connection it is subject to slow 
        // start mode.
        int best_request_queue_size = 4;

        // If the number of unserved and currently served requests to peer exceeds this
        // number, further requests will be dropped. This is the same value found in
        // settings_, unless peer' client is BitComet, in which case this is capped at
        // 50 (any further requests have been observed to be dropped by BC).
        int max_outgoing_request_queue_size;

        // If peer times out too frequently (without ever sending a block), it is
        // disconnected.
        int num_consecutive_timeouts = 0;

        enum state state = state::disconnected;

        // The block currently being received is put here. This is used to determine
        // whether we can cancel a request, because if we're already receiving a block,
        // we can't cancel it.
        // TODO this feels hacky
        block_info in_transit_block = invalid_block;

        // We need an accurate figure on the current upload rate every time a block
        // arrives so that the ideal request queue size may be updated. throughput_rate
        // is insufficient for it operates with a 1 second granularity, but multiple 
        // blocks may arrive every second, in which case it would not give accurate 
        // values. It resets its value every second.
        per_round_counter<1> per_second_downloaded_bytes;
    };

    // Info and status regarding this peer. One instance persists throughout the session,
    // which is constantly updated but copies for stat aggregation are made on demand.
    info info_;

    // These fields are used when the exact number of bytes downloaded are requested
    // between calls, instead of a weighed average of the transfer rates. These are
    // reset with each call.
    mutable int num_uploaded_piece_bytes_ = 0;
    mutable int num_downloaded_piece_bytes_ = 0;

    // This is the average network round-trip-time (in milliseconds) between issuing a
    // request and receiving a block (note that it doesn't have to be the same block
    // since peers are not required to serve our requests in order, so this is more of
    // a general approximation).
    // Measured in milliseconds.
    sliding_average<20> avg_request_rtt_;

    // We measure the average time it takes (in milliseconds) to do disk jobs as this
    // affects the value that is picked for a peer's ideal request queue size (counting
    // disk latency is part of a requests's full round trip time, though it has a lower
    // weight as disk_io may buffer block before writing it to disk, meaning the
    // callbacks will be invoked with practically zero latency).
    // Measured in milliseconds.
    sliding_average<20> avg_disk_write_time_;

    // This is only used when connecting to the peer. If we couldn't connect by the time
    // this timer expires, the connection is aborted.
    deadline_timer connect_timeout_timer_;

    // After expiring every few minutes (2 by default) this timer tests whether we've
    // sent any messages (last_send_time_), and if not, sends a keep alive message
    // to keep the connection going.
    deadline_timer keep_alive_timer_;

    // Started when we send block requests and stopped and restarted every time one of
    // the requests is served. If none is served before the timer expires, peer has
    // timed out and on_request_timeout is called. If all our requests have been
    // served in a timely manner, the timeout is not restarted after stopping it.
    //
    // Start sites:
    // handle_block, send_request, make_requests, on_request_timeout
    //
    // Cancel sites:
    // disconnect, handle_block, handle_rejected_request, abort_outgoing_requests,
    // on_request_timeout
    deadline_timer request_timeout_timer_;

    // If neither endpoint has become interested in the other in 10 minutes, the peer
    // is disconnected. This means that every time we are no longer interested and peer
    // is not interested, or the other way around, this timer has to be started, and
    // stopped if either side becomes interested.
    deadline_timer inactivity_timeout_timer_;

    // If peer is on parole, it may only download a single piece in which no other peer
    // may participate. This is because normally multiple blocks are downloaded from
    // multiple peers and if one turns out to be bad (and more peers helped to complete
    // it), we have no way of determining which peer misbehaved. So as a result all are
    // suspected and each is assigned a "parole piece" which only this peer downloads.
    // The result of this download determines the guilt of this peer.
    // If peer_session is destructed without having the chance to finish this piece,
    // the download is placed into downloads_, letting others finish it. This has
    // the risk of putting another peer on parole if this one sent us corrupt pieces,
    // so we may want to discard the piece as is (TODO).
    std::unique_ptr<piece_download> parole_download_;

    // When this is an incoming connection, this peer_session must attach to a torrent
    // using this callback after peer's handshake has been received and a torrent info
    // hash could be extracted. It is not used otherwise.
    std::function<torrent_frontend(const sha1_hash&)> torrent_attacher_;

public:

    /**
     * Instantiate an outbound connection (when connections are made by torrent, i.e. the
     * torrent is known), but does NOT start the session or connect, that is done by
     * calling start.
     *
     * The socket must be initialized, but not opened, nor connected.
     */
    peer_session(asio::io_service& ios,
        tcp::endpoint peer_endpoint,
        bandwidth_controller& bandwidth_controller,
        const peer_session_settings& settings,
        torrent_frontend torrent);

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
    peer_session(asio::io_service& ios,
        tcp::endpoint peer_endpoint,
        bandwidth_controller& bandwidth_controller,
        const peer_session_settings& settings,
        std::function<torrent_frontend(const sha1_hash&)> torrent_attacher);

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

    /**
     * If there are outstanding asynchronous operations, such as a socket send or 
     * receive, we wait for them to complete. This is important when sending or
     * receiving a block, in which case no payload data is wasted this way.
     * This should be preferred over abort.
     */
    void stop();

    /**
     * All pending network operations are aborted by calling cancel on the IO objects,
     * i.e. all in transit data will be lost.
     */
    void abort();

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

    bool is_connecting() const noexcept;
    bool is_handshaking() const noexcept;
    bool is_connected() const noexcept;
    bool is_disconnecting() const noexcept;
    bool is_disconnected() const noexcept;

    /**
     * When peer_session is stopped gracefully, it transitions from connected to
     * disconnecting, then finally to disconnected. If it's aborted, it transitions
     * from connected to disconnected. If one only wishes to know whether peer_session
     * is effectively finished (disconnecting or disconnected), use is_stopped.
     */
    bool is_stopped() const noexcept;

    bool am_choked() const noexcept;
    bool am_interested() const noexcept;
    bool is_peer_choked() const noexcept;
    bool is_peer_interested() const noexcept;
    bool is_peer_on_parole() const noexcept;
    bool is_peer_seed() const noexcept;
    bool is_outbound() const noexcept;
    bool has_pending_disk_op() const noexcept;
    bool has_pending_socket_op() const noexcept;
    bool has_pending_async_op() const noexcept;
    bool has_peer_timed_out() const noexcept;

    /** Returns true if both sides of the connection support the extension. */
    bool is_extension_enabled(const int extension) const noexcept;

    enum state state() const noexcept;
    stats get_stats() const noexcept;
    void get_stats(stats& s) const noexcept;
    detailed_stats get_detailed_stats() const noexcept;
    void get_detailed_stats(detailed_stats& s) const noexcept;

    time_point last_outgoing_unchoke_time() const noexcept;
    time_point connection_established_time() const noexcept;
    seconds connection_duration() const noexcept;

    const peer_id_t& peer_id() const noexcept;

    const tcp::endpoint& local_endpoint() const noexcept;
    const tcp::endpoint& remote_endpoint() const noexcept;

    int upload_rate() const noexcept;
    int download_rate() const noexcept;

    /**
     * Returns how many bytes were transferred since the last time the function was
     * called and resets the value. This is used for deciding which peers to unchoke.
     * (A round is the interval between two calls to the same function.)
     */
    int num_bytes_uploaded_this_round() const noexcept;
    int num_bytes_downloaded_this_round() const noexcept;

    /** Sends a choke message and drops serving all pending requests made by peer. */
    void choke_peer();
    void unchoke_peer();
    void suggest_piece(const piece_index_t piece);

    /**
     * This is called (by torrent) when a piece was successfully downloaded. It may
     * alter our interest in peer.
     */
    void announce_new_piece(const piece_index_t piece);

private:

    /** Initializes fields common to both constructors. */
    peer_session(asio::io_service& ios, tcp::endpoint peer_endpoint,
        bandwidth_controller& bandwidth_controller,
        const peer_session_settings& settings);

    /** If our interest changes, sends the corresponding send_{un,}interested message. */
    void update_interest();

    // ----------------------
    // -- {dis,}connecting --
    // ----------------------

    void connect();
    void on_connected(const std::error_code& error = std::error_code());

    /**
     * This is called by each of the four async operations callbacks if they detect
     * that we're disconnecting (gracefully stopping). If there are no outstanding
     * operations left, this finally disconnects peer and calls stop_handler_.
     */
    void try_finish_disconnecting();

    /** error indicates why peer was disconnected. */
    void disconnect(const std::error_code& error);
    void detach_parole_download();

    /**
     * Just a convenience function that returns true if we are disconnecting or have
     * disconnected or if error is operation_aborted. This is used by handlers passed
     * to async operations to check if the connection has been or is being torn down. 
     */
    bool should_abort(const std::error_code& error = std::error_code()) const noexcept;

    // -------------
    // -- sending --
    // -------------

    /**
     * This is the main async "cycle" for sending messages. Registers an async write
     * to socket to drain from send_buffer_ as much as our current quota allows.
     */
    void send();
    void request_upload_bandwidth();
    bool can_send() const noexcept;

    /**
     * This is the handler for send. Clears num_bytes_sent bytes from send_buffer_,
     * handles errors, adjusts send quota and calls send to continue the cycle.
     */
    void on_sent(const std::error_code& error, size_t num_bytes_sent);
    void update_send_stats(const int num_bytes_sent) noexcept;

    // ---------------
    // -- receiving --
    // ---------------

    /**
     * Registers an asynchronous read operation on socket to read in as much as possible,
     * limited by our receive quota, into message_parser_.
     */
    void receive();
    void request_download_bandwidth();
    
    /**
     * If we don't expect piece payloads (in which case receive operations are
     * constrained by how fast we can write to disk, and resumed once disk writes
     * finished, in on_block_saved), we should always have enough space for protocol
     * chatter (non payload messages), otherwise the async receive cycle would stop,
     * i.e. there'd be no one reregistering the async receive calls.
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
    bool am_expecting_block() const noexcept;

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

    // -- standard BitTorrent messages --
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
    // -- DHT extension messages --
    // -- Fast extension messages --
    void handle_suggest_piece();
    void handle_have_all();
    void handle_have_none();
    void handle_reject_request();
    void handle_allowed_fast();

    /**
     * BitComet rejects messages by way of sending an empty block message, so the logic
     * in handle_reject_request is extracted so that it may be called from handle_block
     * as well.
     * request is an iterator pointing into or past the end of outgoing_requests_.
     */
    void handle_rejected_request(std::vector<pending_block>::iterator request);

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
     * Updates piece transfer rates and related statistics which in the case of
     * download rate affects how many requests we'll issue in the future.
     */
    void update_download_stats(const int num_bytes);
    void update_upload_stats(const int num_bytes);

    bool is_request_valid(const block_info& request) const noexcept;
    bool is_block_info_valid(const block_info& block) const noexcept;
    bool is_piece_index_valid(const piece_index_t index) const noexcept;
    bool should_accept_request(const block_info& block) const noexcept;

    void handle_unexpected_block(const block_info& block, message msg);

    // These methods are called when the peer sends us messages that it is not allowed to
    // send (e.g. they're choked). Note: these handlers must NOT extract anything from
    // message_parser_ as that has already been done by their corresponding handle
    // functions from which they are called.

    /** If we get too many unrequested blocks, disconnect peer to avoid being flooded. */
    void handle_illicit_block(const block_info& block);

    /**
     * This is called if the peer sends us requests even though it is choked. After a
     * few such occurences (currently 300), peer is disconnected. Every 10 requests peer
     * is choked again, because it may not have gotten our choke message.
     */
    void handle_illicit_request(const block_info& block);

    void handle_unknown_message();


    /**
     * If we're expecting a block and message parser has half finished messages, we
     * test whether it's a block, and if it is, try to extract information about it.
     * See info::in_transit_block comment.
     */
    void probe_in_transit_block() noexcept;

    // ----------
    // -- disk --
    // ----------

    void save_block(const block_info& block_info,
        disk_buffer block_data, piece_download& piece_download);
    void on_block_saved(const std::error_code& error,
        const block_info& block, const time_point start_time);
    void on_block_fetched(const std::error_code& error, const block_source& block);

    /**
     * This is invoked by piece_download when the piece has been fully downloaded and
     * hashed by disk_io. This is where hash fails and parole mode is handled as well as
     * the piece_download corresponding to piece is removed from downloads_.
     */
    void on_piece_hashed(const piece_download& download,
        const bool is_piece_good, const int num_bytes_downloaded);

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
     * Each of the below methods appends its message to send_buffer_ and calls send
     * at the end, but the payload may be buffered for a while before it is written to
     * socket.
     * The first five senders simply send the message and record that they have done so.
     * Testing whether it is prudent to do so (e.g. don't send an interested message
     * if we're already interested) is done by other methods that use them.
     */

    // -- standard BitTorrent messages --
    void send_handshake();
    void send_bitfield();
    void send_keep_alive();
    void send_choke();
    void send_unchoke();
    void send_interested();
    void send_not_interested();
    void send_have(const piece_index_t piece);
    void send_request(const block_info& block);
    void send_block(const block_source& block);
    void send_cancel(const block_info& block);
    // -- DHT extension messages --
    void send_port(const int port);
    // -- Fast extension messages --
    void send_suggest_piece(const piece_index_t piece);
    void send_have_all();
    void send_have_none();
    void send_reject_request(const block_info& block);
    void send_allowed_fast(const piece_index_t piece);
    void send_allowed_fast_set();

    /** Sends either a bitfield, have_all or have_none. */
    void send_piece_availability();

    // -------------------
    // -- request logic --
    // -------------------

    /**
     * We can make requests if we're below the max number of outstanding requests
     * and we're not choked and we're interested.
     */
    bool can_make_requests() const noexcept;
    void make_requests();

    /**
     * Chooses one of the below modes in which to make requests depending on the
     * torrent's and this session's state.
     * All make_requests* functions merely append the new requests to outgoing_requests_,
     * but don't actually send any requests. A view of into outgoing_requests_ of the
     * new requests is placed there is returned.
     */
    view<pending_block> distpach_make_requests();
    view<pending_block> make_requests_in_parole_mode();
    view<pending_block> make_requests_in_normal_mode();
    view<pending_block> make_requests_in_endgame_mode();
    view<pending_block> view_of_new_requests(const int n);

    /**
     * Tries to pick blocks from downloads in which this peer participates. We always
     * strive to download as few simultaneous blocks at a time from a peer as possible,
     * so we always try to continue our own downloads first.
     * New requests are placed in outgoing_requests_.
     * The number of blocks that have been placed in the request queue are returned.
     */
    int continue_downloads();

    /**
     * Tries to join  piece download started by another peer, if there are any, and
     * pick blocks for those piece downloads.
     * New requests are placed in outgoing_requests_.
     * The number of blocks that have been placed in the request queue are returned.
     */
    int join_download();
    std::shared_ptr<piece_download> find_shared_download();

    /**
     * Starts a new download and registers it in shared_downloads_ so that other
     * peers may join.
     * New requests are placed in outgoing_requests_.
     * The number of blocks that have been placed in the request queue are returned.
     */
    int start_download();

    int num_to_request() const noexcept;

    /**
     * This must be called when we know that we're not going to receive previously
     * requested blocks, so that they may be requested from other peers.
     */
    void abort_outgoing_requests();

    // -------------------
    // -- timeout logic --
    // -------------------

    /**
     * Finds the most suitable block to time out. This is usually the last block we
     * sent, since timing out the last block gives us the possibility of downloading it
     * from another peer and receiving it in time to cancel it with this peer, and by
     * the time the other blocks that were sent earlier (if any), will have a greater
     * chance of arriving, avoiding the need to time them out. However, if this is the
     * only peer that has the block, we must not time out the block.
     */
    void on_request_timeout(const std::error_code& error);
    void on_connect_timeout(const std::error_code& error);
    void on_inactivity_timeout(const std::error_code& error);
    void on_keep_alive_timeout(const std::error_code& error);

    std::vector<pending_block>::iterator find_request_to_time_out() noexcept;

    /**
     * The number of seconds after which we consider the request to have timed out.
     * This is always a number derived from the latest download metrics.
     */
    seconds calculate_request_timeout() const;

    // -----------
    // -- utils --
    // -----------

    void generate_allowed_fast_set();

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
        request,
        info
    };

    template<typename... Args>
    void log(const log_event event, const char* format, Args&&... args) const;
    template<typename... Args>
    void log(const log_event event, const log::priority priority,
        const char* format, Args&&... args) const;

    /** Tries to detect client's software from its peer_id in its handshake. */
    void try_identify_client();

    /** If no piece download is found, an assertion is triggered. */
    piece_download& find_download(const piece_index_t piece) noexcept;

    class send_cork;
};

inline bool peer_session::is_connecting() const noexcept
{
    return state() == state::connecting;
}

inline bool peer_session::is_handshaking() const noexcept
{
    return state() == state::handshaking;
}

inline bool peer_session::is_connected() const noexcept
{
    return state() == state::connected;
}

inline bool peer_session::is_disconnecting() const noexcept
{
    return state() == state::disconnecting;
}

inline bool peer_session::is_disconnected() const noexcept
{
    return state() == state::disconnected;
}

inline bool peer_session::is_stopped() const noexcept
{
    return is_disconnecting() || is_disconnected();
}

inline bool peer_session::am_choked() const noexcept
{
    return info_.am_choked;
}

inline bool peer_session::is_peer_choked() const noexcept
{
    return info_.is_peer_choked;
}

inline bool peer_session::am_interested() const noexcept
{
    return info_.am_interested;
}

inline bool peer_session::is_peer_interested() const noexcept
{
    return info_.is_peer_interested;
}

inline bool peer_session::is_peer_on_parole() const noexcept
{
    return info_.is_peer_on_parole;
}

inline bool peer_session::is_peer_seed() const noexcept
{
    return info_.is_peer_seed;
}

inline bool peer_session::is_outbound() const noexcept
{
    return info_.is_outbound;
}

inline bool peer_session::has_pending_disk_op() const noexcept
{
    return op_state_[op::disk_read] || op_state_[op::disk_write];
}

inline bool peer_session::has_pending_socket_op() const noexcept
{
    return op_state_[op::send] || op_state_[op::receive];
}

inline bool peer_session::has_pending_async_op() const noexcept
{
    return has_pending_socket_op() || has_pending_disk_op();
}

inline bool peer_session::has_peer_timed_out() const noexcept
{
    return info_.has_peer_timed_out;
}

inline enum peer_session::state peer_session::state() const noexcept
{
    return info_.state;
}

inline time_point peer_session::last_outgoing_unchoke_time() const noexcept
{
    return info_.last_outgoing_unchoke_time;
}

inline time_point peer_session::connection_established_time() const noexcept
{
    return info_.connection_established_time;
}

inline seconds peer_session::connection_duration() const noexcept
{
    if(connection_established_time() == time_point()) return seconds(0);
    return duration_cast<seconds>(cached_clock::now() - connection_established_time());
}

inline const peer_id_t& peer_session::peer_id() const noexcept
{
    return info_.peer_id;
}

inline const tcp::endpoint& peer_session::local_endpoint() const noexcept
{
    return info_.local_endpoint;
}

inline const tcp::endpoint& peer_session::remote_endpoint() const noexcept
{
    return info_.remote_endpoint;
}

inline int peer_session::num_bytes_uploaded_this_round() const noexcept
{
    const auto n = num_uploaded_piece_bytes_;
    num_uploaded_piece_bytes_ = 0;
    return n;
}

inline int peer_session::num_bytes_downloaded_this_round() const noexcept
{
    const auto n = num_downloaded_piece_bytes_;
    num_downloaded_piece_bytes_ = 0;
    return n;
}

inline int peer_session::download_rate() const noexcept
{
    return info_.download_rate.rate();
}

inline int peer_session::upload_rate() const noexcept
{
    return info_.upload_rate.rate();
}

// -- pending block --

inline bool operator==(const pending_block& a, const pending_block& b) noexcept
{
    return static_cast<const block_info&>(a) == static_cast<const block_info&>(b)
        && a.request_time == b.request_time
        && a.has_timed_out == b.has_timed_out;
}

inline bool operator==(const pending_block& a, const block_info& b) noexcept
{
    return static_cast<const block_info&>(a) == b;
}

inline bool operator==(const block_info& b, const pending_block& a) noexcept
{
    return a == b;
}

inline bool operator!=(const pending_block& a, const pending_block& b) noexcept
{
    return !(a == b);
}

inline bool operator!=(const pending_block& a, const block_info& b) noexcept
{
    return !(a == b);
}

inline bool operator!=(const block_info& b, const pending_block& a) noexcept
{
    return !(a == b);
}

} // namespace tide

namespace std {

template<> struct hash<tide::pending_block>
{
    size_t operator()(const tide::pending_block& b) const noexcept
    {
        return std::hash<tide::block_info>()(static_cast<const tide::block_info&>(b))
             + std::hash<tide::time_point::rep>()(tide::to_int<tide::milliseconds>(
                    b.request_time.time_since_epoch()))
             + std::hash<bool>()(b.has_timed_out);
    }
};

} // namespace std


#endif // TIDE_PEER_SESSION_HEADER
