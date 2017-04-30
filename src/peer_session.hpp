#ifndef TORRENT_PEER_SESSION_HEADER
#define TORRENT_PEER_SESSION_HEADER

#include "peer_session_error.hpp"
#include "block_disk_buffer.hpp"
#include "sliding_average.hpp"
#include "message_parser.hpp"
#include "state_tracker.hpp"
#include "send_buffer.hpp"
#include "block_info.hpp"
#include "peer_info.hpp"
#include "socket.hpp"
#include "units.hpp"
#include "time.hpp"
//#include "stat.hpp"

#include <system_error>
#include <vector>
#include <memory>

#include <asio/io_service.hpp>

class piece_download_locator;
class bandwidth_controller;
class disk_read_buffer;
class piece_download;
class torrent_info;
class piece_picker;
class settings;
class disk_io;

struct peer_session
{
    /**
     * These are the fields that we get from torrent either through the constructor when
     * this is an outbound connection, or when we attach to a torrent after the peer
     * handshake when this is an inbound connection. To test whether we succesfully
     * attached to a torrent, torrent_info must not be nullptr (the others may be, as
     * optimizations may be employed, such as the omission of a piece_download_locator
     * when seeding, but torrent_info must be present).
     */
    struct torrent_specific_args
    {
        std::shared_ptr<piece_picker> picker;
        std::shared_ptr<piece_download_locator> locator;
        std::shared_ptr<torrent_info> info;
    };

private:

    enum states : uint8_t
    {
        idling       = 0x0,
        // Whether we're currently reading to or writing from socket. Both operations
        // last until their handles are invoked. This is used to block access to the
        // socket to accumulate work to be done into batches to amortize costs.
        receiving    = 0x1,
        sending      = 0x2,
        reading_disk = 0x4,
        writing_disk = 0x8
    };

    state_tracker<uint8_t> m_work_state;

    std::unique_ptr<tcp::socket> m_socket;

    // We try to fill up the send buffer as much as possible before draining it to
    // socket to minimize the number of context switches (syscalls) by writing to the
    // socket.
    send_buffer m_send_buffer;

    // We receive from socket directly into message_parser's internal buffer.
    message_parser m_message_parser;

    // The disk thread used for async piece fetches and writes.
    disk_io& m_disk_io;

    bandwidth_controller& m_bandwidth_controller;

    // These are the tunable parameters that the user provides.
    const settings& m_settings;

    // NOTE: if this starts as an incoming connection, we won't have this field until we
    // finished the handshake and attached ourselves to a torrent.
    std::shared_ptr<piece_picker> m_piece_picker;

    // This is where all current active piece downloads can be accessed.
    //
    // NOTE: if this starts as an incoming connection, we won't have this field until we
    // finished the handshake and attached ourselves to a torrent. It's also null if
    // we're seeding (no point in having a download locator when we're not downloading).
    std::shared_ptr<piece_download_locator> m_piece_download_locator;


    // We aggregate all peer's stats in a torrent wide torrent_info instance.
    //
    // NOTE: if this starts as an incoming connection, we won't have this field until we
    // finished the handshake and attached ourselves to a torrent.
    // It must not be null. If it is, disconnect immediately.
    std::shared_ptr<torrent_info> m_torrent_info;

    /** Used to represent requests we had sent out. */
    struct pending_block : public block_info
    {
        bool has_timed_out = false;

        pending_block(piece_index_t index, int offset, int length)
            : block_info(index, offset, length)
        {}
        pending_block(block_info b) : block_info(std::move(b)) {}

        friend bool operator==(const pending_block& a, const pending_block& b) noexcept
        {
            return static_cast<const block_info&>(a) == static_cast<const block_info&>(b)
                && a.has_timed_out == b.has_timed_out;
        }

        friend bool operator!=(const pending_block& a, const pending_block& b) noexcept
        {
            return !(a == b);
        }
    };

    // Our pending requests that we sent to peer. This is emptied if we are choked, as
    // in that case we don't expect outstanding requests to be served. If we receive a
    // block that is not in this list, we dump it as it's not expected.
    std::vector<pending_block> m_sent_requests;

    // The requests we got from peer. Peer's requests are stored here as long as we can
    // cancel them. Once the requested blocks are sent out, the corresponding request
    // is removed from here.
    std::vector<block_info> m_received_requests;

    // These are the active piece downloads in which this peer_session is participating.
    std::vector<std::shared_ptr<piece_download>> m_piece_downloads;

    // If peer is on parole, it may only download a single piece in which no other peer
    // may participate. This is because normally multiple blocks are downloaded from
    // multiple peers and if one turns out to be bad (and more peers helped to complete
    // it), we have no way of determining which peer misbehaved. So as a result all are
    // suspected and each is assigned a "parole piece" which only this peer downloads.
    // The result of this download determines the guilt of this peer.
    std::unique_ptr<piece_download> m_parole_piece;

    // Info and status regarding this peer. One instance persists throughout the session,
    // which is constantly updated but copies for stat aggregation are made on demand.
    peer_info m_info;

    // The request queue (the number of blocks we requests from the peer in one go) is
    // recalculated using the download rate of one round (between to calls to update())
    // in an attempt to always keep the link fully saturated. Currently a one second
    // network delay is assumed, but this should be increased if (TODO make tunable)
    // performance suffers, as it is cheaper to overestimate.
    int m_best_request_queue_length = 8;

    // If peer sends requests while it's choked this counter is increased. After 300
    // such requests, peer is disconnected.
    int m_num_illicit_requests = 0;

    // Record the number of unwanted blocks we receive from peer. After a few we
    // disconnect so as to avoid being flooded.
    int m_num_unwanted_blocks = 0;

    // After a certain number of subsequent disk read/write failures peer is disconnected
    // because it implies that there is a problem that could not be fixed.
    int m_num_disk_io_failures = 0;

    // If the number of unserved and currently served requests from peer exceeds this
    // number, further requests will be dropped (once FAST extension is implemented
    // reject_request messages will also be sent).
    int m_max_pending_requests;

    // Various statistics (up/down rates etc) for this peer.
    // TODO consider only collecting stats in peer_info
    //stat m_stats;

    // All of the below only pertain to actual payload (piece) data.
    sliding_average<20> m_upload_rate;
    sliding_average<20> m_download_rate;
    // This is the average network round-trip-time for a request.
    sliding_average<20> m_avg_request_rtt;

    time_point m_connection_time;
    time_point m_connected_time;

    // We record each time the send buffer is drained and the receive buffer is filled.
    // All of these values are only estimates, as they are updated from a central cached
    // timepoint updated around every 100ms.
    time_point m_last_send_time;
    time_point m_last_receive_time;

    time_point m_last_outgoing_choke_time;
    time_point m_last_incoming_choke_time;

    time_point m_last_outgoing_unchoke_time;
    time_point m_last_incoming_unchoke_time;

    time_point m_last_outgoing_interest_time;
    time_point m_last_incoming_interest_time;

    time_point m_last_outgoing_uninterest_time;
    time_point m_last_incoming_uninterest_time;

    time_point m_last_outgoing_request_time;
    time_point m_last_incoming_request_time;

    time_point m_last_outgoing_block_time;
    time_point m_last_incoming_block_time;

    // This is only used when connecting to the peer. If we couldn't connect by the time
    // this timer expires, the connection is aborted.
    deadline_timer m_connect_timeout_timer;

    // After expiring every few minutes (2 by default) this timer tests whether we've
    // sent any messages (m_last_send_time), and if not, sends a keep alive message
    // to keep the connection going.
    deadline_timer m_keep_alive_timer;

    // Started when we send block requests and stopped and restarted every time one of
    // the requests is served. If none is served before the timer expires, peer has
    // timed out and handle_request_timeout() is called. If all our requests have been
    // served in a timely manner, the timeout is not restarted after stopping it.
    deadline_timer m_request_timeout_timer;

    // If neither endpoint has become interested in the other in 10 minutes, the peer
    // is disconnected. This means that every time we are no longer interested and peer
    // is not interested, or the other way around, this timer has to be started, and
    // stopped if either side becomes interested.
    deadline_timer m_inactivity_timeout_timer;

    // When this is an incoming connection, this peer_session must attach to a torrent
    // using this callback after peer's handshake has been received and a torrent info
    // hash could be extracted. It is not used otherwise.
    std::function<torrent_specific_args(const sha1_hash&)> m_torrent_attacher;

public:

    /**
     * Instantiate an outbound connection (when connections are made by torrent, i.e. the
     * torrent is known).
     *
     * The socket must be initialized, but not opened.
     */
    peer_session(
        std::unique_ptr<tcp::socket> socket,
        tcp::endpoint peer_endpoint,
        disk_io& disk_io,
        bandwidth_controller& bandwidth_controller,
        const settings& settings,
        torrent_specific_args torrent_args
    );

    /**
     * Instantiate an inbound connection, that is, it is now known to which torrent this
     * peer belongs until the handshake is completed.
     *
     * The socket must be initialized, but not opened.
     *
     * The torrent_attacher handler is called after we receive peer's handshake. This is
     * used to locate the torrent to which this connection belongs. After this, we have
     * the torrent's info hash so we can send our handshake as well. If this succeeds,
     * the peer is fully connected.
     */
    peer_session(
        std::unique_ptr<tcp::socket> socket,
        tcp::endpoint peer_endpoint,
        disk_io& disk_io,
        bandwidth_controller& bandwidth_controller,
        const settings& settings,
        std::function<torrent_specific_args(const sha1_hash&)> torrent_attacher
    );

    ~peer_session();

    void disconnect(const std::error_code& error);
    void pause();
    void quick_stop();
    void try_resume();

    bool is_connecting() const noexcept;
    bool is_disconnecting() const noexcept;
    bool is_finished() const noexcept;
    bool is_on_parole() const noexcept;

    /**
     * This is the "tick" in the peer_session's "clock". Does various timeout checks,
     * depending on the current state. Updates round statistics (e.g. up/download rates).
     */
    void update();

    /** Sends a choke message and drops serving all pending requests made by peer. */
    void choke_peer();

    /** Sends an unchoke message and immediately creates block requests. */
    void unchoke_peer();

    /**
     * This is called (by torrent) when a piece was successfully downloaded. It may alter
     * our interest in peer.
     */
    void announce_new_piece(const piece_index_t piece);

private:

    /** Initializes fields for both constructors. */
    peer_session(
        std::unique_ptr<tcp::socket> socket,
        tcp::endpoint peer_endpoint,
        disk_io& disk_io,
        bandwidth_controller& bandwidth_controller,
        const settings& settings
    );

    /** If our interest changes, sends the corresponding send_{un,}interested message. */
    void update_interest();

    /**
     * Called every update, optimizes the number of blocks we request to fully utilize
     * the connection.
     */
    void adjust_best_request_queue_length() noexcept;
    void abort_our_requests();

    // ----------------------
    // -- {dis,}connecting --
    // ----------------------

    void connect();
    void on_connected(const std::error_code& error);

    // -----------------------
    // -- sending to socket --
    // -----------------------

    /**
     * This is the main async "cycle" for sending messages. Registers an async write
     * to socket to drain from m_send_buffer as much as our current quota allows.
     */
    void send();
    void request_upload_bandwidth();
    bool can_send() const noexcept;

    /**
     * This is the handler for send(). Clears num_bytes_sent bytes from m_send_buffer,
     * handles errors, adjusts send quota and calls send() to continue the cycle.
     */
    void on_sent(const std::error_code& error, size_t num_bytes_sent);
    void record_sent_bytes(const int num_bytes_sent) noexcept;

    // ---------------------------
    // -- receiving from socket --
    // ---------------------------

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
     * finished), we should always have enough space for protocol chatter, otherwise
     * the async receive cycle would stop.
     */
    void ensure_protocol_chatter();
    int get_num_to_receive() const noexcept;

    /**
     * Accounts for the bytes read, subtracts num_bytes_received from the send quota,
     * checks if the async_read_some() operation read all available bytes and if not,
     * tries synchronously read the rest. Then it dispatches message handling.
     */
    void on_received(const std::error_code& error, size_t num_bytes_received);
    void record_received_bytes(const int num_bytes_received) noexcept;

    void adjust_receive_buffer(const int num_bytes, const bool was_choked);
    bool should_grow_receive_buffer() const noexcept;
    bool am_expecting_piece() const noexcept;

    /**
     * If the receive buffer is completely filled up in a receive operation, it may mean
     * that there are more bytes left in socket. This function attempts to synchronously
     * read them. The number of bytes read is returned.
     */
    int flush_socket();

    // ----------------------
    // -- message handling --
    // ----------------------
    // Each message handler extracts the current message from the receive buffer (thus
    // advancing to the next message).

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
    void handle_block();
    void handle_cancel();

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

    /**
     * This is invoked by piece_download when the piece has been fully downloaded and
     * hashed by disk_io. This is where hash fails and parole mode is handled as well as
     * the piece_download corresponding to piece is removed from m_piece_downloads.
     */
    void on_piece_hashed(const piece_index_t piece, const bool is_piece_good);
    void on_block_saved(const std::error_code& error, const block_info& block);
    void on_block_read(const std::error_code& error, const block_source& block);

    // ---------------------
    // -- message sending --
    // ---------------------

    /**
     * This is used by public sender methods (choke_peer(), announce_new_piece() etc) to
     * see if we are in a state where we can send messages (not connecting,
     * disconnecting or stopped).
     */
    bool is_ready_to_send() const noexcept;

    // Each of the below methods append their message to m_send_buffer and call send()
    // at the end, but the payload may be buffered for a while before it is written to
    // socket.
    // The first 5 senders simply send the message and record that they have done so.
    // Testing whether it is prudent to do so (e.g. don't send an interested message
    // if we're already interested) is done by other methods that use them.

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

    /** If we're below the max number of outstanding requests threshold. TODO */
    bool can_send_requests() const noexcept;

    /**
     * Either one of these is called by send_requests(). Both merely add the request
     * message to the m_sent_request queue but don't send off the message. This is done
     * by send_requests(), if any requests have been made in either of these functions.
     */
    void make_requests_in_parole_mode();
    void make_requests_in_normal_mode();
    
    /** Tries to pick blocks from downloads in which this peer participates. */
    void continue_downloads();

    /**
     * Tries to join a piece download started by another peer, if there are any, and
     * pick blocks for those piece downloads.
     */
    void join_download();

    /**
     * Starts a new download and registers it in m_piece_download_locator so that other
     * peers may join.
     */
    void start_download();

    // -------------------
    // -- timeout logic --
    // -------------------

    bool has_request_timed_out() const;

    /** The number of seconds after which we consider the request to have timed out. */
    seconds request_timeout() const;

    void handle_request_timeout(const std::error_code& error);
    void cancel_request_handler(const block_info& block);
    void handle_connect_timeout(const std::error_code& error);
    void handle_inactivity_timeout(const std::error_code& error);
    void handle_keep_alive_timeout(const std::error_code& error);

    // -------------

    enum class log_event
    {
        connecting,
        disconnecting,
        incoming,
        outgoing,
        disk,
        invalid_message,
        parole,
        timeout
    };

    template<typename... Args>
    void log(const log_event event, const std::string& format, Args&&... args);

    int get_piece_length(const piece_index_t piece) const noexcept;

    template<typename Duration, typename Handler>
    void start_timer(deadline_timer& timer, const Duration& expires_in, Handler handler);

    // Credit to libtorrent:
    // http://blog.libtorrent.org/2012/12/principles-of-high-performance-programs/
    class send_cork;
};

inline bool peer_session::is_ready_to_send() const noexcept
{
    return !is_disconnecting() && !is_finished() && !is_connecting();
}

inline bool peer_session::is_connecting() const noexcept
{
    return m_info.state == peer_info::state_t::connecting;
}

inline bool peer_session::is_disconnecting() const noexcept
{
    return m_info.state == peer_info::state_t::disconnecting;
}

inline bool peer_session::is_finished() const noexcept
{
    return m_info.state == peer_info::state_t::stopped;
}

inline bool peer_session::is_on_parole() const noexcept
{
    return m_info.is_on_parole;
}

#endif // TORRENT_PEER_SESSION_HEADER
