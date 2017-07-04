#ifndef TIDE_TRACKER_HEADER
#define TIDE_TRACKER_HEADER

#include "string_view.hpp"
#include "peer_entry.hpp"
#include "settings.hpp"
#include "payload.hpp"
#include "socket.hpp"
#include "units.hpp"
#include "time.hpp"

#include <unordered_map>
#include <system_error>
#include <functional>
#include <utility>
#include <string>
#include <memory>
#include <vector>
#include <array>

#include <asio/io_service.hpp>

namespace tide {

// TODO consider renaming the protocol specific names in request to more sensible ones
struct tracker_request
{
    enum class event_t
    {
        // This is used by udp_tracker because an event field is always included so we
        // must differentiate it from the other three events.
        none      = 0,
        // Must be sent to the tracker when the client becomes a seeder. Must not be
        // present if the client started as a seeder.
        completed = 1,
        // The first request to tracker must include this value.
        started   = 2,
        // Must be sent to tracker if the client is shutting down gracefully.
        stopped   = 3,
    };

    // --------------
    // -- required --
    // --------------

    sha1_hash info_hash;
    peer_id_t peer_id;
    uint16_t port;
    int64_t uploaded;
    int64_t downloaded;
    int64_t left;

    // --------------
    // -- optional --
    // --------------

    // The number of peers the client wishes to receive from the tracker. If omitted and
    // the tracker is UDP, -1 is sent to signal the tracker to determine the number of
    // peers, and if it's ommitted and the tracker is HTTP, this is typically swapped
    // for 50.
    int num_want = -1;

    // Indicates that client accepts a compact response (each peer takes up only 6 bytes
    // where the first four bytes constitute the IP address and the last 2 the port
    // number, in Network Byte Order). The default is true to save network traffic (
    // many trackers don't consider this and send compact lists anyway).
    bool compact = true;

    // Indicates that the tracker should omit the peer id fields in the peers dictionary
    // in non-compact mode (in compact mode this is ignored). Again, default is true to
    // save traffic.
    bool no_peer_id = true;

    // Must be specified in the three specific cases as described in event_t.
    event_t event = event_t::none;

    // True IP address of the client in dotted quad format. This is only necessary if
    // the IP addresss from which the HTTP request originated is not the same as the
    // client's host address. This happens if the client is communicating through a
    // proxy, or when the tracker is on the same NAT'd subnet as peer (in which case it
    // is necessary that tracker not give out an unroutable address to peer).
    std::string ip;

    // If a previous announce contained a tracker_id, it should be included here.
    std::string tracker_id;
};

/**
 * This makes sure that all important fields are included in the tracker request
 * and should be preferred over manually setting fields.
 */
class tracker_request_builder
{
    // Some of the parameters in a request are mandatory, so this counter is incremented
    // with each mandatory field that was added and when build is invoked it is checked
    // whether it matches the number of required parameters .
    int m_required_param_counter = 0;
    tracker_request m_request;

public:

    // --------------
    // -- required --
    // --------------

    tracker_request_builder& info_hash(sha1_hash info_hash);
    tracker_request_builder& peer_id(peer_id_t peer_id);
    tracker_request_builder& port(uint16_t port);
    tracker_request_builder& uploaded(int64_t uploaded);
    tracker_request_builder& downloaded(int64_t downloaded);
    tracker_request_builder& left(int64_t left);

    // --------------
    // -- optional --
    // --------------

    tracker_request_builder& compact(bool b);
    tracker_request_builder& no_peer_id(bool b);
    tracker_request_builder& event(tracker_request::event_t event);
    tracker_request_builder& ip(std::string ip);
    tracker_request_builder& num_want(int num_want);
    tracker_request_builder& tracker_id(std::string tracker_id);

    /** Verifies that all required fields have been set and throws if not. */
    tracker_request build();
};

struct tracker_response
{
    // If this is not empty, no other fields in response are valid. It contains a
    // human-readable error message as to why the request was invalid.
    std::string failure_reason;

    // Optional. Similar to failure_reason, but the response is still processed.
    std::string warning_message;

    // Optional.
    std::string tracker_id;

    // The number of seconds the client should wait before recontacting tracker.
    seconds interval;

    // If present, the client must not reannounce itself before the end of this interval.
    seconds min_interval;

    int32_t num_seeders;
    int32_t num_leechers;

    // This is only used when tracker includes the peer ids of a peer. However, virtually
    // all trackers use compact mode nowadays to save bandwidth, so consider phasing this
    // out.
    std::vector<peer_entry> peers;
    std::vector<tcp::endpoint> ipv4_peers;
    // TODO support ipv6
    std::vector<tcp::endpoint> ipv6_peers;
};

struct scrape_response
{
    struct torrent_status
    {
        // The info_hash identifying the torrent.
        sha1_hash info_hash;
        int32_t num_seeders;
        int32_t num_leechers;
        // The total number of times a 'complete' event has been registered with this
        // tracker for this torrent.
        int32_t num_downloaded;
    };

    std::vector<torrent_status> torrent_statuses;
    std::string failure_reason;
};

enum class tracker_errc
{
    timed_out,
    invalid_response,
    response_too_small,
    wrong_response_type,
    invalid_transaction_id
};

struct tracker_error_category : public std::error_category
{
    const char* name() const noexcept override { return "tracker"; }
    std::string message(int env) const override;
};

const tracker_error_category& tracker_category();
std::error_code make_error_code(tracker_errc e);
std::error_condition make_error_condition(tracker_errc e);

} // namespace tide

namespace std {
template<> struct is_error_code_enum<tide::tracker_errc> : public true_type {};
}

namespace tide {

/**
 * This is an interface for the two possible trackers: UDP and HTTP/S.
 * In all cases a single tracker instance may be shared among multiple torrents, so all
 * derived instances must be equipped to deal with this.
 */
class tracker
{
protected:

    // The full announce URL of the form "tracker.host.domain:port/announce". Note that
    // the protocol identifier (e.g. "udp://") included in the .torrent metainfo file
    // is stripped after determining the tracker's protocol. The port number need not be
    // included, in which case the default 80 for HTTP and 443 for HTTPS used.
    std::string m_url;

    const settings& m_settings;

    // Even though there might be multiple concurrent requests, a single timeout timerr
    // is employed as we do not know if, in the case of multiple concurrent requests,
    // tracker will serve them in order, and if it served a request out of order we know
    // it is responsive, so timing out becomes unnecessary.
    deadline_timer m_timeout_timer;

    // The total number of times we tried to contact tracker in a row, but failed.
    // TODO not actually incremented
    int m_num_fails = 0;

    time_point m_last_announce_time;
    time_point m_last_scrape_time;

    // These fields are used to mark a tracker as "faulty", so that user can query a
    // tracker and move onto the next.
    bool m_is_reachable = true;
    bool m_had_protocol_error = false;

    // When we abort all tracker connections this is set to false. TODO
    bool m_is_aborted = false;

public:

    tracker(std::string url, asio::io_service& ios, const settings& settings);
    // TODO should we send an exit message when destructing?
    virtual ~tracker() = default;

    /**
     * Starts an asynchronous tracker announcement/request. Network errors are reported
     * via the error_code, but semantic errors (i.e. invalid fields in the request) are
     * reported via the tracker_response.failure_reason field (in which case all other
     * fields in response are empty/invalid.
     */
    virtual void announce(tracker_request params,
        std::function<void(const std::error_code&, tracker_response)> handler) = 0;

    /**
     * A scrape request is used to get data about one, multiple or all torrents tracker
     * manages. If in the second overload info_hashes is empty, the maximum number of
     * requestable torrents are scraped that tracker has.
     */
    virtual void scrape(std::vector<sha1_hash> info_hashes,
        std::function<void(const std::error_code&, scrape_response)> handler) = 0;

    /**
     * This should be called when torrent is shutting down but we don't want to wait
     * for pending announcements.
     */
    virtual void abort() = 0;

    const std::string& url() const noexcept { return m_url; }
    time_point last_announce_time() const noexcept { return m_last_announce_time; }
    time_point last_scrape_time() const noexcept { return m_last_scrape_time; }

    /**
     * These are used to query if tracker is currently reachable or if it had exhibited
     * any protocol errors in its response in the past. The former is set to false after
     * we timed out and set to true again if we could reach tracker.
     */
    bool is_reachable() const noexcept { return m_is_reachable; }
    bool had_protocol_error() const noexcept { return m_had_protocol_error; }
    int num_fails() const noexcept { return m_num_fails; }

protected:

    enum class log_event
    {
        connecting,
        incoming,
        outgoing,
        invalid_message,
        timeout
    };

    template<typename... Args>
    void log(const log_event event, const char* format, Args&&... args) const;
};

/** Currently not implemented. */
struct http_tracker final : public tracker
{
    http_tracker(std::string host, asio::io_service& ios, const settings& settings);
    void announce(tracker_request params,
        std::function<void(const std::error_code&, tracker_response)> handler) override;
    void scrape(std::vector<sha1_hash> info_hashes,
        std::function<void(const std::error_code&, scrape_response)> handler) override;
    void abort() override;
};

/**
 * Implements: http://bittorrent.org/beps/bep_0015.html
 *
 * NOTE: it is NOT thread-safe!
 */
class udp_tracker final : public tracker
{
    /** Each exchanged message has an action field specifying the message's intent. */
    enum action_t : uint8_t
    {
        connect   = 0,
        announce_ = 1,
        scrape_   = 2,
        error     = 3
    };

    /**
     * Multiple torrents may be associated with the same tracker so we need to separate
     * each torrent's announce/scrape request. This means each request that torrent
     * makes to tracker needs to have its own send buffer, expected action in response
     * etc, but still use tracker's socket and receive buffer for communicating.
     */
    struct request
    {
        // This is the state in which request currently is, i.e. which message we're
        // expecting next from tracker (response may be action_t::error, however).
        action_t action = action_t::connect;

        // Each request has its own transaction id so tracker responses can be properly
        // routed to a specific request. 0 means it is uninitialized.
        int32_t transaction_id = 0;

        explicit request(int32_t tid) : transaction_id(tid) {}
        virtual ~request() = default;

        virtual void on_error(const std::error_code& error) = 0;
    };

    struct announce_request : public request
    {
        // These are the request arguments to be sent to tracker.
        tracker_request params;

        // This is the callback to be invoked once our request is served.
        std::function<void(const std::error_code&, tracker_response)> handler;

        // There is only ever one outstanding datagram, which is stored here until it's
        // confirmed that it has been sent.
        // The size is fixed at 98 bytes because that's the largest message we'll ever
        // send (announce), and also the most common, so might as well save ourselves
        // the allocation churn (though note that if the message is smaller, the buffer
        // passed to socket should be capped).
        fixed_payload<98> payload;

        announce_request(int32_t tid, tracker_request p,
            std::function<void(const std::error_code&, tracker_response)> h);

        void on_error(const std::error_code& error) override { handler(error, {}); }
    };

    struct scrape_request : public request
    {
        // These are the torrents we want info about. It may be empty, in which case we
        // request info about all torrents tracker has.
        std::vector<sha1_hash> info_hashes;

        // This is the callback to be invoked once our request is served.
        std::function<void(const std::error_code&, scrape_response)> handler;

        // There is only ever one outstanding datagram, which is stored here until it's
        // confirmed that it has been sent.
        // Size cannot be fixed because info_hashes is of variable size.
        struct payload payload;

        scrape_request(int32_t tid, std::vector<sha1_hash> i,
            std::function<void(const std::error_code&, scrape_response)> h);

        void on_error(const std::error_code& error) override { handler(error, {}); }
    };

    // Pending requests are mapped to their transaction ids.
    std::unordered_map<int32_t, std::unique_ptr<request>> m_requests;

    // While we may have many requests sent "at the same time", we may only receive and
    // process a single datagram at a time. The buffer is fixed at 1500 bytes which is
    // the limit of Ethernet v2 MTU, so this is about the upper limit to avoid
    // fragmentation. This buffer is lazily allocated on the first use.
    std::unique_ptr<std::array<uint8_t, 1500>> m_receive_buffer;

    // A single UDP socket is used for all tracker connections. That is, if multiple
    // torrents are assigned the same tracker, they all make their requests/announcements
    // via this socket.
    udp::socket m_socket;
    udp::resolver m_resolver;

    enum class state_t : uint8_t
    {
        disconnected,
        connecting,
        connected
    };

    state_t m_state = state_t::disconnected;

    // After establishing a connection with tracker and receiving a connection_id, the
    // connection is alive for one minute. This saves some bandwidth and unnecessary
    // round trip times.
    time_point m_last_connect_time;

    // This is set to signal that we're receiving into m_receive_buffer, which is
    // necessary because we may only receive a single datagram at any given time, i.e.
    // only serve a single request.
    bool m_is_receiving = false;

    // The constructor launches an async host resolution, during which no request may be
    // launched, so execution must halt if this is false.
    bool m_is_resolved = false;

    // This value we receive from tracker in response to our connect message, which we
    // then have to include in every subsequent message to prove it's still us
    // interacting with tracker. We can use it for one minute after receiving it.
    int64_t m_connection_id;

public:

    /**
     * url may or may not include the "udp://" protocol identifier, but it must include
     * the port number.
     */
    udp_tracker(const std::string& url, asio::io_service& ios, const settings& settings);
    ~udp_tracker();

    void abort() override;

    void announce(tracker_request params,
        std::function<void(const std::error_code&, tracker_response)> handler) override;
    void scrape(std::vector<sha1_hash> info_hashes,
        std::function<void(const std::error_code&, scrape_response)> handler) override;

    udp::endpoint remote_endpoint() const noexcept;
    udp::endpoint local_endpoint() const noexcept;

private:

    void on_host_resolved(const std::error_code& error, udp::resolver::iterator it);

    /**
     * Creates an entry in m_requests and return a reference to the request instance.
     * Request must be either announce_request or scrape_request.
     */
    template<typename Request, typename Params, typename Handler>
    Request& create_request_entry(Params params, Handler handler);

    /**
     * Sending an announce or a scrape requests entails the same sort of logic up until
     * issuing the request, so this function takes care of those tasks. Function must be
     * either send_announce_request or send_scrape_request.
     */
    template<typename Request, typename Function>
    void execute_request(Request& request, Function f);

    /** Creates a random transaction id. */
    static int create_transaction_id();

    /** Determines whether it is time to establish connection to tracker again. */
    bool must_connect() const noexcept;

    /**
     * To avoid spoofing, first we have to "connect" to tracker (even though UDP is a
     * connectionless protocol) by sending them a transaction_id, receiving a
     * connection_id, which is then sent back for verification.
     */
    template<typename Request>
    void send_connect_request(Request& request);
    void send_announce_request(announce_request& request);
    void send_scrape_request(scrape_request& request);
    
    template<typename Request>
    void send_message(Request& request, const size_t num_bytes_to_send);

    /** Checks errors and makes sure the entire send buffer was transmitted. */
    void on_message_sent(request& request,
        const std::error_code& error, const size_t num_bytes_sent);

    void receive_message();

    /**
     * This handles all responses and dispatches the message handling to the response's
     * matching handler and resets the timeout timer. The first two fields of the
     * message are always as follows:
     * int32_t action
     * int32_t transaction_id
     * And action is used to determine which handler is invoked.
     */
    void on_message_received(const std::error_code& error,
        const size_t num_bytes_received);

    /**
     * If multiple torrents announce in quick succession and we have yet to establish
     * a connection, only the first one connects while the rest mark themselves (in the
     * action field) as connecting but they don't in fact do anything but wait for the
     * first requester to finish establishing the connection. All connecting/waiting
     * requests are located and continued here.
     */
    void handle_connect_response(request& request, const size_t num_bytes_received);
    void handle_announce_response(announce_request& request,
        const size_t num_bytes_received);
    void handle_scrape_response(scrape_request& request, const size_t num_bytes_received);
    void handle_error_response(request& request, const size_t num_bytes_received);

    /**
     * Requests issued during establishing a connection are put on
     * hold until the other operations finish. This resumes them.
     */
    void resume_stalled_requests();

    /**
     * Cancels all outstanding operations and if we haven't tried all endpoints mapped
     * to tracker's host, we try to send all pending requests to that host. Otherwise,
     * all requests' handlers are invoked notifying the callers.

     TODO should cancel the first pending request only
     */ 
    void handle_timeout(const std::error_code& error);

    /**
     * Each pending request's handler is called with error and all pending requests are
     * removed. This should be called if the error is not tied to a single request (e.g.
     * internet connection is down), or it is not clear which request to associate with
     * this error (e.g. wrong transaction_id -- which request's handler to call?).
     */
    void on_global_error(const std::error_code& error);
};

/**
 * A tracker may be used by more than a single torrent, but torrents need to record
 * some state specific to them, so these can't be stored in the tracker. Thus, each
 * torrent has its own tracker_entry.
 */
struct tracker_entry
{
    std::shared_ptr<class tracker> tracker;

    // Each tracker announce starts with a 'started' event. Each tracker that received
    // such a message, must be sent a 'completed' event once the download is done, and
    // a 'stopped' event when the torrent is gracefully stopped.
    bool has_sent_started = false;
    bool has_sent_completed = false;
    bool has_sent_stopped = false;

    // If torrent's metainfo file supports the announce-list extension, then trackers
    // are grouped in tiers, and the announce-list is a list of these tiers. This field
    // denotes the zero-based index of that group in announce-list.
    uint8_t tier = 0;

    // We should not announce more frequently than every 'interval' seconds, however,
    // 'completed' and 'stopped' events must be sent regardless of these fields.
    // min_interval is optional, and it means we must not reannounce more frequently
    // than this (except in the above cases), not even if user forces a reannounce.
    seconds interval;
    seconds min_interval;

    time_point last_announce_time;
    time_point last_scrape_time;

    // If there was an error with tracker, it will be kept here.
    std::error_code last_error;

    // The last warning message is stored here.
    std::string warning_message;
};

namespace util {

bool is_udp_tracker(string_view url) noexcept;
bool is_http_tracker(string_view url) noexcept;

} // namespace util
} // namespace tide

#endif // TIDE_TRACKER_HEADER
