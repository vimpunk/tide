#include "string_utils.hpp"
#include "tracker.hpp"
#include "bdecode.hpp"
#include "address.hpp"
#include "endian.hpp"

#include <sstream>
#include <algorithm>
#include <stdexcept>
#include <cassert>
#include <cmath> // pow

#include <cstdio> // printf  TODO remove

namespace tide {

std::vector<tcp::endpoint> parse_peers(string_view peers_string)
{
    assert(peers_string.length() % 6 == 0);
    const int num_peers = peers_string.length() / 6;
    std::vector<tcp::endpoint> peers;
    peers.reserve(num_peers);
    for(auto i = 0, offset = 0; i < num_peers; ++i, offset += 6)
    {
        // Endpoints are encoded as a 32 bit integer for the IP address and a
        // 16 bit integer for the port.
        address_v4 ip(endian::parse<uint32_t>(&peers_string[offset]));
        const uint16_t port = endian::parse<uint16_t>(&peers_string[offset] + 4);
        peers.emplace_back(std::move(ip), port);
    }
    return peers;
}

std::vector<peer_entry> parse_peers(const blist& peers_list)
{
    std::vector<peer_entry> peers;
    peers.reserve(peers_list.size());
    for(bmap peer : peers_list.all_bmaps())
    {
        string_view peer_id;
        string_view ip;
        int64_t port;
        peer.try_find_string_view("peer_id", peer_id);
        if(!peer.try_find_string_view("ip", ip)) continue;
        if(!peer.try_find_number("port", port)) continue;
        std::error_code ec;
        // TODO check for correctness, ip.data is not 0 terminated
        peer_entry entry;
        entry.endpoint = tcp::endpoint(
            address_v4::from_string(ip.data(), ec), port);
        if(ec) continue;
        std::copy(peer_id.begin(), peer_id.end(), entry.id.begin());
        peers.emplace_back(std::move(entry));
    }
    return peers;
}

// -------------
// tracker error
// -------------

std::string tracker_error_category::message(int env) const
{
    // TODO complete
    switch(static_cast<tracker_errc>(env))
    {
    case tracker_errc::invalid_response:
        return "Invalid response";
    case tracker_errc::wrong_response_type:
        return "Not the expected response type";
    case tracker_errc::wrong_response_length:
        return "Not the expected response length";
    case tracker_errc::invalid_transaction_id:
        return "Invalid transaction id";
    case tracker_errc::timed_out:
        return "Tracker timed out";
    default:
        return "Unknown error";
    }
}

const tracker_error_category& tracker_category()
{
    static tracker_error_category instance;
    return instance;
}

std::error_code make_error_code(tracker_errc e)
{
    return std::error_code(static_cast<int>(e), tracker_category());
}

std::error_condition make_error_condition(tracker_errc e)
{
    return std::error_condition(static_cast<int>(e), tracker_category());
}

// ------------
// tracker base
// ------------

tracker::tracker(std::string url, const settings& settings)
    : url_(std::move(url))
    , settings_(settings)
{}

template<typename... Args>
void tracker::log(const log_event event, const char* format, Args&&... args) const
{
    log(event, log::priority::normal, format, std::forward<Args>(args)...);
}

template<typename... Args>
void tracker::log(const log_event event, const log::priority priority,
    const char* format, Args&&... args) const
{
    std::stringstream ss;
    ss << url() << '|';
    switch(event)
    {
    case log_event::connecting: ss << "CONNECTING"; break;
    case log_event::incoming: ss << "IN"; break;
    case log_event::outgoing: ss << "OUT"; break;
    case log_event::invalid_message: ss << "INVALID MESSAGE"; break;
    case log_event::timeout: ss << "TIMEOUT"; break;
    }
    log::log_engine(ss.str(), util::format(format,
        std::forward<Args>(args)...), priority);
}

// ------------
// http tracker
// ------------

http_tracker::http_tracker(asio::io_context& ios,
    std::string host, const settings& settings)
    : tracker(host, settings)
    , socket_(ios)
    , resolver_(ios)
    , timeout_timer_(ios)
{}

void http_tracker::abort()
{
}

void http_tracker::announce(tracker_request parameters,
    std::function<void(const std::error_code&, tracker_response)> handler)
{
    execute_request<announce_request>(std::move(parameters), std::move(handler));
}

void http_tracker::scrape(std::vector<sha1_hash> info_hashes,
    std::function<void(const std::error_code&, scrape_response)> handler)
{
    execute_request<scrape_request>(std::move(info_hashes), std::move(handler));
}

template<typename Request, typename Parameters, typename Handler>
void http_tracker::execute_request(Parameters parameters, Handler handler)
{
    if(is_aborted_) { return; }

    auto r = std::make_unique<Request>();
    // TODO cache host
    r->payload.method(http::verb::get);
    r->payload.target(create_target_string(parameters));
    r->payload.set(http::field::host, util::extract_host(url_));
    r->payload.prepare_payload();
    r->handler = std::move(handler);
    requests_.emplace_back(std::move(r));

    if(!is_resolved_)
    {
        resolver_.async_resolve(
            tcp::resolver::query(tcp::v4(), util::extract_host(url_), ""),
            [this](const std::error_code& error, tcp::resolver::iterator it)
            { on_host_resolved(error, it); });
        const auto host = util::extract_host(url_);
        std::printf("host: %s\n", host.c_str());
        return;
    }

    execute_one_request();
}

void http_tracker::on_host_resolved(
    const std::error_code& error, tcp::resolver::iterator it)
{
    if(is_aborted_) { return; }
    if(error)
    {
        for(auto& request : requests_) { request->on_error(error); }
        return;
    }

    // If there was no error we must have a valid endpoint.
    endpoint_ = *it;
    endpoint_.port(util::extract_port(url_));
    is_resolved_ = true;

    log(log_event::connecting, "tracker (%s) resolved to: %s:%i",
        url_.c_str(), endpoint_.address().to_string().c_str(), endpoint_.port());

    execute_one_request();
}

void http_tracker::execute_one_request()
{
    if(is_requesting_ || requests_.empty()) { return; }

    // We may need to reopen socket if the previous HTTP connection closed it.
    if(!socket_.is_open())
    {
        std::error_code error;
        // Connect also opens socket.
        socket_.connect(endpoint_, error);
        if(error)
        {
            for(auto& request : requests_) { request->on_error(error); }
            return;
        }
    }

    is_requesting_ = true;
    auto& request = current_request();
    if(dynamic_cast<announce_request*>(&request))
    {
        http::async_write(socket_, request.payload,
            [this](const auto& error, const size_t num_bytes_sent)
            { on_message_sent(error, num_bytes_sent); });
        http::async_read(socket_, response_buffer_, response_,
            [this](const auto& error, const size_t num_bytes_received)
            { on_announce_response(error, num_bytes_received); });
    }
    else
    {
        http::async_write(socket_, request.payload,
            [this](const auto& error, const size_t num_bytes_sent)
            { on_message_sent(error, num_bytes_sent); });
        http::async_read(socket_, response_buffer_, response_,
            [this](const auto& error, const size_t num_bytes_received)
            { on_scrape_response(error, num_bytes_received); });
    }
    start_timeout();
}

inline void http_tracker::start_timeout()
{
    start_timer(timeout_timer_,
        current_request().num_retries == 0 ? seconds(15) : settings_.tracker_timeout,
        [this](const auto& error) { on_timeout(error); });
}

inline void http_tracker::on_timeout(const std::error_code& error)
{
    // If the timed out request was removed this is a false alarm.
    if(requests_.empty()) { return; }

    request& request = current_request();
    if(is_aborted_ || (error == asio::error::operation_aborted))
    {
        return;
    }
    else if(error)
    {
        request.on_error(error);
        return;
    }

    if(++request.num_retries < settings_.max_http_tracker_timeout_retries)
    {
        log(log_event::timeout, "retrying %s request",
            dynamic_cast<const announce_request*>(&request) ? "announce" : "scrape");
    }
    else
    {
        request.on_error(make_error_code(tracker_errc::timed_out));
        log(log_event::timeout, "%s request timed out after %i seconds of retrying",
            dynamic_cast<const announce_request*>(&request) ? "announce" : "scrape",
            15 + request.num_retries * settings_.max_http_tracker_timeout_retries);
        requests_.pop_front();
    }
    // Try to execute either this request again or another one.
    execute_one_request();
}

inline void http_tracker::on_message_sent(
    const std::error_code& error, const size_t num_bytes_sent)
{
    if((error != http::error::end_of_stream) && error)
    {
        on_request_error(error);
        return;
    }
}

inline void http_tracker::on_announce_response(
    const std::error_code& error, const size_t num_bytes_received)
{
    std::error_code ec;
    timeout_timer_.cancel(ec);
    ec.clear();
    // We reached EoS, i.e. the connection died, so we must close the socket.
    if(error == http::error::end_of_stream)
    {
        std::printf("EOF in announce response\n");
        socket_.shutdown(tcp::socket::shutdown_both, ec);
        socket_.close(ec);
        ec.clear();
        if(response_.body().empty())
        {
            // Response is empty which means that there was an error with our request.
            on_request_error(make_error_code(tracker_errc::invalid_response));
            return;
        }
    }
    else if(error)
    {
        on_request_error(error);
        return;
    }

    assert(!requests_.empty());
    assert(dynamic_cast<announce_request*>(&current_request()));
    auto& request = static_cast<announce_request&>(current_request());

    request.handler(ec, parse_announce_response(ec));
    requests_.pop_front();

    if(!requests_.empty()) { execute_one_request(); }
}

tracker_response http_tracker::parse_announce_response(std::error_code& error)
{
    auto resp_map = decode_bmap(response_.body(), error);
    if(error || resp_map.empty())
    {
        const auto& s = resp_map.to_string();
        log(log_event::invalid_message,
            "error decoding response bencode map: %s", s.c_str());
        return {};
    }

    tracker_response response;
    if(resp_map.try_find_string("failure reason", response.failure_reason))
    {
        // noop (when the failure reason field is set, no other field may be set)
    }
    else
    {
        resp_map.try_find_string("warning message", response.warning_message);
        resp_map.try_find_string("tracker id", response.tracker_id);
        int64_t buffer = 0;
        if(resp_map.try_find_number("complete", buffer))
            response.num_seeders = buffer;
        if(resp_map.try_find_number("incomplete", buffer))
            response.num_leechers = buffer;
        string_view peers_string;
        blist peers_list;
        if(resp_map.try_find_string_view("peers", peers_string))
        {
            response.ipv4_peers = parse_peers(peers_string);
        }
        else if(resp_map.try_find_blist("peers", peers_list))
        {
            response.peers = parse_peers(peers_list);
        }
        log(log_event::incoming,
            "received ANNOUNCE (interval: %i; num_leechers: %i;"
            " num_seeders: %i; num_peers: %i)",
            response.interval.count(), response.num_leechers,
            response.num_seeders, response.ipv4_peers.size() + response.peers.size());
    }
    return response;
}

inline void http_tracker::on_scrape_response(
    const std::error_code& error, const size_t num_bytes_received)
{
    std::error_code ec;
    timeout_timer_.cancel(ec);
    ec.clear();
    if(error)
    {
        on_request_error(error);
        return;
    }

    assert(!requests_.empty());
    assert(dynamic_cast<scrape_request*>(&current_request()));
    auto& request = static_cast<scrape_request&>(current_request());

    // TODO
}

std::string http_tracker::create_target_string(const tracker_request& r) const
{
    std::string target("/announce?");
    // required fields
    target += "info_hash=" + util::url_encode(r.info_hash.begin(), r.info_hash.end());
    target += "&peer_id=" + util::url_encode(r.peer_id.begin(), r.peer_id.end());
    target += "&port=" + std::to_string(r.port);
    target += "&uploaded=" + std::to_string(r.uploaded);
    target += "&downloaded=" + std::to_string(r.downloaded);
    target += "&left=" + std::to_string(r.left);
    // optional fields
    if(r.num_want > 0)
        target += "&numwant=" + std::to_string(r.num_want);
    if(r.compact)
        target += "&compact=1";
    else
        target += "&compact=0";
    if(r.no_peer_id)
        target += "&no_peer_id=1";
    else
        target += "&no_peer_id=0";
    if(!r.ip.empty())
        target += "&ip=" + r.ip;
    if(!r.tracker_id.empty())
        target += "&trackerid=" + r.tracker_id;
    return target;
}

std::string http_tracker::create_target_string(const std::vector<sha1_hash>& r) const
{
    std::string target("/scrape?");
    // TODO we must extract the scrape url from url, it's not the same as the announce url
    return target;
}

inline http_tracker::request& http_tracker::current_request() noexcept
{
    // FIXME this fired
    assert(!requests_.empty());
    return *requests_.front();
}

inline void http_tracker::on_request_error(const std::error_code& error)
{
    current_request().on_error(error);
    requests_.pop_front();
}

// -----------
// udp tracker
// -----------

inline udp_tracker::request::request(asio::io_context& ios, int32_t tid)
    : transaction_id(tid)
    , timeout_timer(ios)
{}

inline udp_tracker::announce_request::announce_request(
    asio::io_context& ios, int32_t tid, tracker_request p,
    std::function<void(const std::error_code&, tracker_response)> h
)
    : request(ios, tid)
    , parameters(std::move(p))
    , handler(std::move(h))
{}

inline udp_tracker::scrape_request::scrape_request(
    asio::io_context& ios, int32_t tid, std::vector<sha1_hash> i,
    std::function<void(const std::error_code&, scrape_response)> h
)
    : request(ios, tid)
    , info_hashes(std::move(i))
    , handler(std::move(h))
{}

udp_tracker::udp_tracker(asio::io_context& ios,
    const std::string& url, const settings& settings
)
    : tracker(/*util::strip_protocol_identifier(*/url/*)*/, settings)
    , socket_(ios)
    , resolver_(ios)
{}

udp_tracker::~udp_tracker()
{
    abort();
}

void udp_tracker::abort()
{
    is_aborted_ = true;
    std::error_code ec;
    for(auto& e : requests_) { e.second->timeout_timer.cancel(ec); }
    socket_.cancel();
    // It is reasonable to assume that we won't be needing receive buffer for now.
    receive_buffer_.reset();
    requests_.clear();
}

udp::endpoint udp_tracker::remote_endpoint() const noexcept
{
    return socket_.remote_endpoint();
}

udp::endpoint udp_tracker::local_endpoint() const noexcept
{
    return socket_.local_endpoint();
}

void udp_tracker::announce(tracker_request parameters,
    std::function<void(const std::error_code&, tracker_response)> handler)
{
    if(!is_aborted_)
    {
        execute_request(create_request_entry<announce_request>(
                std::move(parameters), std::move(handler)),
            [this](announce_request& r) { send_announce_request(r); });
    }
}

void udp_tracker::scrape(std::vector<sha1_hash> info_hashes,
    std::function<void(const std::error_code&, scrape_response)> handler)
{
    if(!is_aborted_)
    {
        execute_request(create_request_entry<scrape_request>(std::move(info_hashes),
            std::move(handler)), [this](scrape_request& r) { send_scrape_request(r); });
    }
}

template<typename Request, typename Parameters, typename Handler>
Request& udp_tracker::create_request_entry(Parameters parameters, Handler handler)
{
    const auto tid = create_transaction_id();
    // Return value is pair<iterator, bool>, and *iterator is pair<int, uptr<request>>.
    request& request = *requests_.emplace(tid,
        std::make_unique<Request>(socket_.get_io_context(), tid,
            std::move(parameters), std::move(handler))
    ).first->second;
    return static_cast<Request&>(request);
}

inline int udp_tracker::create_transaction_id()
{
    static int r = 0;
    return ++r;
}

template<typename Request, typename Function>
void udp_tracker::execute_request(Request& request, Function f)
{
    if(!is_resolved_)
    {
        resolver_.async_resolve(
            udp::resolver::query(udp::v4(), util::extract_host(url_), ""),
            [this](const std::error_code& error, udp::resolver::iterator it)
            { on_host_resolved(error, it); });
        return;
    }
    // connection_id to tracker remains valid for a minute after which we must claim
    // a new one by issuing a connect request 
    if(must_connect())
    {
        state_ = state::disconnected;
    }
    assert(socket_.is_open());

    switch(state_)
    {
    case state::disconnected:
        send_connect_request(request);
        break;
    case state::connecting:
        // Another torrent started a request but could not fully establish connection
        // to tracker before this request was started, so this request must wait till
        // the connection is set up.
        // This is done by marking request as connecting (even though this request is
        // not responsible for establishing the connection), and when the connection is
        // set up by the other requester, the execution of this request is resumed.
        request.action = action::connect;
        break;
    case state::connected:
        f(request);
        break;
    }
}

void udp_tracker::on_host_resolved(
    const std::error_code& error, udp::resolver::iterator it)
{
    if(is_aborted_) { return; }
    if(error)
    {
        // Host resolution is done on the first request, though it is possible that
        // other torrents have issued requests while this was working, so let all
        // of them know that we could not resolve host.
        for(auto& entry : requests_) { entry.second->on_error(error); }
        return;
    }

    // If there was no error we should have a valid endpoint.
    assert(it != udp::resolver::iterator());
    udp::endpoint ep(*it);
    ep.port(util::extract_port(url_));

    log(log_event::connecting, "tracker (%s) resolved to: %s:%i",
        url_.c_str(), ep.address().to_string().c_str(), ep.port());

    // Connect also opens socket.
    std::error_code ec;
    socket_.connect(ep, ec);
    if(ec)
    {
        for(auto& entry : requests_) { entry.second->on_error(error); }
        return;
    }
    is_resolved_ = true;
    resume_stalled_requests();
}

inline bool udp_tracker::must_connect() const noexcept
{
    return state_ != state::connecting
        && cached_clock::now() - last_connect_time_ >= minutes(1);
}

/**
 * Message format (length = 16):
 * int64_t protocol_id = 0x41727101980 // magic constant
 * int32_t action = 0 // connect
 * int32_t transaction_id // randomly choosen by us
 */
template<typename Request>
void udp_tracker::send_connect_request(Request& request)
{
    log(log_event::outgoing, "sending CONNECT (trans_id: %i)", request.transaction_id);
    state_ = state::connecting;
    request.action = action::connect;
    request.payload
        .i64(0x41727101980)
        .i32(action::connect)
        .i32(request.transaction_id);
    send_message(request, 16);
    receive_message();
}

/**
 * Message format (length = 16):
 * int32_t action = 0 // connect
 * int32_t transaction_id
 * int64_t connection_id
 */
inline void udp_tracker::handle_connect_response(
    request& request, const size_t num_bytes_received)
{
    if(num_bytes_received < 16)
    {
        if(request.num_retries < settings_.max_udp_tracker_timeout_retries)
        {
            retry(request);
        }
        else
        {
            had_protocol_error_ = true;
            request.on_error(make_error_code(tracker_errc::wrong_response_length));
            requests_.erase(request.transaction_id);
        }
        return;
    }

    state_ = state::connected;
    last_connect_time_ = cached_clock::now();
    connection_id_ = endian::parse<int64_t>(receive_buffer_->data() + 8);
    log(log_event::incoming, "received CONNECT (trans_id: %i, conn.id: %i)",
        request.transaction_id, connection_id_);
    // Continue requests that were stalled because we were connecting.
    resume_stalled_requests();
}

void udp_tracker::resume_stalled_requests()
{
    if(requests_.empty()) { return; }

    if(must_connect())
    {
        state_ = state::disconnected;
        request& r = *requests_.begin()->second;
        // TODO this is so fugly OMFG!!!!
        if(dynamic_cast<announce_request*>(&r))
            send_connect_request(static_cast<announce_request&>(r));
        else
            send_connect_request(static_cast<scrape_request&>(r));
        return;
    }

    // This doesn't guarantee in order execution--is this a problem?
    for(const auto& entry : requests_)
    {
        auto& r = *entry.second;
        if(r.action == action::connect)
        {
            if(dynamic_cast<announce_request*>(&r))
                send_announce_request(static_cast<announce_request&>(r));
            else
                send_scrape_request(static_cast<scrape_request&>(r));
        }
    }
}

/**
 * Message format (len 98):
 * int64_t connection_id
 * int32_t action = 1 // announce
 * int32_t transaction_id
 * 20-byte string info_hash
 * 20-byte string peer_id
 * int64_t downloaded
 * int64_t left
 * int64_t uploaded
 * int32_t event // 0: none; 1: completed; 2: started; 3: stopped
 * int32_t IP address // 0: default
 * int32_t key
 * int32_t num_want // -1: default
 * int16_t port
 */
void udp_tracker::send_announce_request(announce_request& request)
{
    request.action = action::announce_;
    tracker_request& parameters = request.parameters;

    log(log_event::outgoing,
        "sending ANNOUNCE (trans_id: %i; peer_id: %s; down: %lli;"
        " left: %lli; up: %lli; event: %s; num_want: %i; port: %i)",
        request.transaction_id, parameters.peer_id.data(), parameters.downloaded,
        parameters.left, parameters.uploaded, parameters.event == tracker_request::started
                ? "started" : parameters.event == tracker_request::completed
                    ? "completed" : parameters.event == tracker_request::stopped
                        ? "stopped" : "none",
        parameters.num_want, parameters.port);

    request.payload.clear();
    request.payload
        .i64(connection_id_)
        .i32(action::announce_)
        .i32(static_cast<int>(request.transaction_id))
        .buffer(parameters.info_hash)
        .buffer(parameters.peer_id)
        .i64(parameters.downloaded)
        .i64(parameters.left)
        .i64(parameters.uploaded)
        .i32(static_cast<int>(parameters.event))
        .i32(0) // IP address, we don't set this for now TODO
        .i32(0) // TODO key: what is this?
        .i32(parameters.num_want)
        .u16(parameters.port);
    send_message(request, 98);
    receive_message();
}

/**
 * Message format (length = 20 + n * (IPv6 ? 18 : 6))
 * int32_t action = 1 // announce
 * int32_t transaction_id
 * int32_t interval
 * int32_t leechers
 * int32_t seeders
 * n * <int32_t IP address, int16_t TCP port>
 */
inline void udp_tracker::handle_announce_response(
    announce_request& request, const size_t num_bytes_received)
{
    if((num_bytes_received < 20) || ((num_bytes_received - 20) % 6 != 0))
    {
        if(request.num_retries < settings_.max_udp_tracker_timeout_retries)
        {
            retry(request);
        }
        else
        {
            had_protocol_error_ = true;
            request.on_error(make_error_code(tracker_errc::wrong_response_length));
            requests_.erase(request.transaction_id);
        }
        return;
    }

    last_announce_time_ = cached_clock::now();

    // Skip the 4 byte action and 4 byte transaction_id fields.
    const char* buffer = receive_buffer_->data() + 8;
    tracker_response response;
    response.interval = seconds(endian::parse<int32_t>(buffer));
    response.num_leechers = endian::parse<int32_t>(buffer += 4);
    response.num_seeders = endian::parse<int32_t>(buffer += 4);
    buffer += 4;
    // TODO branch here depending on ipv4 or ipv6 request (but currently ipv6 isn't sup.)
    response.ipv4_peers = parse_peers(string_view(buffer, num_bytes_received - 20));

    log(log_event::incoming,
        "received ANNOUNCE (trans_id: %i; interval: %i; num_leechers: %i;"
        " num_seeders: %i; num_peers: %i)",
        request.transaction_id, response.interval.count(), response.num_leechers,
        response.num_seeders, response.ipv4_peers.size());

    auto handler = std::move(request.handler);
    requests_.erase(request.transaction_id);
    handler({}, std::move(response));
}

/**
 * Message format (length = 16 + n * 20):
 * int64_t connection_id
 * int32_t action = 2 // scrape
 * int32_t transaction_id
 * n * 20-byte string info_hash
 */
inline void udp_tracker::send_scrape_request(scrape_request& request)
{
    // TODO
}

/**
 * Message format (length = 8 + n * 12):
 * int32_t action = 2 // scrape
 * int32_t transaction_id
 * n * int32_t seeders
 * n * int32_t completed
 * n * int32_t leechers
 */
inline void udp_tracker::handle_scrape_response(
    scrape_request& request, const size_t num_bytes_received)
{
    // TODO
}

template<typename Request>
void udp_tracker::send_message(Request& request, const size_t num_bytes_to_send)
{
    assert(socket_.is_open());
    log(log_event::outgoing, "sending %i bytes (trans_id: %i)",
        num_bytes_to_send, request.transaction_id);
    socket_.async_send(asio::buffer(request.payload.data, num_bytes_to_send),
        [this, &request](const std::error_code& error, size_t num_bytes_sent)
        { on_message_sent(request, error, num_bytes_sent); });
    start_timeout(request);
}

inline void udp_tracker::on_message_sent(request& request,
    const std::error_code& error, const size_t num_bytes_sent)
{
    if(error)
    {
        // TODO depending on the error let everyone know
        request.on_error(error);
        requests_.erase(request.transaction_id);
        return;
    }

    log(log_event::outgoing, "sent %i bytes (trans_id: %i)",
        num_bytes_sent, request.transaction_id);

    switch(request.action)
    {
    case action::connect:
        assert(num_bytes_sent == 16); // TODO check if udp guarantees draining send buffer
        break;
    case action::announce_:
        assert(num_bytes_sent == 98);
        break;
    case action::scrape_:
        assert(num_bytes_sent == 16 + 20 *
            std::min(int(static_cast<scrape_request&>(request).info_hashes.size()), 74));
        break;
    }
}

inline void udp_tracker::receive_message()
{
    // Don't receive if we're already receiving or there are no requests that expect
    // a response.
    if(is_receiving_ || requests_.empty()) { return; }

    log(log_event::incoming, "preparing receive op");
    if(receive_buffer_ == nullptr)
    {
        receive_buffer_ = std::make_unique<std::array<char, 1500>>();
    }
    is_receiving_ = true;
    socket_.async_receive(asio::buffer(*receive_buffer_, receive_buffer_->max_size()),
        [this](const std::error_code& error, size_t num_bytes_received)
        { on_message_received(error, num_bytes_received); });
}

inline void udp_tracker::on_message_received(
    const std::error_code& error, const size_t num_bytes_received)
{
    if((error == asio::error::operation_aborted) || is_aborted_)
    {
        return;
    }
    else if((error == std::errc::timed_out) || (error == asio::error::timed_out))
    {
        is_reachable_ = false;
        // TODO we should probably let others know? and we should retry a few times
        return;
    }
    else if(error)
    {
        on_global_error(error);
        return;
    }

    is_receiving_ = false;

    if(num_bytes_received < 8)
    {
        // We need at least 8 bytes for the action and transaction_id.
        had_protocol_error_ = true;
        on_global_error(make_error_code(tracker_errc::wrong_response_length));
        return;
    }

    assert(receive_buffer_);
    const char* buffer = receive_buffer_->data();
    const int32_t action = endian::parse<int32_t>(buffer);
    const int32_t transaction_id = endian::parse<int32_t>(buffer + 4);
    if((action < action::connect) || (action > action::error))
    {
        had_protocol_error_ = true;
        on_global_error(make_error_code(tracker_errc::invalid_response));
        return;
    }

    // Now we have to find the request with this transaction id.
    auto it = requests_.find(transaction_id);
    if(it == requests_.end())
    {
        // Tracker sent us a bad transaction id, so we have no choice but let all pending
        // requests know (since we don't know to which requests this reply was addressed).
        on_global_error(make_error_code(tracker_errc::invalid_transaction_id));
        return;
    }

    request& request = *it->second;
    std::error_code ec;
    request.timeout_timer.cancel(ec);
    if((action != action::error) && (action != request.action))
    {
        request.on_error(make_error_code(tracker_errc::wrong_response_type));
        requests_.erase(request.transaction_id);
        // This request resulted in an error but others may not, so continue.
        receive_message();
        return;
    }

    log(log_event::incoming, "received %i bytes (trans_id: %i; action: %i)",
        num_bytes_received, request.transaction_id, action);

    switch(request.action)
    {
    case action::connect:
        handle_connect_response(request, num_bytes_received);
        break;
    case action::announce_:
        handle_announce_response(
            static_cast<announce_request&>(request), num_bytes_received);
        receive_message();
        break;
    case action::scrape_:
        handle_scrape_response(static_cast<scrape_request&>(request), num_bytes_received);
        receive_message();
        break;
    case action::error:
        handle_error_response(request, num_bytes_received);
        receive_message();
        break;
    }
}

/**
 * Message format:
 * int32_t action = 3 // error
 * int32_t transaction_id
 * string message
 */
inline void udp_tracker::handle_error_response(
    request& request, const size_t num_bytes_received)
{
    // Skip action and transaction_id fields.
    const auto buffer = receive_buffer_->data() + 8;
    const int error_msg_len = num_bytes_received - 8;
    // TODO this is a pretty ugly way to do "polymorphism", try to unify handler
    // invocation in the base class
    if(dynamic_cast<announce_request*>(&request))
    {
        tracker_response r;
        r.failure_reason = std::string(buffer, buffer + error_msg_len);
        log(log_event::incoming, "received announce ERROR (trans_id: %i; error_msg: %s)",
            request.transaction_id, r.failure_reason.c_str());
        static_cast<announce_request&>(request).handler({}, std::move(r));
    }
    else
    {
        scrape_response r;
        r.failure_reason = std::string(buffer, buffer + error_msg_len);
        log(log_event::incoming, "received scrape ERROR (trans_id: %i; error_msg: %s)",
            request.transaction_id, r.failure_reason.c_str());
        static_cast<scrape_request&>(request).handler({}, std::move(r));
    }
    requests_.erase(request.transaction_id);
}

inline void udp_tracker::on_global_error(const std::error_code& error)
{
    // TODO this is a place holder until a better solution is found
    for(auto& entry : requests_) { entry.second->on_error(error); }
    //requests_.clear();
    // TODO we want to remove pending requests -- probably?
}

inline void udp_tracker::start_timeout(request& request)
{
    start_timer(request.timeout_timer,
        seconds(15 * static_cast<size_t>(std::pow(2, request.num_retries))),
        [this, &request](const auto& error) { on_timeout(error, request); });
}

inline void udp_tracker::on_timeout(const std::error_code& error, request& request)
{
    if(is_aborted_ || (error == asio::error::operation_aborted))
    {
        return;
    }
    else if(error)
    {
        request.on_error(error);
        return;
    }

    if(request.num_retries < settings_.max_udp_tracker_timeout_retries)
    {
        retry(request);
    }
    else
    {
        request.on_error(make_error_code(tracker_errc::timed_out));
        log(log_event::timeout, "request#%i timed out after %i seconds of retrying",
            request.transaction_id, 15 * static_cast<size_t>(
                std::pow(2, request.num_retries)));
        requests_.erase(request.transaction_id);
    }
}

inline void udp_tracker::retry(request& request)
{
    ++request.num_retries;
    if(dynamic_cast<announce_request*>(&request))
        retry(static_cast<announce_request&>(request));
    else
        retry(static_cast<scrape_request&>(request));
}

inline void udp_tracker::retry(announce_request& request)
{
    log(log_event::timeout, "retrying announce request");
    execute_request(request, [this](announce_request& r) { send_announce_request(r); });
}

inline void udp_tracker::retry(scrape_request& request)
{
    log(log_event::timeout, "retrying scrape request");
    execute_request(request, [this](scrape_request& r) { send_scrape_request(r); });
}

// -----------------------
// tracker request builder
// -----------------------
// -- required --

tracker_request_builder& tracker_request_builder::info_hash(sha1_hash info_hash)
{
    request_.info_hash = info_hash;
    ++required_param_counter_;
    return *this;
}

tracker_request_builder& tracker_request_builder::peer_id(peer_id_t peer_id)
{
    request_.peer_id = peer_id;
    ++required_param_counter_;
    return *this;
}

tracker_request_builder& tracker_request_builder::port(uint16_t port)
{
    request_.port = port;
    ++required_param_counter_;
    return *this;
}

tracker_request_builder& tracker_request_builder::uploaded(int64_t uploaded)
{
    if(uploaded < 0)
    {
        throw std::invalid_argument("invalid 'uploaded' field in tracker request");
    }
    request_.uploaded = uploaded;
    ++required_param_counter_;
    return *this;
}

tracker_request_builder& tracker_request_builder::downloaded(int64_t downloaded)
{
    if(downloaded < 0)
    {
        throw std::invalid_argument("invalid 'downloaded' field in tracker request");
    }
    request_.downloaded = downloaded;
    ++required_param_counter_;
    return *this;
}

tracker_request_builder& tracker_request_builder::left(int64_t left)
{
    if(left < 0)
    {
        throw std::invalid_argument("invalid 'left' field in tracker request");
    }
    request_.left = left;
    ++required_param_counter_;
    return *this;
}

// -- optional --

tracker_request_builder& tracker_request_builder::compact(bool b)
{
    request_.compact = b;
    return *this;
}

tracker_request_builder& tracker_request_builder::no_peer_id(bool b)
{
    request_.no_peer_id = b;
    return *this;
}

tracker_request_builder& tracker_request_builder::event(int event)
{
    request_.event = event;
    return *this;
}

tracker_request_builder& tracker_request_builder::ip(std::string ip)
{
    std::error_code ec;
    address::from_string(ip, ec);
    if(ec)
    {
        throw std::invalid_argument("bad ip address in tracker_request_builder");
    }
    request_.ip = std::move(ip);
    return *this;
}

tracker_request_builder& tracker_request_builder::num_want(int num_want)
{
    request_.num_want = num_want;
    return *this;
}

tracker_request_builder& tracker_request_builder::tracker_id(std::string tracker_id)
{
    request_.tracker_id = std::move(tracker_id);
    return *this;
}

tracker_request tracker_request_builder::build()
{
    return request_;
}

namespace util {

bool is_udp_tracker(string_view url) noexcept
{
    static constexpr char udp[] = "udp://";
    return url.length() >= 3
        && std::equal(url.begin(), url.begin() + sizeof(udp) - 1, udp);
}

bool is_http_tracker(string_view url) noexcept
{
    static constexpr char http[] = "http://";
    return url.length() >= 3
        && std::equal(url.begin(), url.begin() + sizeof(http) - 1, http);
}

} // namespace util
} // namespace tide
