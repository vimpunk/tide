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

namespace tide {

// -------------------
// -- tracker error --
// -------------------

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

// ------------------
// -- tracker base --
// ------------------

tracker::tracker(std::string url, asio::io_service& ios, const settings& settings)
    : m_url(std::move(url))
    , m_settings(settings)
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

// ------------------
// -- http tracker --
// ------------------
// TODO

// -----------------
// -- udp tracker --
// -----------------

inline udp_tracker::request::request(asio::io_service& ios, int32_t tid)
    : transaction_id(tid)
    , timeout_timer(ios)
{}

inline udp_tracker::announce_request::announce_request(
    asio::io_service& ios, int32_t tid, tracker_request p,
    std::function<void(const std::error_code&, tracker_response)> h
)
    : request(ios, tid)
    , params(std::move(p))
    , handler(std::move(h))
{}

inline udp_tracker::scrape_request::scrape_request(
    asio::io_service& ios, int32_t tid, std::vector<sha1_hash> i,
    std::function<void(const std::error_code&, scrape_response)> h
)
    : request(ios, tid)
    , info_hashes(std::move(i))
    , handler(std::move(h))
{}

udp_tracker::udp_tracker(const std::string& url,
    asio::io_service& ios, const settings& settings
)
    : tracker(/*util::strip_protocol_identifier(*/url/*)*/, ios, settings)
    , m_socket(ios)
    , m_resolver(ios)
{}

udp_tracker::~udp_tracker()
{
    abort();
}

void udp_tracker::abort()
{
    m_is_aborted = true;
    std::error_code ec;
    for(auto& e : m_requests) { e.second->timeout_timer.cancel(ec); }
    m_socket.cancel();
    // it is reasonable to assume that we won't be needing receive buffer for now
    m_receive_buffer.reset();
    m_requests.clear();
}

udp::endpoint udp_tracker::remote_endpoint() const noexcept
{
    return m_socket.remote_endpoint();
}

udp::endpoint udp_tracker::local_endpoint() const noexcept
{
    return m_socket.local_endpoint();
}

void udp_tracker::announce(tracker_request params,
    std::function<void(const std::error_code&, tracker_response)> handler)
{
    if(!m_is_aborted)
    {
        execute_request(create_request_entry<announce_request>(
                std::move(params), std::move(handler)),
            [this](announce_request& r) { send_announce_request(r); });
    }
}

void udp_tracker::scrape(std::vector<sha1_hash> info_hashes,
    std::function<void(const std::error_code&, scrape_response)> handler)
{
    if(!m_is_aborted)
    {
        execute_request(create_request_entry<scrape_request>(std::move(info_hashes),
            std::move(handler)), [this](scrape_request& r) { send_scrape_request(r); });
    }
}

template<typename Request, typename Params, typename Handler>
Request& udp_tracker::create_request_entry(Params params, Handler handler)
{
    const auto tid = create_transaction_id();
    // return value is pair<iterator, bool>, and *iterator is pair<int, uptr<request>>
    request& request = *m_requests.emplace(tid,
        std::make_unique<Request>(m_socket.get_io_service(), tid,
            std::move(params), std::move(handler))
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
    if(!m_is_resolved)
    {
        m_resolver.async_resolve(
            udp::resolver::query(udp::v4(), util::extract_host(url()), ""),
            [this](const std::error_code& error, udp::resolver::iterator it)
            { on_host_resolved(error, it); });
        return;
    }
    // connection_id to tracker remains valid for a minute after which we must claim
    // a new one by issuing a connect request 
    if(must_connect())
    {
        m_state = state::disconnected;
    }
    assert(m_socket.is_open());

    switch(m_state)
    {
    case state::disconnected:
        send_connect_request(request);
        break;
    case state::connecting:
        // another torrent started a request but could not fully establish connection
        // to tracker before this request was started, so this request must wait till
        // the connection is set up
        // this is done by marking request as connecting (even though this request is
        // not responsible for establishing the connection), and when the connection is
        // set up by the other requester, the execution of this request is resumed
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
    if(m_is_aborted) { return; }
    if(error)
    {
        // host resolution is done on the first request, though it is possible that
        // other torrents have issued requests while this was working, so let all
        // of them know that we could not resolve host
        for(auto& entry : m_requests) { entry.second->on_error(error); }
        return;
    }

    // if there was no error we should have a valid endpoint
    assert(it != udp::resolver::iterator());
    udp::endpoint ep(*it);
    ep.port(util::extract_port(m_url));

    log(log_event::connecting, "tracker (%s) resolved to: %s:%i",
        m_url.c_str(), ep.address().to_string().c_str(), ep.port());

    // connect also opens socket
    std::error_code ec;
    m_socket.connect(ep, ec);
    if(ec)
    {
        for(auto& entry : m_requests) { entry.second->on_error(error); }
        return;
    }
    m_is_resolved = true;
    resume_stalled_requests();
}

inline bool udp_tracker::must_connect() const noexcept
{
    return m_state != state::connecting
        && cached_clock::now() - m_last_connect_time >= minutes(1);
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
    m_state = state::connecting;
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
        if(request.num_retries < m_settings.max_udp_tracker_timeout_retries)
        {
            retry(request);
        }
        else
        {
            m_had_protocol_error = true;
            request.on_error(make_error_code(tracker_errc::wrong_response_length));
            m_requests.erase(request.transaction_id);
        }
        return;
    }

    m_state = state::connected;
    m_last_connect_time = cached_clock::now();
    m_connection_id = endian::parse<int64_t>(m_receive_buffer->data() + 8);
    log(log_event::incoming, "received CONNECT (trans_id: %i, conn.id: %i)",
        request.transaction_id, m_connection_id);
    // continue requests that were stalled because we were connecting
    resume_stalled_requests();
}

void udp_tracker::resume_stalled_requests()
{
    if(m_requests.empty()) { return; }

    if(must_connect())
    {
        m_state = state::disconnected;
        request& r = *m_requests.begin()->second;
        // TODO this is so fugly OMFG!!!!
        if(dynamic_cast<announce_request*>(&r))
            send_connect_request(static_cast<announce_request&>(r));
        else
            send_connect_request(static_cast<scrape_request&>(r));
        return;
    }

    // this doesn't guarantee in order execution--is this a problem?
    for(const auto& entry : m_requests)
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
    tracker_request& params = request.params;

    log(log_event::outgoing,
        "sending ANNOUNCE (trans_id: %i; peer_id: %s; down: %lli;"
        " left: %lli; up: %lli; event: %s; num_want: %i; port: %i)",
        request.transaction_id, params.peer_id.data(), params.downloaded,
        params.left, params.uploaded, params.event == tracker_request::started
                ? "started" : params.event == tracker_request::completed
                    ? "completed" : params.event == tracker_request::stopped
                        ? "stopped" : "none",
        params.num_want, params.port);

    request.payload.clear();
    request.payload
        .i64(m_connection_id)
        .i32(action::announce_)
        .i32(static_cast<int>(request.transaction_id))
        .buffer(params.info_hash)
        .buffer(params.peer_id)
        .i64(params.downloaded)
        .i64(params.left)
        .i64(params.uploaded)
        .i32(static_cast<int>(params.event))
        .i32(0) // IP address, we don't set this for now TODO
        .i32(0) // TODO key: what is this?
        .i32(params.num_want)
        .u16(params.port);
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
        if(request.num_retries < m_settings.max_udp_tracker_timeout_retries)
        {
            retry(request);
        }
        else
        {
            m_had_protocol_error = true;
            request.on_error(make_error_code(tracker_errc::wrong_response_length));
            m_requests.erase(request.transaction_id);
        }
        return;
    }

    m_last_announce_time = cached_clock::now();

    // skip the 4 byte action and 4 byte transaction_id fields
    const uint8_t* buffer = m_receive_buffer->data() + 8;
    tracker_response response;
    response.interval = seconds(endian::parse<int32_t>(buffer));
    response.num_leechers = endian::parse<int32_t>(buffer += 4);
    response.num_seeders = endian::parse<int32_t>(buffer += 4);
    buffer += 4;
    // TODO branch here depending on ipv4 or ipv6 request (but currently ipv6 isn't sup.)
    const int num_peers = (num_bytes_received - 20) / 6;
    response.ipv4_peers.reserve(num_peers);
    for(auto i = 0; i < num_peers; ++i, buffer += 6)
    {
        // endpoints are encoded as a 32 bit integer for the IP address and a 16 bit
        // integer for the port
        address_v4 ip(endian::parse<uint32_t>(buffer));
        const uint16_t port = endian::parse<uint16_t>(buffer + 4);
        response.ipv4_peers.emplace_back(std::move(ip), port);
    }

    log(log_event::incoming,
        "received ANNOUNCE (trans_id: %i; interval: %i; num_leechers: %i;"
        " num_seeders: %i; num_peers: %i)",
        request.transaction_id, response.interval, response.num_leechers,
        response.num_seeders, num_peers);

    auto handler = std::move(request.handler);
    m_requests.erase(request.transaction_id);
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
    assert(m_socket.is_open());
    log(log_event::outgoing, "sending %i bytes (trans_id: %i)",
        num_bytes_to_send, request.transaction_id);
    m_socket.async_send(asio::buffer(request.payload.data, num_bytes_to_send),
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
        m_requests.erase(request.transaction_id);
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
    // don't receive if we're already receiving or there are no requests that expect
    // a response
    if(m_is_receiving || m_requests.empty()) { return; }

    log(log_event::incoming, "preparing receive op");
    if(m_receive_buffer == nullptr)
    {
        m_receive_buffer = std::make_unique<std::array<uint8_t, 1500>>();
    }
    m_is_receiving = true;
    m_socket.async_receive(asio::buffer(*m_receive_buffer, m_receive_buffer->max_size()),
        [this](const std::error_code& error, size_t num_bytes_received)
        { on_message_received(error, num_bytes_received); });
}

inline void udp_tracker::on_message_received(
    const std::error_code& error, const size_t num_bytes_received)
{
    if((error == asio::error::operation_aborted) || m_is_aborted)
    {
        return;
    }
    else if((error == std::errc::timed_out) || (error == asio::error::timed_out))
    {
        m_is_reachable = false;
        // TODO we should probably let others know? and we should retry a few times
        return;
    }
    else if(error)
    {
        on_global_error(error);
        return;
    }

    m_is_receiving = false;

    if(num_bytes_received < 8)
    {
        // we need at least 8 bytes for the action and transaction_id
        m_had_protocol_error = true;
        on_global_error(make_error_code(tracker_errc::wrong_response_length));
        return;
    }

    assert(m_receive_buffer);
    const uint8_t* buffer = m_receive_buffer->data();
    const int32_t action = endian::parse<int32_t>(buffer);
    const int32_t transaction_id = endian::parse<int32_t>(buffer + 4);
    if((action < action::connect) || (action > action::error))
    {
        m_had_protocol_error = true;
        on_global_error(make_error_code(tracker_errc::invalid_response));
        return;
    }

    // now we have to find the request with this transaction id
    auto it = m_requests.find(transaction_id);
    if(it == m_requests.end())
    {
        // tracker sent us a bad transaction id, so we have no choice but let all pending
        // requests know (since we don't know to which requests this reply was addressed)
        on_global_error(make_error_code(tracker_errc::invalid_transaction_id));
        return;
    }

    request& request = *it->second;
    std::error_code ec;
    request.timeout_timer.cancel(ec);
    if((action != action::error) && (action != request.action))
    {
        request.on_error(make_error_code(tracker_errc::wrong_response_type));
        m_requests.erase(request.transaction_id);
        // this request resulted in an error but others may not, so continue
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
    // skip action and transaction_id fields
    const auto buffer = m_receive_buffer->data() + 8;
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
    m_requests.erase(request.transaction_id);
}

inline void udp_tracker::on_global_error(const std::error_code& error)
{
    // TODO this is a place holder until a better solution is found
    for(auto& entry : m_requests) { entry.second->on_error(error); }
    //m_requests.clear();
    // TODO we want to remove pending requests -- probably?
}

inline void udp_tracker::start_timeout(request& request)
{
    request.timeout_timer.expires_from_now(
        seconds(15 * static_cast<size_t>(std::pow(2, request.num_retries))));
    request.timeout_timer.async_wait([this, &request](const std::error_code& error)
        { handle_timeout(error, request); });
}

inline void udp_tracker::handle_timeout(const std::error_code& error, request& request)
{
    if(m_is_aborted || (error == asio::error::operation_aborted))
    {
        return;
    }
    else if(error)
    {
        request.on_error(error);
        return;
    }

    if(request.num_retries < m_settings.max_udp_tracker_timeout_retries)
    {
        retry(request);
    }
    else
    {
        request.on_error(make_error_code(tracker_errc::timed_out));
        log(log_event::timeout, "request#%i timed out after %i seconds of retrying",
            request.transaction_id, 15 * static_cast<size_t>(
                std::pow(2, request.num_retries)));
        m_requests.erase(request.transaction_id);
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

// -----------------------------
// -- tracker request builder --
// -----------------------------
// -- required --
// --------------

tracker_request_builder& tracker_request_builder::info_hash(sha1_hash info_hash)
{
    m_request.info_hash = info_hash;
    ++m_required_param_counter;
    return *this;
}

tracker_request_builder& tracker_request_builder::peer_id(peer_id_t peer_id)
{
    m_request.peer_id = peer_id;
    ++m_required_param_counter;
    return *this;
}

tracker_request_builder& tracker_request_builder::port(uint16_t port)
{
    m_request.port = port;
    ++m_required_param_counter;
    return *this;
}

tracker_request_builder& tracker_request_builder::uploaded(int64_t uploaded)
{
    if(uploaded < 0)
    {
        throw std::invalid_argument("invalid 'uploaded' field in tracker request");
    }
    m_request.uploaded = uploaded;
    ++m_required_param_counter;
    return *this;
}

tracker_request_builder& tracker_request_builder::downloaded(int64_t downloaded)
{
    if(downloaded < 0)
    {
        throw std::invalid_argument("invalid 'downloaded' field in tracker request");
    }
    m_request.downloaded = downloaded;
    ++m_required_param_counter;
    return *this;
}

tracker_request_builder& tracker_request_builder::left(int64_t left)
{
    if(left < 0)
    {
        throw std::invalid_argument("invalid 'left' field in tracker request");
    }
    m_request.left = left;
    ++m_required_param_counter;
    return *this;
}

// --------------
// -- optional --
// --------------

tracker_request_builder& tracker_request_builder::compact(bool b)
{
    m_request.compact = b;
    return *this;
}

tracker_request_builder& tracker_request_builder::no_peer_id(bool b)
{
    m_request.no_peer_id = b;
    return *this;
}

tracker_request_builder& tracker_request_builder::event(int event)
{
    m_request.event = event;
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
    m_request.ip = std::move(ip);
    return *this;
}

tracker_request_builder& tracker_request_builder::num_want(int num_want)
{
    m_request.num_want = num_want;
    return *this;
}

tracker_request_builder& tracker_request_builder::tracker_id(std::string tracker_id)
{
    m_request.tracker_id = std::move(tracker_id);
    return *this;
}

tracker_request tracker_request_builder::build()
{
    return m_request;
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
