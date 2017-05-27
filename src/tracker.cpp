#include "tracker.hpp"
#include "bdecode.hpp"
#include "address.hpp"
#include "endian.hpp"

#include <stdexcept>

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

tracker_request_builder& tracker_request_builder::client_id(peer_id client_id)
{
    m_request.client_id = client_id;
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

tracker_request_builder& tracker_request_builder::event(tracker_request::event_t event)
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

std::string tracker_request_builder::build_url()
{
    if(m_required_param_counter != 6)
    {
        throw std::invalid_argument("missing required field(s) in tracker request");
    }

    std::string path = "?";
    // TODO
    return path;
}

// -------------------
// -- tracker error --
// -------------------

std::string tracker_error_category::message(int env) const
{
    switch(static_cast<tracker_errc>(env))
    {
    case tracker_errc::invalid_response:
        return "invalid response";
    case tracker_errc::response_too_small:
        return "response was below the minimum size for the message type";
    case tracker_errc::wrong_response_type:
        return "not the expected response type";
    case tracker_errc::timed_out:
        return "tracker timed out";
    default:
        return "unknown error";
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

tracker::tracker(std::string host, asio::io_service& ios, const settings& settings)
    : m_host(std::move(host))
    , m_ios(ios)
    , m_settings(settings)
    , m_timeout_timer(ios)
{
    assert(!m_host.empty());
}

// -----------------
// -- udp tracker --
// -----------------

udp_tracker::announce_request::announce_request(
    int32_t tid,
    tracker_request p,
    std::function<void(const std::error_code&, tracker_response)> h
)
    : request(tid)
    , params(std::move(p))
    , handler(std::move(h))
{}

udp_tracker::scrape_request::scrape_request(
    int32_t tid,
    std::vector<sha1_hash> i,
    std::function<void(const std::error_code&, scrape_response)> h
)
    : request(tid)
    , info_hashes(std::move(i))
    , handler(std::move(h))
{}

udp_tracker::udp_tracker(
    std::string host,
    asio::io_service& ios,
    const settings& settings,
    udp::resolver& resolver
)
    : tracker(std::move(host), ios, settings)
    , m_socket(ios)
    , m_resolver(resolver)
{}

udp_tracker::~udp_tracker()
{
    abort();
}

void udp_tracker::announce(
    tracker_request params,
    std::function<void(const std::error_code&, tracker_response)> handler)
{
    execute_request(
        create_request_entry<announce_request>(std::move(params), std::move(handler)),
        [this](announce_request& r)
        {
            send_announce_request(r);
        }
    );
}

void udp_tracker::scrape(
    std::vector<sha1_hash> info_hashes,
    std::function<void(const std::error_code&, scrape_response)> handler)
{
    execute_request(
        create_request_entry<scrape_request>(std::move(info_hashes), std::move(handler)),
        [this](scrape_request& r)
        {
            send_scrape_request(r);
        }
    );
}

template<typename Request, typename Params, typename Handler>
Request& udp_tracker::create_request_entry(Params params, Handler handler)
{
    const auto tid = create_transaction_id();
    // return value is pair<iterator, bool>, and *iterator is pair<int, uptr<request>>
    request& request = *m_requests.emplace(
        tid, std::make_unique<Request>(tid, std::move(params), std::move(handler))
    ).first->second;
    return static_cast<Request&>(request);
}

// TODO refactor this
template<typename Request, typename Function>
void udp_tracker::execute_request(Request& request, Function f)
{
    if(m_is_aborted)
    {
        return;
    }

    if(!m_socket.is_open())
    {
        std::error_code ec;
        m_socket.open(udp::v4(), ec);
        if(ec)
        {
            request.handler(ec, {});
            return;
        }
    }

    // if we don't have any endpoints yet, we haven't done a host resolution, or
    // we have, but didn't find anything; try again now and execute request once
    // DNS query finished
    const time_point now = cached_clock::now();
    if(m_dns_state == dns_state_t::not_resolved
       || (m_endpoints.empty() && (now - m_last_host_lookup_time > minutes(10))))
    {
        m_dns_state = dns_state_t::resolving;
        m_resolver.async_resolve(
            udp::resolver::query(m_host, 0), // port is ignored
            [this](const std::error_code& error, udp::resolver::iterator it)
            {
                on_host_lookup(error, it);
            }
        );
        return;
    }

    // connection_id to tracker remains valid for a minute after which we must claim
    // a new one by issueing a connect request
    if((m_state != state_t::disconnected) && (now - m_last_connect_time > minutes(1)))
    {
        m_state = state_t::disconnected;
    }

    switch(m_state)
    {
    case state_t::disconnected:
        connect_to_tracker(request);
        break;
    case state_t::connecting:
        // another torrent started a request but could not fully establish connection
        // to tracker before this request was started, so this request must wait till
        // the connection is set up
        // this is done by marking request as connecting (even though this request is
        // not responsible for establishing the connection), and when the connection is
        // set up by the other requester, the execution of this request is resumed
        request.action = action_t::connect;
        break;
    case state_t::connected:
        f(request);
        break;
    }
}

void udp_tracker::abort()
{
    m_is_aborted = true;
    m_resolver.cancel();
    m_timeout_timer.cancel();
    m_socket.cancel();
    // it is reasonable to assume that we won't be needing receive buffer for now
    m_receive_buffer.clear();
    m_requests.clear();
}

void udp_tracker::on_host_lookup(
    const std::error_code& error, udp::resolver::iterator it)
{
    if(m_is_aborted)
    {
        return;
    }
    if(error)
    {
        // TODO
        return;
    }
    while(it != udp::resolver::iterator())
    {
        target t;
        t.endpoint = *it++;
        m_endpoints.emplace_back(std::move(t));
    }
    m_dns_state = dns_state_t::resolved;
    m_last_host_lookup_time = cached_clock::now();
}

inline void udp_tracker::connect_to_tracker(announce_request& request)
{
    request.payload.clear();
    request.payload
        .i64(0x41727101980)
        .i32(action_t::connect)
        .i32(request.transaction_id);
    send_connect_request(request);
}

inline void udp_tracker::connect_to_tracker(scrape_request& request)
{
    request.payload.data.clear();
    request.payload
        .i64(0x41727101980)
        .i32(action_t::connect)
        .i32(request.transaction_id);
    send_connect_request(request);
}

// Message format (length = 16):
// int64_t protocol_id = 0x41727101980 // magic constant
// int32_t action = 0 // connect
// int32_t transaction_id // randomly choosen by us
inline void udp_tracker::send_connect_request(request& request)
{
    m_state = state_t::connecting;
    request.action = action_t::connect;
    choose_target();
    assert(m_socket.is_open());
    send_message(request, 16);
    receive_message(16);
}

// Message format (length = 16):
// int32_t action = 0 // connect
// int32_t transaction_id
// int64_t connection_id
inline void udp_tracker::handle_connect_response(
    request& request, const size_t num_bytes_received)
{
    if(num_bytes_received < 16)
    {
        on_global_error(make_error_code(tracker_errc::response_too_small));
        //request.on_error(make_error_code(tracker_errc::response_too_small));
        //m_requests.erase(request.transaction_id);
        return;
    }

    m_state = state_t::connected;
    m_last_connect_time = cached_clock::now();
    m_connection_id = detail::parse<int64_t>(m_receive_buffer.data() + 8);
    resume_stalled_requests();
}

inline void udp_tracker::resume_stalled_requests()
{
    // TODO this doesn't guarantee in order execution -- is this a problem?
    for(const auto& entry : m_requests)
    {
        auto& r = *entry.second;
        if(r.action == action_t::connect)
        {
            if(dynamic_cast<announce_request*>(&r))
            {
                send_announce_request(static_cast<announce_request&>(r));
            }
            else
            {
                send_scrape_request(static_cast<scrape_request&>(r));
            }
        }
    }
}

// Message format (len 98):
// int64_t connection_id
// int32_t action = 1 // announce
// int32_t transaction_id
// 20-byte string info_hash
// 20-byte string peer_id
// int64_t downloaded
// int64_t left
// int64_t uploaded
// int32_t event // 0: none; 1: completed; 2: started; 3: stopped
// int32_t IP address // 0: default
// int32_t key
// int32_t num_want // -1: default
// int16_t port
void udp_tracker::send_announce_request(announce_request& request)
{
    request.action = action_t::announce_1;
    tracker_request& params = request.params;
    request.payload.clear();
    request.payload
        .i64(m_connection_id)
        .i32(action_t::announce_1)
        .i32(request.transaction_id)
        .buffer(params.info_hash)
        .buffer(params.client_id)
        .i64(params.downloaded)
        .i64(params.left)
        .i64(params.uploaded)
        .i32(static_cast<int>(params.event))
        .i32(0) // IP address, we don't set this for now TODO
        .i32(0) // TODO key: what is this?
        .i32(params.num_want)
        .i16(params.port);
    send_message(request, 98);
    receive_message(20 + params.num_want * 6);
}

// Message format (length = ipv4: 20 + n * 6; ipv6: 20 + n * 18):
// int32_t action = 1 // announce
// int32_t transaction_id
// int32_t interval
// int32_t leechers
// int32_t seeders
// n * <int32_t IP address, int16_t TCP port>
inline void udp_tracker::handle_announce_response(
    announce_request& request, const size_t num_bytes_received)
{
    // remove handler from request because we remove request before calling handler
    auto handler = std::move(request.handler);
    std::error_code ec;

    if((num_bytes_received < 20) || ((num_bytes_received - 20) % 6 != 0))
    {
        ec = make_error_code(tracker_errc::response_too_small);
        handler(ec, {});
        return;
    }

    // skip the 4 byte action and 4 byte transaction_id fields
    const uint8_t* buffer = m_receive_buffer.data() + 8;
    tracker_response response;
    response.interval = detail::parse<int32_t>(buffer);
    response.num_leechers = detail::parse<int32_t>(buffer += 4);
    response.num_seeders = detail::parse<int32_t>(buffer += 4);
    // TODO branch here depending on ipv4 or ipv6 request (but currently ipv6 isn't sup.)
    // endpoints are encoded as a 32 bit integer for the IP address and a 16 bit integer
    // for the port
    const int num_peers = (num_bytes_received - 20) / 6;
    response.ipv4_peers.reserve(num_peers);
    for(auto i = 0; i < num_peers; ++i, buffer += 6)
    {
        address_v4 ip(detail::parse<uint32_t>(buffer));
        const uint16_t port = detail::parse<uint16_t>(buffer + 4);
        response.ipv4_peers.emplace_back(std::move(ip), port);
    }

    m_requests.erase(request.transaction_id);
    handler(ec, std::move(response));
}

// Message format (length = 16 + n * 20):
// int64_t connection_id
// int32_t action = 2 // scrape
// int32_t transaction_id
// n * 20-byte string info_hash
inline void udp_tracker::send_scrape_request(scrape_request& request)
{
    // TODO
}

// Message format (length = 8 + n * 12):
// int32_t action = 2 // scrape
// int32_t transaction_id
// n * int32_t seeders
// n * int32_t completed
// n * int32_t leechers
inline void udp_tracker::handle_scrape_response(
    scrape_request& request, const size_t num_bytes_received)
{
    // TODO
}

inline void udp_tracker::send_message(request& request, const size_t num_bytes_to_send)
{
    assert(m_current_target);
    m_socket.async_send_to(
        asio::buffer(request.send_buffer(), num_bytes_to_send),
        m_current_target->endpoint,
        [this, &request](const std::error_code& error, size_t num_bytes_sent)
        {
            on_message_sent(request, error, num_bytes_sent);
        }
    );
}

inline void udp_tracker::on_message_sent(
    request& request, const std::error_code& error, const size_t num_bytes_sent)
{
    if(error)
    {
        request.on_error(error);
        m_requests.erase(request.transaction_id);
        return;
    }

    switch(request.action)
    {
    case action_t::connect:
        assert(num_bytes_sent == 16); // TODO check if udp guarantees draining send buffer
        break;
    case action_t::announce_1:
        assert(num_bytes_sent == 98);
        break;
    case action_t::scrape_1:
        break;
    }
}

inline void udp_tracker::receive_message(const size_t num_bytes_to_receive)
{
    assert(m_current_target);
    if(m_is_receiving)
    {
        // TODO resuming receiving response to request is a bit of a problem
        return;
    }
    if(m_receive_buffer.size() < num_bytes_to_receive)
    {
        m_receive_buffer.resize(num_bytes_to_receive);
    }
    m_socket.async_receive_from(
        asio::buffer(m_receive_buffer, num_bytes_to_receive),
        m_current_target->endpoint,
        [this](const std::error_code& error, size_t num_bytes_received)
        {
            on_message_received(error, num_bytes_received);
        }
    );
    m_timeout_timer.expires_from_now(seconds(m_settings.tracker_timeout_s));
    m_timeout_timer.async_wait([this](const std::error_code& error)
    {
        handle_timeout(error);
    });
}

inline void udp_tracker::on_message_received(
    const std::error_code& error, const size_t num_bytes_received)
{
    if(error)
    {
        on_global_error(error);
        return;
    }

    // even if the received message will not pass the following postcondition check, we
    // could reach host before the timeout timer cancelled the operation, so clear its
    // timeout marker
    assert(m_current_target);
    m_current_target->has_timed_out = false;

    std::error_code ec;
    check_receive_postconditions(ec, num_bytes_received);
    if(ec)
    {
        on_global_error(error);
        return;
    }

    // TODO
    const auto buffer = m_receive_buffer.data();
    const auto action = static_cast<action_t>(detail::parse<int32_t>(buffer));
    const auto transaction_id = detail::parse<int32_t>(buffer + 4);
    // now we have to find the request with this transaction id
    auto it = m_requests.find(transaction_id);
    if(it == m_requests.end())
    {
        // tracker sent us a bad transaction id, so we have no choice but let everyone
        // know
        on_global_error(make_error_code(tracker_errc::invalid_transaction_id));
        return;
    }
    request = *it->second;
    if((action != action_t::error) && (action != request.action))
    {
        // we didn't get an announce
        request.on_error(make_error_code(tracker_errc::wrong_response_type));
        m_requests.erase(request.transaction_id);
        return;
    }

    switch(request.action)
    {
    case action_t::connect:
        handle_connect_response(request, num_bytes_received);
        break;
    case action_t::announce_1:
        handle_announce_response(request, num_bytes_received);
        break;
    case action_t::scrape_1:
        handle_scrape_response(request, num_bytes_received);
        break;
    case action_t::error:
        handle_error_response(request, num_bytes_received);
        break;
    }
}

inline void udp_tracker::check_receive_postconditions(
    std::error_code& error, const size_t num_bytes_received)
{
    if(m_is_aborted)
    {
        error = std::make_error_code(std::errc::operation_aborted);
    }
    else if(num_bytes_received < 8)
    {
        // we need at least 8 bytes for the action and transaction_id
        error = make_error_code(tracker_errc::response_too_small);
    }
}

// Message format:
// int32_t action = 3 // error
// int32_t transaction_id
// string message
inline void udp_tracker::handle_error_response(
    request& request, const size_t num_bytes_received)
{
    // skip action and transaction_id fields
    const auto buffer = request.receive_buffer.data() + 8;
    const int error_msg_length = num_bytes_received - 8;
    const announce_request* announce = dynamic_cast<announce_request*>(&request);
    if(announce)
    {
        tracker_response r;
        r.failure_reason = std::string(buffer, buffer + error_msg_len);
        announce->handler({}, std::move(r));
    }
    else
    {
        const scrape_request* scrape = static_cast<scrape_request*>(&request)
        assert(scrape);
        scrape_response r;
        r.failure_reason = std::string(buffer, buffer + error_msg_len);
        scrape->handler({}, std::move(r));
    }
    m_requests.erase(request.transaction_id);
}

inline void udp_tracker::on_global_error(const std::error_code& error)
{
    for(auto& entry : m_requests)
    {
        entry.second->on_error(error);
    }
    m_requests.clear();
    m_receive_buffer.clear();
}

void udp_tracker::handle_timeout(request& request, const std::error_code& error)
{
    if(m_is_aborted)
    {
        on_global_error(std::make_error_code(std::errc::operation_aborted));
        return;
    }
    else if(error)
    {
        on_global_error(error);
        return;
    }

    // we try to contact another endpoint, but if we pick one that we couldn't reach
    // in the past and ever since, we assume all endpoints are unreachable, so notify
    // caller of the error; otherwise we resend all pending requests to the newly picked
    // endpoint
    assert(m_current_target);
    m_current_target->has_timed_out = true;
    choose_target();
    if(m_current_target->is_unreachable || !m_current_target->has_timed_out)
    {
        request.on_error(make_error_code(tracker_errc::timed_out));
        m_requests.erase(request.transaction_id);
    }
    else
    {
        //TODO
        //resend_outstanding_requests();
    }
}

inline int udp_tracker::create_transaction_id()
{
    static int r = 0;
    return ++r;
}

inline void udp_tracker::choose_target() const
{
    assert(!m_endpoints.empty());
    // endpoints may have failed previously so find one that we haven't marked as
    // failed, otherwise pick the first one and see if it works this time
    for(const auto& t : m_endpoints)
    {
        if(!t.is_unreachable && !t.has_timed_out)
        {
            m_current_target = &t;
            return;
        }
    }
    m_current_target = &m_endpoints.front();
}
