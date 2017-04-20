#include "bandwidth_controller.hpp"
#include "piece_download_pool.hpp"
#include "piece_download.hpp"
#include "piece_picker.hpp"
#include "peer_session.hpp"
#include "torrent_info.hpp"
#include "settings.hpp"
#include "disk_io.hpp"
#include "payload.hpp"
#include "view.hpp"

#include <algorithm>
#include <stdexcept>
#include <cassert>
#include <string>
#include <cmath>
#include <cstdio> // snprintf

using namespace std::placeholders;

template<typename Bytes> block_info parse_block_info(const Bytes& data);

/**
 * Used when we expect successive writes to socket to amortize the overhead of context
 * switches by blocking (corking) the socket until we're done and writing the accrued
 * messages in one batch.
 */
class peer_session::send_cork
{
    peer_session& m_peer_session;
    bool m_should_uncork = false;

public:

    explicit send_cork(peer_session& p) : m_peer_session(p)
    {
        if(!m_peer_session.m_work_state.is(sending))
        {
            // block other send operations by pretending to be sending
            m_peer_session.m_work_state.started(sending);
            m_should_uncork = true;
        }
    }

    ~send_cork()
    {
        if(m_should_uncork)
        {
            m_peer_session.m_work_state.stopped(sending);
            m_peer_session.send();
        }
    }
};

peer_session::peer_session(
    std::unique_ptr<tcp::socket> socket,
    tcp::endpoint peer_endpoint,
    disk_io& disk_io,
    bandwidth_controller& bandwidth_controller,
    const settings& settings
)
    : m_socket(std::move(socket))
    , m_disk_io(disk_io)
    , m_bandwidth_controller(bandwidth_controller)
    , m_settings(settings)
    , m_connect_timeout_timer(m_socket->get_io_service())
    , m_keep_alive_timer(m_socket->get_io_service())
    , m_request_timeout_timer(m_socket->get_io_service())
    , m_inactivity_timeout_timer(m_socket->get_io_service())
{
    assert(m_socket);
    m_info.peer_endpoint = std::move(peer_endpoint);
    //m_info.
}

peer_session::peer_session(
    std::unique_ptr<tcp::socket> socket,
    tcp::endpoint peer_endpoint,
    disk_io& disk_io,
    bandwidth_controller& bandwidth_controller,
    const settings& settings,
    torrent_specific_args torrent_args
)
    : peer_session(
        std::move(socket),
        std::move(peer_endpoint),
        disk_io,
        bandwidth_controller,
        settings
    )
{
    m_piece_picker = torrent_args.picker;
    m_piece_download_pool = torrent_args.pool;
    m_torrent_info = torrent_args.info;

    assert(m_piece_download_pool);
    assert(m_torrent_info);

    m_info.torrent_id = m_torrent_info->id;
    m_info.is_outbound = true;

    // if the download pool is null in an outgoing connection, it means we're seeding
    // (since there is no need for a download pool for seeding)
    if(m_piece_download_pool == nullptr)
    {
        m_info.am_seed = true;
    }

    connect();
}

peer_session::peer_session(
    std::unique_ptr<tcp::socket> socket,
    tcp::endpoint peer_endpoint,
    disk_io& disk_io,
    bandwidth_controller& bandwidth_controller,
    const settings& settings,
    std::function<torrent_specific_args(const sha1_hash&)> torrent_attacher
)
    : peer_session(
        std::move(socket),
        std::move(peer_endpoint),
        disk_io,
        bandwidth_controller,
        settings
    )
{
    m_torrent_attacher = std::move(torrent_attacher);
    m_info.is_outbound = false;
    connect();
}

peer_session::~peer_session()
{
    disconnect(peer_session_error_t::unknown);
}

inline void peer_session::connect()
{
    std::error_code ec;
    m_socket->open(m_info.peer_endpoint.protocol(), ec);
    if(ec)
    {
        disconnect(ec);
        return;
    }

    // set socket to non-blocking
    m_socket->non_blocking(true, ec);
    if(ec)
    {
        disconnect(ec);
        return;
    }

    m_socket->async_connect(
        m_info.peer_endpoint,
        [this](const std::error_code& error)
        {
            on_connected(error);
        }
    );
    m_info.state = peer_info::state_t::connecting;
    m_connection_time = cached_clock::now();

    start_timer(
        m_connect_timeout_timer,
        seconds(m_settings.peer_connect_timeout_s),
        [this](const std::error_code& error)
        {
            handle_connect_timeout(error);
        }
    );
}

void peer_session::on_connected(const std::error_code& error)
{
    std::error_code ec;
    m_connect_timeout_timer.cancel(ec);
    if(ec)
    {
        disconnect(ec);
        return;
    }

    if(error)
    {
        disconnect(error);
        return;
    }

    m_connected_time = cached_clock::now();
    log(
        log_event::connected,
        "connected to %s in %ims",
        m_info.peer_endpoint.address().to_string(),
        total_milliseconds(m_connected_time - m_connection_time)
    );

    m_info.local_endpoint = m_socket->local_endpoint(ec);
    if(ec)
    {
        disconnect(ec);
        return;
    }

    m_info.state = peer_info::state_t::in_handshake;

    if(m_settings.encryption_policy == settings::encryption_policy_t::no_encryption)
    {
        if(m_info.is_outbound)
        {
            send_handshake();
        }
        // otherwise send_handshake() is called after we received peer's handshake
        receive();
    }
    else
    {
        assert(false && "currently only no_encryption policy is supported");
    }

    start_timer(
        m_keep_alive_timer,
        seconds(m_settings.peer_timeout_s),
        [this](const std::error_code& error)
        {
            handle_keep_alive_timeout(error);
        }
    );
}

void peer_session::disconnect(const std::error_code& error)
{
    // return if we're already disconnecting (should this happen though? can happen
    // with the timer helper methods)
    if(is_disconnecting() || is_finished())
    {
        return;
    }

    std::error_code ec;
    m_keep_alive_timer.cancel(ec);
    m_inactivity_timeout_timer.cancel(ec);
    // we don't care about timer errors at this point

    if(m_piece_picker != nullptr)
    {
        m_piece_picker->decrease_frequency(m_info.available_pieces);
    }

    // if we have any pending requests, tell their corresponding piece downloads that
    // we won't get the blocks
    abort_our_requests();

    m_info.state = peer_info::state_t::disconnecting;

    m_socket->close(ec);
    if(ec)
    {
        // uhm?
    }

    // TODO finish

    m_info.state = peer_info::state_t::stopped;
    m_work_state.started(idle);
}

void peer_session::abort_our_requests()
{
    std::error_code ec;
    m_request_timeout_timer.cancel(ec);
    if(ec)
    {
        disconnect(ec);
        return;
    }
    // TODO VERIFY THIS
    auto piece_download = m_piece_downloads.end();
    // tell each download that we won't get our requested blocks
    for(const auto& block : m_sent_requests)
    {
        // it is likely that most of the current requests belong to one piece download,
        // so cache it TODO
        if(piece_download == m_piece_downloads.end()
           || (*piece_download)->piece_index() != block.index)
        {
            piece_download = std::find_if(
                m_piece_downloads.begin(),
                m_piece_downloads.end(),
                [index = block.index](const auto& download)
                {
                    return download->piece_index() == index;
                }
            );
        }
        if(piece_download != m_piece_downloads.end())
        {
            (*piece_download)->abort_download(block);
        }
    }
}

void peer_session::choke_peer()
{
    if(!is_ready_to_send() || m_info.is_peer_choked)
    {
        return;
    }
    // TODO abort serving requests
    for(const auto& block : m_received_requests)
    {
        m_disk_io.abort_block_fetch(m_info.torrent_id, block);
    }
    m_received_requests.clear();
    send_choke();
}

void peer_session::unchoke_peer()
{
    if(is_ready_to_send() && m_info.is_peer_choked)
    {
        send_unchoke();
    }
}

void peer_session::announce_new_piece(const piece_index_t piece)
{
    // don't send a have msg if peer has it
    if(is_ready_to_send() && !m_info.available_pieces[piece])
    {
        // send_have() is called by torrent when a new piece is received, so recalculate
        // whether we're interested in this peer, for we may have received the only piece
        // peer has in which we were interested.
        determine_if_interested();
        send_have(piece);
    }
}

void peer_session::determine_if_interested()
{
    const bool was_interested = m_info.am_interested;
    m_info.am_interested = m_piece_picker->am_interested_in(m_info.available_pieces);

    if(!was_interested && m_info.am_interested)
    {
        std::error_code ec;
        m_inactivity_timeout_timer.cancel(ec);
        if(ec)
        {
            disconnect(ec);
            return;
        }

        send_interested();
        if(!m_info.am_choked)
        {
            send_requests();
        }
    }
    else if(was_interested && !m_info.am_interested)
    {
        send_not_interested();
        // if peer isn't interested either, we enter a state of inactivity, so we must
        // guard against idling too long
        if(!m_info.is_peer_interested)
        {
            start_timer(
                m_inactivity_timeout_timer,
                minutes(10),
                [this](const std::error_code& error)
                {
                    handle_inactivity_timeout(error);
                }
            );
        }
    }
}

void peer_session::adjust_best_request_queue_length() noexcept
{
    if(m_info.has_peer_timed_out)
    {
        m_best_request_queue_length = 1;
        return;
    }
    // TODO
    m_best_request_queue_length = m_info.piece_down_rate / 0x4000; // 16 KiB
}

// -----------------------
// -- sending to socket --
// -----------------------

void peer_session::send()
{
    if(is_disconnecting() || is_finished())
    {
        return;
    }

    request_upload_bandwidth();

    if(!can_send())
    {
        if(m_send_buffer.is_empty())
        {
            log(log_event::outgoing, "send buffer empty");
        }
        else
        {
            log(log_event::outgoing, "can't send");
        }
        return;
    }

    const int num_bytes_to_send = std::min(m_send_buffer.size(), m_info.send_quota);
    m_socket->async_write_some(
        m_send_buffer.get_send_buffers(num_bytes_to_send),
        [this](const std::error_code& error, size_t num_bytes_sent)
        {
            on_send(error, num_bytes_sent);
        }
    );
    m_work_state.started(sending);

    log(
        log_event::outgoing,
        "sending/available bytes: %i/%i; quota left: %i",
        num_bytes_to_send,
        m_send_buffer.size(),
        m_info.send_quota
    );
}

bool peer_session::can_send() const noexcept
{
    return !m_work_state.is(sending)
        && !m_send_buffer.is_empty()
        && m_info.send_quota > 0;
}

void peer_session::request_upload_bandwidth()
{
    // TODO
}

void peer_session::on_send(const std::error_code& error, size_t num_bytes_sent)
{
    m_send_buffer.consume(num_bytes_sent);
    record_sent_bytes(num_bytes_sent);

    if(error)
    {
        log(log_event::outgoing, "error while sending");
        disconnect(error);
        return;
    }

    m_info.send_quota -= num_bytes_sent;
    m_last_send_time = cached_clock::now();
    m_work_state.stopped(sending);

    log(
        log_event::outgoing,
        "sent bytes: %i; quota left: %i; send buffer size: %i",
        num_bytes_sent,
        m_info.send_quota,
        m_send_buffer.size()
    );

    // this call to send() will only write to socket again if during the first write
    // there were more bytes in send buffer to send than we had quota for, and since the
    // first thing in send is asking for more bandwidth quota, we may be able to send
    // off the rest of the send buffer's contents.
    // TODO determine if this conjecture is correct: isn't send -> callback invocation
    // faster than we could reasonably expect more bandwidth to be allocated? is this
    // superfluous?
    send();
}

inline void peer_session::record_sent_bytes(const int num_bytes_sent) noexcept
{
    //m_stats.record_sent_bytes(num_bytes_sent);
    m_info.total_uploaded_bytes += num_bytes_sent;
    m_torrent_info->total_uploaded_bytes += num_bytes_sent;
}

// ---------------------------
// -- receiving from socket --
// ---------------------------

void peer_session::receive()
{
    if(is_disconnecting() || is_finished())
    {
        return;
    }

    request_download_bandwidth();
    if(!can_receive())
    {
        if(m_info.receive_quota <= 0)
        {
            log(log_event::incoming, "can't receive, no receive quota");
        }
        else if(m_work_state.is(receiving))
        {
            log(log_event::incoming, "can't receive, already receiving");
        }
        else if(am_expecting_piece()
                && m_work_state.is(reading_disk)
                && m_disk_io.is_overwhelmed())
        {
            log(log_event::incoming, "can't receive, disk too saturated");
        }
        return;
    }

    // pending bytes written to disk are also counted as part of the receive buffer
    const auto max_receive_size = m_message_parser.free_space_size()
                                - m_info.num_pending_disk_write_bytes;
    const auto num_to_receive = std::min(max_receive_size, m_info.receive_quota);
    if(num_to_receive == 0)
    {
        return;
    }

    view<uint8_t> buffer = m_message_parser.get_receive_buffer(num_to_receive);
    m_socket->async_read_some(
        asio::mutable_buffers_1(buffer.data(), buffer.size()),
        [this](const std::error_code& error, size_t num_bytes_received)
        {
            on_receive(error, num_bytes_received);
        }
    );
    m_work_state.started(receiving);

    log(
        log_event::incoming,
        "receiving bytes: %i; receive buffer free space: %i; quota left: %i",
        num_to_receive,
        m_message_parser.free_space_size(),
        m_info.receive_quota
    );
}

bool peer_session::can_receive() const noexcept
{
    if(am_expecting_piece()
       && m_work_state.is(reading_disk)
       && m_disk_io.is_overwhelmed())
    {
        return false;
    }
    return (m_info.receive_quota > 0) && !m_work_state.is(receiving);
}

void peer_session::request_download_bandwidth()
{
    // TODO
}

void peer_session::on_receive(const std::error_code& error, size_t num_bytes_received)
{
    if(error)
    {
        log(log_event::incoming, "error while receiving");
        disconnect(error);
        return;
    }

    m_message_parser.record_received_bytes(num_bytes_received);
    // if we completely filled up receive buffer it may mean socket has some bytes left
    if(m_message_parser.is_full())
    {
        // flush_socket will reserve buffer space if there is still data in socket
        num_bytes_received += flush_socket();
    }

    m_info.receive_quota -= num_bytes_received;
    m_last_receive_time = cached_clock::now();
    record_received_bytes(num_bytes_received);

    log(
        log_event::incoming,
        "received bytes: %i; quota left: %i; message parser buffer (used/avail.): %i/%i",
        num_bytes_received,
        m_info.receive_quota,
        m_message_parser.size(),
        m_message_parser.buffer_size()
    );

    if(is_disconnecting())
    {
        // flush_socket() spurred a disconnect
        return;
    }

    const bool was_choked = m_info.am_choked;
    handle_messages();
    if(is_disconnecting())
    {
        // handle_messages() spurred a disconnect
        return;
    }
    // react to receive data and grow or shrink receive buffer accordingly
    adjust_receive_buffer(was_choked, num_bytes_received);
    m_work_state.stopped(receiving);

    receive();
}

inline void peer_session::record_received_bytes(const int num_bytes_received) noexcept
{
    //m_stats.record_record_bytes(num_bytes_sent);
    m_info.total_downloaded_bytes += num_bytes_received;
    m_torrent_info->total_downloaded_bytes += num_bytes_received;
}

inline void peer_session::adjust_receive_buffer(
    const bool was_choked,
    const int num_bytes_received
)
{
    const int buffer_size = m_message_parser.buffer_size();
    const bool got_choked = !was_choked && m_info.am_choked;

    if(should_grow_receive_buffer(got_choked, num_bytes_received))
    {
        m_message_parser.reserve(m_message_parser.buffer_size() * 2);
        log(
            log_event::incoming,
            "grew receive buffer form %i to %i",
            buffer_size,
            m_message_parser.buffer_size()
        );
    }
    else if(num_bytes_received < 0.1 * m_message_parser.buffer_size()
            && !am_expecting_piece()
            && !m_info.am_interested)
    {
        // shrink buffer if the number of bytes received in the last read is small and
        // we don't expect pieces TODO consider if necessary
        //m_message_parser.shrink_to_fit(m_message_parser.buffer_size() * 0.3);
    }
    else if(got_choked)
    {
        // we're choked, 100 bytes should suffice to receive further protocol chatter
        m_message_parser.shrink_to_fit(100);
        log(
            log_event::incoming,
            "shrunk receive buffer form %i to %i",
            buffer_size,
            m_message_parser.buffer_size()
        );
    }
}

inline bool peer_session::should_grow_receive_buffer(
    const bool got_choked,
    const int num_bytes_received
) const noexcept
{
    assert(m_settings.max_receive_buffer_size != -1);
    // grow if we didn't get choked and filled the buffer, or if we didn't get choked
    // and we're expecting a block and don't have space for it (and we can't exceed the
    // user set max buffer size)
    return !got_choked
        && m_message_parser.buffer_size() < m_settings.max_receive_buffer_size
        && (num_bytes_received == m_message_parser.buffer_size())
            || (am_expecting_piece() && (m_message_parser.free_space_size() < 0x4000));
}

inline bool peer_session::am_expecting_piece() const noexcept
{
    return (m_info.num_pending_download_bytes > 0) && !m_info.am_choked;
}

inline int peer_session::flush_socket()
{
    assert(m_message_parser.is_full());
    // we may not have read all of the available bytes buffered in socket: try sync read
    // remaining bytes
    std::error_code ec;
    const int num_available_bytes = m_socket->available(ec);
    if(ec)
    {
        disconnect(ec);
    }
    else if(num_available_bytes > 0)
    {
        m_message_parser.reserve(m_message_parser.buffer_size() + num_available_bytes);
        view<uint8_t> buffer = m_message_parser.get_receive_buffer(num_available_bytes);
        const auto num_bytes_read = m_socket->read_some(
            asio::mutable_buffers_1(buffer.data(), buffer.size()), ec
        );
        if((ec == asio::error::would_block) || (ec == asio::error::try_again))
        {
            // this is not an error, don't disconnect
        }
        else if(ec)
        {
            disconnect(ec);
        }
        else
        {
            log(log_event::incoming, "sync read %i bytes from socket", num_bytes_read);
            m_message_parser.record_received_bytes(num_bytes_read);
            return num_bytes_read;
        }
    }
    return 0;
}

// ----------------------
// -- message handling --
// ----------------------

inline void peer_session::handle_messages()
{
    if(m_info.state == peer_info::state_t::in_handshake)
    {
        if(m_message_parser.has_handshake())
        {
            handle_handshake();
        }
        // otherwise we don't have the full handshake yet, so receive more bytes and
        // come back to try again (receive is called at the end of on_send, after this
        // function returns)
        return;
    }
    else if(m_info.state == peer_info::state_t::bitfield_exchange)
    {
        // we can set the state to connected here (handle_bitfield() won't test this),
        // so we don't have to set it twice due to the early exit below
        m_info.state = peer_info::state_t::connected;
        if(m_message_parser.type() == message_t::bitfield)
        {
            handle_bitfield();
        }
    }

    // send response messages at the end of the function in one batch
    send_cork cork(*this);
    while(!is_disconnecting() && m_message_parser.has_message())
    {
        switch(m_message_parser.type())
        {
        case message_t::bitfield:
            // bitfield messages are only received right after the handshake
            handle_illicit_bitfield();
            break;
        case message_t::keep_alive:
            handle_keep_alive();
            break;
        case message_t::choke:
            handle_choke();
            break;
        case message_t::unchoke:
            handle_unchoke();
            break;
        case message_t::interested:
            handle_interested();
            break;
        case message_t::not_interested:
            handle_not_interested();
            break;
        case message_t::have:
            handle_have();
            break;
        case message_t::request:
            handle_request();
            break;
        case message_t::block:
            handle_block();
            break;
        case message_t::cancel:
            handle_cancel();
            break;
        default:
            handle_unknown_message();
        }
    }
}

void peer_session::handle_handshake()
{
    handshake handshake;
    try
    {
        handshake = m_message_parser.extract_handshake();
    }
    catch(const std::runtime_error& error)
    {
        log(log_event::invalid_message, "couldn't parse handshake");
        disconnect(peer_session_error_t::invalid_handshake);
        return;
    }

    sha1_hash info_hash;
    for(int i = 0; i < info_hash.size(); ++i)
    {
        info_hash[i] = handshake.info_hash[i];
    }

    torrent_specific_args args = m_torrent_attacher(info_hash);
    if(args.info == nullptr)
    {
        // this means we couldn't find a torrent to which we could be attached, likely
        // due to peer's bad info_hash
        disconnect(peer_session_error_t::invalid_info_hash);
        return;
    }

    m_piece_picker = args.picker;
    m_piece_download_pool = args.pool;
    m_torrent_info = args.info;

    if(m_piece_download_pool == nullptr)
    {
        m_info.am_seed = true;
    }

    if(!m_info.is_outbound)
    {
        // if the connection was initiated by peer, we still need to send our handshake
        send_handshake();
    }
    // move on to the next stage
    m_info.state = peer_info::state_t::bitfield_exchange;
    send_bitfield();
}

inline void peer_session::handle_bitfield()
{
    assert(m_info.state == peer_info::state_t::bitfield_exchange);

    message msg = m_message_parser.extract();
    const int num_pieces = m_torrent_info->num_pieces;
    if(!bt_bitfield::is_bitfield_data_valid(msg.data, num_pieces))
    {
        // peer sent an invalid bitfield, disconnect immediately
        disconnect(peer_session_error_t::invalid_info_hash);
        return;
    }

    m_info.available_pieces = bt_bitfield(msg.data, num_pieces);
    m_info.is_peer_seed = m_info.available_pieces.are_all_set();

    // check if we're interested in peer now that we know its piece availability
    determine_if_interested();
}

inline void peer_session::handle_keep_alive()
{
    m_message_parser.skip();
    // NOP TODO perhaps consider doing something. this message means peer hasn't sent
    // anything in a while, so maybe we should incentivize it to send sth somehow?
}

inline void peer_session::handle_choke()
{
    if(m_message_parser.extract().data.size() != 1)
    {
        log(log_event::invalid_message, "wrong choke message length");
        disconnect(peer_session_error_t::invalid_choke_message);
        return;
    }
    if(!m_info.am_choked)
    {
        m_info.am_choked = true;
        abort_our_requests();
    }
    m_info.num_pending_download_bytes = 0;
    m_last_incoming_choke_time = cached_clock::now();
}

inline void peer_session::handle_unchoke()
{
    if(m_message_parser.extract().data.size() != 1)
    {
        log(log_event::invalid_message, "wrong unchoke message length");
        disconnect(peer_session_error_t::invalid_unchoke_message);
        return;
    }
    if(m_info.am_choked)
    {
        m_info.am_choked = false;
    }
    m_last_incoming_unchoke_time = cached_clock::now();

    if(m_info.am_interested)
    {
        send_requests();
    }
}

inline void peer_session::handle_interested()
{
    if(m_message_parser.extract().data.size() != 1)
    {
        log(log_event::invalid_message, "wrong interested message length");
        disconnect(peer_session_error_t::invalid_interested_message);
        return;
    }
    if(!m_info.is_peer_interested)
    {
        m_info.is_peer_interested = true;

        std::error_code ec;
        m_inactivity_timeout_timer.cancel(ec);
        if(ec)
        {
            disconnect(ec);
            return;
        }
    }
    m_last_incoming_interest_time = cached_clock::now();
}

inline void peer_session::handle_not_interested()
{
    if(m_message_parser.extract().data.size() != 1)
    {
        log(log_event::invalid_message, "wrong not_interested message length");
        disconnect(peer_session_error_t::invalid_not_interested_message);
        return;
    }
    if(m_info.is_peer_interested)
    {
        m_info.is_peer_interested = false;
        if(!m_info.am_interested)
        {
            // we aren't interested either, so we enter a state of inactivity, so we must
            // guard against idling too long
            start_timer(
                m_inactivity_timeout_timer,
                minutes(10),
                [this](const std::error_code& error)
                {
                    handle_inactivity_timeout(error);
                }
            );
        }
    }
    m_last_incoming_uninterest_time = cached_clock::now();
}

inline void peer_session::handle_have()
{
    message msg = m_message_parser.extract();
    if(msg.data.size() != 4)
    {
        log(log_event::invalid_message, "wrong have message length");
        disconnect(peer_session_error_t::invalid_have_message);
        return;
    }

    const piece_index_t piece = parse_i32(msg.data.begin());
    if(!is_piece_index_valid(piece))
    {
        log(log_event::invalid_message, "invalid piece index in have message");
        disconnect(peer_session_error_t::invalid_have_message);
        return;
    }
    if(m_info.available_pieces[piece])
    {
        // got a redundant have message
        return;
    }

    m_piece_picker->increase_frequency(piece);
    m_info.available_pieces.set(piece);
    // only need to recalculate if we're not already interested
    if(!m_info.am_interested)
    {
        determine_if_interested();
    }
}

inline void peer_session::handle_request()
{

    message msg = m_message_parser.extract();
    if(msg.data.size() != 3 * 4)
    {
        log(log_event::invalid_message, "wrong request message length");
        disconnect(peer_session_error_t::invalid_request_message);
        return;
    }

    if(m_info.is_peer_choked)
    {
        handle_illicit_request();
        return;
    }
    else if(!m_info.is_peer_interested)
    {
        // peer is not choked but according to our data it is not interested either, so
        // pretend that we got an interested message as peer's may have gotten lost
        m_info.is_peer_interested = true;
        m_last_incoming_interest_time = cached_clock::now();
    }

    const block_info block_info = parse_block_info(msg.data);
    if(!is_request_valid(block_info))
    {
        log(
            log_event::invalid_message,
            "invalid request (piece: %i, offset: %i, length: %i)",
            block_info.index,
            block_info.offset,
            block_info.length
        );
        disconnect(peer_session_error_t::invalid_request_message);
        return;
    }

    if(should_accept_request(block_info))
    {
        // at this point we can serve the request
        m_last_incoming_request_time = cached_clock::now();
        m_received_requests.emplace_back(block_info);
        m_disk_io.fetch_block(
            m_info.torrent_id,
            block_info,
            [this](const std::error_code& error, block_source block)
            {
                on_block_read(error, block);
            }
        );
        m_work_state.started(reading_disk);
        m_info.num_pending_disk_read_bytes += block_info.length;

        log(
            log_event::disk,
            "disk read launched, serving request (piece: %i, offset: %i, length: %i)",
            block_info.index,
            block_info.offset,
            block_info.length
        );
    }
}

inline bool peer_session::should_accept_request(const block_info& block) const noexcept
{
    // TODO check if max block size is still enforced
    // don't serve request if peer reached its max allowed outstanding requests or
    // if the requested block is larger than 16KiB
    return m_received_requests.size() < m_max_pending_requests
        || block.length <= 0x4000;
}

inline void peer_session::handle_cancel()
{
    message msg = m_message_parser.extract();
    if(msg.data.size() != 1 + 3 * 4)
    {
        log(log_event::invalid_message, "wrong cancel message length");
        disconnect(peer_session_error_t::invalid_cancel_message);
        return;
    }

    const block_info block_info = parse_block_info(msg.data);
    if(!is_request_valid(block_info))
    {
        log(
            log_event::invalid_message,
            "invalid cancel (piece: %i, offset: %i, length: %i)",
            block_info.index,
            block_info.offset,
            block_info.length
        );
        disconnect(peer_session_error_t::invalid_cancel_message);
        return;
    }

    auto request = std::find_if(
        m_received_requests.begin(),
        m_received_requests.end(),
        [&block_info](const auto& request)
        {
            return block_info == request;
        }
    );
    if(request != m_received_requests.cend())
    {
        m_disk_io.abort_block_fetch(m_info.torrent_id, block_info);
        m_received_requests.erase(request);

        log(
            log_event::disk,
            "disk abort launched, cancelling request (piece: %i, offset: %i, length: %i)",
            block_info.index,
            block_info.offset,
            block_info.length
        );
    }
}

void peer_session::handle_block()
{
    message msg = m_message_parser.extract();
    if(msg.data.size() < 12)
    {
        log(log_event::invalid_message, "wrong block message length");
        disconnect(peer_session_error_t::invalid_block_message);
        return;
    }

    const block_info block_info = parse_block_info(msg.data);
    if(!is_block_info_valid(block_info))
    {
        log(
            log_event::invalid_message,
            "invalid block (piece: %i, offset: %i, length: %i)",
            block_info.index,
            block_info.offset,
            block_info.length
        );
        disconnect(peer_session_error_t::invalid_block_message);
        return;
    }

    auto request = std::find_if(
        m_sent_requests.begin(),
        m_sent_requests.end(),
        [&block_info](const auto& request)
        {
            return block_info.index == request.index
                && block_info.offset == request.offset
                && block_info.length == request.length;
        }
    );
    if(request == m_sent_requests.cend())
    {
        // we're not expecting this block (give 2 second slack)
        if(!m_info.am_interested
           && cached_clock::now() - m_last_outgoing_uninterest_time > seconds(2))
        {
            handle_illicit_block();
        }
        else
        {
            handle_unexpected_block(block_info, std::move(msg));
        }
        return;
    }
    // erase request from queue as we either got it or no longer expect it
    m_sent_requests.erase(request);

    if(block_info.length == 0)
    {
        // this is used by BitComet to reject messages, I think // TODO
        //handle_rejected_request(block_info);
        return;
    }

    const auto request_rtt = cached_clock::now() - m_last_outgoing_request_time;
    m_avg_request_time.add_sample(total_milliseconds(request_rtt));

    if((request_rtt < request_timeout()) && m_info.has_peer_timed_out)
    {
        // peer has timed out before but managed to deliver this time
        m_info.has_peer_timed_out = false;
    }
    else if(request_rtt > request_timeout())
    {
        m_info.has_peer_timed_out = true;
    }
    adjust_best_request_queue_length();

    if(m_piece_picker->my_bitfield()[block_info.index])
    {
        // we already have this piece
        log(
            log_event::incoming,
            "already have block (piece: %i, offset: %i, length: %i)",
            block_info.index,
            block_info.offset,
            block_info.length
        );
        m_info.total_wasted_bytes += block_info.length;
        return;
    }

    if(!m_sent_requests.empty())
    {
        // there are still outstanding requests, reset request timeout timer
        start_timer(
            m_request_timeout_timer,
            request_timeout(),
            [this](const std::error_code& error)
            {
                handle_request_timeout(error);
            }
        );
        if(is_disconnecting())
        {
            return;
        }
    }

    // now find the piece download corresponding to this request
    auto it = std::find_if(
        m_piece_downloads.begin(),
        m_piece_downloads.end(),
        [index = block_info.index](const auto& download)
        {
            return download->piece_index() == index;
        }
    );
    assert(
        it != m_piece_downloads.end() && "there is no corresponding piece download for"
        "this request, which shouldn't happen; it means that you accidentaly forgot to"
        "remove a request from m_send_requests when removing a piece download"
    );
    auto& piece_download = *it;
    piece_download->got_block(
        m_info.peer_id,
        block_info,
        [this, piece = block_info.index](const bool is_piece_good)
        {
            on_piece_hashed(piece, is_piece_good);
        }
    );

    m_info.num_pending_download_bytes -= block_info.length;
    m_last_incoming_block_time = cached_clock::now();

    m_disk_io.save_block(
        m_info.torrent_id,
        block_info,
        std::vector<uint8_t>(msg.data.begin() + 8, msg.data.end()),
        [this, block_info](const std::error_code& error)
        {
            on_block_saved(error, block_info);
        },
        [this, piece_download](const bool is_piece_good)
        {
            piece_download->notify_all_of_hash_result(is_piece_good);
        }
    );
    m_work_state.started(writing_disk);
    m_info.num_pending_disk_write_bytes += block_info.length;

    log(
        log_event::disk, 
        "launched disk write, saving block (piece: %i, offset: %i, length: %i)",
        block_info.index,
        block_info.offset,
        block_info.length
    );
}

inline bool peer_session::is_request_valid(const block_info& request) const noexcept
{
    return m_piece_picker->my_bitfield()[request.index] && is_block_info_valid(request);
}

inline bool peer_session::is_block_info_valid(const block_info& block) const noexcept
{
    const int piece_length = get_piece_length(block.index);
    const bool is_block_offset_valid = block.offset < piece_length;
    const bool is_block_length_valid = piece_length - block.offset >= block.length;

    return is_piece_index_valid(block.index)
        && is_block_offset_valid
        && is_block_length_valid
        && block.length <= 0x4000; // TODO decide what the maximum block size should be
}

inline int peer_session::get_piece_length(const piece_index_t piece) const noexcept
{
    return piece == m_torrent_info->num_pieces -1 ? m_torrent_info->last_piece_length
                                                  : m_torrent_info->piece_length;
}

inline bool peer_session::is_piece_index_valid(const piece_index_t index) const noexcept
{
    return (index >= 0) && (index < m_piece_picker->num_pieces());
}

inline void peer_session::handle_unexpected_block(const block_info& block, message msg)
{
    m_info.total_wasted_bytes += block.length;
    // TODO uhm, we should probably do more here
}

inline void peer_session::handle_illicit_request()
{
    ++m_num_invalid_requests;
    log(log_event::incoming, "%i illicit requests", m_num_invalid_requests);
    if(cached_clock::now() - seconds(2) <= m_last_outgoing_choke_time)
    {
        // don't mind request messages (though don't serve them) up to 2 seconds after
        // choking peer
        return;
    }
    if((m_num_invalid_requests % 10 == 0) && m_info.is_peer_choked)
    {
        // every now and then remind peer that it is choked
        send_choke();
    }
    else if(m_num_invalid_requests > 300)
    {
        // don't tolerate this forever
        disconnect(peer_session_error_t::sent_requests_when_choked);
        return;
    }
}

inline void peer_session::handle_illicit_block()
{
    if(++m_num_unwanted_blocks > 50)
    {
        disconnect(peer_session_error_t::unwanted_blocks);
    }
}

inline void peer_session::handle_illicit_bitfield()
{
    log(log_event::invalid_message, "received bitfield (not after handshake)");
    disconnect(peer_session_error_t::invalid_bitfield_message);
}

inline void peer_session::handle_unknown_message()
{
    log(log_event::invalid_message, "received unknown message");
    disconnect(peer_session_error_t::unknown_message);
}

// ----------
// -- disk --
// ----------

void peer_session::on_piece_hashed(const piece_index_t piece, const bool is_piece_good)
{
    auto piece_download = std::find_if(
        m_piece_downloads.begin(),
        m_piece_downloads.end(),
        [piece](const auto& download)
        {
            return download->piece_index() == piece;
        }
    );
    assert(piece_download != m_piece_downloads.end());

    if(is_piece_good)
    {
        if(is_on_parole())
        {
            // peer cleared itself, so it's no longer on parole
            m_info.is_on_parole = false;
            log(log_event::parole, "peer cleared suspicion, no longer on parole");
        }
    }
    else
    {
        ++m_info.num_hash_fails;

        log(
            log_event::parole,
            "peer participated in corrupt piece download (%i hash fails)",
            m_info.num_hash_fails
        );

        if(is_on_parole() || (*piece_download)->is_unique_download())
        {
            if(is_on_parole())
            {
                // release parole piece download
                m_parole_piece.reset();
            }
            // this peer was the sole participant in this download so we know that it
            // sent us a corrupt piece
            disconnect(peer_session_error_t::corrupt_piece);
        }
        else
        {
            m_info.is_on_parole = true;
            // TODO probably other repercussions
        }
    }
    m_piece_downloads.erase(piece_download);
}

void peer_session::on_block_saved(const std::error_code& error, const block_info& block)
{
    m_work_state.stopped(writing_disk);
    m_info.num_pending_disk_write_bytes -= block.length;
    if(error)
    {
        log(log_event::disk, "disk failure #%i", m_num_disk_io_failures + 1);
        if(++m_num_disk_io_failures > 100)
        {
            disconnect(error);
        }
        return;
    }
    m_num_disk_io_failures = 0;
    m_info.total_bytes_written_to_disk += block.length;

    log(
        log_event::disk,
        "saved block to disk (piece: %i, offset: %i, length: %i)\n"
        "disk stats (written: %i; pending write: %i; read: %i; pending read: %i)",
        block.index,
        block.offset,
        block.length,
        m_info.total_bytes_written_to_disk,
        m_info.num_pending_disk_write_bytes,
        m_info.total_bytes_read_from_disk,
        m_info.num_pending_disk_read_bytes
    );

    // we can likely receive more now that we finished writing to disk
    receive();
}

void peer_session::on_block_read(const std::error_code& error, const block_source& block)
{
    m_work_state.stopped(reading_disk);
    m_info.num_pending_disk_read_bytes -= block.length;
    if(error == asio::error::operation_aborted)
    {
        log(
            log_event::disk,
            "block fetch aborted (piece: %i, offset: %i, length: %i)",
            block.index,
            block.offset,
            block.length
        );
        // we aborted the block fetch, we no longer need to send the block
        return;
    }
    else if(error)
    {
        log(log_event::disk, "disk failure #%i", m_num_disk_io_failures + 1);
        if(++m_num_disk_io_failures > 100)
        {
            disconnect(error);
        }
        return;
    }
    m_num_disk_io_failures = 0;
    m_info.total_bytes_read_from_disk += block.length;

    log(
        log_event::disk,
        "read block from disk (piece: %i, offset: %i, length: %i)\n"
        "disk stats (written: %i; pending write: %i; read: %i; pending read: %i)",
        block.index,
        block.offset,
        block.length,
        m_info.total_bytes_written_to_disk,
        m_info.num_pending_disk_write_bytes,
        m_info.total_bytes_read_from_disk,
        m_info.num_pending_disk_read_bytes
    );

    send_block(block);
}

// ---------------------
// -- message sending --
// ---------------------

// --------------------------------------------------------------------
// HANDSHAKE <pstrlen=49+len(pstr)><pstr><reserved><info hash><peer id>
// --------------------------------------------------------------------
// pstrlen : length of the protocol identifier
// pstr : the protocol identifier
// reserved : all current implementations use all 0s, each bit changes the protocol
// info hash : the torrent's 20 byte info hash
// peer id : the peer's 20 byte unique id (client id)
void peer_session::send_handshake()
{
    static constexpr char protocol_id[] = "BitTorrent protocol";
    static constexpr int protocol_id_length = sizeof(protocol_id) - 1;
    static_assert(protocol_id_length == 19, "making sure char[] has '\0'");

    m_send_buffer.append(
        payload(protocol_id_length + 49)
            .i8(protocol_id_length)
            .buffer(protocol_id)
            .i64(0) // currently no support for extensions
            .buffer(m_torrent_info->info_hash)
            .buffer(m_settings.client_id)
    );

    send();

    log(
        log_event::outgoing,
        "sending handshake (protocol: %s; reserved: %s; info_hash: %s, client_id: %s)",
        protocol_id,
        "0",
        m_torrent_info->info_hash.data(),
        m_settings.client_id.data()
    );
}

// ----------------------------------
// BITFIELD <len=1+X><id=5><bitfield>
// ----------------------------------
// Only ever sent as the first message. Optional, and need not be sent if a client has
// no pieces.
//
// Variable length, where X is the length of the bitfield. The payload is the bitfield
// representing the pieces that have been successfully downloaded. The high bit in the
// first byte corresponds to piece index 0.
// Bits that are cleared indicate a missing piece, and set bits indicate a valid and
// available piece. Spare bits at the end are set to zero.
// If a peer receives a bitfield of the wrong length, it should drop the connection, or
// if the bitfield has any of the spare bits set.
void peer_session::send_bitfield()
{
    assert(m_piece_picker != nullptr);

    const auto& my_pieces = m_piece_picker->my_bitfield();
    const int msg_size = 1 + my_pieces.data().size();
    m_send_buffer.append(
        payload(4 + msg_size)
            .i32(msg_size)
            .i8(message_t::bitfield)
            .buffer(my_pieces.data())
    );

    send();

    log(
        log_event::outgoing,
        "sending bitfield (%s)",
        m_piece_picker->my_bitfield().to_string()
    );
}

// ------------------
// KEEP-ALIVE <len=0>
// ------------------
void peer_session::send_keep_alive()
{
    static constexpr uint8_t payload[] = { 0,0,0,0 };
    m_send_buffer.append(payload);

    send();

    log(log_event::outgoing, "sending keep_alive");
}

// -------------
// CHOKE <len=1>
// -------------
void peer_session::send_choke()
{
    static constexpr uint8_t payload[] = { 0,0,0,1, message_t::choke };
    m_send_buffer.append(payload);
    m_info.is_peer_choked = true;
    m_last_outgoing_choke_time = cached_clock::now();

    send();

    log(log_event::outgoing, "sending choke");
}

// ---------------
// UNCHOKE <len=1>
// ---------------
void peer_session::send_unchoke()
{
    static constexpr uint8_t payload[] = { 0,0,0,1, message_t::unchoke };
    m_send_buffer.append(payload);
    m_info.is_peer_choked = false;
    m_last_outgoing_unchoke_time = cached_clock::now();

    send();

    log(log_event::outgoing, "sending unchoke");
}

// ------------------
// INTERESTED <len=1>
// ------------------
void peer_session::send_interested()
{
    assert(!m_info.am_interested);

    static constexpr uint8_t payload[] = { 0,0,0,1, message_t::interested };
    m_send_buffer.append(payload);
    m_info.am_interested = true;
    m_last_outgoing_interest_time = cached_clock::now();

    send();

    log(log_event::outgoing, "sending interested");
}

// ----------------------
// NOT INTERESTED <len=1>
// ----------------------
void peer_session::send_not_interested()
{
    assert(m_info.am_interested);

    static constexpr uint8_t payload[] = { 0,0,0,1, message_t::not_interested };
    m_send_buffer.append(payload);
    m_info.am_interested = false;
    m_last_outgoing_uninterest_time = cached_clock::now();

    send();

    log(log_event::outgoing, "sending not_interested");
}

// -------------------------------
// HAVE <len=5><id=4><piece index>
// -------------------------------
inline void peer_session::send_have(const piece_index_t piece)
{
    m_send_buffer.append(
        payload(4 + 5)
            .i32(5)
            .i8(message_t::have)
            .i32(piece)
    );
    send();
    log(log_event::outgoing, "sending have (piece: %i)", piece);
}

// ---------------------------------------------
// REQUEST <len=13><id=6><index><offset><length>
// ---------------------------------------------
// Block size should be 2^14 (16KB - 16,384 bytes).
// Max request block size is 2^15 (32KB - 32,768 bytes), but many clients will refuse
// to serve this amount.
/*
void peer_session::send_request(const block& block)
{
    m_send_buffer.append(
        payload(4 + 13)
            .i32(13)
            .i8(message_t::request)
            .i32(block.index)
            .i32(block.offset)
            .i32(block.length)
    );
    m_sent_requests.emplace(block.index, block.offset, block.length);

    log(
        log_event::outgoing,
        "sending request (piece: %i, offset: %i, length: %i)",
        block.index,
        block.offset,
        block.length
    );
}
*/
// To eliminate the full round trip time of receiving the requested piece before sending
// the next request, m_best_request_queue_length number of requests or less are sent in
// one.
void peer_session::send_requests()
{
    assert(m_info.am_interested && !m_info.am_choked);

    std::vector<block_info> blocks = make_request_queue();
    if(blocks.size() == 0)
    {
        return;
    }

    payload payload(blocks.size() * (4 + 13));
    for(auto& block : blocks)
    {
        payload.i32(13)
               .i8(message_t::request)
               .i32(block.index)
               .i32(block.offset)
               .i32(block.length);
        log(
            log_event::outgoing,
            "sending request (piece: %i, offset: %i, length: %i)",
            block.index,
            block.offset,
            block.length
        );

        m_info.num_pending_download_bytes += block.length;
        m_sent_requests.emplace_back(std::move(block));
    }
    m_send_buffer.append(std::move(payload));

    send();

    log(log_event::outgoing, "sent request queue (length: %i)", blocks.size());
}

inline std::vector<block_info> peer_session::make_request_queue()
{
    return is_on_parole() ? make_requests_in_parole_mode()
                          : make_requests_in_normal_mode();
}

inline std::vector<block_info> peer_session::make_requests_in_parole_mode()
{
    assert(m_piece_picker != nullptr);

    if(m_parole_piece == nullptr)
    {
        const auto piece = m_piece_picker->pick_and_reserve(m_info.available_pieces);
        if(piece == piece_picker::no_piece)
        {
            return {};
        }
        m_parole_piece = std::make_unique<piece_download>(piece, get_piece_length(piece));
    }

    if(m_parole_piece->can_request())
    {
        return m_parole_piece->make_request_queue(m_best_request_queue_length);
    }
    return {};
}

inline std::vector<block_info> peer_session::make_requests_in_normal_mode()
{
    assert(m_piece_picker && m_piece_download_pool);

    std::vector<block_info> request_queue;
    int left = m_best_request_queue_length;

    // if we have active downloads, prefer to finish those (this will result in less
    // peers per piece download, i.e. lower chance of a bad peer polluting many pieces)
    for(auto& download : m_piece_downloads)
    {
        if(request_queue.size() == left)
        {
            break;
        }
        if(download->can_request())
        {
            for(auto& block : download->make_request_queue(left))
            {
                request_queue.emplace_back(std::move(block));
                --left;
            }
        }
    }

    // if left is not 0, we try to join a download using piece_download_pool
    if(left > 0)
    {
        auto download = m_piece_download_pool->find_for(m_info.available_pieces);
        if(download != nullptr)
        {
            for(auto& block : download->make_request_queue(left))
            {
                request_queue.emplace_back(std::move(block));
                --left;
            }
            // now we participated in this piece download as well
            m_piece_downloads.emplace_back(download);
        }
    }

    // if we still need blocks, we pick a piece and start a new download, and add it
    // to the shared downloads via m_piece_download_pool
    if(left > 0)
    {
        const auto piece = m_piece_picker->pick_and_reserve(m_info.available_pieces);
        if(piece != piece_picker::no_piece)
        {
            auto download = std::make_shared<piece_download>(
                piece, get_piece_length(piece)
            );
            for(auto& block : download->make_request_queue(left))
            {
                request_queue.emplace_back(std::move(block));
                --left;
            }
            m_piece_downloads.emplace_back(download);
            m_piece_download_pool->add(download);
        }
    }

    return request_queue;
}

// -------------------------------------------
// PIECE <len=9+X><id=7><index><offset><block>
// -------------------------------------------
void peer_session::send_block(const block_source& block)
{
    const int msg_size = 1 + 2 * 4 + block.length;
    payload payload(4 + msg_size);
    payload.i32(msg_size)
           .i8(message_t::block)
           .i32(block.index)
           .i32(block.offset);
    for(const auto& chunk : block.chunks)
    {
        payload.buffer(chunk);
    }
    m_send_buffer.append(std::move(payload));

    m_info.total_uploaded_piece_bytes += block.length;
    m_sent_requests.emplace_back(block.index, block.offset, block.length);

    send();

    log(
        log_event::outgoing,
        "sending block (piece: %i, offset: %i, length: %i)",
        block.index,
        block.offset,
        block.length
    );
}

// --------------------------------------------
// CANCEL <len=13><id=8><index><offset><length>
// --------------------------------------------
void peer_session::send_cancel(const block_info& block)
{
    m_send_buffer.append(
        payload(4 + 13)
            .i32(13)
            .i8(message_t::cancel)
            .i32(block.index)
            .i32(block.offset)
            .i32(block.length)
    );
    send();

    log(
        log_event::outgoing,
        "sending cancel (piece: %i, offset: %i, length: %i)",
        block.index,
        block.offset,
        block.length
    );
}

// -------------------------------
// PORT <len=3><id=9><listen-port>
// -------------------------------
void peer_session::send_port(const int port)
{
    m_send_buffer.append(
        payload(4 + 3)
            .i32(3)
            .i8(message_t::port)
            .i16(port)
    );
    send();
    log(log_event::outgoing, "sending port (%i)", port);
}

// -------------------
// -- timeout logic --
// -------------------

bool peer_session::has_request_timed_out() const
{
    return !m_sent_requests.empty()
        && cached_clock::now() - m_last_outgoing_request_time > request_timeout();
}

void peer_session::handle_request_timeout(const std::error_code& error)
{
    if(error == asio::error::operation_aborted)
    {
        return;
    }
    else if(error)
    {
        disconnect(error);
        return;
    }

    log(log_event::outgoing, "request to peer has timed out");

    m_best_request_queue_length = 1;
    m_info.has_peer_timed_out = true;

    // Find the most suitable block to time out. This is usually the last block we sent
    // because if we time out the last block, we can download it from another peer and
    // perhaps receive it in time to have a chance at cancelling it from this peer. And
    // by that time the other blocks, sent earlier (if any), will have a greater chance
    // of arriving, avoiding timing them out. However, if this is the only peer that has
    // the block, we must not time out the block.
    // For more info: http://blog.libtorrent.org/2011/11/block-request-time-outs/

    auto rit = m_sent_requests.rbegin();
    const auto rend = m_sent_requests.rend();

    assert(m_piece_picker != nullptr);

    while(rit != rend)
    {
        if(!rit->has_timed_out && (m_piece_picker->frequency(rit->index) > 1))
        {
            break;
        }
        ++rit;
    }

    if(rit != rend)
    {
        pending_block& request = *rit;
        request.has_timed_out = true;

        // find piece download corresponding to request
        auto piece_download = std::find_if(
            m_piece_downloads.rbegin(),
            m_piece_downloads.rend(),
            [index = request.index](const auto& download)
            {
                return download->piece_index() == index;
            }
        );

        assert(
            piece_download != m_piece_downloads.rbegin()
            && "Haven't found the piece download to one of our corresponding timed " 
            "out requests. This means that you forgot to adjust up the m_sent_request " 
            "queue somewhere."
        );

        (*piece_download)->time_out(
            m_info.peer_id,
            request,
            [this](const block_info& block)
            {
                cancel_request_handler(block);
            }
        );

        log(
            log_event::timeout,
            "timing out block (piece: %i, offset: %i, length: %i)",
            request.index,
            request.offset,
            request.length
        );
    }
    // try to send requests again, with updated queue length
    send_requests();
}

void peer_session::cancel_request_handler(const block_info& block)
{
    // TODO check if it makes sense to send the cancel message and other stuff
    // also, if this is all that's necesary, just take out the middleman
    send_cancel(block);
}

seconds peer_session::request_timeout() const
{
    // TODO calculate timeout value with some formula, possibly from libtorrent
}

void peer_session::handle_connect_timeout(const std::error_code& error)
{
    if(error == asio::error::operation_aborted)
    {
        return;
    }
    else if(error)
    {
        disconnect(error);
    }
    else
    {
        log(
            log_event::timeout,
            "connecting timedout, elapsed time: %ims",
            total_milliseconds(cached_clock::now() - m_connection_time)
        );
        disconnect(peer_session_error_t::connect_timeout);
    }
}

void peer_session::handle_inactivity_timeout(const std::error_code& error)
{
    if(error == asio::error::operation_aborted)
    {
        return;
    }
    else if(error)
    {
        disconnect(error);
    }
    else
    {
        log(log_event::timeout, "inactivity timeout");
        disconnect(peer_session_error_t::inactivity_timeout);
    }
}

void peer_session::handle_keep_alive_timeout(const std::error_code& error)
{
    if(error == asio::error::operation_aborted)
    {
        return;
    }
    else if(error)
    {
        disconnect(error);
        return;
    }

    log(log_event::timeout, "keep_alive timeout");
    if(cached_clock::now() - m_last_send_time > seconds(m_settings.peer_timeout_s))
    {
        send_keep_alive();
    }
    start_timer(
        m_keep_alive_timer,
        seconds(m_settings.peer_timeout_s),
        [this](const std::error_code& error)
        {
            handle_keep_alive_timeout(error);
        }
    );
}

// -----------
// -- utils --
// -----------

template<typename... Args>
void peer_session::log(
    const log_event log_event,
    const std::string& format,
    Args&&... args
)
{
    // + 1 for '\0'
    const size_t length = std::snprintf(nullptr, 0, format.c_str(), args...) + 1;
    std::unique_ptr<char[]> buffer(new char[length]);
    std::snprintf(buffer.get(), length, format.c_str(), args...);
    // -1 to exclude the '\0' at the end
    std::string message(buffer.get(), buffer.get() + length - 1);
}

template<
    typename Duration,
    typename Handler
> void peer_session::start_timer(
    deadline_timer& timer,
    const Duration& expires_in,
    Handler handler
)
{
    std::error_code ec;
    // setting expires from now also cancels pending async waits (which is what we want)
    timer.expires_from_now(expires_in, ec);
    if(ec)
    {
        disconnect(ec);
        return;
    }
    timer.async_wait(std::move(handler));
}

/**
 * Produces block_info objects by parsing the supplied byte sequence. Bytes must be a
 * container of byte types (std::vector, std::array, view...).
 */
template<typename Bytes>
block_info parse_block_info(const Bytes& data)
{
    assert(data.size() >= 3 * 4);

    auto byte_it = data.cbegin();
    const auto end = data.cend();
    const piece_index_t index = parse_i32(byte_it);
    const int offset = parse_i32(byte_it += 4);

    if(data.size() == 3 * 4)
    {
        // it's a request/cancel message with fixed message length
        return block_info(index, offset, parse_i32(byte_it += 4));
    }
    else
    {
        // it's a block message, we get the block's length by subtracting the index and
        // offset fields' added length from the total message length
        return block_info(index, offset, data.size() - 2 * 4);
    }
}
