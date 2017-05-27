#include "piece_download_locator.hpp"
#include "bandwidth_controller.hpp"
#include "piece_download.hpp"
#include "piece_picker.hpp"
#include "peer_session.hpp"
#include "torrent_info.hpp"
#include "string_utils.hpp"
#include "settings.hpp"
#include "disk_io.hpp"
#include "payload.hpp"
#include "endian.hpp"
#include "view.hpp"

#include <algorithm>
#include <stdexcept>
#include <cassert>
#include <string>
#include <bitset>
#include <cmath> // min, max
#include <cstdio> // snprintf

#include <iostream>

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
        if(!m_peer_session.m_work_state(sending))
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
    const peer_session_settings& settings
)
    : m_socket(std::move(socket))
    , m_disk_io(disk_io)
    , m_bandwidth_controller(bandwidth_controller)
    , m_settings(settings)
    , m_max_outgoing_request_queue_size(m_settings.max_outgoing_request_queue_size)
    , m_connect_timeout_timer(m_socket->get_io_service())
    , m_keep_alive_timer(m_socket->get_io_service())
    , m_request_timeout_timer(m_socket->get_io_service())
    , m_inactivity_timeout_timer(m_socket->get_io_service())
{
    assert(m_socket);
    assert(m_settings.max_receive_buffer_size != -1);
    m_info.peer_endpoint = std::move(peer_endpoint);
    m_work_state.started(idling);
    m_work_state.started(slow_start);
}

peer_session::peer_session(
    std::unique_ptr<tcp::socket> socket,
    tcp::endpoint peer_endpoint,
    disk_io& disk_io,
    bandwidth_controller& bandwidth_controller,
    const peer_session_settings& settings,
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
    m_piece_download_locator = torrent_args.locator;
    m_torrent_info = torrent_args.info;
    m_new_piece_handler = torrent_args.new_piece_handler;

    assert(m_piece_download_locator);
    assert(m_torrent_info);
    assert(m_piece_picker);

    // initialize peer's bitfield
    m_info.available_pieces = bt_bitfield(m_torrent_info->num_pieces);
    m_info.torrent_id = m_torrent_info->id;
    m_info.is_outbound = true;
    m_info.am_seed = m_torrent_info->is_seeding;

    connect();
}

peer_session::peer_session(
    std::unique_ptr<tcp::socket> socket,
    tcp::endpoint peer_endpoint,
    disk_io& disk_io,
    bandwidth_controller& bandwidth_controller,
    const peer_session_settings& settings,
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
    on_connected(std::error_code());
}

peer_session::~peer_session()
{
    disconnect(peer_session_errc::unknown);
}

const peer_session_info& peer_session::stats() noexcept
{
    // we don't keep track of these values as these fields in peer_session_info are only
    // useful for stats collection, so it suffices to update them only when requested
    //m_info.send_buffer_size = m_send_buffer.size();
    //m_info.receive_buffer_size = m_message_parser.size();
    m_info.upload_rate = m_upload_rate.bytes_per_second();
    m_info.download_rate = m_download_rate.bytes_per_second();
    m_info.piece_downloads.clear();
    for(const auto& download : m_piece_downloads)
    {
        m_info.piece_downloads.emplace_back(download->piece_index());
    }
    return m_info;
}

void peer_session::update_stats(peer_session_info& stats) const noexcept
{
    /*
    stats.torrent_id;
    stats.id;
    stats.peer_client;
    stats.extensions;
    stats.available_pieces;
    stats.local_endpoint;
    stats.peer_endpoint;
    stats.downloading_pieces;
    stats.total_downloaded_piece_bytes = m_info.total_downloaded_bytes;
    stats.total_uploaded_piece_bytes = m_info.total_downloaded_bytes;
    stats.total_downloaded_bytes = m_info.total_downloaded_bytes;
    stats.total_uploaded_bytes = m_info.total_downloaded_bytes;
    stats.total_wasted_bytes = m_info.total_downloaded_bytes;
    stats.upload_rate = m_info.total_downloaded_bytes;
    stats.download_rate = m_info.total_downloaded_bytes;
    stats.peak_upload_rate = m_info.total_downloaded_bytes;
    stats.peak_download_rate = m_info.total_downloaded_bytes;
    stats.upload_rate_limit = m_info.total_downloaded_bytes;
    stats.download_rate_limit = m_info.total_downloaded_bytes;
    stats.send_buffer_size = m_info.send_buffer_size;
    stats.send_buffer_size_used = m_info.send_buffer_size_used;
    stats.receive_buffer_size = m_info.receive_buffer_size;
    stats.receive_buffer_size_used = m_info.receive_buffer_size_used ;
    stats.num_hash_fails = m_info.num_hash_fails;
    stats.num_timed_out_requests = m_info.num_timed_out_requests;
    stats.total_bytes_written_to_disk = m_info.total_bytes_written_to_disk;
    stats.total_bytes_read_from_disk = m_info.total_bytes_read_from_disk;
    stats.num_pending_disk_write_bytes = m_info.num_pending_disk_write_bytes;
    stats.num_pending_disk_read_bytes = m_info.num_pending_disk_read_bytes;
    stats.num_outstanding_bytes = m_info.num_outstanding_bytes;
    stats.best_request_queue_size = m_info.best_request_queue_size ;
    stats.send_quota = m_info.send_quota;
    stats.receive_quota = m_info.receive_quota;
    stats.am_interested = m_info.am_interested ;
    stats.am_choked = m_info.am_choked ;
    stats.is_peer_interested = m_info.is_peer_interested;
    stats.is_peer_choked = m_info.is_peer_choked;
    stats.am_seed = m_info.am_seed;
    stats.is_peer_seed = m_info.is_peer_seed;
    stats.is_outbound = m_info.is_on_parole;
    stats.is_on_parole = m_info.is_on_parole;
    stats.has_peer_timed_out = m_info.has_peer_timed_out;
    stats.state = m_info.state;
    */
}

inline void peer_session::connect()
{
    std::error_code ec;
    log(log_event::connecting, "opening socket");
    m_socket->open(m_info.peer_endpoint.protocol(), ec);
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
    m_info.state = peer_session_info::state_t::connecting;
    m_connection_started_time = cached_clock::now();

    start_timer(
        m_connect_timeout_timer,
        seconds(m_settings.peer_connect_timeout_s),
        [this](const std::error_code& error)
        {
            handle_connect_timeout(error);
        }
    );

    log(log_event::connecting, "started establishing connection");
}

void peer_session::on_connected(const std::error_code& error)
{
    std::error_code ec;
    m_connect_timeout_timer.cancel(ec);

    if(error || !m_socket->is_open())
    {
        disconnect(error);
        return;
    }

    log(log_event::connecting, "setting non-blocking io mode");
    m_socket->non_blocking(true, ec);
    if(ec)
    {
        disconnect(ec);
        return;
    }

    m_connection_established_time = cached_clock::now();
    m_info.connection_established_time = m_connection_established_time;

    log(log_event::connecting,
        "connected to %s in %ims",
        m_info.peer_endpoint.address().to_string().c_str(),
        total_milliseconds(m_connection_established_time - m_connection_started_time)
    );

    m_info.local_endpoint = m_socket->local_endpoint(ec);
    if(ec)
    {
        disconnect(ec);
        return;
    }

    m_info.state = peer_session_info::state_t::in_handshake;

    if(m_settings.encryption_policy
            == peer_session_settings::encryption_policy_t::no_encryption)
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

    m_info.state = peer_session_info::state_t::disconnecting;

    log(log_event::disconnecting,
        "preparing to disconnect... reason: %s",
        error.message().c_str()
    );

    std::error_code ec;
    m_keep_alive_timer.cancel(ec);
    m_inactivity_timeout_timer.cancel(ec);

    if(m_piece_picker != nullptr)
    {
        m_piece_picker->decrease_frequency(m_info.available_pieces);
    }

    // if we have any pending requests, tell their corresponding piece downloads that
    // we won't get the blocks
    abort_our_requests();

    m_socket->close(ec);
    m_info.state = peer_session_info::state_t::stopped;

    log(log_event::disconnecting, "tore down connection");

    // TODO tell disk_io to stop serving peer's outstanding requests
}

void peer_session::abort_our_requests()
{
    std::error_code ec;
    m_request_timeout_timer.cancel(ec);

    // TODO VERIFY THIS
    auto piece_download = m_piece_downloads.end();
    // tell each download that we won't get our requested blocks
    for(const pending_block& block : m_sent_requests)
    {
        // it is likely that most of the current requests belong to one piece download,
        // so we're caching it in piece_download, but still need to check it
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
    m_info.num_outstanding_bytes = 0;
    m_torrent_info->num_outstanding_bytes = 0;
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
        // TODO
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
        // peer has in which we were interested. TODO what if we're receiving that piece?
        update_interest();
        send_have(piece);
    }
}

void peer_session::update_interest()
{
    const bool was_interested = m_info.am_interested;
    m_info.am_interested = m_piece_picker->am_interested_in(m_info.available_pieces);

    if(!was_interested && m_info.am_interested)
    {
        std::error_code ec;
        m_inactivity_timeout_timer.cancel(ec);

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

// -------------
// -- sending --
// -------------

void peer_session::send()
{
    if(is_disconnecting() || is_finished())
    {
        return;
    }

    request_upload_bandwidth();

    if(!can_send())
    {
        return;
    }

    const int num_bytes_to_send = std::min(m_send_buffer.size(), m_info.send_quota);
    assert(num_bytes_to_send > 0);
    m_socket->async_write_some(
        m_send_buffer.get_send_buffers(num_bytes_to_send),
        [this](const std::error_code& error, size_t num_bytes_sent)
        {
            on_sent(error, num_bytes_sent);
        }
    );
    m_work_state.started(sending);

    log(log_event::outgoing,
        "sending: %i; available: %i; quota: %i",
        num_bytes_to_send,
        m_send_buffer.size(),
        m_info.send_quota
    );
}

bool peer_session::can_send() const noexcept
{
    if(m_send_buffer.is_empty())
    {
        log(log_event::outgoing, "CAN'T SEND, buffer empty");
        return false;
    }
    else if(m_work_state(sending))
    {
        log(log_event::outgoing, "CAN'T SEND, already sending");
        return false;
    }
    else if(m_info.send_quota <= 0)
    {
        log(log_event::outgoing, "CAN'T SEND, no quota left");
        return false;
    }
    return true;
}

void peer_session::request_upload_bandwidth()
{
    // TODO this is temporary for the first test
    m_info.send_quota = m_send_buffer.size();
    if(m_info.send_quota == 0)
    {
        m_info.send_quota = 0x4000;
    }
}

void peer_session::on_sent(const std::error_code& error, size_t num_bytes_sent)
{
    if(error)
    {
        log(log_event::outgoing, "error while sending");
        disconnect(error);
        return;
    }

    update_send_stats(num_bytes_sent);
    m_send_buffer.consume(num_bytes_sent);
    m_work_state.stopped(sending);

    log(log_event::outgoing,
        "sent: %i; quota: %i; send buffer size: %i; total sent: %i",
        num_bytes_sent,
        m_info.send_quota,
        m_send_buffer.size(),
        m_info.total_uploaded_bytes
    );

    // this call to send() will only write to socket again if during the first write
    // there were more bytes in send buffer to send than we had quota for, and since the
    // first thing in send is asking for more bandwidth quota, we may be able to send
    // off the rest of the send buffer's contents
    if(!m_send_buffer.is_empty())
    {
        send();
    }
}

inline void peer_session::update_send_stats(const int num_bytes_sent) noexcept
{
    m_info.send_quota -= num_bytes_sent;
    m_last_send_time = cached_clock::now();
    m_info.total_uploaded_bytes += num_bytes_sent;
    m_torrent_info->total_uploaded_bytes += num_bytes_sent;
}

// ---------------
// -- receiving --
// ---------------

void peer_session::receive()
{
    if(is_disconnecting() || is_finished())
    {
        return;
    }

    request_download_bandwidth();

    if(!can_receive())
    {
        return;
    }

    ensure_protocol_exchange();
    const int num_to_receive = get_num_to_receive();
    if(num_to_receive == 0)
    {
        log(log_event::incoming, "CAN'T RECEIVE, no space in buffer");
        return;
    }

    view<uint8_t> buffer = m_message_parser.get_receive_buffer(num_to_receive);
    m_socket->async_read_some(
        asio::mutable_buffers_1(buffer.data(), buffer.size()),
        [this](const std::error_code& error, size_t num_bytes_received)
        {
            on_received(error, num_bytes_received);
        }
    );
    m_work_state.started(receiving);

    log(log_event::incoming,
        "receiving: %i; receive buffer free space: %i; quota: %i",
        num_to_receive,
        m_message_parser.free_space_size(),
        m_info.receive_quota
    );
}

void peer_session::request_download_bandwidth()
{
    // TODO this is temporary for the first test
    m_info.receive_quota = 4 * 0x4000;
}

bool peer_session::can_receive() const noexcept
{
    if(m_info.receive_quota <= 0)
    {
        log(log_event::incoming, "CAN'T RECEIVE, no receive quota");
        return false;
    }
    else if(m_work_state(receiving))
    {
        log(log_event::incoming, "CAN'T RECEIVE, already receiving");
        return false;
    }
    else if(am_expecting_piece()
            && m_work_state(reading_disk)
            && m_disk_io.is_overwhelmed())
    {
        // we're writing to disk and expecting more pieces to come in but the disk is
        // overflown with work as it is, so wait for it to finish current write jobs,
        // after which the on_block_saved handle is invoked in which we start receiving
        // again
        log(log_event::incoming, "CAN'T RECEIVE, disk too saturated");
        return false;
    }
    return true;
}

void peer_session::ensure_protocol_exchange()
{
    if(!am_expecting_piece()
       && m_message_parser.is_full()
       && m_message_parser.buffer_size() < m_settings.max_receive_buffer_size)
    {
        // TODO think about the ideal size to reserve here
        m_message_parser.reserve(std::min(
            m_message_parser.buffer_size() + 128,
            m_settings.max_receive_buffer_size
        ));
    }
}

int peer_session::get_num_to_receive() const noexcept
{
    // pending bytes written to disk are also counted as part of the receive buffer
    // until they are flushed to disk; this is the organic cap on the download rate if
    // we're disk bound
    const auto max_receive_size = std::max(
        m_message_parser.free_space_size() - m_info.num_pending_disk_write_bytes, 0
    );
    return std::min(max_receive_size, m_info.receive_quota);
}

void peer_session::on_received(const std::error_code& error, size_t num_bytes_received)
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
        // flush_socket takes care of reserving buffer space if there is still data
        // in socket
        num_bytes_received += flush_socket();
    }

    update_receive_stats(num_bytes_received);

    log(log_event::incoming,
        "received: %i; receive buffer size: %i; quota: %i; total received: %i",
        num_bytes_received,
        m_message_parser.buffer_size(),
        m_info.receive_quota,
        m_info.total_downloaded_bytes
    );

    if(is_disconnecting())
    {
        // flush_socket() spurred a disconnect
        return;
    }

    // send response messages at the end of the function in one batch
    send_cork cork(*this);
    const bool was_choked = m_info.am_choked;
    handle_messages();
    if(is_disconnecting())
    {
        // handle_messages() spurred a disconnect
        return;
    }
    // react to amount of received data and grow or shrink receive buffer accordingly
    adjust_receive_buffer(was_choked);
    m_work_state.stopped(receiving);

    receive();
}

inline void peer_session::update_receive_stats(const int num_bytes_received) noexcept
{
    m_info.receive_quota -= num_bytes_received;
    m_last_receive_time = cached_clock::now();
    m_info.total_downloaded_bytes += num_bytes_received;
    m_torrent_info->total_downloaded_bytes += num_bytes_received;
}

inline void peer_session::adjust_receive_buffer(const bool was_choked)
{
    const int old_buffer_size = m_message_parser.buffer_size();
    const bool got_choked = !was_choked && m_info.am_choked;

    if(!m_info.am_choked && (old_buffer_size < m_settings.max_receive_buffer_size))
    {
        const int free_space_size = m_message_parser.free_space_size();
        if(am_expecting_piece() && (free_space_size < 0x4000))
        {
            // if we have space to grow and are expecting a block but don't have enough
            // receive space for it, increase buffer size to fit the number of
            // outstanding bytes (of course capped by max receive buffer size)
            m_message_parser.reserve(std::min(
                old_buffer_size + m_info.num_outstanding_bytes - free_space_size,
                m_settings.max_receive_buffer_size
            ));
        }
        else if(m_message_parser.is_full())
        {
            // otherwise we're not expecting blocks but since we're not choked and
            // managed to fill the receive buffer we should still grow it
            m_message_parser.reserve(std::min(
                old_buffer_size * 2,
                m_settings.max_receive_buffer_size
            ));
            log(log_event::incoming,
                "grew receive buffer from %i to %i",
                old_buffer_size, m_message_parser.buffer_size()
            );
        }
    }
    else if(got_choked && old_buffer_size > 1024)
    {
        // if we went from unchoked to choked (and if buffer is large enough, otherwise
        // don't bother), 100 bytes should suffice to receive further protocol chatter
        // (if we have unfinished messages in receive buffer it will not shrink below
        // the last valid message byte)
        m_message_parser.shrink_to_fit(100);
        log(log_event::incoming,
            "shrunk receive buffer from %i to %i",
            old_buffer_size, m_message_parser.buffer_size()
        );
    }
}

inline bool peer_session::am_expecting_piece() const noexcept
{
    return (m_info.num_outstanding_bytes > 0) && !m_info.am_choked;
}

inline int peer_session::flush_socket()
{
    assert(m_message_parser.is_full());
    // we may not have read all of the available bytes buffered in socket:
    // try sync read remaining bytes
    std::error_code ec;
    const int num_available_bytes = m_socket->available(ec);
    if(ec)
    {
        disconnect(ec);
    }
    else if(num_available_bytes > 0)
    {
        // get_receive_buffer(n) ensures that we can receive n bytes
        view<uint8_t> buffer = m_message_parser.get_receive_buffer(num_available_bytes);
        const auto num_bytes_read = m_socket->read_some(
            asio::mutable_buffers_1(buffer.data(), buffer.size()), ec
        );
        if((ec == asio::error::would_block) || (ec == asio::error::try_again))
        {
            // this is not an error, just ignore
            log(log_event::incoming, "failed to sync read from socket");
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
    if(m_info.state == peer_session_info::state_t::in_handshake)
    {
        if(m_message_parser.has_handshake())
        {
            handle_handshake();
            if(is_disconnecting())
            {
                // error in peer's handshake
                return;
            }
        }
        else
        {
            // otherwise we don't have the full handshake yet, so receive more bytes and
            // come back to try again (receive is called  after this function returns)
            return;
        }
    }

    if(m_message_parser.has_message()
       && m_info.state == peer_session_info::state_t::bitfield_exchange)
    {
        if(m_message_parser.type() == message_t::bitfield)
        {
            handle_bitfield();
            if(is_disconnecting())
            {
                // error in peer's bitfield
                return;
            }
        }
        m_info.state = peer_session_info::state_t::connected;
    }

    while(!is_disconnecting()
          && m_message_parser.has_message()
          && m_send_buffer.size() <= m_settings.max_send_buffer_size)
    {
        switch(m_message_parser.type())
        {
        case message_t::bitfield:
            // bitfield messages may only be sent after the handshake, in the bitfield
            // exchange state in peer_session_info::state_t
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
    // TODO consider throwing exceptions in the individual message handlers so that we
    // don't have to test against whether a handler caused us to disconnect so often
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
        disconnect(peer_session_errc::invalid_handshake);
        return;
    }

    sha1_hash info_hash;
    std::copy(
        handshake.info_hash.cbegin(),
        handshake.info_hash.cend(),
        info_hash.begin()
    );
    if(m_info.is_outbound)
    {
        // we started the connection, so compare peer's hash to ours
        if(info_hash != m_torrent_info->info_hash)
        {
            disconnect(peer_session_errc::invalid_info_hash);
            return;
        }
    }
    else
    {
        torrent_specific_args torrent_args = m_torrent_attacher(info_hash);
        if(torrent_args.info == nullptr)
        {
            // this means we couldn't find a torrent to which we could be attached,
            // likely due to peer's bad info_hash
            disconnect(peer_session_errc::invalid_info_hash);
            return;
        }

        m_piece_picker = torrent_args.picker;
        m_piece_download_locator = torrent_args.locator;
        m_torrent_info = torrent_args.info;
        m_new_piece_handler = torrent_args.new_piece_handler;

        // initialize peer's bitfield now that we know the number of pieces this
        // torrent has
        m_info.available_pieces = bt_bitfield(m_torrent_info->num_pieces);
        m_info.torrent_id = m_torrent_info->id;
        m_info.am_seed = m_torrent_info->is_seeding;

        // if the connection was initiated by peer, we still need to send our handshake
        send_handshake();
    }
    std::copy(
        handshake.reserved.cbegin(),
        handshake.reserved.cend(),
        m_info.extensions.begin()
    );
    std::copy(
        handshake.peer_id.cbegin(),
        handshake.peer_id.cend(),
        m_info.id.begin()
    );

    try_identify_client();
    if((m_info.client == "BitComet") && m_max_outgoing_request_queue_size > 50)
    {
        m_max_outgoing_request_queue_size = 50;
    }

    log(log_event::incoming,
        "HANDSHAKE (protocol: %s; extensions: %s; info_hash: %s; client_id: %s%s)",
        handshake.protocol_id.data(),
        m_info.extensions.data(),
        info_hash.data(),
        m_info.id.data(),
        m_info.client.empty() ? "" : ("; " + m_info.client).c_str()
    );

    /*
    std::string extensions_str = [this]() -> std::string
    {
        std::string ret;
        ret.reserve(64);
        for(const uint8_t b : m_info.extensions)
        {
            for(const char c : std::bitset<8>(b).to_string())
            {
                ret += c;
            }
        }
        return ret;
    }();
    std::string info_hash_str = detail::to_hex(info_hash);
    log(log_event::outgoing,
        "HANDSHAKE (protocol: %s; extensions: %s; info_hash: %s; client_id: %s%s)",
        handshake.protocol_id,
        extensions_str.c_str(),
        info_hash_str.c_str(),
        m_info.id.data(),
        m_info.client.empty() ? "" : ("; " + m_info.client).c_str()
    );
    */

    // move on to the next stage
    m_info.state = peer_session_info::state_t::bitfield_exchange;
    send_bitfield();
}

inline void peer_session::handle_bitfield()
{
    assert(m_info.state == peer_session_info::state_t::bitfield_exchange);

    message msg = m_message_parser.extract();
    const int num_pieces = m_torrent_info->num_pieces;
    if(!bt_bitfield::is_bitfield_data_valid(msg.data, num_pieces))
    {
        // peer sent an invalid bitfield, disconnect immediately
        disconnect(peer_session_errc::invalid_bitfield_message);
        return;
    }

    m_info.available_pieces = bt_bitfield(msg.data, num_pieces);
    m_info.is_peer_seed = m_info.available_pieces.are_all_set();

    log(log_event::incoming,
        "BITFIELD (%s)",
        m_info.available_pieces.to_string().c_str()
    );

    // check if we're interested in peer now that we know its piece availability
    update_interest();
}

inline void peer_session::handle_keep_alive()
{
    m_message_parser.skip();
    log(log_event::incoming, "KEEP-ALIVE");
    if(!m_info.is_peer_choked && m_info.is_peer_interested)
    {
        // peer is unchoked and interested but it's not sending us requests so our
        // unchoke message may not have gotten through, send it again
        send_unchoke();
    }
}

inline void peer_session::handle_choke()
{
    log(log_event::incoming, "CHOKE");
    if(m_message_parser.extract().data.size() != 0)
    {
        log(log_event::invalid_message, "wrong choke message length");
        disconnect(peer_session_errc::invalid_choke_message);
        return;
    }
    if(!m_info.am_choked)
    {
        m_info.am_choked = true;
        m_work_state.stopped(slow_start);
        abort_our_requests();
    }
    m_last_incoming_choke_time = cached_clock::now();
}

inline void peer_session::handle_unchoke()
{
    log(log_event::incoming, "UNCHOKE");
    if(m_message_parser.extract().data.size() != 0)
    {
        log(log_event::invalid_message, "wrong unchoke message length");
        disconnect(peer_session_errc::invalid_unchoke_message);
        return;
    }
    m_info.am_choked = false;
    m_last_incoming_unchoke_time = cached_clock::now();
    if(m_info.am_interested)
    {
        send_requests();
    }
}

inline void peer_session::handle_interested()
{
    log(log_event::incoming, "INTERESTED");
    if(m_message_parser.extract().data.size() != 0)
    {
        log(log_event::invalid_message, "wrong interested message length");
        disconnect(peer_session_errc::invalid_interested_message);
        return;
    }
    if(!m_info.is_peer_interested)
    {
        m_info.is_peer_interested = true;
        std::error_code ec;
        m_inactivity_timeout_timer.cancel(ec);
    }
    m_last_incoming_interest_time = cached_clock::now();
}

inline void peer_session::handle_not_interested()
{
    log(log_event::incoming, "NOT INTERESTED");
    if(m_message_parser.extract().data.size() != 0)
    {
        log(log_event::invalid_message, "wrong not_interested message length");
        disconnect(peer_session_errc::invalid_not_interested_message);
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
        disconnect(peer_session_errc::invalid_have_message);
        return;
    }

    const piece_index_t piece = detail::parse<int32_t>(msg.data.begin());

    log(log_event::incoming, "HAVE %i", piece);

    if(!is_piece_index_valid(piece))
    {
        log(log_event::invalid_message, "invalid piece index in have message");
        disconnect(peer_session_errc::invalid_have_message);
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
        update_interest();
    }
}

inline void peer_session::handle_request()
{
    message msg = m_message_parser.extract();
    if(msg.data.size() != 3 * 4)
    {
        log(log_event::invalid_message, "wrong request message length");
        disconnect(peer_session_errc::invalid_request_message);
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

    log(log_event::incoming,
        "REQUEST (piece: %i, offset: %i, length: %i)",
        block_info.index, block_info.offset, block_info.length
    );

    if(!is_request_valid(block_info))
    {
        log(log_event::invalid_message,
            "invalid request (piece: %i, offset: %i, length: %i)",
            block_info.index, block_info.offset, block_info.length
        );
        disconnect(peer_session_errc::invalid_request_message);
        return;
    }

    if(should_accept_request(block_info))
    {
        // at this point we can serve the request
        // TODO don't issue request to disk if it's overwhelmed
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
        m_torrent_info->num_pending_disk_read_bytes += block_info.length;

        log(log_event::disk,
            "disk read launched, serving request (piece: %i, offset: %i, length: %i)",
            block_info.index, block_info.offset, block_info.length
        );
    }
}

inline bool peer_session::should_accept_request(const block_info& block) const noexcept
{
    // TODO check if max block size is still enforced
    // don't serve request if peer reached its max allowed outstanding requests or
    // if the requested block is larger than 16KiB
    return m_received_requests.size() < m_settings.max_incoming_request_queue_size
        || block.length <= 0x4000;
}

inline void peer_session::handle_cancel()
{
    message msg = m_message_parser.extract();
    if(msg.data.size() != 1 + 3 * 4)
    {
        log(log_event::invalid_message, "wrong cancel message length");
        disconnect(peer_session_errc::invalid_cancel_message);
        return;
    }

    const block_info block_info = parse_block_info(msg.data);

    log(log_event::incoming,
        "CANCEL (piece: %i, offset: %i, length: %i)",
        block_info.index, block_info.offset, block_info.length
    );

    if(!is_request_valid(block_info))
    {
        log(log_event::invalid_message,
            "invalid cancel (piece: %i, offset: %i, length: %i)",
            block_info.index, block_info.offset, block_info.length
        );
        disconnect(peer_session_errc::invalid_cancel_message);
        return;
    }

    auto request = std::find_if(
        m_received_requests.begin(),
        m_received_requests.end(),
        [&block_info](const auto& request)
        {
            return request == block_info;
        }
    );
    if(request != m_received_requests.cend())
    {
        // TODO
        m_received_requests.erase(request);
        log(log_event::disk, "disk abort launched, cancelling request");
    }
}

inline bool peer_session::is_request_valid(const block_info& request) const noexcept
{
    return m_piece_picker->my_bitfield()[request.index] && is_block_info_valid(request);
}

void peer_session::handle_block()
{
    message msg = m_message_parser.extract();
    if(msg.data.size() < 12)
    {
        log(log_event::invalid_message, "wrong block message length");
        disconnect(peer_session_errc::invalid_block_message);
        return;
    }

    const block_info block_info = parse_block_info(msg.data);

    log(log_event::incoming,
        "BLOCK (piece: %i, offset: %i, length: %i)",
        block_info.index, block_info.offset, block_info.length
    );

    if(!is_block_info_valid(block_info))
    {
        log(log_event::invalid_message, "invalid block");
        disconnect(peer_session_errc::invalid_block_message);
        return;
    }

    auto request = std::find_if(
        m_sent_requests.begin(),
        m_sent_requests.end(),
        [&block_info](const pending_block& request)
        {
            return request == block_info;
        }
    );
    if(request == m_sent_requests.cend())
    {
        // we don't want this block (give 2 second slack)
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

    adjust_request_timeout();
    update_download_stats(block_info.length);

    if(m_piece_picker->my_bitfield()[block_info.index])
    {
        // we already have this piece
        log(log_event::incoming, "already have block");
        m_info.total_wasted_bytes += block_info.length;
        m_torrent_info->total_wasted_bytes += block_info.length;
    }
    else
    {
        // now find the piece download to which this request belongs
        auto it = std::find_if(
            m_piece_downloads.begin(),
            m_piece_downloads.end(),
            [index = block_info.index](const auto& download)
            {
                return download->piece_index() == index;
            }
        );
        assert(it != m_piece_downloads.end());
        auto& piece_download = *it;
        piece_download->got_block(
            m_info.id,
            block_info,
            [this, piece = block_info.index](const bool is_piece_good)
            {
                on_piece_hashed(piece, is_piece_good);
            }
        );
        disk_buffer block = m_disk_io.get_write_buffer();
        assert(block);
        // exclude the block header (index and offset, both 4 bytes)
        std::copy(msg.data.begin() + 8, msg.data.end(), block.data());
        save_block(block_info, std::move(block), *piece_download);
    }
    send_requests();
}

inline void peer_session::adjust_request_timeout() // TODO rename
{
    const auto request_rtt = cached_clock::now() - m_last_outgoing_request_time;
    m_avg_request_rtt.add_sample(total_milliseconds(request_rtt));
    log(log_event::request, "request rtt: %ims", total_milliseconds(request_rtt));

    const auto timeout = request_timeout();
    if((request_rtt < timeout) && m_info.has_peer_timed_out)
    {
        // peer has timed out before but managed to deliver this time
        m_info.has_peer_timed_out = false;
    }
    else if(request_rtt > timeout)
    {
        m_info.has_peer_timed_out = true;
    }
    adjust_best_request_queue_size();

    if(m_sent_requests.empty())
    {
        // we don't expect more requests, stop the timer
        std::error_code ec;
        m_request_timeout_timer.cancel(ec);
    }
    else
    {
        // there are still outstanding requests, reset request timeout timer
        start_timer(
            m_request_timeout_timer,
            timeout,
            [this](const std::error_code& error)
            {
                handle_request_timeout(error);
            }
        );
    }
}

inline void peer_session::adjust_best_request_queue_size() noexcept
{
    if(m_info.has_peer_timed_out)
    {
        m_best_request_queue_size = 1;
        m_work_state.stopped(slow_start);
        return;
    }

    const int old_best_request_queue_size = m_best_request_queue_size;
    if(m_work_state(slow_start))
    {
        // if our download rate is not increasing significantly anymore, exit slow start
        // TODO this is not working properly
        if(m_download_rate.deviation() < 10000)
        {
            log(log_event::request,
                "download rate (mean: %i, deviation: %i) is not increasing much,"
                "leaving slow start",
                m_download_rate.bytes_per_second(),
                m_download_rate.deviation()
            );
            m_work_state.stopped(slow_start);
            return;
        }
        ++m_best_request_queue_size;
    }
    else
    {
        // TODO figure out good formula, this is just a placeholder
        m_best_request_queue_size = (m_download_rate.bytes_per_second()
                                     * m_avg_disk_write_time.mean() * 0.5) / 0x4000;
    }

    if(m_best_request_queue_size > m_settings.max_outgoing_request_queue_size)
    {
        m_best_request_queue_size = m_settings.max_outgoing_request_queue_size;
    }
    else if(m_best_request_queue_size < 2)
    {
        m_best_request_queue_size = 2;
    }

    assert(m_best_request_queue_size > 0);

    if(m_best_request_queue_size != old_best_request_queue_size)
    {
        log(log_event::request,
            "ideal request queue size changed from %i to %i",
            old_best_request_queue_size,
            m_best_request_queue_size
        );
    }
}

inline void peer_session::update_download_stats(const int num_bytes)
{
    m_info.num_outstanding_bytes -= num_bytes;
    m_info.total_downloaded_piece_bytes += num_bytes;
    m_torrent_info->num_outstanding_bytes -= num_bytes;
    m_torrent_info->total_downloaded_piece_bytes += num_bytes;
    m_last_incoming_block_time = cached_clock::now();
    m_download_rate.update(num_bytes);
    m_info.download_rate = m_download_rate.bytes_per_second();
    if(m_info.download_rate > m_info.peak_download_rate)
    {
        m_info.peak_download_rate = m_info.download_rate;
    }
    log(log_event::request, "download rate: %i bytes/s", m_info.download_rate);
}

inline bool peer_session::is_block_info_valid(const block_info& block) const noexcept
{
    const int piece_length = get_piece_length(block.index);
    assert(piece_length > 0);
    const bool is_block_offset_valid = block.offset < piece_length;
    const bool is_block_length_valid = piece_length - block.offset >= block.length;

    return is_piece_index_valid(block.index)
        && is_block_offset_valid
        && is_block_length_valid
        && block.length <= 0x8000; // TODO decide what the maximum block size should be
}

inline int peer_session::get_piece_length(const piece_index_t piece) const noexcept
{
    return piece == m_torrent_info->num_pieces -1 ? m_torrent_info->last_piece_length
                                                  : m_torrent_info->piece_length;
}

inline bool peer_session::is_piece_index_valid(const piece_index_t index) const noexcept
{
    return (index >= 0) && (index < m_torrent_info->num_pieces);
}

inline void peer_session::handle_unexpected_block(const block_info& block, message msg)
{
    m_info.total_wasted_bytes += block.length;
    m_torrent_info->total_wasted_bytes += block.length;
    // TODO uhm, we should probably do more here
}

inline void peer_session::handle_illicit_request()
{
    ++m_num_illicit_requests;
    log(log_event::incoming, "%i illicit requests", m_num_illicit_requests);

    if(cached_clock::now() - seconds(2) <= m_last_outgoing_choke_time)
    {
        // don't mind request messages (though don't serve them) up to 2 seconds after
        // choking peer
        return;
    }

    if((m_num_illicit_requests % 10 == 0) && m_info.is_peer_choked)
    {
        // every now and then remind peer that it is choked
        send_choke();
    }
    else if(m_num_illicit_requests > 300)
    {
        // don't tolerate this forever
        disconnect(peer_session_errc::sent_requests_when_choked);
    }
}

inline void peer_session::handle_illicit_block()
{
    log(log_event::incoming, "%i unwanted blocks", m_num_unwanted_blocks);
    if(++m_num_unwanted_blocks > 50)
    {
        disconnect(peer_session_errc::unwanted_blocks);
    }
}

inline void peer_session::handle_illicit_bitfield()
{
    log(log_event::invalid_message, "bitfield not after handshake");
    disconnect(peer_session_errc::invalid_bitfield_message);
}

inline void peer_session::handle_unknown_message()
{
    log(log_event::invalid_message, "unknown message");
    disconnect(peer_session_errc::unknown_message);
}

// ----------
// -- disk --
// ----------

inline void peer_session::save_block(
    const block_info& block_info,
    disk_buffer block_data,
    piece_download& piece_download)
{
    m_work_state.started(writing_disk);
    m_info.num_pending_disk_write_bytes += block_info.length;
    m_torrent_info->num_pending_disk_write_bytes += block_info.length;
    m_disk_io.save_block(
        m_info.torrent_id,
        block_info,
        std::move(block_data),
        [this, block_info, start_time = cached_clock::now()](const std::error_code& error)
        {
            on_block_saved(error, block_info, start_time);
        },
        // TODO verify that piece download's lifetime is preserved, otherwise use
        // shared_ptr
        [this, &piece_download](const bool is_piece_good)
        {
            // this callback is invoked when adding this block has finished piece and
            // hashing the piece is done; it notifies all peer_sessions who helped to
            // download this piece of the hash test, including this instance
            piece_download.notify_all_of_hash_result(is_piece_good);
        }
    );
    log(log_event::disk, 
        "launched disk write, saving block (piece: %i, offset: %i, length: %i)",
        block_info.index, block_info.offset, block_info.length
    );
}

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
        log(log_event::disk, "piece (%i) passed hash test", piece);
        if(is_on_parole())
        {
            // release parole piece download
            m_parole_piece.reset();
            // peer cleared itself, so it's no longer on parole
            m_info.is_on_parole = false;
            log(log_event::parole, "peer cleared suspicion, no longer on parole");
        }
    }
    else
    {
        ++m_info.num_hash_fails;

        log(log_event::parole,
            "piece (%i) failed hash test (%i fails)",
            piece, m_info.num_hash_fails
        );

        if(is_on_parole() || (*piece_download)->is_exclusive())
        {
            // delete parole piece download
            m_parole_piece.reset();
            // this peer was the sole participant in this download so we know that it
            // sent us a corrupt piece
            disconnect(peer_session_errc::corrupt_piece);
        }
        else
        {
            m_info.is_on_parole = true;
            // TODO probably other repercussions
        }
    }
    m_piece_downloads.erase(piece_download);
}

void peer_session::on_block_saved(
    const std::error_code& error,
    const block_info& block,
    const time_point start_time)
{
    m_work_state.stopped(writing_disk);
    m_info.num_pending_disk_write_bytes -= block.length;
    m_torrent_info->num_pending_disk_write_bytes -= block.length;
    if(error)
    {
        // TODO this means we cannot serve peer's request. should we try again?
        log(log_event::disk, "disk failure #%i", m_num_disk_io_failures + 1);
        if(++m_num_disk_io_failures > 100)
        {
            disconnect(error);
        }
        return;
    }
    m_num_disk_io_failures = 0;
    m_info.total_bytes_written_to_disk += block.length;
    // TODO consider recording disk read/write stats in disk_io/torrent_storage
    m_torrent_info->total_bytes_written_to_disk += block.length;
    m_avg_disk_write_time.add_sample(
        total_milliseconds(cached_clock::now() - start_time)
    );

    log(log_event::disk,
        "saved block to disk (piece: %i, offset: %i, length: %i) -- "
        "disk write stats (total: %i; pending: %i)",
        block.index, block.offset, block.length,
        m_info.total_bytes_written_to_disk, m_info.num_pending_disk_write_bytes
    );

    // we can likely receive more now that we finished writing to disk
    receive();
}

void peer_session::on_block_read(const std::error_code& error, const block_source& block)
{
    m_work_state.stopped(reading_disk);
    m_info.num_pending_disk_read_bytes -= block.length;
    m_torrent_info->num_pending_disk_read_bytes -= block.length;

    if(error == asio::error::operation_aborted)
    {
        log(log_event::disk,
            "block fetch aborted (piece: %i, offset: %i, length: %i)",
            block.index, block.offset, block.length
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
    m_info.total_uploaded_piece_bytes += block.length;
    m_torrent_info->total_bytes_read_from_disk += block.length;
    m_torrent_info->total_downloaded_piece_bytes += block.length;

    m_upload_rate.update(block.length);
    m_info.upload_rate = m_upload_rate.bytes_per_second();
    if(m_info.upload_rate > m_info.peak_upload_rate)
    {
        m_info.peak_upload_rate = m_info.upload_rate;
    }

    log(log_event::disk,
        "read block from disk (piece: %i, offset: %i, length: %i) -- "
        "disk read stats (total: %i; pending: %i)",
        block.index, block.offset, block.length,
        m_info.total_bytes_read_from_disk, m_info.num_pending_disk_read_bytes
    );

    send_block(block);
}

// ---------------------
// -- message sending --
// ---------------------

// --------------------------------------------------------------------
// HANDSHAKE <pstrlen=49+len(pstr)><pstr><reserved><info hash><peer id>
// --------------------------------------------------------------------
// pstrlen : length of the protocol identifier (currently 19)
// pstr : the protocol identifier (currently "BitTorrent protocol")
// reserved : all current implementations use all 0s, each bit changes the protocol
// info hash : the torrent's 20 byte info hash
// peer id : the peer's 20 byte unique id (client id)
void peer_session::send_handshake()
{
    static constexpr char protocol_id[] = "BitTorrent protocol";
    static constexpr char protocol_id_length = sizeof(protocol_id) - 1;
    // currently no support for extensions
    const uint8_t extensions[8] = { 0,0,0,0,0,0,0,0 };
    m_send_buffer.append(fixed_payload<protocol_id_length + 49>()
        .i8(protocol_id_length)
        .range(protocol_id, protocol_id + protocol_id_length)
        .buffer(extensions)
        .buffer(m_torrent_info->info_hash)
        .buffer(m_settings.client_id)
    );
    send();
    log(log_event::outgoing,
        "HANDSHAKE (protocol: %s; extensions: %s; info_hash: %s, client_id: %s)",
        protocol_id,
        extensions,
        m_torrent_info->info_hash.data(),
        m_settings.client_id.data()
    );

    /*
    std::string extensions_str = [&extensions]() -> std::string
    {
        std::string ret;
        ret.reserve(64);
        for(const uint8_t b : extensions)
        {
            for(const char c : std::bitset<8>(b).to_string())
            {
                ret += c;
            }
        }
        return ret;
    }();
    std::string info_hash_str = detail::to_hex(m_torrent_info->info_hash);
    log(log_event::outgoing,
        "HANDSHAKE (protocol: %s; extensions: %s; info_hash: %s; client_id: %s)",
        protocol_id,
        extensions_str.c_str(),
        info_hash_str.c_str(),
        m_settings.client_id.data()
    );
    */

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

    if(m_piece_picker->have_no_pieces())
    {
        return;
    }

    const auto& my_pieces = m_piece_picker->my_bitfield();
    const int msg_size = 1 + my_pieces.data().size();
    m_send_buffer.append(payload(4 + msg_size)
        .i32(msg_size)
        .i8(message_t::bitfield)
        .buffer(my_pieces.data())
    );
    send();
    log(log_event::outgoing,
        "BITFIELD (%s)",
        m_piece_picker->my_bitfield().to_string().c_str()
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
    log(log_event::outgoing, "KEEP_ALIVE");
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
    log(log_event::outgoing, "CHOKE");
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
    log(log_event::outgoing, "UNCHOKE");
}

// ------------------
// INTERESTED <len=1>
// ------------------
void peer_session::send_interested()
{
    static constexpr uint8_t payload[] = { 0,0,0,1, message_t::interested };
    m_send_buffer.append(payload);
    m_info.am_interested = true;
    m_last_outgoing_interest_time = cached_clock::now();
    send();
    log(log_event::outgoing, "INTERESTED");
}

// ----------------------
// NOT INTERESTED <len=1>
// ----------------------
void peer_session::send_not_interested()
{
    static constexpr uint8_t payload[] = { 0,0,0,1, message_t::not_interested };
    m_send_buffer.append(payload);
    m_info.am_interested = false;
    m_work_state.stopped(slow_start);
    m_last_outgoing_uninterest_time = cached_clock::now();
    send();
    log(log_event::outgoing, "NOT_INTERESTED");
}

// -------------------------------
// HAVE <len=5><id=4><piece index>
// -------------------------------
inline void peer_session::send_have(const piece_index_t piece)
{
    m_send_buffer.append(fixed_payload<4 + 5>()
        .i32(5)
        .i8(message_t::have)
        .i32(piece)
    );
    send();
    log(log_event::outgoing, "HAVE (piece: %i)", piece);
}

// ---------------------------------------------
// REQUEST <len=13><id=6><index><offset><length>
// ---------------------------------------------
// Block size should be 2^14 (16KB - 16,384 bytes).
// Max request block size is 2^15 (32KB - 32,768 bytes), but many clients will refuse
// to serve this amount.
void peer_session::send_request(const block_info& block)
{
    m_send_buffer.append(fixed_payload<4 + 13>()
        .i32(13)
        .i8(message_t::request)
        .i32(block.index)
        .i32(block.offset)
        .i32(block.length)
    );
    m_sent_requests.emplace_back(block.index, block.offset, block.length);
    m_last_outgoing_request_time = cached_clock::now();
    log(log_event::outgoing,
        "REQUEST (piece: %i, offset: %i, length: %i)",
        block.index, block.offset, block.length
    );
}

void peer_session::send_requests()
{
    log(log_event::request,
        "preparing request queue (outstanding requests: %i, ideal queue size: %i)",
        m_sent_requests.size(),
        m_best_request_queue_size
    );
    assert(m_info.am_interested && !m_info.am_choked);
    assert(m_piece_picker && m_piece_download_locator);

    if(!can_send_requests())
    {
        return;
    }

    const int num_new_requests = is_on_parole() ? make_requests_in_parole_mode()
                                                : make_requests_in_normal_mode();
    if(num_new_requests > 0)
    {
        payload requests(num_new_requests * (4 + 13));
        assert(num_new_requests <= m_sent_requests.size());
        for(auto i = m_sent_requests.size() - num_new_requests;
            i < m_sent_requests.size();
            ++i)
        {
            // craft the payload for each block that was put in m_sent_requests by the
            // above functions
            const pending_block& block = m_sent_requests[i];
            requests
                .i32(13)
                .i8(message_t::request)
                .i32(block.index)
                .i32(block.offset)
                .i32(block.length);
            log(log_event::outgoing,
                "REQUEST (piece: %i, offset: %i, length: %i)",
                block.index, block.offset, block.length
            );
            m_info.num_outstanding_bytes += block.length;
            m_torrent_info->num_outstanding_bytes += block.length;
        }
        m_send_buffer.append(std::move(requests));

        log(log_event::outgoing, "request queue length: %i", num_new_requests);

        send();

        m_last_outgoing_request_time = cached_clock::now();
        start_timer(
            m_request_timeout_timer,
            request_timeout(),
            [this](const std::error_code& error)
            {
                handle_request_timeout(error);
            }
        );
    }
}

inline bool peer_session::can_send_requests() const noexcept
{
    return m_sent_requests.size() < m_best_request_queue_size
        && m_info.am_interested
        && !m_info.am_choked;
}

inline int peer_session::make_requests_in_parole_mode()
{
    // pick a parole piece for this peer if it hasn't been assigned one yet since it
    // participated in a failed hash test
    if(m_parole_piece == nullptr)
    {
        const auto piece = m_piece_picker->pick_and_reserve(m_info.available_pieces);
        if(piece == piece_picker::no_piece)
        {
            return 0;
        }
        m_parole_piece = std::make_unique<piece_download>(
            piece,
            get_piece_length(piece),
            [this, piece](const bool is_piece_good)
            {
                m_new_piece_handler(piece, is_piece_good);
            }
        );
        log(log_event::request, "picked piece (%i) in parole mode", piece);
    }

    int num_new_requests = 0;
    if(m_parole_piece->can_request())
    {
        for(auto& request : m_parole_piece->make_request_queue(num_to_request()))
        {
            m_sent_requests.emplace_back(std::move(request));
            ++num_new_requests;
        }
    }
    return num_new_requests;
}

inline int peer_session::make_requests_in_normal_mode()
{
    // if we have active downloads, prefer to finish those (this will result in less
    // peers per piece download, i.e. lower chance of a bad peer polluting many pieces)
    int num_new_requests = continue_downloads();

    // we try to join a download using piece_download_locator as long as we need more
    // blocks and there are downloads to join
    while(m_sent_requests.size() < m_best_request_queue_size)
    {
        int num_blocks = join_download();
        if(num_blocks == 0)
        {
            break;
        }
        num_new_requests += num_blocks;
    }

    // while we still need blocks, we pick a piece and start a new download, and add it
    // to the shared downloads via m_piece_download_locator
    while(m_sent_requests.size() < m_best_request_queue_size)
    {
        int num_blocks = start_download();
        if(num_blocks == 0)
        {
            break;
        }
        num_new_requests += num_blocks;
    }
    return num_new_requests;
}

inline int peer_session::continue_downloads()
{
    int num_new_requests = 0;
    for(auto& download : m_piece_downloads)
    {
        if(m_sent_requests.size() == m_best_request_queue_size)
        {
            break;
        }
        if(download->can_request())
        {
            log(log_event::request,
                "continuing piece (%i) download",
                download->piece_index()
            );
            for(auto& request : download->make_request_queue(num_to_request()))
            {
                m_sent_requests.emplace_back(std::move(request));
                ++num_new_requests;
            }
        }
    }
    return num_new_requests;
}

inline int peer_session::join_download()
{
    int num_new_requests = 0;
    auto download = m_piece_download_locator->find(m_info.available_pieces);
    if(download)
    {
        log(log_event::request, "joining piece download (%i)", download->piece_index());
        for(auto& request : download->make_request_queue(num_to_request()))
        {
            m_sent_requests.emplace_back(std::move(request));
            ++num_new_requests;
        }
        // now we participated in this piece download as well
        // TODO make sure we don't add the same download twice
        m_piece_downloads.emplace_back(download);
    }
    return num_new_requests;
}

inline int peer_session::start_download()
{
    int num_new_requests = 0;
    const auto piece = m_piece_picker->pick_and_reserve(m_info.available_pieces);
    if(piece != piece_picker::no_piece)
    {
        log(log_event::request, "picked piece (%i)", piece);
        auto download = std::make_shared<piece_download>(
            piece,
            get_piece_length(piece),
            [this, piece](const bool is_piece_good)
            {
                m_new_piece_handler(piece, is_piece_good);
            }
        );
        for(auto& request : download->make_request_queue(num_to_request()))
        {
            m_sent_requests.emplace_back(std::move(request));
            ++num_new_requests;
        }
        // add download to shared database so other peer_sessions may join
        m_piece_download_locator->add(download);
        m_piece_downloads.emplace_back(download);
    }
    return num_new_requests;
}

inline int peer_session::num_to_request() const noexcept
{
    return std::max(m_best_request_queue_size - int(m_sent_requests.size()), 0);
}

// ------------------------------------------
// BLOCK <len=9+X><id=7><index><offset><data>
// ------------------------------------------
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
    m_last_outgoing_block_time = cached_clock::now();
    m_upload_rate.update(block.length);

    send();

    log(log_event::outgoing,
        "BLOCK (piece: %i, offset: %i, length: %i)",
        block.index, block.offset, block.length
    );
}

// --------------------------------------------
// CANCEL <len=13><id=8><index><offset><length>
// --------------------------------------------
void peer_session::send_cancel(const block_info& block)
{
    // TODO check if we're not already receiving this block in which case we cannot send
    // a cancel
    if(block == m_receiving_block)
    {
        return;
    }
    m_send_buffer.append(fixed_payload<4 + 13>()
        .i32(13)
        .i8(message_t::cancel)
        .i32(block.index)
        .i32(block.offset)
        .i32(block.length)
    );
    send();
    log(log_event::outgoing,
        "CANCEL (piece: %i, offset: %i, length: %i)",
        block.index, block.offset, block.length
    );
}

// -------------------------------
// PORT <len=3><id=9><listen-port>
// -------------------------------
void peer_session::send_port(const int port)
{
    m_send_buffer.append(fixed_payload<4 + 3>()
        .i32(3)
        .i8(message_t::port)
        .i16(port)
    );
    send();
    log(log_event::outgoing, "PORT (%i)", port);
}

// -------------------
// -- timeout logic --
// -------------------

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

    m_best_request_queue_size = 1;
    m_info.has_peer_timed_out = true;
    ++m_info.num_timed_out_requests;
    ++m_torrent_info->num_timed_out_requests;

    // start from the back to find the most recently sent request to time out
    // (for more info: http://blog.libtorrent.org/2011/11/block-request-time-outs/)
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
        // this should not happen, means that we forgot to delete request from 
        // m_sent_requests when we received it
        assert(piece_download != m_piece_downloads.rbegin());
        (*piece_download)->time_out(
            m_info.id,
            request,
            [this](const block_info& block)
            {
                // this will be invoked if we get this block from another peer sooner
                send_cancel(block);
            }
        );
        log(log_event::timeout,
            "timing out block (piece: %i, offset: %i, length: %i)",
            request.index, request.offset, request.length
        );
    }
    // try to send requests again, with updated request queue length
    if(m_info.am_interested && !m_info.am_choked)
    {
        send_requests();
    }
}

seconds peer_session::request_timeout() const
{
    int timeout = m_avg_request_rtt.mean() + 4 * m_avg_request_rtt.deviation();
    // to avoid being timing out peer instantly timeouts should never be less than two
    // seconds
    return seconds(std::max(2, timeout));
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
        log(log_event::timeout,
            "connecting timed out, elapsed time: %ims",
            total_milliseconds(cached_clock::now() - m_connection_started_time)
        );
        disconnect(peer_session_errc::connect_timeout);
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
        disconnect(peer_session_errc::inactivity_timeout);
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
    if(cached_clock::now() - m_last_send_time > seconds(120))
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
    const log_event event,
    const std::string& format,
    Args&&... args) const
{
    // TODO proper logging
    std::cerr << '[';
    if(event != log_event::connecting)
    {
        std::cerr << '+';
        std::cerr << total_seconds(cached_clock::now() - m_connection_established_time);
        std::cerr << "s | ";
    }
    switch(event)
    {
    case log_event::connecting:
        std::cerr << "CONNECTING";
        break;
    case log_event::disconnecting:
        std::cerr << "DISCONNECTING";
        break;
    case log_event::incoming:
        std::cerr << "IN";
        break;
    case log_event::outgoing:
        std::cerr << "OUT";
        break;
    case log_event::disk:
        std::cerr << "DISK";
        break;
    case log_event::invalid_message:
        std::cerr << "INVALID MESSAGE";
        break;
    case log_event::parole:
        std::cerr << "PAROLE";
        break;
    case log_event::timeout:
        std::cerr << "TIMEOUT";
        break;
    case log_event::request:
        std::cerr << "REQUEST";
        break;
    }
    std::cerr << "] -- ";

    // + 1 for '\0'
    const size_t length = std::snprintf(nullptr, 0, format.c_str(), args...) + 1;
    std::unique_ptr<char[]> buffer(new char[length]);
    std::snprintf(buffer.get(), length, format.c_str(), args...);
    // -1 to exclude the '\0' at the end
    std::string message(buffer.get(), buffer.get() + length - 1);
    std::cerr << message << '\n';
}

template<typename Duration, typename Handler>
void peer_session::start_timer(
    deadline_timer& timer,
    const Duration& expires_in,
    Handler handler)
{
    std::error_code ec;
    // setting expires from now also cancels pending async waits (which is what we want)
    timer.expires_from_now(expires_in, ec);
    timer.async_wait(std::move(handler));
}

inline bool matches(char* id, char* client)
{
    return id[0] == client[0] && id[1] == client[1];
}

inline void peer_session::try_identify_client()
{
    // https://wiki.theory.org/BitTorrentSpecification#peer_id
    m_info.client = [this]() -> std::string
    {
        if(m_info.id[0] == '-')
        {
            // Azureus-style encoding
            const auto matches = [this](const char* client) -> bool
            {
                return m_info.id[1] == client[0]
                    && m_info.id[2] == client[1];
            };
            if(matches("7T")) return "aTorrent";
            else if(matches("AB")) return "AnyEvent::BitTorrent";
            else if(matches("AG") || matches("A~")) return "Ares";
            else if(matches("AR")) return "Arctic";
            else if(matches("AV")) return "Avicora";
            else if(matches("AT")) return "Artemis";
            else if(matches("AX")) return "BitPump";
            else if(matches("AZ")) return "Azureus";
            else if(matches("BB")) return "BitBuddy";
            else if(matches("BC")) return "BitComet";
            else if(matches("BE")) return "Baretorrent";
            else if(matches("BF")) return "Bitflu";
            else if(matches("BG")) return "BTG";
            else if(matches("BL"))
            {
                // BitCometLite uses 6 digits for version number as opposed to the
                // standard 4 for most other Azureus style peer ids
                return m_info.id[1 + 2 + 6] == '-' ? "BitCometLite"
                                                   : "BitBlinder";
            }
            else if(matches("BP")) return "BitTorrent Pro";
            else if(matches("BR")) return "BitRocket";
            else if(matches("BS")) return "BTSlave";
            else if(matches("BT")) return "Mainline";
            else if(matches("Bt")) return "Bt";
            else if(matches("BW")) return "BitWombat";
            else if(matches("BX")) return "~Bittorrent X";
            else if(matches("CD")) return "Enhanced CTorrent";
            else if(matches("CT")) return "CTorrent";
            else if(matches("DE")) return "DelugeTorrent";
            else if(matches("DP")) return "Propagate Data Client";
            else if(matches("EB")) return "EBit";
            else if(matches("ES")) return "electric sheep";
            else if(matches("FC")) return "FileCroc";
            else if(matches("FD")) return "Free Download Managder";
            else if(matches("FT")) return "FoxTorrent";
            else if(matches("FX")) return "Freebox BitTorrent";
            else if(matches("GS")) return "GSTorrent";
            else if(matches("HK")) return "hekate";
            else if(matches("HL")) return "Halite";
            else if(matches("HM")) return "hMule";
            else if(matches("HN")) return "Hydranode";
            else if(matches("IL")) return "iLivid";
            else if(matches("JS")) return "Justseed.it client";
            else if(matches("JT")) return "JavaTorrent";
            else if(matches("KG")) return "KGet";
            else if(matches("KT")) return "KTorrent";
            else if(matches("LC")) return "LeechCraft";
            else if(matches("LH")) return "LH-ABC";
            else if(matches("LP")) return "Lphant";
            else if(matches("LT")) return "libtorrent";
            else if(matches("lt")) return "libTorrent";
            else if(matches("LW")) return "LimeWire";
            else if(matches("MK")) return "Meerkat";
            else if(matches("MO")) return "MonoTorrent";
            else if(matches("MP")) return "MooPolice";
            else if(matches("MR")) return "Miro";
            else if(matches("MT")) return "MoonlightTorrent";
            else if(matches("NB")) return "Net::BitTorrent";
            else if(matches("NX")) return "Net Transport";
            else if(matches("OS")) return "OneSwarm";
            else if(matches("OT")) return "OmegaTorrent";
            else if(matches("PB")) return "Protocol::BitTorrent";
            else if(matches("PD")) return "Pando";
            else if(matches("PI")) return "PicoTorrent";
            else if(matches("PT")) return "PHPTracker";
            else if(matches("qB")) return "qBittorrent";
            else if(matches("QD")) return "QQDownload";
            else if(matches("QT")) return "Qt 4 Torrent example";
            else if(matches("RT")) return "Retriever";
            else if(matches("RZ")) return "RezTorrent";
            else if(matches("S~")) return "Shareaza alpha/beta";
            else if(matches("SB")) return "~Swiftbit";
            else if(matches("SD")) return "Thunder (XunLei)";
            else if(matches("SM")) return "SoMud";
            else if(matches("SP")) return "BitSpirit";
            else if(matches("SS")) return "SwarmScope";
            else if(matches("ST")) return "SymTorrent";
            else if(matches("st")) return "sharktorrent";
            else if(matches("SZ")) return "Shareaza";
            else if(matches("TB")) return "Torch";
            else if(matches("TE")) return "terasaur Seed Bank";
            else if(matches("TL")) return "Tribler";
            else if(matches("TN")) return "TorrentDotNET";
            else if(matches("TR")) return "Transmission";
            else if(matches("TS")) return "Torrentstrom";
            else if(matches("TT")) return "TuoTu";
            else if(matches("UL")) return "uLeecher!";
            else if(matches("UM")) return "µTorrent for Mac";
            else if(matches("UT")) return "µTorrent";
            else if(matches("VG")) return "Vagaa";
            else if(matches("WD")) return "WebTorrent Desktop";
            else if(matches("WT")) return "BitLet";
            else if(matches("WW")) return "WebTorrent";
            else if(matches("WY")) return "FireTorrent";
            else if(matches("XF")) return "Xfplay";
            else if(matches("XL")) return "Xunlei";
            else if(matches("XS")) return "XSwifter";
            else if(matches("XT")) return "XanTorrent";
            else if(matches("XX")) return "Xtorrent";
            else if(matches("ZT")) return "ZipTorrent";
        }
        else
        {
            // Shad0w-style encoding
            const auto matches = [this](const char client) -> bool
            {
                return m_info.id[0] == client;
            };
            if(matches('A')) return "ABC";
            else if(matches('O')) return "Osprey Permaseed";
            else if(matches('Q')) return "BTQueue";
            else if(matches('R')) return "Tribler";
            else if(matches('S')) return "Shadow";
            else if(matches('T')) return "BitTornado";
            else if(matches('U')) return "UPnP NAT Bit Torrent";
        }
        return "";
    }();
}

/**
 * Produces block_info objects by parsing the supplied byte sequence. Bytes must be a
 * container of byte types (std::vector, std::array, view...) and at least 12 long.
 */
template<typename Bytes>
block_info parse_block_info(const Bytes& data)
{
    assert(data.size() >= 3 * 4);

    auto byte_it = data.cbegin();
    const auto end = data.cend();
    const piece_index_t index = detail::parse<piece_index_t>(byte_it);
    const int offset = detail::parse<int>(byte_it += 4);

    if(data.size() == 3 * 4)
    {
        // it's a request/cancel message with fixed message length
        return block_info(index, offset, detail::parse<int>(byte_it += 4));
    }
    else
    {
        // it's a block message, we get the block's length by subtracting the index and
        // offset fields' added length from the total message length
        return block_info(index, offset, data.size() - 2 * 4);
    }
}
