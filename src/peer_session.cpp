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

/*
// TODO make logging compilation dependent, and move this into the logger header
// this invokes each class' log method
#ifdef TORRENT_LOG
# define LOG(m) do log(m); while(0)
#else
# define LOG(m)
#endif
*/

namespace tide {

// peer_session needs to be kept alive until all async ops complete, so we bind a
// shared_ptr to `this` to each async op's handler along with `this`
#define SHARED_THIS this, self(shared_from_this())

using namespace std::placeholders;

template<typename Bytes> block_info parse_block_info(const Bytes& data);

/**
 * Used when we expect successive writes to socket to amortize the overhead of context
 * switches by blocking (corking) the socket until we're done and writing the accrued
 * messages in one batch.
 *
 * Credit to libtorrent:
 * http://blog.libtorrent.org/2012/12/principles-of-high-performance-programs/
 */
class peer_session::send_cork
{
    peer_session& m_session;
    bool m_should_uncork = false;

public:

    explicit send_cork(peer_session& p) : m_session(p)
    {
        if(!m_session.m_op_state[op_t::send])
        {
            // block other send operations by pretending to be sending
            m_session.m_op_state.set(op_t::send);
            m_should_uncork = true;
        }
    }

    ~send_cork()
    {
        if(m_should_uncork)
        {
            m_session.m_op_state.unset(op_t::send);
            m_session.send();
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
    , m_connect_timeout_timer(m_socket->get_io_service())
    , m_keep_alive_timer(m_socket->get_io_service())
    , m_request_timeout_timer(m_socket->get_io_service())
    , m_inactivity_timeout_timer(m_socket->get_io_service())
{
    assert(m_socket);
    assert(m_settings.max_receive_buffer_size != -1);
    m_info.remote_endpoint = std::move(peer_endpoint);
    m_info.max_outgoing_request_queue_size = settings.max_outgoing_request_queue_size;
    m_op_state.set(op_t::slow_start);
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
        settings)
{
    m_piece_picker = torrent_args.piece_picker;
    m_shared_downloads = torrent_args.shared_downloads;
    m_torrent_info = torrent_args.torrent_info;
    m_piece_completion_handler = torrent_args.piece_completion_handler;

    assert(m_shared_downloads);
    assert(m_torrent_info);
    assert(m_piece_picker);

    // initialize peer's bitfield
    m_info.available_pieces = bt_bitfield(m_torrent_info->num_pieces);
    m_info.is_outbound = true;
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
        settings)
{
    m_torrent_attacher = std::move(torrent_attacher);
    m_info.is_outbound = false;
}

peer_session::~peer_session()
{
    disconnect(peer_session_errc::stopped);
    // at this point we should have no more pending operations
    assert(!has_pending_disk_op());
}

void peer_session::start()
{
    if(m_info.state == state_t::disconnected)
    {
        if(!m_info.was_started_before)
        {
            if(is_outbound())
                connect();
            else
                on_connected();
            m_info.was_started_before = true;
        }
        else
        {
            m_info.is_outbound = true;
            connect();
        }
    }
}

void peer_session::stop(const stop_mode_t stop_mode)
{
    if(m_info.state != state_t::disconnected)
    {
        if(stop_mode == stop_mode_t::abort)
        {
            disconnect(peer_session_errc::stopped);
        }
        else
        {
            m_info.state = state_t::disconnecting;
        }
    }
}

inline void peer_session::connect()
{
    std::error_code ec;
    log(log_event::connecting, "opening socket");
    m_socket->open(m_info.remote_endpoint.protocol(), ec);
    if(ec)
    {
        disconnect(ec);
        return;
    }

    m_socket->async_connect(m_info.remote_endpoint,
        [SHARED_THIS](const std::error_code& error) { on_connected(error); });

    m_info.state = state_t::connecting;
    m_info.connection_started_time = cached_clock::now();

    start_timer(m_connect_timeout_timer, m_settings.peer_connect_timeout,
        [SHARED_THIS](const std::error_code& error) { on_connect_timeout(error); });
    log(log_event::connecting, "started establishing connection");
}

void peer_session::on_connected(const std::error_code& error)
{
    if(should_abort(error))
    {
        disconnect(peer_session_errc::stopped);
    }

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

    m_info.connection_established_time = cached_clock::now();
    log(log_event::connecting, "connected to %s in %ims",
        m_info.remote_endpoint.address().to_string().c_str(),
        total_milliseconds(m_info.connection_established_time
            - m_info.connection_started_time));
    m_info.local_endpoint = m_socket->local_endpoint(ec);
    if(ec)
    {
        disconnect(ec);
        return;
    }

    m_info.state = state_t::in_handshake;
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

    start_timer(m_keep_alive_timer, m_settings.peer_timeout,
        [SHARED_THIS](const std::error_code& error) { on_keep_alive_timeout(error); });
}

inline bool peer_session::should_abort(const std::error_code& error) const noexcept
{
    return (error == asio::error::operation_aborted) || is_stopped();
}

void peer_session::disconnect(const std::error_code& error)
{
    if(is_disconnected()) { return; }

    //m_info.state = state_t::disconnecting;
    log(log_event::disconnecting,
        "preparing to disconnect; reason: %s",
        error.message().c_str());

    std::error_code ec;
    m_keep_alive_timer.cancel(ec);
    m_inactivity_timeout_timer.cancel(ec);

    // if we have any pending requests, tell their corresponding piece downloads that
    // we won't get the blocks and to remove this peer from their participant registry
    abort_outgoing_requests();
    detach_downloads();
    if(m_piece_picker != nullptr)
    {
        m_piece_picker->decrease_frequency(m_info.available_pieces);
    }

    m_socket->close(ec);
    m_info.state = state_t::disconnected;
    if(m_torrent_info)
    {
        m_torrent_info->num_outstanding_bytes -= m_info.num_outstanding_bytes;
    }

    log(log_event::disconnecting, "tore down connection");

    // TODO tell disk_io to stop serving peer's outstanding requests
    // TODO record partially received payload as wasted
    // TODO clear pending sent and received requests queue
}

inline void peer_session::abort_outgoing_requests()
{
    std::error_code ec;
    m_request_timeout_timer.cancel(ec);

    // TODO VERIFY THIS
    piece_download* download = nullptr;
    // tell each download that we won't get our requested blocks
    for(const pending_block& block : m_sent_requests)
    {
        // it is likely that most of the current requests belong to one piece download,
        // so we're caching it in download above, but still need to check it
        if(!download || (download->piece_index() != block.index))
        {
            download = find_download(block.index);
        }
        if(download)
        {
            download->abort_request(static_cast<const block_info&>(block));
        }
    }
    m_info.num_outstanding_bytes = 0;
    m_torrent_info->num_outstanding_bytes = 0;
    m_sent_requests.clear();
}

inline void peer_session::detach_downloads()
{
    for(auto& download : m_downloads)
    {
        download->remove_peer(m_info.peer_id);
    }
    if(m_parole_download)
    {
        if(m_parole_download->num_blocks_left() < m_parole_download->num_blocks())
        {
            // if download of this piece has been begun, it means we have passed a
            // reference to this piece download to disk_io::save_block's completion
            // handler, so we must place it in m_shared_downloads to keep the memory
            // valid; moreover, even though it was a piece downloaded by a suspicious
            // peer, chances are it was good so we don't want to waste it
            m_parole_download->remove_peer(m_info.peer_id);
            m_shared_downloads->emplace_back(std::move(m_parole_download));
        }
        else
        {
            // if we have a parole piece assigned to this peer, it means we're not yet
            // seeding (or we forgot to release m_parole_download), so we must have
            // a picker
            assert(m_piece_picker);
            // otherwise we must free this piece from piece picker for other peers to
            // download this piece
            m_piece_picker->unreserve(m_parole_download->piece_index());
            m_parole_download.reset();
        }
    }
    m_downloads.clear();
}

peer_session::stats peer_session::get_stats() const noexcept
{
    stats s;
    get_stats(s);
    return s;
}

void peer_session::get_stats(stats& s) const noexcept
{
    s.torrent_id = m_torrent_info ? m_torrent_info->id : -1;
    s.peer_id = m_info.peer_id;
    s.client = m_info.client;
    s.avg_request_rtt = milliseconds(m_avg_request_rtt.mean());
    s.upload_rate = m_upload_rate.bytes_per_second();
    s.download_rate = m_download_rate.bytes_per_second();
    s.peak_upload_rate = m_upload_rate.peak();
    s.peak_download_rate = m_download_rate.peak();
    s.used_send_buffer_size = m_send_buffer.size();
    s.total_send_buffer_size = m_send_buffer.size();
    s.used_receive_buffer_size = m_message_parser.size();
    s.total_receive_buffer_size = m_message_parser.buffer_size();
}

peer_session::detailed_stats peer_session::get_detailed_stats() const noexcept
{
    detailed_stats s;
    get_detailed_stats(s);
    return s;
}

void peer_session::get_detailed_stats(detailed_stats& s) const noexcept
{
    get_stats(static_cast<stats&>(s));
    // TODO don't copy over string type elements as those have likely not changed
    static_cast<info&>(s) = m_info;
    s.piece_downloads.clear();
    s.piece_downloads.reserve(m_downloads.size());
    for(const auto& d : m_downloads)
    {
        s.piece_downloads.emplace_back(d->piece_index());
    }
}

void peer_session::choke_peer()
{
    if(!is_ready_to_send() || is_peer_choked())
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
    if(is_ready_to_send() && is_peer_choked())
    {
        send_unchoke();
    }
}

void peer_session::announce_new_piece(const piece_index_t piece)
{
    // we're either shutting down or still connecting, so we can't proceed, though in
    // the latter case we'll send our pieces after the handshake anyway
    if(is_ready_to_send())
    {
        // don't send a have msg if peer already has the piece
        if(!m_info.available_pieces[piece])
        {
            send_have(piece);
        }
        // send_have() is called by torrent when a new piece is received, so recalculate
        // whether we're interested in this peer, for we may have received the only piece
        // peer has in which we were interested TODO what if we're receiving that piece?
        update_interest();
        if(m_shared_downloads && am_seeder())
        {
            // we've become a seeder through this piece, we're not going to need this
            m_shared_downloads.reset();
        }
    }
}

void peer_session::update_interest()
{
    const bool was_interested = m_info.am_interested;
    const bool am_interested = m_piece_picker->am_interested_in(m_info.available_pieces);
    if(!was_interested && am_interested)
    {
        m_info.am_interested = true;
        std::error_code ec;
        m_inactivity_timeout_timer.cancel(ec);
        send_interested();
        if(can_send_requests())
        {
            send_requests();
        }
    }
    else if(was_interested && !am_interested)
    {
        m_info.am_interested = false;
        send_not_interested();
        // if peer isn't interested either, we enter a state of inactivity, so we must
        // guard against idling too long
        if(!is_peer_interested())
        {
            start_timer(m_inactivity_timeout_timer, minutes(10),
                [SHARED_THIS](const std::error_code& error)
                { on_inactivity_timeout(error); });
        }
    }
    if(am_seeder() && m_info.is_peer_seed)
    {
        disconnect(peer_session_errc::both_seeders);
    }
}

inline bool peer_session::am_seeder() const noexcept
{
    return m_torrent_info ? m_torrent_info->state[torrent_info::state_t::seeding]
                          : false;
}

// -------------
// -- sending --
// -------------

void peer_session::send()
{
    if(is_stopped())
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
    m_socket->async_write_some(m_send_buffer.get_send_buffers(num_bytes_to_send),
        [SHARED_THIS](const std::error_code& error, size_t num_bytes_sent)
        { on_sent(error, num_bytes_sent); });

    m_op_state.set(op_t::send);

    log(log_event::outgoing, "sending: %i; available: %i; quota: %i",
        num_bytes_to_send, m_send_buffer.size(), m_info.send_quota);
}

bool peer_session::can_send() const noexcept
{
    if(m_send_buffer.is_empty())
    {
        log(log_event::outgoing, "CAN'T SEND, buffer empty");
        return false;
    }
    else if(m_op_state[op_t::send])
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
    m_op_state.unset(op_t::send);
    if(should_abort(error))
    {
        // we are disconnecting, so pending async ops were cancelled
        return;
    }
    else if(error)
    {
        log(log_event::outgoing, "error while sending");
        disconnect(error);
        return;
    }

    update_send_stats(num_bytes_sent);
    m_send_buffer.consume(num_bytes_sent);

    log(log_event::outgoing, "sent: %i; quota: %i; send buffer size: %i; total sent: %i",
        num_bytes_sent, m_info.send_quota, m_send_buffer.size(),
        m_info.total_uploaded_bytes);

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
    m_info.last_send_time = cached_clock::now();
    m_info.total_uploaded_bytes += num_bytes_sent;
    m_torrent_info->total_uploaded_bytes += num_bytes_sent;
}

// ---------------
// -- receiving --
// ---------------

void peer_session::receive()
{
    // TODO is it necessary to test agains being disconnected?
    // send/receive shouldn't be called if this is the case but leave it here for now
    // just to be safe
    if(is_stopped())
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
    m_socket->async_read_some(asio::mutable_buffers_1(buffer.data(), buffer.size()),
        [SHARED_THIS](const std::error_code& error, size_t num_bytes_received)
        { on_received(error, num_bytes_received); });

    m_op_state.set(op_t::receive);

    log(log_event::incoming, "receiving: %i; receive buffer free space: %i; quota: %i",
        num_to_receive, m_message_parser.free_space_size(), m_info.receive_quota);
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
    else if(m_op_state[op_t::receive])
    {
        log(log_event::incoming, "CAN'T RECEIVE, already receiving");
        return false;
    }
    else if(am_expecting_piece()
            && m_op_state[op_t::disk_read]
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
        m_message_parser.reserve(std::min(m_message_parser.buffer_size() + 128,
            m_settings.max_receive_buffer_size));
    }
}

inline int peer_session::get_num_to_receive() const noexcept
{
    // pending bytes written to disk are also counted as part of the receive buffer
    // until they are flushed to disk; this is used to throttle download rate if
    // we're disk bound (so as not to further overwhelm disk)
    const auto max_receive_size = std::max(
        m_message_parser.free_space_size() - m_info.num_pending_disk_write_bytes, 0);
    return std::min(max_receive_size, m_info.receive_quota);
}

void peer_session::on_received(const std::error_code& error, size_t num_bytes_received)
{
    m_op_state.unset(op_t::receive);
    if(should_abort(error))
    {
        // we are disconnecting, so pending async ops were cancelled
        return;
    }
    else if(error)
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
        num_bytes_received, m_message_parser.buffer_size(), m_info.receive_quota,
        m_info.total_downloaded_bytes);
    if(is_disconnected())
    {
        // flush_socket() spurred a disconnect
        return;
    }

    // send response messages at the end of the function in one batch
    send_cork cork(*this);
    const bool was_choked = am_choked();
    handle_messages();
    if(is_disconnected())
    {
        // handle_messages() spurred a disconnect
        // TODO consider throwing here for clearer control flow
        return;
    }
    adjust_receive_buffer(was_choked);
    receive();
}

inline void peer_session::update_receive_stats(const int num_bytes_received) noexcept
{
    m_info.receive_quota -= num_bytes_received;
    m_info.last_receive_time = cached_clock::now();
    m_info.total_downloaded_bytes += num_bytes_received;
    m_torrent_info->total_downloaded_bytes += num_bytes_received;
}

inline void peer_session::adjust_receive_buffer(const bool was_choked)
{
    const int old_buffer_size = m_message_parser.buffer_size();
    const bool got_choked = !was_choked && am_choked();

    if(!am_choked() && (old_buffer_size < m_settings.max_receive_buffer_size))
    {
        const int free_space_size = m_message_parser.free_space_size();
        if(am_expecting_piece() && (free_space_size < 0x4000))
        {
            // if we have space to grow and are expecting a block but don't have enough
            // receive space for it, increase buffer size to fit the number of
            // outstanding bytes (of course capped by max receive buffer size)
            m_message_parser.reserve(std::min(
                old_buffer_size + m_info.num_outstanding_bytes - free_space_size,
                m_settings.max_receive_buffer_size));
        }
        else if(m_message_parser.is_full())
        {
            // otherwise we're not expecting blocks but since we're not choked and
            // managed to fill the receive buffer we should still grow it
            // TODO but we may actually be choked, so this is wrong
            m_message_parser.reserve(std::min(
                old_buffer_size * 2, m_settings.max_receive_buffer_size));
        }
        log(log_event::incoming, "grew receive buffer from %i to %i",
            old_buffer_size, m_message_parser.buffer_size());
    }
    else if(got_choked && old_buffer_size > 1024)
    {
        // if we went from unchoked to choked (and if buffer is large enough, otherwise
        // don't bother), 100 bytes should suffice to receive further protocol chatter
        // (if we have unfinished messages in receive buffer it will not shrink below
        // the last valid message byte)
        m_message_parser.shrink_to_fit(100);
        log(log_event::incoming, "shrunk receive buffer from %i to %i",
            old_buffer_size, m_message_parser.buffer_size());
    }
}

inline bool peer_session::am_expecting_piece() const noexcept
{
    return (m_info.num_outstanding_bytes > 0) && !am_choked();
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
            asio::mutable_buffers_1(buffer.data(), buffer.size()), ec);
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
    if(m_info.state == state_t::in_handshake)
    {
        if(m_message_parser.has_handshake())
        {
            handle_handshake();
            if(is_disconnected())
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

    if(m_message_parser.has_message() && (m_info.state == state_t::bitfield_exchange))
    {
        if(m_message_parser.type() == message_t::bitfield)
        {
            handle_bitfield();
            if(is_disconnected())
            {
                // error in peer's bitfield
                return;
            }
        }
        m_info.state = state_t::connected;
    }

    while(!is_disconnected()
          && m_message_parser.has_message()
          && m_send_buffer.size() <= m_settings.max_send_buffer_size)
    {
        switch(m_message_parser.type())
        {
        // bitfield messages may only be sent after the handshake, in the bitfield
        // exchange state in state_t
        case message_t::bitfield: handle_illicit_bitfield(); break;
        case message_t::keep_alive: handle_keep_alive(); break;
        case message_t::choke: handle_choke(); break;
        case message_t::unchoke: handle_unchoke(); break;
        case message_t::interested: handle_interested(); break;
        case message_t::not_interested: handle_not_interested(); break;
        case message_t::have: handle_have(); break;
        case message_t::request: handle_request(); break;
        case message_t::block: handle_block(); break;
        case message_t::cancel: handle_cancel(); break;
        default:
            handle_unknown_message();
        }
    }

    // now check if the next message we're expecting and have not fully received is a
    // block, and if so, record it
    const_view<uint8_t> bytes = m_message_parser.peek_raw();
    if(bytes.length() >= 5)
    {
        const message_t type = static_cast<message_t>(bytes[4]);
        if((type == message_t::block) && (bytes.length() >= 17))
        {
            // trim off the first 5 bytes (msg_len(4) + msg_type(1))
            m_info.in_transit_block = parse_block_info(bytes.subview(5));
        }
    }
}

// --------------------------------------------------------------------
// HANDSHAKE <pstrlen=49+len(pstr)><pstr><reserved><info hash><peer id>
// --------------------------------------------------------------------
void peer_session::handle_handshake()
{
    handshake handshake;
    try
    {
        handshake = m_message_parser.extract_handshake();
    }
    catch(const std::runtime_error& error)
    {
        log(log_event::invalid_message, "couldn't parse HANDSHAKE");
        disconnect(peer_session_errc::invalid_handshake);
        return;
    }

    sha1_hash info_hash;
    std::copy(handshake.info_hash.cbegin(),
        handshake.info_hash.cend(), info_hash.begin());
    if(m_info.is_outbound)
    {
        // we started the connection, so we already sent our handshake,
        // so just verify peer's info_hash
        if(info_hash != m_torrent_info->info_hash)
        {
            disconnect(peer_session_errc::invalid_info_hash);
            return;
        }
    }
    else
    {
        torrent_specific_args torrent_args = m_torrent_attacher(info_hash);
        if(torrent_args.torrent_info == nullptr)
        {
            // this means we couldn't find a torrent to which we could be attached,
            // likely due to peer's bad info_hash
            disconnect(peer_session_errc::invalid_info_hash);
            return;
        }

        m_piece_picker = torrent_args.piece_picker;
        m_shared_downloads = torrent_args.shared_downloads;
        m_torrent_info = torrent_args.torrent_info;
        m_piece_completion_handler = torrent_args.piece_completion_handler;
        assert(m_torrent_info);
        if(am_seeder())
        {
            assert(m_piece_picker);
            assert(m_shared_downloads);
            assert(m_piece_completion_handler);
        }
        // initialize peer's bitfield now that we know the number of pieces this
        // torrent has
        m_info.available_pieces = bt_bitfield(m_torrent_info->num_pieces);
        // the connection was initiated by peer, we still need to send our handshake
        send_handshake();
    }
    std::copy(handshake.reserved.cbegin(),
        handshake.reserved.cend(), m_info.extensions.begin());
    std::copy(handshake.peer_id.cbegin(),
        handshake.peer_id.cend(), m_info.peer_id.begin());

    try_identify_client();
    // BitComet clients have been observer to drop requests if we have more than
    // 50 outstanding outgoing requests, so cap this
    if((m_info.client == "BitComet") && (m_info.max_outgoing_request_queue_size > 50))
    {
        m_info.max_outgoing_request_queue_size = 50;
    }

    log(log_event::incoming,
        "HANDSHAKE (protocol: %s; extensions: %s; info_hash: %s; client_id: %s%s)",
        handshake.protocol_id.data(), m_info.extensions.data(),
        info_hash.data(), m_info.peer_id.data(),
        m_info.client.empty() ? "" : ("; " + m_info.client).c_str());

    /*
    // TODO change to this, not sure why I haven't already (think there was an error)
    char extensions_str[65];
    int offset = 0;
    for(const uint8_t b : m_info.extensions)
    {
        std::string word = std::bitset<8>(b).to_string());
        std::copy(word.begin(), word.end(), &extensions_str[offset]);
        offset += 8;
    }
    std::string info_hash_str = util::to_hex(info_hash);
    log(log_event::outgoing,
        "HANDSHAKE (protocol: %s; extensions: %s; info_hash: %s; client_id: %s%s)",
        handshake.protocol_id, extensions_str,
        info_hash_str.c_str(), m_info.peer_id.data(),
        m_info.client.empty() ? "" : ("; " + m_info.client).c_str());
    */

    // proceed to the next stage
    m_info.state = state_t::bitfield_exchange;
    send_bitfield();
}

// ----------------------------------
// BITFIELD <len=1+X><id=5><bitfield>
// ----------------------------------
inline void peer_session::handle_bitfield()
{
    assert(m_info.state == state_t::bitfield_exchange);

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

    log(log_event::incoming, "BITFIELD (%s)",
        m_info.available_pieces.to_string().c_str());

    // check if we're interested in peer now that we know its piece availability
    update_interest();
}

// ------------------
// KEEP-ALIVE <len=0>
// ------------------
inline void peer_session::handle_keep_alive()
{
    m_message_parser.skip();
    log(log_event::incoming, "KEEP_ALIVE");
    if(!is_peer_choked() && is_peer_interested())
    {
        // peer is unchoked and interested but it's not sending us requests so our
        // unchoke message may not have gotten through, send it again
        send_unchoke();
    }
}

// -------------
// CHOKE <len=1>
// -------------
inline void peer_session::handle_choke()
{
    log(log_event::incoming, "CHOKE");
    if(m_message_parser.extract().data.size() != 0)
    {
        log(log_event::invalid_message, "wrong CHOKE message length");
        disconnect(peer_session_errc::invalid_choke_message);
        return;
    }
    if(!am_choked())
    {
        m_info.am_choked = true;
        m_op_state.unset(op_t::slow_start);
        abort_outgoing_requests();
    }
    m_info.last_incoming_choke_time = cached_clock::now();
}

// ---------------
// UNCHOKE <len=1>
// ---------------
inline void peer_session::handle_unchoke()
{
    log(log_event::incoming, "UNCHOKE");
    if(m_message_parser.extract().data.size() != 0)
    {
        log(log_event::invalid_message, "wrong UNCHOKE message length");
        disconnect(peer_session_errc::invalid_unchoke_message);
        return;
    }
    m_info.am_choked = false;
    m_info.last_incoming_unchoke_time = cached_clock::now();
    if(can_send_requests())
    {
        send_requests();
    }
}

// ------------------
// INTERESTED <len=1>
// ------------------
inline void peer_session::handle_interested()
{
    log(log_event::incoming, "INTERESTED");
    if(m_message_parser.extract().data.size() != 0)
    {
        log(log_event::invalid_message, "wrong INTERESTED message length");
        disconnect(peer_session_errc::invalid_interested_message);
        return;
    }
    if(!is_peer_interested())
    {
        m_info.is_peer_interested = true;
        std::error_code ec;
        m_inactivity_timeout_timer.cancel(ec);
    }
    m_info.last_incoming_interest_time = cached_clock::now();
}

// ----------------------
// NOT INTERESTED <len=1>
// ----------------------
inline void peer_session::handle_not_interested()
{
    log(log_event::incoming, "NOT_INTERESTED");
    if(m_message_parser.extract().data.size() != 0)
    {
        log(log_event::invalid_message, "wrong NOT_INTERESTED message length");
        disconnect(peer_session_errc::invalid_not_interested_message);
        return;
    }
    if(is_peer_interested())
    {
        m_info.is_peer_interested = false;
        if(!m_info.am_interested)
        {
            // we aren't interested either, so we enter a state of inactivity, so we must
            // guard against idling too long
            start_timer(m_inactivity_timeout_timer, minutes(10),
                [SHARED_THIS](const std::error_code& error)
                { on_inactivity_timeout(error); });
        }
    }
    m_info.last_incoming_uninterest_time = cached_clock::now();
}

inline void peer_session::handle_have()
{
    message msg = m_message_parser.extract();
    if(msg.data.size() != 4)
    {
        log(log_event::invalid_message, "wrong HAVE message length");
        disconnect(peer_session_errc::invalid_have_message);
        return;
    }

    const piece_index_t piece = endian::parse<int32_t>(msg.data.begin());

    log(log_event::incoming, "HAVE %i", piece);

    if(!is_piece_index_valid(piece))
    {
        log(log_event::invalid_message, "invalid piece index in HAVE message");
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

// ---------------------------------------------
// REQUEST <len=13><id=6><index><offset><length>
// ---------------------------------------------
inline void peer_session::handle_request()
{
    message msg = m_message_parser.extract();
    if(msg.data.size() != 3 * 4)
    {
        log(log_event::invalid_message, "wrong REQUEST message length");
        disconnect(peer_session_errc::invalid_request_message);
        return;
    }

    if(is_peer_choked())
    {
        handle_illicit_request();
        return;
    }
    else if(!is_peer_interested())
    {
        // peer is not choked but according to our data it is not interested either, so
        // pretend that we got an interested message as peer's may have gotten lost
        m_info.is_peer_interested = true;
        m_info.last_incoming_interest_time = cached_clock::now();
    }

    const block_info block_info = parse_block_info(msg.data);
    if(!is_request_valid(block_info))
    {
        log(log_event::invalid_message,
            "invalid REQUEST (piece: %i, offset: %i, length: %i)",
            block_info.index, block_info.offset, block_info.length);
        disconnect(peer_session_errc::invalid_request_message);
        return;
    }
    log(log_event::incoming, "REQUEST (piece: %i, offset: %i, length: %i)",
        block_info.index, block_info.offset, block_info.length);

    if(should_accept_request(block_info))
    {
        // at this point we can serve the request
        // TODO don't issue request to disk if it's overwhelmed
        m_info.last_incoming_request_time = cached_clock::now();
        m_received_requests.emplace_back(block_info);

        m_disk_io.fetch_block(m_torrent_info->id, block_info,
            [SHARED_THIS](const std::error_code& error, block_source block)
            { on_block_read(error, block); });
        m_op_state.set(op_t::disk_read);
        m_info.num_pending_disk_read_bytes += block_info.length;
        m_torrent_info->num_pending_disk_read_bytes += block_info.length;

        log(log_event::disk,
            "disk read launched, serving request (piece: %i, offset: %i, length: %i)",
            block_info.index, block_info.offset, block_info.length);
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

// --------------------------------------------
// CANCEL <len=13><id=8><index><offset><length>
// --------------------------------------------
inline void peer_session::handle_cancel()
{
    message msg = m_message_parser.extract();
    if(msg.data.size() != 1 + 3 * 4)
    {
        log(log_event::invalid_message, "wrong CANCEL message length");
        disconnect(peer_session_errc::invalid_cancel_message);
        return;
    }

    const block_info block_info = parse_block_info(msg.data);
    if(!is_request_valid(block_info))
    {
        log(log_event::invalid_message,
            "invalid CANCEL (piece: %i, offset: %i, length: %i)",
            block_info.index, block_info.offset, block_info.length);
        disconnect(peer_session_errc::invalid_cancel_message);
        return;
    }
    log(log_event::incoming, "CANCEL (piece: %i, offset: %i, length: %i)",
        block_info.index, block_info.offset, block_info.length);

    auto request = std::find_if(m_received_requests.begin(), m_received_requests.end(),
        [&block_info](const auto& request) { return request == block_info; });
    if(request != m_received_requests.cend())
    {
        // TODO we likely launched a disk read for this block, so cancel it
        m_received_requests.erase(request);
        log(log_event::disk, "disk abort launched, cancelling request");
    }
}

inline bool peer_session::is_request_valid(const block_info& request) const noexcept
{
    return m_piece_picker->my_bitfield()[request.index] && is_block_info_valid(request);
}

// ------------------------------------------
// BLOCK <len=9+X><id=7><index><offset><data>
// ------------------------------------------
void peer_session::handle_block()
{
    message msg = m_message_parser.extract();
    if(msg.data.size() < 12)
    {
        log(log_event::invalid_message, "wrong BLOCK message length");
        disconnect(peer_session_errc::invalid_block_message);
        return;
    }

    const block_info block_info = parse_block_info(msg.data);
    if(!is_block_info_valid(block_info))
    {
        log(log_event::invalid_message,
            "invalid BLOCK (piece: %i, offset: %i, length: %i)",
            block_info.index, block_info.offset, block_info.length);
        disconnect(peer_session_errc::invalid_block_message);
        return;
    }
    log(log_event::incoming, "BLOCK (piece: %i, offset: %i, length: %i)",
        block_info.index, block_info.offset, block_info.length);

    auto request = std::find_if(m_sent_requests.begin(), m_sent_requests.end(),
        [&block_info](const pending_block& request) { return request == block_info; });
    if(request == m_sent_requests.cend())
    {
        // we don't want this block (give 2 second slack)
        if(!m_info.am_interested
           && cached_clock::now() - m_info.last_outgoing_uninterest_time > seconds(2))
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
        //find piece_download and abort_request
        return;
    }

    adjust_request_timeout();
    update_download_stats(block_info.length);
    m_info.in_transit_block = invalid_block;

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
        piece_download& download = *find_download(block_info.index);
        // it's safe to pass only this instead of SHARED_THIS because we remove
        // this callback if we disconnect/destruct
        download.got_block(m_info.peer_id, block_info,
            [this, &download](const bool is_piece_good)
            { on_piece_hashed(download, is_piece_good); });
        disk_buffer block = m_disk_io.get_write_buffer();
        assert(block);
        // exclude the block header (index and offset, both 4 bytes)
        std::copy(msg.data.begin() + 8, msg.data.end(), block.data());
        save_block(block_info, std::move(block), download);
    }

    if(can_send_requests())
    {
        send_requests();
    }
}

inline void peer_session::adjust_request_timeout() // TODO rename
{
    const auto request_rtt = cached_clock::now() - m_info.last_outgoing_request_time;
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
        start_timer(m_request_timeout_timer, timeout,
            [SHARED_THIS](const std::error_code& error) { on_request_timeout(error); });
    }
}

inline void peer_session::adjust_best_request_queue_size() noexcept
{
    if(m_info.has_peer_timed_out)
    {
        m_info.best_request_queue_size = 1;
        m_op_state.unset(op_t::slow_start);
        return;
    }

    const int old_best_request_queue_size = m_info.best_request_queue_size;
    if(m_op_state[op_t::slow_start])
    {
        // if our download rate is not increasing significantly anymore, exit slow start
        // TODO FIXME this is not working properly
        if(m_download_rate.deviation() < 5000)
        {
            log(log_event::request,
                "leaving slow start -- download rate (mean: %i, deviation: %i)",
                m_download_rate.bytes_per_second(), m_download_rate.deviation());
            m_op_state[op_t::slow_start] = false;
            return;
        }
        ++m_info.best_request_queue_size;
    }
    else
    {
        // TODO figure out good formula, this is just a placeholder
        m_info.best_request_queue_size = (m_download_rate.bytes_per_second()
                                       /* m_avg_disk_write_time.mean() * 0.5*/) / 0x4000;
    }

    if(m_info.best_request_queue_size > m_info.max_outgoing_request_queue_size)
    {
        m_info.best_request_queue_size = m_info.max_outgoing_request_queue_size;
    }
    else if(m_info.best_request_queue_size < 2)
    {
        m_info.best_request_queue_size = 2;
    }

    if(m_info.best_request_queue_size != old_best_request_queue_size)
    {
        log(log_event::request, "ideal request queue size changed from %i to %i",
            old_best_request_queue_size, m_info.best_request_queue_size);
    }
}

inline void peer_session::update_download_stats(const int num_bytes)
{
    m_info.num_outstanding_bytes -= num_bytes;
    m_info.total_downloaded_piece_bytes += num_bytes;
    m_torrent_info->num_outstanding_bytes -= num_bytes;
    m_torrent_info->total_downloaded_piece_bytes += num_bytes;
    m_info.last_incoming_block_time = cached_clock::now();
    m_download_rate.update(num_bytes);
    m_torrent_info->download_rate.update(num_bytes);
    log(log_event::request, "download rate: %i bytes/s",
        m_download_rate.bytes_per_second());
}

inline bool peer_session::is_block_info_valid(const block_info& block) const noexcept
{
    const int piece_length = get_piece_length(*m_torrent_info, block.index);
    assert(piece_length > 0);
    const bool is_block_offset_valid = block.offset < piece_length;
    const bool is_block_length_valid = piece_length - block.offset >= block.length;

    return is_piece_index_valid(block.index)
        && is_block_offset_valid
        && is_block_length_valid
        && block.length <= 0x8000; // TODO decide what the maximum block size should be
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
    ++m_info.num_illicit_requests;
    log(log_event::incoming, "%i illicit requests", m_info.num_illicit_requests);

    if(cached_clock::now() - seconds(2) <= m_info.last_outgoing_choke_time)
    {
        // don't mind request messages (though don't serve them) up to 2 seconds after
        // choking peer
        return;
    }

    if((m_info.num_illicit_requests % 10 == 0) && is_peer_choked())
    {
        // every now and then remind peer that it is choked
        send_choke();
    }
    else if(m_info.num_illicit_requests > 300)
    {
        // don't tolerate this forever
        disconnect(peer_session_errc::sent_requests_when_choked);
    }
}

inline void peer_session::handle_illicit_block()
{
    log(log_event::incoming, "%i unwanted blocks", m_info.num_unwanted_blocks);
    if(++m_info.num_unwanted_blocks > 50)
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

inline void peer_session::save_block(const block_info& block_info,
    disk_buffer block_data, piece_download& download)
{
    m_op_state.set(op_t::disk_write);
    m_info.num_pending_disk_write_bytes += block_info.length;
    m_torrent_info->num_pending_disk_write_bytes += block_info.length;

    m_disk_io.save_block(m_torrent_info->id, block_info, std::move(block_data),
        [SHARED_THIS, block_info, start_time = cached_clock::now()]
        (const std::error_code& error) { on_block_saved(error, block_info, start_time); },
        // note that it's safe to pass a reference to download as only torrent may
        // remove a piece_download from m_shared_downloads, and if download is 
        // m_parole_download, it is added to m_shared_downloads if we disconnect before 
        // finishing the download;
        // on_piece_hashed is indirectly invoked through this handler if
        // peer_session is still alive tat that point
        [&download, completion_handler = m_piece_completion_handler](bool is_piece_good)
        { completion_handler(download, is_piece_good); });

    log(log_event::disk, 
        "launched disk write, saving block (piece: %i, offset: %i, length: %i)",
        block_info.index, block_info.offset, block_info.length);
}

void peer_session::on_piece_hashed(
    const piece_download& download, const bool is_piece_good)
{
    // TODO this is an async op as well -- should we finish this in graceful disconnect
    // mode or just exit?
    is_piece_good ? handle_valid_piece(download) : handle_corrupt_piece(download);
}

inline void peer_session::handle_valid_piece(const piece_download& download)
{
    log(log_event::disk, "piece (%i) passed hash test", download.piece_index());
    if(is_peer_on_parole())
    {
        // peer cleared itself, so it's no longer on parole
        assert(&download == m_parole_download.get());
        m_parole_download.reset();
        m_info.is_peer_on_parole = false;
        log(log_event::parole, "peer cleared suspicion, no longer on parole");
    }
    m_info.total_verified_piece_bytes += get_piece_length(
        *m_torrent_info, download.piece_index());
    auto it = std::find_if(m_downloads.begin(), m_downloads.end(),
        [piece = download.piece_index()](const auto& pd)
        { return pd->piece_index() == piece; });
    assert(it != m_downloads.end());
    m_downloads.erase(it);
}

inline void peer_session::handle_corrupt_piece(const piece_download& download)
{
    log(log_event::parole, "piece (%i) failed hash test (%i fails)",
        download.piece_index(), m_info.num_hash_fails);

    ++m_info.num_hash_fails;
    m_info.total_wasted_bytes += get_piece_length(
        *m_torrent_info, download.piece_index());
    if(is_peer_on_parole() || download.is_exclusive())
    {
        if(is_peer_on_parole()) 
        {
            assert(&download == m_parole_download.get());
            // delete parole piece download
            m_parole_download.reset();
        }
        // this peer was the sole participant in this download so we know that it
        // sent us a corrupt piece
        disconnect(peer_session_errc::corrupt_piece);
    }
    else
    {
        m_info.is_peer_on_parole = true;
    }
}

void peer_session::on_block_saved(const std::error_code& error,
    const block_info& block, const time_point start_time)
{
    m_op_state.unset(op_t::disk_write);
    m_info.num_pending_disk_write_bytes -= block.length;
    m_torrent_info->num_pending_disk_write_bytes -= block.length;
    if(error)
    {
        // TODO this means we cannot serve peer's request. should we try again?
        log(log_event::disk, "disk failure #%i", m_info.num_disk_io_failures + 1);
        if(++m_info.num_disk_io_failures > 100)
        {
            disconnect(error);
        }
        return;
    }

    m_info.num_disk_io_failures = 0;
    m_info.total_bytes_written_to_disk += block.length;
    // TODO consider recording disk read/write stats in disk_io/torrent_storage
    m_torrent_info->total_bytes_written_to_disk += block.length;
    m_avg_disk_write_time.add_sample(
        total_milliseconds(cached_clock::now() - start_time));

    log(log_event::disk,
        "saved block to disk (piece: %i, offset: %i, length: %i) -- "
        "disk write stats (total: %i; pending: %i)",
        block.index, block.offset, block.length, m_info.total_bytes_written_to_disk,
        m_info.num_pending_disk_write_bytes);

    if(should_abort())
    {
        // we're disconnecting, abort (don't move this above, we still need to record
        // stats for torrent)
        return;
    }

    // we can likely receive more now that we finished writing to disk
    receive();
}

void peer_session::on_block_read(const std::error_code& error, const block_source& block)
{
    m_op_state.unset(op_t::disk_read);

    if(error == disk_io_errc::operation_aborted)
    {
        // the block read was cancelled
        log(log_event::disk, "block fetch aborted (piece: %i, offset: %i, length: %i)",
            block.index, block.offset, block.length);
        return;
    }
    else if(error)
    {
        log(log_event::disk, "disk failure #%i", m_info.num_disk_io_failures + 1);
        if(++m_info.num_disk_io_failures > 100)
        {
            disconnect(error);
        }
        return;
    }

    // reset disk failuires to 0 since it only counts consecutive failures
    m_info.num_disk_io_failures = 0;
    m_info.total_bytes_read_from_disk += block.length;
    m_info.total_uploaded_piece_bytes += block.length;
    m_info.num_pending_disk_read_bytes -= block.length;
    m_torrent_info->total_bytes_read_from_disk += block.length;
    m_torrent_info->total_uploaded_piece_bytes += block.length;
    m_torrent_info->num_pending_disk_read_bytes -= block.length;
    m_upload_rate.update(block.length);
    m_torrent_info->upload_rate.update(block.length);

    log(log_event::disk,
        "read block from disk (piece: %i, offset: %i, length: %i) -- "
        "disk read stats (total: %i; pending: %i)",
        block.index, block.offset, block.length, m_info.total_bytes_read_from_disk,
        m_info.num_pending_disk_read_bytes);

    if(should_abort())
    {
        // we're disconnecting (we exit function here so as to record disk_io stats,
        // though peer_session won't need them but torrent will), don't service block
        // even if we're gracefully disconnecting
        return;
    }
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
        .buffer(m_settings.client_id));
    send();

    log(log_event::outgoing,
        "HANDSHAKE (protocol: %s; extensions: %s; info_hash: %s, client_id: %s)",
        protocol_id, extensions, m_torrent_info->info_hash.data(),
        m_settings.client_id.data());

    /*
    std::string extensions_str = [&extensions]() -> std::string
    {
        std::string ret;
        ret.reserve(64);
        for(const uint8_t b : extensions)
        {
            ret += std::bitset<8>(b).to_string())
        }
        return ret;
    }();
    std::string info_hash_str = util::to_hex(m_torrent_info->info_hash);
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

    if(m_piece_picker->has_no_pieces())
    {
        return;
    }

    const auto& my_pieces = m_piece_picker->my_bitfield();
    const int msg_size = 1 + my_pieces.data().size();
    m_send_buffer.append(payload(4 + msg_size)
        .i32(msg_size)
        .i8(message_t::bitfield)
        .buffer(my_pieces.data()));
    send();
    log(log_event::outgoing, "BITFIELD (%s)",
        m_piece_picker->my_bitfield().to_string().c_str());
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
    m_info.last_outgoing_choke_time = cached_clock::now();
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
    m_info.last_outgoing_unchoke_time = cached_clock::now();
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
    m_info.last_outgoing_interest_time = cached_clock::now();
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
    m_op_state.unset(op_t::slow_start);
    m_info.last_outgoing_uninterest_time = cached_clock::now();
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
        .i32(piece));
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
        .i32(block.length));
    m_sent_requests.emplace_back(block.index, block.offset, block.length);
    m_info.last_outgoing_request_time = cached_clock::now();
    log(log_event::outgoing, "REQUEST (piece: %i, offset: %i, length: %i)",
        block.index, block.offset, block.length);
}

void peer_session::send_requests()
{
    log(log_event::request,
        "preparing request queue (outstanding requests: %i, ideal queue size: %i)",
        m_sent_requests.size(), m_info.best_request_queue_size);
    assert(can_send_requests());
    assert(m_piece_picker && m_shared_downloads);

    const int num_new_requests = is_peer_on_parole()
        ? make_requests_in_parole_mode()
        : make_requests_in_normal_mode();
    if(num_new_requests <= 0)
    {
        return;
    }

    payload requests(num_new_requests * (4 + 13));
    assert(num_new_requests <= m_sent_requests.size());
    for(auto i = m_sent_requests.size() - num_new_requests;
        i < m_sent_requests.size();
        ++i)
    {
        // craft the payload for each block that was put in m_sent_requests by the
        // above functions
        const pending_block& block = m_sent_requests[i];
        requests.i32(13)
            .i8(message_t::request)
            .i32(block.index)
            .i32(block.offset)
            .i32(block.length);
        log(log_event::outgoing, "REQUEST (piece: %i, offset: %i, length: %i)",
            block.index, block.offset, block.length);
        m_info.num_outstanding_bytes += block.length;
        m_torrent_info->num_outstanding_bytes += block.length;
    }
    log(log_event::outgoing, "request queue length: %i", num_new_requests);
    m_send_buffer.append(std::move(requests));

    send();

    m_info.last_outgoing_request_time = cached_clock::now();
    start_timer(m_request_timeout_timer, request_timeout(),
        [SHARED_THIS](const std::error_code& error) { on_request_timeout(error); });
}

inline bool peer_session::can_send_requests() const noexcept
{
    return m_sent_requests.size() < m_info.best_request_queue_size
        && am_interested()
        && !am_choked();
}

inline int peer_session::make_requests_in_parole_mode()
{
    // pick a parole piece for this peer if it hasn't been assigned one yet since it
    // participated in a failed hash test
    if(m_parole_download == nullptr)
    {
        const auto piece = m_piece_picker->pick_and_reserve(m_info.available_pieces);
        if(piece == piece_picker::invalid_piece)
        {
            return 0;
        }
        m_parole_download = std::make_unique<piece_download>(
            piece, get_piece_length(*m_torrent_info, piece));
        log(log_event::request, "picked piece (%i) in parole mode", piece);
    }

    int num_new_requests = 0;
    if(m_parole_download->can_request())
    {
        for(auto& request : m_parole_download->make_request_queue(num_to_request()))
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

    // we try to join a download using m_shared_downloads as long as we need more
    // blocks and there are downloads to join
    while(m_sent_requests.size() < m_info.best_request_queue_size)
    {
        const int num_blocks = join_download();
        if(num_blocks == 0) { break; }
        num_new_requests += num_blocks;
    }

    // while we still need blocks, we pick a piece and start a new download, and add it
    // to the shared downloads via m_shared_downloads
    while(m_sent_requests.size() < m_info.best_request_queue_size)
    {
        const int num_blocks = start_download();
        if(num_blocks == 0) { break; }
        num_new_requests += num_blocks;
    }
    return num_new_requests;
}

inline int peer_session::continue_downloads()
{
    int num_new_requests = 0;
    for(auto& download : m_downloads)
    {
        if(m_sent_requests.size() == m_info.best_request_queue_size)
        {
            break;
        }
        if(download->can_request())
        {
            log(log_event::request, "continuing piece (%i) download",
                download->piece_index());
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
    // find a suitable shared piece_download
    auto download = find_shared_download();
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
        m_downloads.emplace_back(download);
    }
    return num_new_requests;
}

std::shared_ptr<piece_download> peer_session::find_shared_download()
{
    assert(m_shared_downloads);
    for(auto download : *m_shared_downloads)
    {
        assert(download); // this shouldn't fire as finished downloads are always removed
        if(m_info.available_pieces[download->piece_index()])
        {
            return download;
        }
    }
    return nullptr;
}

inline int peer_session::start_download()
{
    int num_new_requests = 0;
    const auto piece = m_piece_picker->pick_and_reserve(m_info.available_pieces);
    if(piece != piece_picker::invalid_piece)
    {
        log(log_event::request, "picked piece (%i)", piece);
        auto download = std::make_shared<piece_download>(
            piece, get_piece_length(*m_torrent_info, piece));
        for(auto& request : download->make_request_queue(num_to_request()))
        {
            m_sent_requests.emplace_back(std::move(request));
            ++num_new_requests;
        }
        // add download to shared database so other peer_sessions may join
        m_shared_downloads->emplace_back(download);
        m_downloads.emplace_back(download);
    }
    return num_new_requests;
}

inline int peer_session::num_to_request() const noexcept
{
    return std::max(m_info.best_request_queue_size - int(m_sent_requests.size()), 0);
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
    m_info.last_outgoing_block_time = cached_clock::now();
    m_upload_rate.update(block.length);

    send();

    log(log_event::outgoing,
        "BLOCK (piece: %i, offset: %i, length: %i) -- upload rate: %i bytes/s",
        block.index, block.offset, block.length, m_upload_rate.bytes_per_second());

    // now that we sent this block, remove it from m_received_requests
    auto it = std::find_if(
        m_received_requests.begin(), m_received_requests.end(),
        [&block](const auto& request)
        { return request == static_cast<const block_info&>(block); });
    assert(it != m_received_requests.end());
    m_received_requests.erase(it);
}

// --------------------------------------------
// CANCEL <len=13><id=8><index><offset><length>
// --------------------------------------------
void peer_session::send_cancel(const block_info& block)
{
    // if we're already receiving this block we cannot (shouldn't) send a cancel
    if(block != m_info.in_transit_block)
    {
        m_send_buffer.append(fixed_payload<4 + 13>()
            .i32(13)
            .i8(message_t::cancel)
            .i32(block.index)
            .i32(block.offset)
            .i32(block.length));
        send();
        log(log_event::outgoing, "CANCEL (piece: %i, offset: %i, length: %i)",
            block.index, block.offset, block.length);
    }
}

// -------------------------------
// PORT <len=3><id=9><listen-port>
// -------------------------------
void peer_session::send_port(const int port)
{
    m_send_buffer.append(fixed_payload<4 + 3>()
        .i32(3)
        .i8(message_t::port)
        .i16(port));
    send();
    log(log_event::outgoing, "PORT (%i)", port);
}

// -------------------
// -- timeout logic --
// -------------------

void peer_session::on_request_timeout(const std::error_code& error)
{
    if(should_abort(error))
    {
        return;
    }
    else if(error)
    {
        disconnect(error);
        return;
    }

    log(log_event::outgoing, "request to peer has timed out");

    m_info.best_request_queue_size = 1;
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
        // it's safe to pass only this instead of SHARED_THIS because we remove
        // this callback before we disconnect/destruct;
        // callback will be invoked if we get this block from another peer sooner
        find_download(request.index)->time_out(m_info.peer_id, request,
            [this](const block_info& block) { send_cancel(block); });
        log(log_event::timeout, "timing out block (piece: %i, offset: %i, length: %i)",
            request.index, request.offset, request.length);
    }
    // try to send requests again, with updated request queue length
    if(can_send_requests())
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

void peer_session::on_connect_timeout(const std::error_code& error)
{
    if(should_abort(error))
    {
        return;
    }
    else if(error)
    {
        disconnect(error);
    }
    else
    {
        log(log_event::timeout, "connecting timed out, elapsed time: %ims",
            total_milliseconds(cached_clock::now() - m_info.connection_started_time));
        disconnect(peer_session_errc::connect_timeout);
    }
}

void peer_session::on_inactivity_timeout(const std::error_code& error)
{
    if(should_abort(error))
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

void peer_session::on_keep_alive_timeout(const std::error_code& error)
{
    if(should_abort(error))
    {
        return;
    }
    else if(error)
    {
        disconnect(error);
        return;
    }

    log(log_event::timeout, "keep_alive timeout");
    if(cached_clock::now() - m_info.last_send_time > seconds(120))
    {
        send_keep_alive();
    }
    start_timer(m_keep_alive_timer, m_settings.peer_timeout,
        [SHARED_THIS](const std::error_code& error) { on_keep_alive_timeout(error); });
}

// -----------
// -- utils --
// -----------

template<typename... Args>
void peer_session::log(const log_event event, const char* format, Args&&... args) const
{
    // TODO proper logging
    std::cerr << '[';
    if(event != log_event::connecting)
    {
        std::cerr << '+';
        std::cerr << total_seconds(cached_clock::now()
            - m_info.connection_established_time);
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
    const size_t length = std::snprintf(nullptr, 0, format, args...) + 1;
    std::unique_ptr<char[]> buffer(new char[length]);
    std::snprintf(buffer.get(), length, format, args...);
    // -1 to exclude the '\0' at the end
    // TODO this is temporary
    std::string message(buffer.get(), buffer.get() + length - 1);
    std::cerr << message << '\n';
}

inline piece_download* peer_session::find_download(const piece_index_t piece) noexcept
{
    auto it = std::find_if(m_downloads.begin(), m_downloads.end(),
        [piece](const auto& download) { return download->piece_index() == piece; });
    // if we didn't find download among m_downloads, we must be on parole and this must
    // be the parole download, however, so m_parole_download must be valid at this point
    if(it == m_downloads.end())
    {
        assert(m_parole_download);
        return m_parole_download.get();
    }
    assert(it->get());
    return it->get();
}

inline void peer_session::try_identify_client()
{
    // https://wiki.theory.org/BitTorrentSpecification#peer_id
    m_info.client = [this]() -> std::string
    {
        if(m_info.peer_id[0] == '-')
        {
            // Azureus-style encoding
            const auto matches = [this](const char* client) -> bool
            {
                return m_info.peer_id[1] == client[0]
                    && m_info.peer_id[2] == client[1];
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
                return m_info.peer_id[1 + 2 + 6] == '-' ? "BitCometLite"
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
                return m_info.peer_id[0] == client;
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
    const piece_index_t index = endian::parse<piece_index_t>(byte_it);
    const int offset = endian::parse<int>(byte_it += 4);

    if(data.size() == 3 * 4)
    {
        // it's a request/cancel message with fixed message length
        return block_info(index, offset, endian::parse<int32_t>(byte_it += 4));
    }
    else
    {
        // it's a block message, we get the block's length by subtracting the index and
        // offset fields' added length from the total message length
        return block_info(index, offset, data.size() - 2 * 4);
    }
}

} // namespace tide

#undef SHARED_THIS
