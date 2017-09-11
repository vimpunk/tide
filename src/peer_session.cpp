#include "bandwidth_controller.hpp"
#include "piece_download.hpp"
#include "disk_io_error.hpp"
#include "piece_picker.hpp"
#include "peer_session.hpp"
#include "torrent_info.hpp"
#include "string_utils.hpp"
#include "sha1_hasher.hpp"
#include "num_utils.hpp"
#include "settings.hpp"
#include "payload.hpp"
#include "address.hpp"
#include "endian.hpp"
#include "view.hpp"

#include <algorithm>
#include <stdexcept>
#include <cassert>
#include <string>
#include <cmath> // min, max
#ifdef TIDE_ENABLE_LOGGING
# include <sstream>
#endif // TIDE_ENABLE_LOGGING

#include <asio/io_service.hpp>

namespace tide {

// peer_session needs to be kept alive until all async ops complete, so we bind a
// shared_ptr to peer_session to each async op's handler along with `this`
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
        if(!m_session.m_op_state[op::send])
        {
            // block other send operations by pretending to be sending
            m_session.m_op_state.set(op::send);
            m_should_uncork = true;
        }
    }

    ~send_cork()
    {
        if(m_should_uncork)
        {
            m_session.m_op_state.unset(op::send);
            if(!m_session.is_stopped()) { m_session.send(); }
        }
    }
};

peer_session::peer_session(
    asio::io_service& ios,
    tcp::endpoint peer_endpoint,
    bandwidth_controller& bandwidth_controller,
    const peer_session_settings& settings
)
    : m_socket(std::make_unique<tcp::socket>(ios))
    , m_bandwidth_controller(bandwidth_controller)
    , m_settings(settings)
    , m_connect_timeout_timer(ios)
    , m_keep_alive_timer(ios)
    , m_request_timeout_timer(ios)
    , m_inactivity_timeout_timer(ios)
{
    // we must be able to receive at least one full block
    assert(m_settings.max_receive_buffer_size >= 0x4000);
    assert(m_settings.max_send_buffer_size >= 0x4000);
    assert(m_settings.peer_connect_timeout > seconds(0));
    assert(m_settings.peer_timeout > seconds(0));

    m_info.remote_endpoint = std::move(peer_endpoint);
    m_info.max_outgoing_request_queue_size = settings.max_outgoing_request_queue_size;
    m_op_state.set(op::slow_start);
}

peer_session::peer_session(
    asio::io_service& ios,
    tcp::endpoint peer_endpoint,
    bandwidth_controller& bandwidth_controller,
    const peer_session_settings& settings,
    torrent_frontend torrent
)
    : peer_session(ios, std::move(peer_endpoint), bandwidth_controller, settings)
{
    m_torrent = torrent;
    assert(m_torrent);

    // initialize peer's bitfield
    m_info.available_pieces = bitfield(m_torrent.info().num_pieces);
    m_info.is_outbound = true;
}

peer_session::peer_session(
    asio::io_service& ios,
    tcp::endpoint peer_endpoint,
    bandwidth_controller& bandwidth_controller,
    const peer_session_settings& settings,
    std::function<torrent_frontend(const sha1_hash&)> torrent_attacher
)
    : peer_session(ios, std::move(peer_endpoint), bandwidth_controller, settings)
{
    m_torrent_attacher = std::move(torrent_attacher);
    m_info.is_outbound = false;

    assert(m_torrent_attacher);
}

peer_session::~peer_session()
{
    // note to self: we only need to remove downloads if session is destroyed; if it's
    // just disconnected, it may mean that we want to continue the session later, in
    // which case we want to have previous downloads (that may not have been finished)
    disconnect(peer_session_errc::stopped);
    for(auto& download : m_downloads) { download->deregister_peer(remote_endpoint()); }
    // at this point we should have no more pending operations
    assert(!has_pending_async_op());
}

void peer_session::start()
{
    if(is_disconnected())
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
    else if(is_disconnecting() && m_socket->is_open())
    {
        // if socket is still open, we can continue the session, but we may need to
        // reinstate the send and receive cycles and deadline timers
        m_info.state = state::connected;
        // if we're not receiving, and not writing to disk (in which case the disk write
        // handler would call receive), we need to resuscitate the receive cycle
        if(!m_op_state[op::receive] && !m_op_state[op::disk_write]) { receive(); }
        // TODO verify; I don't think it's enough to check whether socket is open,
        // as it may be still connecting, in which case we can't just continue the
        // session, so stronger guarantees are necessary
    }
}

void peer_session::stop()
{
    if(!is_stopped())
    {
        // if we don't have async ops, the session is dead, so this shouldn't happen
        assert(has_pending_async_op());
        m_info.state = state::disconnecting;
    }
}

void peer_session::abort()
{
    if(!is_disconnected()) { disconnect(peer_session_errc::stopped); }
}

inline void peer_session::connect()
{
    std::error_code ec;
    log(log_event::connecting, log::priority::low, "opening socket");
    m_socket->open(m_info.remote_endpoint.protocol(), ec);
    if(ec)
    {
        // TODO can we disconnect if we haven't even connected?
        disconnect(ec);
        return;
    }

    m_socket->async_connect(m_info.remote_endpoint,
        [SHARED_THIS](const std::error_code& error) { on_connected(error); });

    m_info.state = state::connecting;
    m_info.connection_started_time = cached_clock::now();
    if(m_torrent) { ++m_torrent.info().num_connecting_sessions; }

    start_timer(m_connect_timeout_timer, m_settings.peer_connect_timeout,
        [SHARED_THIS](const std::error_code& error) { on_connect_timeout(error); });
    log(log_event::connecting, log::priority::low, "started establishing connection");
}

void peer_session::on_connected(const std::error_code& error)
{
    if(m_torrent) { --m_torrent.info().num_connecting_sessions; }

    if(should_abort(error)) { return; }

    std::error_code ec;
    m_connect_timeout_timer.cancel(ec);

    if(error || !m_socket->is_open())
    {
        // TODO can we disconnect if we haven't even connected?
        disconnect(error ? error : std::make_error_code(std::errc::bad_file_descriptor));
        return;
    }

    log(log_event::connecting, log::priority::low, "setting non-blocking io mode");
    m_socket->non_blocking(true, ec);
    if(ec)
    {
        disconnect(ec);
        return;
    }

    m_info.connection_established_time = cached_clock::now();
    log(log_event::connecting, "connected in %lims",
        to_int<milliseconds>(m_info.connection_established_time
            - m_info.connection_started_time));
    m_info.local_endpoint = m_socket->local_endpoint(ec);
    if(ec)
    {
        disconnect(ec);
        return;
    }

    m_info.state = state::handshaking;
    if(m_settings.encryption_policy == peer_session_settings::no_encryption)
    {
        if(m_info.is_outbound) { send_handshake(); }
        // otherwise send_handshake() is called after we've received peer's handshake
        receive();
    }
    else
    {
        assert(false && "currently only no_encryption policy is supported");
    }
}

inline bool peer_session::should_abort(const std::error_code& error) const noexcept
{
    return (error == asio::error::operation_aborted) || is_stopped();
}

void peer_session::disconnect(const std::error_code& error)
{
    if(is_disconnected()) { return; }

#ifdef TIDE_ENABLE_LOGGING
    const auto reason = error.message();
    log(log_event::disconnecting, log::priority::high,
        "reason: %s (#%i)", reason.c_str(), error.value());
#endif // TIDE_ENABLE_LOGGING

    std::error_code ec;
    m_connect_timeout_timer.cancel(ec);
    m_request_timeout_timer.cancel(ec);
    m_keep_alive_timer.cancel(ec);
    m_inactivity_timeout_timer.cancel(ec);

    abort_outgoing_requests();
    if(m_parole_download) { detach_parole_download(); }
    if(m_torrent)
    {
        m_torrent.piece_picker().decrease_frequency(m_info.available_pieces);
    }

    m_socket->shutdown(tcp::socket::shutdown_both, ec);
    m_socket->close(ec);
    m_info.state = state::disconnected;
    log(log_event::disconnecting, "closed socket");
    //TODO are there more outstanding bytes (disk etc) that we need to subtract here?
    //m_torrent.info().num_outstanding_bytes -= m_info.num_outstanding_bytes;
    if(m_torrent) { ++m_torrent.info().num_lingering_disconnected_sessions; }

    // if we have some block data in message buffer but are disconnecting,
    // we won't finish downloading it, so tally the wasted bytes
    if(m_info.in_transit_block != invalid_block)
    {
        m_info.total_wasted_bytes += m_message_parser.size();
        if(m_torrent) m_torrent.info().total_wasted_bytes += m_message_parser.size();
    }

    ////TODO
    //m_send_buffer.clear();
    //m_message_parser.clear();

    log(log_event::disconnecting, "tore down connection");
    // TODO tell disk_io to stop serving peer's outstanding requests
}

inline void peer_session::detach_parole_download()
{
    if(m_parole_download->num_blocks_left() < m_parole_download->blocks().size())
    {
        // we must NOT hold onto this piece because it's reserved in piece picker,
        // meaning no other peer would get it until it's released in the destructor
        // download of this piece has been begun, so we should take the chance and
        // assume peer hasn't sent bad data and put this download in the shared
        // downloads so as not to waste what we already have
        // note that we don't detach this session from the download, that's done in
        // the destructor
        std::shared_ptr<piece_download> download = std::move(m_parole_download);
        // we put this download in our shared_downloads so that we can deregister
        // this peer when the session destructs (we don't do that here as there is
        // a chance the piece has been finished but the verification handler is 
        // invoked only after disconnecting, meaning we can still ban this peer
        // so that we don't connect to it again
        m_downloads.emplace_back(download);
        m_torrent.downloads().emplace_back(download);
    }
    else
    {
        // otherwise we must free this piece from piece picker for other peers to
        // download this piece
        m_torrent.piece_picker().unreserve(m_parole_download->piece_index());
        m_parole_download.reset();
    }
}

peer_session::stats peer_session::get_stats() const noexcept
{
    stats s;
    get_stats(s);
    return s;
}

void peer_session::get_stats(stats& s) const noexcept
{
    s.torrent_id = m_torrent ? m_torrent.info().id : -1;
    s.peer_id = m_info.peer_id;
    s.client = m_info.client;
    s.avg_request_rtt = milliseconds(m_avg_request_rtt.mean());
    s.upload_rate = m_info.upload_rate.rate();
    s.download_rate = m_info.download_rate.rate();
    s.peak_upload_rate = m_info.upload_rate.peak();
    s.peak_download_rate = m_info.download_rate.peak();
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

bool peer_session::is_extension_enabled(const int extension) const noexcept
{
    return m_info.extensions[extension] && m_settings.extensions[extension];
}

void peer_session::choke_peer()
{
    if(!is_connected() || is_peer_choked()) { return; }
    send_choke();
    for(const auto& block : m_incoming_requests)
    {
        // TODO we should tell disk_io and other components of this
        // TODO if block is in the allowed fast set, don't reject
        send_reject_request(block);
    }
    m_incoming_requests.clear();
}

void peer_session::unchoke_peer()
{
    if(is_connected() && is_peer_choked())
    {
        send_unchoke();
        m_info.upload_rate.clear();
    }
}

void peer_session::suggest_piece(const piece_index_t piece)
{
    if(is_connected()
       && is_extension_enabled(extensions::fast)
       && !m_info.available_pieces[piece])
    {
        send_suggest_piece(piece);
    }
}

void peer_session::announce_new_piece(const piece_index_t piece)
{
    // no need to send a have message if we're shutting down, otherwise we're still
    // connecting or handshaking, in which case we'll send our piece availability after
    // this stage is done
    if(is_connected())
    {
        // don't send a have msg if peer already has the piece
        if(!m_info.available_pieces[piece]) { send_have(piece); }
        // send_have() is called by torrent when a new piece is received, so recalculate
        // whether we're interested in this peer, for we may have received the only piece
        // peer has in which we were interested
        update_interest();
#ifdef TIDE_ENABLE_DEBUGGING
        // if we've become a seeder we shouldn't have any downloads left then
        // (torrent should post hash results first, then announce to peers)
        if(m_torrent.piece_picker().has_all_pieces() && !m_downloads.empty())
        {
            // FIXME this branch executed (shouldn't)
            std::string s;
            for(const auto& d : m_downloads)
            {
                s += util::format("dl(%i|%i/%i|%i)", d->piece_index(),
                    d->num_received_blocks(), d->num_blocks(), d->peers().size()) + " ";
            }
            log(log_event::info, log::priority::high,
                "became seeder but have %i downloads left: %s",
                m_downloads.size(), s.c_str());
        }
#endif // TIDE_ENABLE_DEBUGGING
    }
}

void peer_session::update_interest()
{
    const bool was_interested = m_info.am_interested;
    const bool am_interested = m_torrent
        .piece_picker().am_interested_in(m_info.available_pieces);
    if(!was_interested && am_interested)
    {
        m_info.am_interested = true;
        std::error_code ec;
        m_inactivity_timeout_timer.cancel(ec);
        send_interested();
        if(can_make_requests()) { make_requests(); }
        log(log_event::info, "became interested in peer");
    }
    else if(was_interested && !am_interested)
    {
        m_info.am_interested = false;
        send_not_interested();
        // if peer isn't interested either, we enter a state of inactivity, so we must
        // guard against idling too long
        if(!is_peer_interested())
        {
            start_timer(m_inactivity_timeout_timer, minutes(5),
                [SHARED_THIS](const std::error_code& error)
                { on_inactivity_timeout(error); });
        }
        log(log_event::info, "no longer interested in peer (have: %i, has %i pieces)",
            m_torrent.piece_picker().num_have_pieces(), m_info.available_pieces.count());
    }
    if(m_torrent.piece_picker().has_all_pieces() && is_peer_seed())
    {
        disconnect(peer_session_errc::both_seeders);
    }
}

// -------------
// -- sending --
// -------------

void peer_session::send()
{
    request_upload_bandwidth();
    if(!can_send()) { return; }

    const int num_bytes_to_send = std::min(m_send_buffer.size(), m_info.send_quota);
    assert(num_bytes_to_send > 0);
    m_socket->async_write_some(m_send_buffer.get_send_buffers(num_bytes_to_send),
        [SHARED_THIS](const std::error_code& error, size_t num_bytes_sent)
        { on_sent(error, num_bytes_sent); });

    m_op_state.set(op::send);

    log(log_event::outgoing, log::priority::low,
        "sending: %i; available: %i; quota: %i",
        num_bytes_to_send, m_send_buffer.size(), m_info.send_quota);
}

bool peer_session::can_send() const noexcept
{
    if(m_send_buffer.empty())
    {
        log(log_event::outgoing, log::priority::low, "CAN'T SEND, buffer empty");
        return false;
    }
    else if(m_op_state[op::send])
    {
        log(log_event::outgoing, log::priority::low, "CAN'T SEND, already sending");
        return false;
    }
    else if(m_info.send_quota <= 0)
    {
        log(log_event::outgoing, log::priority::low, "CAN'T SEND, no quota left");
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
    m_op_state.unset(op::send);
    if(is_disconnecting())
    {
        try_finish_disconnecting();
        return;
    }
    else if(should_abort(error))
    {
        // we are aborting, so pending async ops were cancelled
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

    log(log_event::outgoing,
        "sent: %i; quota: %i; send buffer size: %i; total sent: %lli",
        num_bytes_sent, m_info.send_quota, m_send_buffer.size(),
        m_info.total_uploaded_bytes);

    // this call to send() will only write to socket again if during the first write
    // there were more bytes in send buffer to send than we had quota for, and since the
    // first thing in send is asking for more bandwidth quota, we may be able to send
    // off the rest of the send buffer's contents
    if(!m_send_buffer.empty()) { send(); }
}

inline void peer_session::update_send_stats(const int num_bytes_sent) noexcept
{
    m_info.send_quota -= num_bytes_sent;
    m_info.last_send_time = cached_clock::now();
    m_info.total_uploaded_bytes += num_bytes_sent;
    m_torrent.info().total_uploaded_bytes += num_bytes_sent;
}

// ---------------
// -- receiving --
// ---------------

void peer_session::receive()
{
    assert(!is_stopped());

    if(m_op_state[op::receive])
    {
        log(log_event::incoming, log::priority::low, "CAN'T RECEIVE, already receiving");
        return;
    }

    request_download_bandwidth();
    ensure_protocol_exchange();
    const int num_to_receive = get_num_to_receive();
    if(num_to_receive == 0) { return; }

    view<uint8_t> buffer = m_message_parser.get_receive_buffer(num_to_receive);
    m_socket->async_read_some(asio::mutable_buffers_1(buffer.data(), buffer.size()),
        [SHARED_THIS](const std::error_code& error, size_t num_bytes_received)
        { on_received(error, num_bytes_received); });

    m_op_state.set(op::receive);

    log(log_event::incoming, log::priority::low,
        "receiving: %i; receive buffer free space: %i; quota: %i",
        num_to_receive, m_message_parser.free_space_size(), m_info.receive_quota);
}

void peer_session::request_download_bandwidth()
{
    // TODO this is temporary for the first tests
    m_info.receive_quota = m_settings.max_receive_buffer_size;
}

// TODO is this needed now that get_num_to_receive no longer bases its calculations
// on the current buffer capacity?
void peer_session::ensure_protocol_exchange()
{
    if(!am_expecting_block()
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
    if(m_info.receive_quota <= 0)
    {
        log(log_event::incoming, log::priority::low, "CAN'T RECEIVE, no receive quota");
        return 0;
    }
    // pending bytes written to disk are also counted as part of the receive buffer
    // until they are flushed to disk; this is used to throttle download rate if
    // we're disk bound (so as not to further overwhelm disk)
    auto max_receive_size = m_settings.max_receive_buffer_size
        - m_message_parser.size() - m_info.num_pending_disk_write_bytes;
    if(max_receive_size <= 0)
    {
        // each peer session may receive 1 block worth of data at any given time
        // otherwise downloads would crawl to a halt and saving this amount should be
        // manageable by disk_io under most loads
        max_receive_size = 1 * 0x4000;
        log(log_event::disk, log::priority::high,
            "session disk bound, receive buffer capacity reached, using reserves");
    }
    // this function will choose the max capacity if we have enough quota, which we
    // don't want unless we're expecting blocks
    if(!am_expecting_block())
    {
        max_receive_size = std::min(1024, max_receive_size); // TODO pick better number
    }
    return std::min(max_receive_size, m_info.receive_quota);
}

inline void peer_session::try_finish_disconnecting()
{
    if(!has_pending_async_op())
    {
        // we are gracefully stopping and there are no other pending async ops, so
        // we can shut down now
        disconnect(peer_session_errc::stopped);
        m_torrent.on_peer_session_stopped(*this);
    }
}

void peer_session::on_received(const std::error_code& error, size_t num_bytes_received)
{
    m_op_state.unset(op::receive);
    if(is_disconnecting())
    {
        try_finish_disconnecting();
        return;
    }
    else if(should_abort(error))
    {
        // we have been disconnected, so pending async ops were cancelled
        return;
    }
    else if(error)
    {
        log(log_event::incoming, "error while receiving");
        disconnect(error);
        return;
    }

    assert(num_bytes_received > 0);
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
        "received: %i; receive buffer size: %i; quota: %i; total received: %lli",
        num_bytes_received, m_message_parser.buffer_size(), m_info.receive_quota,
        m_info.total_downloaded_bytes);
    // flush_socket() may have spurred a disconnect
    if(is_disconnected()) { return; }

    // send response messages at the end of the function in one batch
    send_cork _cork(*this);
    const bool was_choked = am_choked();
    handle_messages();
    if(is_disconnected())
    {
        // handle_messages() spurred a disconnect
        // TODO consider throwing in handle_messages for clearer control flow
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
    m_torrent.info().total_downloaded_bytes += num_bytes_received;
}

inline void peer_session::adjust_receive_buffer(const bool was_choked)
{
    const int old_buffer_size = m_message_parser.buffer_size();
    const bool got_choked = !was_choked && am_choked();

    if(!am_choked() && (old_buffer_size < m_settings.max_receive_buffer_size))
    {
        const int free_space_size = m_message_parser.free_space_size();
        if(am_expecting_block() && (free_space_size < 0x4000))
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
            m_message_parser.reserve(std::min(old_buffer_size * 2,
                m_settings.max_receive_buffer_size));
        }
        if(old_buffer_size != m_message_parser.buffer_size())
            log(log_event::incoming, log::priority::low,
                "grew receive buffer from %i to %i",
                old_buffer_size, m_message_parser.buffer_size());
    }
    else if(got_choked && old_buffer_size > 1024)
    {
        // if we went from unchoked to choked (and if buffer is large enough, otherwise
        // don't bother), 100 bytes should suffice to receive further protocol chatter
        // (if we have unfinished messages in receive buffer it will not shrink below
        // the last valid message byte)
        m_message_parser.shrink_to_fit(100);
        log(log_event::incoming, log::priority::low,
            "shrunk receive buffer from %i to %i",
            old_buffer_size, m_message_parser.buffer_size());
    }
}

inline bool peer_session::am_expecting_block() const noexcept
{
    return (m_info.num_outstanding_bytes > 0) && !am_choked();
}

inline int peer_session::flush_socket()
{
    assert(m_message_parser.is_full());
    // we may not have read all of the available bytes buffered in socket:
    // try sync read remaining bytes
    std::error_code ec;
    const auto num_available_bytes = m_socket->available(ec);
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
            log(log_event::incoming, log::priority::low,
                "couldn't sync read from socket");
        }
        else if(ec)
        {
            disconnect(ec);
        }
        else
        {
            assert(num_bytes_read > 0);
            log(log_event::incoming, log::priority::low,
                "sync read %i bytes from socket", num_bytes_read);
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
    if(m_info.state == state::handshaking)
    {
        if(m_message_parser.has_handshake())
        {
            handle_handshake();
            if(is_disconnected()) { return; }
            send_piece_availability();
        }
        else
        {
            // otherwise we don't have the full handshake yet, so receive more bytes and
            // come back later to try again
            return;
        }
    }
    // fallthrough
    if(m_info.state == state::piece_availability_exchange
       && m_message_parser.has_message())
    {
        if(m_message_parser.type() == message::bitfield)
        {
            handle_bitfield();
            if(is_disconnected()) { return; }
        }
        else if(is_extension_enabled(extensions::fast))
        {
            // if the fast extension is set, peer MUST send a piece availability
            // related message after the handshake; otherwise this is optional
            if(m_message_parser.type() == message::have_all)
                handle_have_all();
            else if(m_message_parser.type() == message::have_none)
                handle_have_none();
            else
                disconnect(peer_session_errc::no_piece_availability_message);
            if(is_disconnected()) { return; }
        }
        m_info.state = state::connected;
    }
    // fallthrough
    while(!is_disconnected()
          && m_message_parser.has_message()
          && m_send_buffer.size() <= m_settings.max_send_buffer_size)
    {
#define NOT_AFTER_HANDSHAKE(str) do { \
    log(log_event::invalid_message, str " not after handshake"); \
    disconnect(peer_session_errc::bitfield_not_after_handshake); } while(0)
        switch(m_message_parser.type()) {
        // -- standard BitTorrent messages --
        // bitfield messages may only be sent after the handshake
        case message::bitfield: NOT_AFTER_HANDSHAKE("BITFIELD"); break;
        case message::keep_alive: handle_keep_alive(); break;
        case message::choke: handle_choke(); break;
        case message::unchoke: handle_unchoke(); break;
        case message::interested: handle_interested(); break;
        case message::not_interested: handle_not_interested(); break;
        case message::have: handle_have(); break;
        case message::request: handle_request(); break;
        case message::block: handle_block(); break;
        case message::cancel: handle_cancel(); break;
        // -- DHT extension messages --
        // -- Fast extension messages --
        case message::suggest_piece: handle_suggest_piece(); break;
        // like bitfield, these messages may only be exchanged after the handshake
        case message::have_all: NOT_AFTER_HANDSHAKE("HAVE ALL"); break;
        case message::have_none: NOT_AFTER_HANDSHAKE("HAVE NONE"); break;
        case message::reject_request: handle_reject_request(); break;
        case message::allowed_fast: handle_allowed_fast(); break;
        default: handle_unknown_message();
        }
#undef NOT_AFTER_HANDSHAKE
    }
    m_message_parser.optimize_receive_space();
    if(m_info.num_outstanding_bytes > 0) { probe_in_transit_block(); }
}

inline void peer_session::probe_in_transit_block() noexcept 
{
    // now check if the next message we're expecting and have not fully received is
    // a block, and if so, record it
    const_view<uint8_t> bytes = m_message_parser.view_raw_bytes();
    if(bytes.length() >= 5)
    {
        const int type = bytes[4];
        if((type == message::block) && (bytes.length() >= 17))
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
        if(info_hash != m_torrent.info().info_hash)
        {
            disconnect(peer_session_errc::invalid_info_hash);
            return;
        }
    }
    else
    {
        torrent_frontend torrent = m_torrent_attacher(info_hash);
        m_torrent_attacher = decltype(m_torrent_attacher)(); // no longer need it
        if(!torrent)
        {
            // this means we couldn't find a torrent to which we could be attached,
            // likely due to peer's bad info_hash
            disconnect(peer_session_errc::invalid_info_hash);
            return;
        }
        // initialize peer's bitfield now that we know the number of pieces this
        // torrent has
        m_info.available_pieces = bitfield(m_torrent.info().num_pieces);
        // the connection was initiated by peer, we still need to send our handshake
        send_handshake();
    }
    m_info.extensions.assign(endian::parse<uint64_t>(handshake.reserved.cbegin()));
    std::copy(handshake.peer_id.cbegin(),
        handshake.peer_id.cend(), m_info.peer_id.begin());
    try_identify_client();

    // BitComet clients have been observed to drop requests if we have more than
    // 50 outstanding outgoing requests, so cap this
    if((m_info.client == "BitComet") && (m_info.max_outgoing_request_queue_size > 50))
    {
        m_info.max_outgoing_request_queue_size = 50;
    }

#ifdef TIDE_ENABLE_LOGGING
    const auto extensions_str = extensions::to_string(m_info.extensions);
    if(m_info.client.empty())
    {
        log(log_event::incoming, log::priority::high,
            "HANDSHAKE (protocol: %s; extensions: %s; client_id: %s)",
            handshake.protocol.data(), extensions_str.c_str(), m_info.peer_id.data());
    }
    else
    {
        log(log_event::incoming, log::priority::high,
            "HANDSHAKE (protocol: %s; extensions: %s; client_id: %s; client: %s)",
            handshake.protocol.data(), extensions_str.c_str(), m_info.peer_id.data(),
            m_info.client.c_str());
    }
#endif // TIDE_ENABLE_LOGGING

    // only keep connection alive if connection was properly set up to begin with
    start_timer(m_keep_alive_timer, m_settings.peer_timeout,
        [SHARED_THIS](const std::error_code& error) { on_keep_alive_timeout(error); });
}

// ----------------------------------
// BITFIELD <len=1+X><id=5><bitfield>
// ----------------------------------
inline void peer_session::handle_bitfield()
{
    assert(m_info.state == state::piece_availability_exchange);

    message msg = m_message_parser.extract_message();
    const int num_pieces = m_torrent.info().num_pieces;
    if(!bitfield::is_bitfield_data_valid(msg.data, num_pieces))
    {
        // peer sent an invalid bitfield, disconnect immediately
        disconnect(peer_session_errc::invalid_bitfield_message);
        return;
    }

    m_info.available_pieces = bitfield(msg.data, num_pieces);
    m_info.is_peer_seed = m_info.available_pieces.are_all_set();

    // this is expensive, probably don't want to do this
    //const auto pieces = m_info.available_pieces.to_string();
    log(log_event::incoming, "BITFIELD (%s:%i)",
        is_peer_seed() ? "seed" : "leech",
        m_info.available_pieces.count());

    // check if we're interested in peer now that we know its piece availability
    update_interest();
}

// ------------------
// KEEP-ALIVE <len=0>
// ------------------
inline void peer_session::handle_keep_alive()
{
    m_message_parser.skip_message();
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
    if(m_message_parser.extract_message().data.size() != 0)
    {
        log(log_event::invalid_message, "wrong CHOKE message length");
        disconnect(peer_session_errc::invalid_choke_message);
        return;
    }
    if(!am_choked())
    {
        m_info.am_choked = true;
        m_op_state.unset(op::slow_start);
        // the Fast extension modifies the choke semantics in that a choke message no
        // longer implicitly rejects requests, this is done explicitly
        if(!is_extension_enabled(extensions::fast)) { abort_outgoing_requests(); }
    }
    m_info.last_incoming_choke_time = cached_clock::now();
}

// ---------------
// UNCHOKE <len=1>
// ---------------
inline void peer_session::handle_unchoke()
{
    log(log_event::incoming, "UNCHOKE");
    if(m_message_parser.extract_message().data.size() != 0)
    {
        log(log_event::invalid_message, "wrong UNCHOKE message length");
        disconnect(peer_session_errc::invalid_unchoke_message);
        return;
    }
    if(m_info.am_choked)
    {
        // reset these values so that they aren't biased towards earlier values
        // TODO needs more consideration
        m_info.per_second_downloaded_bytes.clear();
        m_info.download_rate.clear();
        m_info.am_choked = false;
    }
    m_info.last_incoming_unchoke_time = cached_clock::now();
    if(can_make_requests()) { make_requests(); }
}

// ------------------
// INTERESTED <len=1>
// ------------------
inline void peer_session::handle_interested()
{
    log(log_event::incoming, "INTERESTED");
    if(m_message_parser.extract_message().data.size() != 0)
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
    if(m_message_parser.extract_message().data.size() != 0)
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
    message msg = m_message_parser.extract_message();
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
    // redundant have message (return so as not to falsely increase piece's frequency)
    if(m_info.available_pieces[piece]) { return; }

    m_torrent.piece_picker().increase_frequency(piece);
    m_info.available_pieces.set(piece);
    // only need to recalculate if we're not interested
    if(!m_info.am_interested) { update_interest(); }
}

// ---------------------------------------------
// REQUEST <len=13><id=6><index><offset><length>
// ---------------------------------------------
inline void peer_session::handle_request()
{
    message msg = m_message_parser.extract_message();
    if(msg.data.size() != 3 * 4)
    {
        log(log_event::invalid_message, "wrong REQUEST message length");
        disconnect(peer_session_errc::invalid_request_message);
        return;
    }

    if(!is_peer_interested())
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

    // if block is in the allowed fast set, we can serve this request
    if(is_peer_choked()
       && (!is_extension_enabled(extensions::fast)
           || std::find(m_outgoing_allowed_set.begin(), m_outgoing_allowed_set.end(),
                   block_info.index) == m_outgoing_allowed_set.end()))
    {
        handle_illicit_request(block_info);
        return;
    }

    log(log_event::incoming, log::priority::high,
        "REQUEST (piece: %i, offset: %i, length: %i)",
        block_info.index, block_info.offset, block_info.length);

    if(should_accept_request(block_info))
    {
        // at this point we can serve the request
        // TODO don't issue request to disk if it's overwhelmed
        m_info.last_incoming_request_time = cached_clock::now();
        m_incoming_requests.emplace_back(block_info);

        m_torrent.fetch_block(block_info,
            [SHARED_THIS](const std::error_code& error, block_source block)
            { on_block_fetched(error, block); });

        m_op_state.set(op::disk_read);
        m_info.num_pending_disk_read_bytes += block_info.length;
        m_torrent.info().num_pending_disk_read_bytes += block_info.length;

        log(log_event::disk, log::priority::high,
            "disk read launched, serving request (piece: %i, offset: %i, length: %i)",
            block_info.index, block_info.offset, block_info.length);
    }
}

inline bool peer_session::should_accept_request(const block_info& block) const noexcept
{
    // TODO check if max block size is still enforced
    // don't serve request if peer reached its max allowed outstanding requests or
    // if the requested block is larger than 16KiB
    return m_incoming_requests.size() < m_settings.max_incoming_request_queue_size
        || block.length <= 0x4000;
}

// --------------------------------------------
// CANCEL <len=13><id=8><index><offset><length>
// --------------------------------------------
inline void peer_session::handle_cancel()
{
    message msg = m_message_parser.extract_message();
    if(msg.data.size() != 13)
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

    auto request = std::find(m_incoming_requests.begin(),
        m_incoming_requests.end(), block_info);
    if(request != m_incoming_requests.cend())
    {
        // TODO we likely launched a disk read for this block, so cancel it
        m_incoming_requests.erase(request);
        log(log_event::disk, "disk abort launched, cancelling request");
        if(is_extension_enabled(extensions::fast)) { send_reject_request(block_info); }
    }
}

inline bool peer_session::is_request_valid(const block_info& request) const noexcept
{
    return is_block_info_valid(request)
        && m_torrent.piece_picker().my_bitfield()[request.index];
}

// ------------------------------------------
// BLOCK <len=9+X><id=7><index><offset><data>
// ------------------------------------------
void peer_session::handle_block()
{
    std::error_code _ec;
    m_request_timeout_timer.cancel(_ec);
    m_info.num_consecutive_timeouts = 0;

    message msg = m_message_parser.extract_message();
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
    log(log_event::incoming, log::priority::high,
        "BLOCK (piece: %i, offset: %i, length: %i)",
        block_info.index, block_info.offset, block_info.length);

    auto request = std::find(m_outgoing_requests.begin(),
        m_outgoing_requests.end(), block_info);
    if(request == m_outgoing_requests.cend())
    {
        handle_illicit_block(block_info);
        return;
    }

    if(block_info.length == 0)
    {
        // BitComet has been observed to use 0 length blocks to reject requests
        handle_rejected_request(request);
        return;
    }

    // erase request from queue as we either got it or no longer expect it
    // (handle_reject_request also erases it so no need to do this after invoking it)
    m_outgoing_requests.erase(request);

    // NOTE: we must upload stats before adjusting request timeout and request queue
    // size as we adjust request timeout based on stats
    update_download_stats(block_info.length);
    adjust_request_timeout();
    adjust_best_request_queue_size();
    m_info.in_transit_block = invalid_block;

    if(m_torrent.piece_picker().my_bitfield()[block_info.index])
    {
        // we already have this piece
        log(log_event::incoming, "received block for piece we already have");
        m_info.total_wasted_bytes += block_info.length;
        m_torrent.info().total_wasted_bytes += block_info.length;
    }
    else
    {
        // we MUST have download, because at this point block is deemed valid, which
        // means its request entry in m_outgoing_requests was found, meaning we expect
        // this block, so its corresponding download instance must also be present
        piece_download& download = find_download(block_info.index);
        download.got_block(remote_endpoint(), block_info);
        disk_buffer block = m_torrent.get_disk_buffer(block_info.length);
        assert(block);
        // exclude the block header (index and offset, both 4 bytes)
        std::copy(msg.data.begin() + 8, msg.data.end(), block.data());
        save_block(block_info, std::move(block), download);
    }

    if(can_make_requests())
        make_requests();
    else if(!m_outgoing_requests.empty())
        start_timer(m_request_timeout_timer, calculate_request_timeout(),
            [SHARED_THIS](const std::error_code& error) { on_request_timeout(error); });
}

inline void peer_session::update_download_stats(const int num_bytes)
{
    m_info.last_incoming_block_time = cached_clock::now();
    m_info.num_outstanding_bytes -= num_bytes;
    m_info.total_downloaded_piece_bytes += num_bytes;
    m_info.download_rate.update(num_bytes);
    m_info.per_second_downloaded_bytes.update(num_bytes);
    m_torrent.info().num_outstanding_bytes -= num_bytes;
    m_torrent.info().total_downloaded_piece_bytes += num_bytes;
    m_torrent.info().download_rate.update(num_bytes);
    m_num_downloaded_piece_bytes += num_bytes;
}

inline void peer_session::adjust_request_timeout() // TODO rename
{
    const auto request_rtt = cached_clock::now() - m_info.last_outgoing_request_time;
    m_avg_request_rtt.update(to_int<milliseconds>(request_rtt));
    log(log_event::request, log::priority::high, "request rtt: %lims",
        to_int<milliseconds>(request_rtt));

    const auto timeout = calculate_request_timeout();
    if((request_rtt < timeout) && m_info.has_peer_timed_out)
    {
        // peer has timed out before but managed to deliver this time
        m_info.has_peer_timed_out = false;
    }
    else if(request_rtt >= timeout)
    {
        m_info.has_peer_timed_out = true;
    }
}

inline void peer_session::adjust_best_request_queue_size() noexcept
{
    if(m_info.has_peer_timed_out)
    {
        m_info.best_request_queue_size = 1;
        m_op_state[op::slow_start] = false;
        return;
    }

    // only adjust request queue size if at least a second has passed
    const auto now = cached_clock::now();
    if(now - m_info.last_request_queue_adjust_time < seconds(1)) { return; }
    m_info.last_request_queue_adjust_time = now;

    const int old_best_request_queue_size = m_info.best_request_queue_size;
    const int num_downloaded = m_info.per_second_downloaded_bytes.value();
    const int deviation = m_info.per_second_downloaded_bytes.deviation();

    log(log_event::request, log::priority::high,
        "downloaded this second: %i b (deviation: %i b)", num_downloaded, deviation);

    if(m_op_state[op::slow_start])
    {
        // if our download rate is not increasing significantly anymore, exit slow start
        if(deviation < 5000)
        {
            log(log_event::request, log::priority::high,
                "leaving slow start (per second deviation: %i b)", deviation);
            m_op_state[op::slow_start] = false;
            return;
        }
        ++m_info.best_request_queue_size;
    }
    else
    {
        // TODO figure out good formula, this is just a placeholder
        m_info.best_request_queue_size = (num_downloaded + (0x4000 - 1)) / 0x4000;
    }

    if(m_info.best_request_queue_size > m_info.max_outgoing_request_queue_size)
    {
        m_info.best_request_queue_size = m_info.max_outgoing_request_queue_size;
    }
    else if(m_info.best_request_queue_size < m_settings.min_outgoing_request_queue_size)
    {
        m_info.best_request_queue_size = m_settings.min_outgoing_request_queue_size;
    }

    if(m_info.best_request_queue_size != old_best_request_queue_size)
    {
        log(log_event::request, log::priority::high,
            "best request queue size changed from %i to %i",
            old_best_request_queue_size, m_info.best_request_queue_size);
    }
}

inline bool peer_session::is_block_info_valid(const block_info& block) const noexcept
{
    const int piece_length = get_piece_length(m_torrent.info(), block.index);
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
    return (index >= 0) && (index < m_torrent.info().num_pieces);
}

inline void peer_session::handle_illicit_request(const block_info& block)
{
    ++m_info.num_illicit_requests;
    log(log_event::incoming, "%i illicit requests", m_info.num_illicit_requests);

    // don't mind request messages (though don't serve them) up to 2 seconds after
    // choking peer, to give it some slack
    if(cached_clock::now() - seconds(2) <= m_info.last_outgoing_choke_time) { return; }

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

    if(is_extension_enabled(extensions::fast)) { send_reject_request(block); }
}

// -----------------------------------------
// SUGGEST PIECE <len=5><id=13><piece index>
// -----------------------------------------
inline void peer_session::handle_suggest_piece()
{
    if(!is_extension_enabled(extensions::fast))
    {
        log(log_event::invalid_message, "SUGGEST PIECE message not supported");
        disconnect(peer_session_errc::unsupported_extension);
        return;
    }

    message msg = m_message_parser.extract_message();
    if(msg.data.size() != 4)
    {
        log(log_event::invalid_message, "wrong SUGGEST PIECE message length");
        disconnect(peer_session_errc::invalid_suggest_piece_message);
        return;
    }

    const piece_index_t piece = endian::parse<int32_t>(msg.data.begin());

    log(log_event::incoming, "SUGGEST PIECE %i", piece);

    if(!is_piece_index_valid(piece))
    {
        log(log_event::invalid_message, "invalid piece index in SUGGEST PIECE message");
        disconnect(peer_session_errc::invalid_suggest_piece_message);
        return;
    }

    if(!m_torrent.piece_picker().my_bitfield()[piece])
    {
        // TODO check if we're alreayd downloading this piece from other peers
        // then decide whether we want to download this piece from peer
    }
}

// -----------------------
// HAVE ALL <len=1><id=14>
// -----------------------
inline void peer_session::handle_have_all()
{
    assert(m_info.state == state::piece_availability_exchange);

    if(!is_extension_enabled(extensions::fast))
    {
        log(log_event::invalid_message, "HAVE ALL message not supported");
        disconnect(peer_session_errc::unsupported_extension);
        return;
    }

    if(m_message_parser.extract_message().data.size() != 0)
    {
        log(log_event::invalid_message, "wrong HAVE ALL message length");
        disconnect(peer_session_errc::invalid_have_all_message);
        return;
    }

    assert(m_info.available_pieces.size() == m_torrent.info().num_pieces);
    m_info.available_pieces.fill();
    m_info.is_peer_seed = true;

    log(log_event::incoming, "HAVE ALL");

    // check if we're interested in peer now that we know its piece availability
    update_interest();
}

// ------------------------
// HAVE NONE <len=1><id=15>
// ------------------------
inline void peer_session::handle_have_none()
{
    assert(m_info.state == state::piece_availability_exchange);

    if(!is_extension_enabled(extensions::fast))
    {
        log(log_event::invalid_message, "HAVE NONE message not supported");
        disconnect(peer_session_errc::unsupported_extension);
        return;
    }

    if(m_message_parser.extract_message().data.size() != 0)
    {
        log(log_event::invalid_message, "wrong HAVE NONE message length");
        disconnect(peer_session_errc::invalid_have_all_message);
        return;
    }

    assert(m_info.available_pieces.size() == m_torrent.info().num_pieces);
    m_info.available_pieces.clear();
    m_info.is_peer_seed = false;
    // we don't need to update interest as peer has no pieces and a connection starts
    // out as not interested, so

    log(log_event::incoming, "HAVE NONE");
}

// -----------------------------------------------------
// REJECT REQUEST <len=13><id=16><index><offset><length>
// -----------------------------------------------------
inline void peer_session::handle_reject_request()
{
    message msg = m_message_parser.extract_message();

    if(!is_extension_enabled(extensions::fast))
    {
        log(log_event::invalid_message, "REJECT REQUEST message not supported");
        disconnect(peer_session_errc::unsupported_extension);
        return;
    }

    if(msg.data.size() != 13)
    {
        log(log_event::invalid_message, "wrong REJECT REQUEST message length");
        disconnect(peer_session_errc::invalid_reject_request_message);
        return;
    }

    const block_info block_info = parse_block_info(msg.data);
    if(!is_block_info_valid(block_info))
    {
        log(log_event::invalid_message,
            "invalid REJECT REQUEST (piece: %i, offset: %i, length: %i)",
            block_info.index, block_info.offset, block_info.length);
        disconnect(peer_session_errc::invalid_cancel_message);
        return;
    }

    handle_rejected_request(std::find(m_outgoing_requests.begin(),
        m_outgoing_requests.end(), block_info));
}

inline void peer_session::handle_rejected_request(
    std::vector<pending_block>::iterator request)
{
    log(log_event::incoming, log::priority::high,
        "REJECT REQUEST (piece: %i, offset: %i, length: %i)",
        request->index, request->offset, request->length);
    if(request != m_outgoing_requests.end())
    {
        // find_download must not trigger the assertion as request is only valid as long
        // as no peer_session in torrent has downloaded it--as soon as we receive it
        // from another peer, we cancel the request from this peer, which removes the
        // request from m_outgoing_requests TODO verify
        find_download(request->index).abort_request(remote_endpoint(), *request);
        m_outgoing_requests.erase(request);
    }
    // we don't have other requests, so stop the timer
    if(m_outgoing_requests.empty())
    {
        std::error_code ec;
        m_request_timeout_timer.cancel(ec);
    }
}

// ----------------------------------------
// ALLOWED FAST <len=5><id=17><piece index>
// ----------------------------------------
inline void peer_session::handle_allowed_fast()
{
    if(!is_extension_enabled(extensions::fast))
    {
        log(log_event::invalid_message, "ALLOWED FAST message not supported");
        disconnect(peer_session_errc::unsupported_extension);
        return;
    }

    message msg = m_message_parser.extract_message();
    if(msg.data.size() != 4)
    {
        log(log_event::invalid_message, "wrong ALLOWED FAST message length");
        disconnect(peer_session_errc::invalid_allow_fast_message);
        return;
    }

    const piece_index_t piece = endian::parse<int32_t>(msg.data.begin());

    log(log_event::incoming, "ALLOWED FAST %i", piece);

    if(!is_piece_index_valid(piece))
    {
        log(log_event::invalid_message, "invalid piece index in ALLOWED FAST message");
        disconnect(peer_session_errc::invalid_allow_fast_message);
        return;
    }

    //if(m_torrent.piece_picker().my_bitfield()[piece]) { return; }

    if(std::find(m_outgoing_allowed_set.begin(),
        m_outgoing_allowed_set.end(), piece) == m_outgoing_allowed_set.end())
    {
        m_outgoing_allowed_set.emplace_back(piece);
        //// TODO if peer has this piece we may consider downloading it
        //if(m_info.available_pieces[piece])
    }
}

inline void peer_session::handle_illicit_block(const block_info& block)
{
    // we don't want this block (give 2 second slack as it may be an old request)
    if(!m_info.am_interested
       && cached_clock::now() - m_info.last_outgoing_uninterest_time > seconds(2))
    {
        if(++m_info.num_unwanted_blocks > 50)
        {
            disconnect(peer_session_errc::unwanted_blocks);
        }
        log(log_event::incoming, "%i unwanted blocks", m_info.num_unwanted_blocks);
    }
    m_info.total_wasted_bytes += block.length;
    m_torrent.info().total_wasted_bytes += block.length;
    log(log_event::incoming, "%i wasted bytes", m_info.total_wasted_bytes);
}

inline void peer_session::handle_unknown_message()
{
    // later when we support custom extensions we'll first pass the current message
    // there and see if they can handle it
    m_message_parser.skip_message();
    log(log_event::invalid_message, "unknown message");
    disconnect(peer_session_errc::unknown_message);
}

// ----------
// -- disk --
// ----------

inline void peer_session::save_block(const block_info& block_info,
    disk_buffer block_data, piece_download& download)
{
    m_op_state.set(op::disk_write);
    m_info.num_pending_disk_write_bytes += block_info.length;
    m_torrent.info().num_pending_disk_write_bytes += block_info.length;

    // note that it's safe to pass a reference to download as only torrent may
    // remove a piece_download from m_shared_downloads, and if download is 
    // m_parole_download, it is added to m_shared_downloads if we disconnect before 
    // finishing the download
    m_torrent.save_block(block_info, std::move(block_data), download,
        [SHARED_THIS, block_info, start_time = cached_clock::now()]
        (const std::error_code& ec) { on_block_saved(ec, block_info, start_time); });

    log(log_event::disk, log::priority::high,
        "launched disk write, saving block (piece: %i, offset: %i, length: %i)",
        block_info.index, block_info.offset, block_info.length);
}

inline void peer_session::on_piece_hashed(const piece_download& download,
    const bool is_piece_good, const int num_bytes_downloaded)
{
#ifdef TIDE_ENABLE_EXPENSIVE_ASSERTS
    const int n = std::count_if(m_outgoing_requests.begin(),
        m_outgoing_requests.end(), [&download](const auto& r)
        { return r.index == download.piece_index(); });
    if(n > 0)
    {
        log(log_event::info, log::priority::high,
            "%i blocks for piece(%i) in m_outgoing_requests after piece completion",
            n, download.piece_index());
        assert(0 && "remaining requests for complete piece!");
    }
#endif // TIDE_ENABLE_LOGGING

    // despite joining this download, we may not have been successful in getting any
    // blocks from peer
    if(num_bytes_downloaded > 0)
    {
        if(is_piece_good)
            handle_valid_piece(download);
        else
            handle_corrupt_piece(download);
    }

    const auto it = std::find_if(m_downloads.begin(), m_downloads.end(),
        [&download](const auto& d) { return d.get() == &download; });
    if(it != m_downloads.end()) { m_downloads.erase(it); }
#ifdef TIDE_ENABLE_DEBUGGING
    else log(log_event::info, log::priority::high, "not removing download(%i)",
            download.piece_index());
#endif // TIDE_ENABLE_DEBUGGING
}

inline void peer_session::handle_valid_piece(const piece_download& download)
{
    log(log_event::disk, log::priority::high,
        "piece(%i) passed hash test", download.piece_index());

    m_info.total_verified_piece_bytes += get_piece_length(
        m_torrent.info(), download.piece_index());

    if(is_peer_on_parole())
    {
        if(m_parole_download && (&download == m_parole_download.get()))
        {
            // peer cleared itself, so it's no longer on parole
            m_parole_download.reset();
            m_info.is_peer_on_parole = false;
            log(log_event::parole, log::priority::high,
                "peer cleared suspicion, no longer on parole");
        }
        else
        {
            log(log_event::parole, log::priority::high,
                "downloaded (non-parole) valid piece from peer while on parole");
        }
    }
}

inline void peer_session::handle_corrupt_piece(const piece_download& download)
{
    log(log_event::parole, log::priority::high,
        "piece(%i) failed hash test (%i fails)",
        download.piece_index(), m_info.num_hash_fails);

    ++m_info.num_hash_fails;
    m_info.total_wasted_bytes += get_piece_length(
        m_torrent.info(), download.piece_index());

    if(is_peer_on_parole()
       && m_parole_download
       && &download == m_parole_download.get())
    {
        log(log_event::parole, "confirmed suspicion through parole download");
        m_parole_download.reset();
    }
    else if(download.is_exclusive())
    {
        log(log_event::parole, log::priority::high,
            "peer sent bad piece, disconnecting peer");
        if(m_parole_download)
        {
            // download is not the parole piece this peer was assigned, our suspicion
            // got confirmed by chance through another download which happend to involve
            // only this peer; free m_parole_download for others to request
            // TODO free from piece picker
            // TODO tell disk_io not to save these blocks; if it has, tell it to consider
            // them corrupt (so that it won't drop other blocks)
            //m_torrent.piece_picker().unreserve(m_parole_download->piece_index());
            m_parole_download.reset();
        }
        disconnect(peer_session_errc::corrupt_piece);
        return;
    }
    else
    {
        log(log_event::parole, "peer on parole effective immediately");
        m_info.is_peer_on_parole = true;
    }
}

void peer_session::on_block_saved(const std::error_code& error,
    const block_info& block, const time_point start_time)
{
    m_info.num_pending_disk_write_bytes -= block.length;
    // there may be multiple concurrent disk operations, so we can only unset this state
    // if we don't expect more bytes to be written to disk
    if(m_info.num_pending_disk_write_bytes == 0) { m_op_state.unset(op::disk_write); }
    m_torrent.info().num_pending_disk_write_bytes -= block.length;
    assert(error != disk_io_errc::invalid_block);
    // it's not really an error if piece turned out to be bad or it was a duplicate block
    // (though the latter should happen very rarely)
    if(error && (error != disk_io_errc::corrupt_data_dropped
                 && error != disk_io_errc::duplicate_block))
    {
        // if block could not be saved we will have to redownload it at some point, so
        // tell its corresponding download instance to free this block for requesting
        if(error == disk_io_errc::block_dropped)
        {
            // the assert in find_download must not fire as in this case (dropped block)
            // we could not advance the hashing, i.e. the completion of the piece, and a
            // piece_download may only be removed once we have fully hashed it
            find_download(block.index).abort_request(remote_endpoint(), block);
        }
        ++m_info.num_disk_io_failures;
        ++m_torrent.info().num_disk_io_failures;
        const auto reason = error.message();
        log(log_event::disk, log::priority::high, "disk failure #%i (%s)",
            m_info.num_disk_io_failures, reason.c_str());
        if(m_info.num_disk_io_failures > 100) { disconnect(error); }
    }
    else
    {
        m_info.num_disk_io_failures = 0;
        m_info.total_bytes_written_to_disk += block.length;
        m_torrent.info().total_bytes_written_to_disk += block.length;
        m_avg_disk_write_time.update(to_int<milliseconds>(
            cached_clock::now() - start_time));

        log(log_event::disk, log::priority::high,
            "saved block to disk (piece: %i, offset: %i, length: %i) - "
            "disk write stats (total: %lli; pending: %lli)",
            block.index, block.offset, block.length, m_info.total_bytes_written_to_disk,
            m_info.num_pending_disk_write_bytes);
    }

    // note: don't move this above, we still need to record stats for torrent,
    // but even more importantly, THIS ALWAYS HAS TO BE CALLED
    if(is_disconnecting())
    {
        try_finish_disconnecting();
        return;
    }
    else if(should_abort(error))
    {
        return;
    }

    // we can likely receive more now that we finished writing to disk
    receive();
}

void peer_session::on_block_fetched(const std::error_code& error,
    const block_source& block)
{
    if(error == disk_io_errc::operation_aborted)
    {
        // the block read was cancelled
        log(log_event::disk, "block fetch aborted (piece: %i, offset: %i, length: %i)",
            block.index, block.offset, block.length);
    }
    else if(error)
    {
        ++m_info.num_disk_io_failures;
        ++m_torrent.info().num_disk_io_failures;
        log(log_event::disk, log::priority::high,
            "disk failure #%i", m_info.num_disk_io_failures);
        if(m_info.num_disk_io_failures > 100) { disconnect(error); }
    }
    else
    {
        // reset disk failuires to 0 since it only counts consecutive failures
        m_info.num_disk_io_failures = 0;
        m_info.total_bytes_read_from_disk += block.length;
        m_info.num_pending_disk_read_bytes -= block.length;
        m_torrent.info().total_bytes_read_from_disk += block.length;
        m_torrent.info().num_pending_disk_read_bytes -= block.length;

        log(log_event::disk, log::priority::high,
            "read block from disk (piece: %i, offset: %i, length: %i) - "
            "disk read stats (total: %lli; pending: %lli)",
            block.index, block.offset, block.length, m_info.total_bytes_read_from_disk,
            m_info.num_pending_disk_read_bytes);
    }

    // there may be multiple concurrent disk operations, so we can only unset this state
    // if we don't expect more bytes to be written to disk
    if(m_info.num_pending_disk_read_bytes == 0) { m_op_state.unset(op::disk_read); }

    // note: don't move this above, we still need to record stats for torrent,
    // but even more importantly, THIS ALWAYS HAS TO BE CALLED
    if(is_disconnecting())
    {
        try_finish_disconnecting();
        return;
    }
    else if(should_abort(error))
    {
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
    static constexpr char protocol[] = "BitTorrent protocol";
    static constexpr char protocol_length = sizeof(protocol) - 1;
    m_send_buffer.append(fixed_payload<protocol_length + 49>()
        .i8(protocol_length)
        .range(protocol, protocol + protocol_length)
        .u64(m_settings.extensions.data())
        .buffer(m_torrent.info().info_hash)
        .buffer(m_settings.client_id));
    send();

#ifdef TIDE_ENABLE_LOGGING
    const auto extensions_str = extensions::to_string(m_settings.extensions);
    log(log_event::outgoing, "HANDSHAKE (protocol: %s; extensions: %s; client_id: %s)",
        protocol, extensions_str.c_str(), m_settings.client_id.data());
#endif // TIDE_ENABLE_LOGGING
}

// ----------------------------------
// BITFIELD <len=1+X><id=5><bitfield>
// ----------------------------------
// Only ever sent as the first message. Optional, and need not be sent if a client has
// no pieces.
//
// The high bit in the first byte corresponds to piece index 0. Spare bits at the end 
// must be set to zero.
// If a peer receives a bitfield of the wrong length, it should drop the connection, or
// if the bitfield has any of the spare bits set.
void peer_session::send_bitfield()
{
    assert(m_torrent);
    assert(!m_torrent.piece_picker().has_no_pieces());

    const auto& my_pieces = m_torrent.piece_picker().my_bitfield();
    const int msg_size = 1 + my_pieces.data().size();
    m_send_buffer.append(payload(4 + msg_size)
        .i32(msg_size)
        .i8(message::bitfield)
        .buffer(my_pieces.data()));
    send();
    log(log_event::outgoing, "BITFIELD");
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
    static constexpr uint8_t payload[] = { 0,0,0,1, message::choke };
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
    static constexpr uint8_t payload[] = { 0,0,0,1, message::unchoke };
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
    static constexpr uint8_t payload[] = { 0,0,0,1, message::interested };
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
    static constexpr uint8_t payload[] = { 0,0,0,1, message::not_interested };
    m_send_buffer.append(payload);
    m_info.am_interested = false;
    m_op_state[op::slow_start] = false;
    m_info.last_outgoing_uninterest_time = cached_clock::now();
    send();
    log(log_event::outgoing, "NOT_INTERESTED");
}

// -------------------------------
// HAVE <len=5><id=4><piece index>
// -------------------------------
inline void peer_session::send_have(const piece_index_t piece)
{
    m_send_buffer.append(fixed_payload<9>()
        .i32(5)
        .i8(message::have)
        .i32(piece));
    send();
    log(log_event::outgoing, "HAVE %i", piece);
}

// ---------------------------------------------
// REQUEST <len=13><id=6><index><offset><length>
// ---------------------------------------------
// Block size should be 2^14 (16KB - 16,384 bytes).
// Max request block size is 2^15 (32KB - 32,768 bytes), but many clients will refuse
// to serve this amount.
void peer_session::send_request(const block_info& block)
{
    m_send_buffer.append(fixed_payload<17>()
        .i32(13)
        .i8(message::request)
        .i32(block.index)
        .i32(block.offset)
        .i32(block.length));
    send();

    log(log_event::outgoing, "REQUEST (piece: %i, offset: %i, length: %i)",
        block.index, block.offset, block.length);

    m_info.last_outgoing_request_time = cached_clock::now();
    m_info.num_outstanding_bytes += block.length;
    m_torrent.info().num_outstanding_bytes += block.length;
    ++m_torrent.info().num_pending_blocks;

    start_timer(m_request_timeout_timer, calculate_request_timeout(),
        [SHARED_THIS](const std::error_code& error) { on_request_timeout(error); });
}

// ------------------------------------------
// BLOCK <len=9+X><id=7><index><offset><data>
// ------------------------------------------
void peer_session::send_block(const block_source& block)
{
    static constexpr int header_size = 4 + 1 + 2 * 4;
    // send_buffer is optimized for sending blocks so we don't need to copy it into a
    // separate buffer, just separate the block header (msg header and block info) and 
    // append the block separately
    fixed_payload<header_size> block_header;
    block_header.i32(header_size + block.length)
                .i8(message::block)
                .i32(block.index)
                .i32(block.offset);
    m_send_buffer.append(block_header);
    m_send_buffer.append(block);
    m_outgoing_requests.emplace_back(block.index, block.offset, block.length);

    update_upload_stats(block.length);

    send();

    log(log_event::outgoing, log::priority::high,
        "BLOCK (piece: %i, offset: %i, length: %i) -- upload rate: %i bytes/s",
        block.index, block.offset, block.length, m_info.upload_rate.rate());

    // now that we sent this block, remove it from m_incoming_requests
    auto it = std::find(m_incoming_requests.begin(), m_incoming_requests.end(), block);
    assert(it != m_incoming_requests.end());
    m_incoming_requests.erase(it);
}

inline void peer_session::update_upload_stats(const int num_bytes)
{
    m_info.last_outgoing_block_time = cached_clock::now();
    m_info.total_uploaded_piece_bytes += num_bytes;
    m_info.upload_rate.update(num_bytes);
    m_torrent.info().total_uploaded_piece_bytes += num_bytes;
    m_torrent.info().upload_rate.update(num_bytes);
    log(log_event::outgoing, log::priority::high,
        "upload rate: %i bytes/s", m_info.upload_rate.rate());
}

// --------------------------------------------
// CANCEL <len=13><id=8><index><offset><length>
// --------------------------------------------
void peer_session::send_cancel(const block_info& block)
{
    // if we're already receiving this block, we can't cancel it
    if(block != m_info.in_transit_block)
    {
        m_send_buffer.append(fixed_payload<17>()
            .i32(13)
            .i8(message::cancel)
            .i32(block.index)
            .i32(block.offset)
            .i32(block.length));
        send();
        --m_torrent.info().num_pending_blocks;
        auto it = std::find(m_outgoing_requests.begin(),
            m_outgoing_requests.end(), block);
        if(it != m_outgoing_requests.end()) { m_outgoing_requests.erase(it); }
        log(log_event::outgoing, "CANCEL (piece: %i, offset: %i, length: %i)",
            block.index, block.offset, block.length);
    }
}

// -------------------------------
// PORT <len=3><id=9><listen-port>
// -------------------------------
void peer_session::send_port(const int port)
{
    m_send_buffer.append(fixed_payload<7>()
        .i32(3)
        .i8(message::port)
        .i16(port));
    send();
    log(log_event::outgoing, "PORT (%i)", port);
}

// -----------------------------------------
// SUGGEST PIECE <len=5><id=13><piece index>
// -----------------------------------------
void peer_session::send_suggest_piece(const piece_index_t piece)
{
    m_send_buffer.append(fixed_payload<9>()
        .i32(5)
        .i8(message::suggest_piece)
        .i32(piece));
    send();
    log(log_event::outgoing, "SUGGEST PIECE (%i)", piece);
}

// -----------------------
// HAVE ALL <len=1><id=14>
// -----------------------
// Only ever sent as the first message.
void peer_session::send_have_all()
{
    static constexpr uint8_t payload[] = { 0,0,0,1, message::have_all };
    m_send_buffer.append(payload);
    send();
    log(log_event::outgoing, "HAVE ALL");
}

// ------------------------
// HAVE NONE <len=1><id=15>
// ------------------------
// Only ever sent as the first message.
void peer_session::send_have_none()
{
    static constexpr uint8_t payload[] = { 0,0,0,1, message::have_none };
    m_send_buffer.append(payload);
    send();
    log(log_event::outgoing, "HAVE NONE");
}

// -----------------------------------------------------
// REJECT REQUEST <len=13><id=16><index><offset><length>
// -----------------------------------------------------
void peer_session::send_reject_request(const block_info& block)
{
    m_send_buffer.append(fixed_payload<17>()
        .i32(13)
        .i8(message::reject_request)
        .i32(block.index)
        .i32(block.offset)
        .i32(block.length));
    send();
    log(log_event::outgoing, "REJECT REQUEST (piece: %i, offset: %i, length: %i)",
        block.index, block.offset, block.length);
}

// ----------------------------------------
// ALLOWED FAST <len=5><id=17><piece index>
// ----------------------------------------
void peer_session::send_allowed_fast(const piece_index_t piece)
{
    m_send_buffer.append(fixed_payload<9>()
        .i32(5)
        .i8(message::allowed_fast)
        .i32(piece));
    send();
    log(log_event::outgoing, "ALLOWED FAST (%i)", piece);
}

void peer_session::send_allowed_fast_set()
{
    generate_allowed_fast_set();
    for(const auto& p : m_outgoing_allowed_set) { send_allowed_fast(p); }
}

inline void peer_session::send_piece_availability()
{
    m_info.state = state::piece_availability_exchange;
    if(is_extension_enabled(extensions::fast))
    {
        // in the fast extension we MUST send a piece availability message
        if(m_torrent.piece_picker().has_all_pieces())
            send_have_all();
        else if(m_torrent.piece_picker().has_no_pieces())
            send_have_none();
        else
            send_bitfield();
    }
    else if(!m_torrent.piece_picker().has_no_pieces())
    {
        // otherwise we only need to send the bitfield if we have any pieces
        // TODO if we only have a few pieces (i.e. not worth sending an entire bitfield)
        // send them in separate have messages
        send_bitfield();
    }
}

// -------------------
// -- request logic --
// -------------------

inline bool peer_session::can_make_requests() const noexcept
{
    // TODO restrict requests if disk is overwhelmed...I think?
    return am_interested()
        && num_to_request() > 0
        && (!am_choked() || !m_incoming_allowed_set.empty());
}

void peer_session::make_requests()
{
    assert(m_torrent);

    // TODO rework this
    if(m_outgoing_requests.size() == 1)
    {
        auto& lingering_block = m_outgoing_requests[0];
        // we have a single pending block left, and it's a block that's supposed to
        // come before the block we received just now; even though peer is not required
        // to serve blocks in order, they have a tendency not to send the first
        // requested block
        if(lingering_block.offset == 0)
        {
            log(log_event::request, log::priority::high,
                "peer hasn't sent the first block, rerequesting");
            lingering_block.request_time = cached_clock::now();
            send_request(lingering_block);
            return;
        }
    }

    log(log_event::request, log::priority::high,
        "preparing request queue (outstanding requests: %i, best queue size: %i)",
        m_outgoing_requests.size(), m_info.best_request_queue_size);

    view<pending_block> new_requests = distpach_make_requests();
    if(new_requests.empty()) { return; }

    auto& torrent_info = m_torrent.info();
    payload payload(new_requests.size() * 17);
    // craft the payload for each block that was put in m_outgoing_requests by the
    // above functions
    for(auto& block : new_requests)
    {
        payload.i32(13)
               .i8(message::request)
               .i32(block.index)
               .i32(block.offset)
               .i32(block.length);
        block.request_time = cached_clock::now();
        log(log_event::outgoing, log::priority::high,
            "REQUEST (piece: %i, offset: %i, length: %i)",
            block.index, block.offset, block.length);
        m_info.num_outstanding_bytes += block.length;
        torrent_info.num_outstanding_bytes += block.length;
        ++torrent_info.num_pending_blocks;
    }
    log(log_event::outgoing, log::priority::high,
        "request queue length: %i", new_requests.size());
    m_send_buffer.append(std::move(payload));
    send();

    if(torrent_info.num_pending_blocks >= torrent_info.num_blocks)
    {
    }

    m_info.last_outgoing_request_time = cached_clock::now();
    start_timer(m_request_timeout_timer, calculate_request_timeout(),
        [SHARED_THIS](const std::error_code& error) { on_request_timeout(error); });
}

inline view<pending_block> peer_session::distpach_make_requests()
{
    // TODO if we're on parole and it's also end-game mode, we should probably not
    // request from this peer (so as not to slow down the download), unless they are
    // the only ones that have some of the pieces
    if(m_torrent.info().state[torrent_info::end_game])
        return make_requests_in_endgame_mode();
    else if(is_peer_on_parole())
        return make_requests_in_parole_mode();
    else
        return make_requests_in_normal_mode();
}

inline view<pending_block> peer_session::make_requests_in_endgame_mode()
{
    // TODO for now
    return make_requests_in_normal_mode();
}

inline view<pending_block> peer_session::make_requests_in_parole_mode()
{
    // pick a parole piece for this peer if it hasn't been assigned one yet since it
    // participated in a failed hash test
    if(m_parole_download == nullptr)
    {
        auto& piece_picker = m_torrent.piece_picker();
        const auto piece = piece_picker.pick(m_info.available_pieces);
        if(piece == piece_picker::invalid_piece)
        {
            return {};
        }
        else if(piece_picker.num_pieces_left() == 1
                && piece_picker.frequency(piece) > 1)
        {
            // if this is the last piece and other peers have this piece, we don't want
            // to stall completion by assigning only a single peer to it
            // FIXME if all peers that have this piece are put on parole this will
            // never dl
            piece_picker.unreserve(piece);
            log(log_event::request, log::priority::high,
                "picked and released piece(%i) to not stall completion", piece);
            return {};
        }
        ++m_torrent.info().num_pending_pieces;
        m_parole_download = std::make_unique<piece_download>(
            piece, get_piece_length(m_torrent.info(), piece));
        // it's safe to pass only this instead of SHARED_THIS because we remove
        // these callbacks from download when we destruct
        m_parole_download->register_peer(remote_endpoint(),
            [this, &download = *m_parole_download]
            (bool is_piece_good, int num_bytes_downloaded)
            { on_piece_hashed(download, is_piece_good, num_bytes_downloaded); },
            [this](const block_info& block) { send_cancel(block); });
        log(log_event::request, log::priority::high,
            "picked piece(%i) in parole mode", piece);
    }
    const int num_new_requests = m_parole_download->pick_blocks(
        m_outgoing_requests, remote_endpoint(), num_to_request());
    log(log_event::request, log::priority::high,
        "%i new parole requests", num_new_requests);
    return view_of_new_requests(num_new_requests);
}

inline view<pending_block> peer_session::make_requests_in_normal_mode()
{
    // if we have active downloads, prefer to finish those (this will result in less
    // peers per piece download, i.e. lower chance of a bad peer polluting many pieces)
    int num_new_requests = continue_downloads();

    // we try to join a download using m_shared_downloads as long as we need more
    // blocks and there are downloads to join
    while(m_outgoing_requests.size() < m_info.best_request_queue_size)
    {
        const int num_blocks = join_download();
        if(num_blocks == 0) { break; }
        num_new_requests += num_blocks;
    }

    // while we still need blocks, we pick a piece and start a new download, and add it
    // to the shared downloads via m_shared_downloads
    while(m_outgoing_requests.size() < m_info.best_request_queue_size)
    {
        const int num_blocks = start_download();
        if(num_blocks == 0) { break; }
        num_new_requests += num_blocks;
    }

    log(log_event::request, log::priority::high, "%i new requests", num_new_requests);
    return view_of_new_requests(num_new_requests);
}

inline view<pending_block> peer_session::view_of_new_requests(const int n)
{
    assert(n <= m_outgoing_requests.size());
    const int first_new_request_pos = m_outgoing_requests.size() - n;
    return {&m_outgoing_requests[first_new_request_pos], size_t(n)};
}

inline int peer_session::continue_downloads()
{
    int num_new_requests = 0;
    for(auto& download : m_downloads)
    {
        if(m_outgoing_requests.size() >= m_info.best_request_queue_size) { break; }
        const int n = download->pick_blocks(
            m_outgoing_requests, remote_endpoint(), num_to_request());
        if(n > 0)
        {
            log(log_event::request, log::priority::high,
                "continuing piece(%i) download with %i block(s)",
                download->piece_index(), n);
            num_new_requests += n;
        }
    }
    return num_new_requests;
}

inline int peer_session::join_download()
{
    int num_new_requests = 0;
    auto download = find_shared_download();
    if(download)
    {
        log(log_event::request, log::priority::high,
            "joining piece(%i) download", download->piece_index());
        // it's safe to pass only this instead of SHARED_THIS because we remove
        // our callback from download when we destruct
        download->register_peer(remote_endpoint(), 
            [this, &download = *download](bool is_piece_good, int num_bytes_downloaded)
            { on_piece_hashed(download, is_piece_good, num_bytes_downloaded); },
            [this](const block_info& block) { send_cancel(block); });
        num_new_requests += download->pick_blocks(
            m_outgoing_requests, remote_endpoint(), num_to_request());
        // now we participated in this piece download as well
        m_downloads.emplace_back(download);
    }
    return num_new_requests;
}

inline std::shared_ptr<piece_download> peer_session::find_shared_download()
{
    for(auto& download : m_torrent.downloads())
    {
        if(m_info.available_pieces[download->piece_index()]
           && std::find(m_downloads.begin(), m_downloads.end(), download)
               == m_downloads.end()
           && download->can_request())
        {
            return download;
        }
    }
    return nullptr;
}

inline int peer_session::start_download()
{
    int num_new_requests = 0;
    const auto piece = m_torrent.piece_picker().pick(m_info.available_pieces);

#ifdef TIDE_ENABLE_EXPENSIVE_ASSERTS
    // test whether piece picker returned a unique piece
    const auto& downloads = m_torrent.downloads();
    bool is_duplicate1 = std::find_if(downloads.begin(), downloads.end(),
        [piece](const auto& d) { return d->piece_index() == piece; }) != downloads.end();
    bool is_duplicate2 = std::find_if(m_downloads.begin(), m_downloads.end(),
        [piece](const auto& d) { return d->piece_index() == piece; }) != m_downloads.end();
    bool is_duplicate3 = m_parole_download
        ? m_parole_download->piece_index() == piece : false;
    if(is_duplicate1 || is_duplicate2 || is_duplicate3)
    {
        const auto s = m_torrent.piece_picker().to_string();
        log(log_event::info, log::priority::high,
            "FATAL: piece picker picked reserved piece(%i): %s", piece, s.c_str());
        assert(0 && "piece picker picked a reserved piece");
    }
#endif // TIDE_ENABLE_EXPENSIVE_ASSERTS

    if(piece != piece_picker::invalid_piece)
    {
        auto& info = m_torrent.info();
        // we might need to enter end-game mode
        if(++info.num_pending_pieces + info.num_downloaded_pieces == info.num_pieces)
        {
            info.state[torrent_info::end_game] = true;
            log(log_event::info, log::priority::high, "entered end-game mode");
        }

        log(log_event::request, log::priority::high, "picked piece(%i)", piece);

        auto download = std::make_shared<piece_download>(
            piece, get_piece_length(info, piece));
        // it's safe to pass only this instead of SHARED_THIS because we remove
        // these callbacks from download when we destruct
        download->register_peer(remote_endpoint(), 
            [this, &download = *download](bool is_piece_good, int num_bytes_downloaded)
            { on_piece_hashed(download, is_piece_good, num_bytes_downloaded); },
            [this](const block_info& block) { send_cancel(block); });
        num_new_requests += download->pick_blocks(
            m_outgoing_requests, remote_endpoint(), num_to_request());

        // add download to shared database so other peer_sessions may join
        m_torrent.downloads().emplace_back(download);
        m_downloads.emplace_back(download);
    }
    return num_new_requests;
}

inline int peer_session::num_to_request() const noexcept
{
    return std::max(m_info.best_request_queue_size - int(m_outgoing_requests.size()), 0);
}

inline void peer_session::abort_outgoing_requests()
{
    std::error_code ec;
    m_request_timeout_timer.cancel(ec);

    auto& torrent_info = m_torrent.info();
    piece_download* download = nullptr;
    // tell each download that we won't get our requested blocks
    for(const pending_block& block : m_outgoing_requests)
    {
        // it is likely that most of these requests belong to one piece download, so 
        // cache it as much as possible
        if(!download || (download->piece_index() != block.index))
        {
            download = &find_download(block.index);
        }
        download->abort_request(remote_endpoint(), block);
        --torrent_info.num_pending_blocks;
        log(log_event::request,
            "aborting outgoing request for block (piece: %i, offset: %i, length: %i)",
            block.index, block.offset, block.length);
    }
    m_info.num_outstanding_bytes = 0;
    m_torrent.info().num_outstanding_bytes = 0;
    m_outgoing_requests.clear();
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

    log(log_event::timeout, log::priority::high,
        "peer has timed out after %lis (requests: %i)",
        to_int<seconds>(cached_clock::now() - m_info.last_outgoing_request_time),
        m_outgoing_requests.size());

    m_info.best_request_queue_size = 1;
    m_info.has_peer_timed_out = true;
    ++m_info.num_timed_out_requests;
    ++m_torrent.info().num_timed_out_requests;

    if(++m_info.num_consecutive_timeouts > 50)
    {
        disconnect(make_error_code(peer_session_errc::request_timeout));
        return;
    }

    if(m_outgoing_requests.empty()) log(log_event::timeout,
        log::priority::high, "request queue is empty o.O");

    auto request = find_request_to_time_out();
    if(request != m_outgoing_requests.end())
    {
        piece_download& download = find_download(request->index);
        if(download.time_out_request(*request))
        {
            request->has_timed_out = true;
            log(log_event::timeout, log::priority::high,
                "timing out block (piece: %i, offset: %i, length: %i, elapsed: %lis)",
                request->index, request->offset, request->length,
                to_int<seconds>(cached_clock::now() - request->request_time));
        }
        else
        {
            log(log_event::timeout, log::priority::high,
                "%i blocks left in piece, NOT timing out block"
                " (piece: %i, offset: %i, length: %i, elapsed: %lis, avg rtt: %lims)",
                download.num_blocks_left(),
                request->index, request->offset, request->length,
                to_int<seconds>(cached_clock::now() - request->request_time),
                download.average_request_rtt().count());
        }
    }
    else
    {
        log(log_event::timeout, "couldn't find block to time out from %i requests",
            m_outgoing_requests.size());
    }

    if(can_make_requests())
        make_requests();
    else if(!m_outgoing_requests.empty())
        start_timer(m_request_timeout_timer, calculate_request_timeout(),
            [SHARED_THIS](const std::error_code& error) { on_request_timeout(error); });
}

inline
std::vector<pending_block>::iterator peer_session::find_request_to_time_out() noexcept
{
    for(int i = m_outgoing_requests.size() - 1; i >= 0; --i)
    {
        const auto& r = m_outgoing_requests[i];
        // only time out a block if it hasn't been timed out before and its piece can be
        // downloaded from more than a single peer
        if(!r.has_timed_out && (m_torrent.piece_picker().frequency(r.index) > 1))
        {
            return m_outgoing_requests.begin() + i;
        }
    }
    return m_outgoing_requests.end();
}

seconds peer_session::calculate_request_timeout() const
{
    // m_avg_request_rtt is in milliseconds
    int t = m_avg_request_rtt.mean() + 4 * m_avg_request_rtt.deviation();
    // to avoid being timing out peer instantly, timeouts should never be less than two
    // seconds
    t = std::max(2, t / 1000);
    log(log_event::request, "request timeout: %is", t);
    return seconds(t);
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
        const auto elapsed = to_int<seconds>(
            cached_clock::now() - m_info.connection_started_time);
        assert(elapsed > 0);
        log(log_event::timeout, "connecting timed out, elapsed time: %is", elapsed);
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
    if(cached_clock::now() - m_info.last_send_time > seconds(120)) { send_keep_alive(); }
    start_timer(m_keep_alive_timer, m_settings.peer_timeout,
        [SHARED_THIS](const std::error_code& error) { on_keep_alive_timeout(error); });
}

// -----------
// -- utils --
// -----------

void peer_session::generate_allowed_fast_set()
{
    const torrent_info& info = m_torrent.info();
    const int n = std::min(info.num_pieces,
        m_settings.allowed_fast_set_size);
    m_outgoing_allowed_set.reserve(n);
    std::string x(24, 0);
    const address& ip = remote_endpoint().address();
    // TODO ipv4 ipv6 branching
    endian::write<uint32_t>(0xff'ff'ff'00 & ip.to_v4().to_ulong(), &x[0]);
    std::copy(info.info_hash.begin(), info.info_hash.end(), x.begin() + 4);
    while(m_outgoing_allowed_set.size() < n)
    {
        const sha1_hash hash = create_sha1_digest(x);
        x.assign(hash.begin(), hash.end());
        for(auto i = 0; (i < 5) && (m_outgoing_allowed_set.size() < n); ++i)
        {
            const uint32_t index = endian::parse<uint32_t>(x.data() + (4 * i))
                % info.num_pieces;
            if(m_outgoing_allowed_set.end() == std::find(
                m_outgoing_allowed_set.begin(), m_outgoing_allowed_set.end(), index))
            {
                m_outgoing_allowed_set.push_back(index);
            }
        }
    }
}

template<typename... Args>
void peer_session::log(const log_event event, const char* format, Args&&... args) const
{
    log(event, log::priority::normal, format, std::forward<Args>(args)...);
}

template<typename... Args>
void peer_session::log(const log_event event, const log::priority priority,
    const char* format, Args&&... args) const
{
#ifdef TIDE_ENABLE_LOGGING
    std::stringstream header;
    if(is_connected() || is_disconnecting())
    {
        header << '+';
        header << to_int<seconds>(
            cached_clock::now() - m_info.connection_established_time);
        header << "s|";
    }
    switch(event)
    {
    case log_event::connecting: header << "CONNECTING"; break;
    case log_event::disconnecting: header << "DISCONNECTING"; break;
    case log_event::incoming: header << "IN"; break;
    case log_event::outgoing: header << "OUT"; break;
    case log_event::disk: header << "DISK"; break;
    case log_event::invalid_message: header << "INVALID MESSAGE"; break;
    case log_event::parole: header << "PAROLE"; break;
    case log_event::timeout: header << "TIMEOUT"; break;
    case log_event::request: header << "REQUEST"; break;
    case log_event::info: header << "INFO"; break;
    }
    // we're not attached to any torrent yet
    const torrent_id_t torrent = m_torrent ? m_torrent.info().id : -1;
    log::log_peer_session(torrent, remote_endpoint(), header.str(),
        util::format(format, std::forward<Args>(args)...), priority);
#endif // TIDE_ENABLE_LOGGING
}

inline piece_download& peer_session::find_download(const piece_index_t piece) noexcept
{
    auto it = std::find_if(m_downloads.begin(), m_downloads.end(),
        [piece](const auto& download) { return download->piece_index() == piece; });
    // if we didn't find download among m_downloads, we must be on parole and this must
    // be the parole download, however, m_parole_download must be valid at this point
    if(it == m_downloads.end())
    {
        // FIXME this fired
        log(log_event::info, "piece(%i) not found in m_downloads");
        assert(m_parole_download);
        assert(m_parole_download->piece_index() == piece);
        return *m_parole_download;
    }
    assert(it->get());
    return **it;
}

void peer_session::try_identify_client()
{
    // https://wiki.theory.org/BitTorrentSpecification#peer_id
    m_info.client = [this]
    {
        if(m_info.peer_id[0] == '-')
        {
            // Azureus-style encoding
            const auto matches = [this](const char* signature) -> bool
            {
                return m_info.peer_id[1] == signature[0]
                    && m_info.peer_id[2] == signature[1];
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
                return m_info.peer_id[1 + 2 + 6] == '-' ? "BitCometLite" : "BitBlinder";
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
 * Produces a block_info object by parsing the supplied byte sequence. Bytes must be a
 * container of byte types (std::vector<uint8_t>, std::array<uint8_t>, view<uint8_t>...)
 * and be at least 12 bytes long.
 */
template<typename Bytes>
block_info parse_block_info(const Bytes& data)
{
    assert(data.size() >= 3 * 4);

    auto it = data.cbegin();
    const auto end = data.cend();
    const piece_index_t index = endian::parse<piece_index_t>(it);
    const int offset = endian::parse<int>(it += 4);

    if(data.size() == 3 * 4)
    {
        // it's a request/cancel message with fixed message length
        return block_info(index, offset, endian::parse<int32_t>(it += 4));
    }
    else
    {
        // it's a block message, we get the block's length by subtracting the index and
        // offset fields' added length from the total message length
        return block_info(index, offset, data.size() - 2 * 4);
    }
}

#undef SHARED_THIS

} // namespace tide
