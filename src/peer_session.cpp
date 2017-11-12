#include "rate_limiter.hpp"
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

// Peer_session needs to be kept alive until all async ops complete, so we bind a
// shared_ptr to peer_session to each async op's handler along with `this`.
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
    peer_session& session_;
    bool should_uncork_ = false;

public:

    explicit send_cork(peer_session& p) : session_(p)
    {
        if(!session_.op_state_[op::send])
        {
            // Block other send operations by pretending to be sending.
            session_.op_state_.set(op::send);
            should_uncork_ = true;
        }
    }

    ~send_cork()
    {
        if(should_uncork_)
        {
            session_.op_state_.unset(op::send);
            if(!session_.is_stopped()) { session_.send(); }
        }
    }
};

peer_session::peer_session(
    asio::io_service& ios,
    tcp::endpoint peer_endpoint,
    torrent_rate_limiter& rate_limiter,
    const peer_session_settings& settings
)
    : socket_(std::make_unique<tcp::socket>(ios))
    , rate_limiter_(rate_limiter)
    , settings_(settings)
    , connect_timeout_timer_(ios)
    , keep_alive_timer_(ios)
    , request_timeout_timer_(ios)
    , inactivity_timeout_timer_(ios)
{
    // We must be able to receive at least one full block.
    assert(settings_.max_receive_buffer_size >= 0x4000);
    assert(settings_.max_send_buffer_size >= 0x4000);
    assert(settings_.peer_connect_timeout > seconds(0));
    assert(settings_.peer_timeout > seconds(0));

    info_.remote_endpoint = std::move(peer_endpoint);
    info_.max_outgoing_request_queue_size = settings.max_outgoing_request_queue_size;
    op_state_.set(op::slow_start);
}

peer_session::peer_session(
    asio::io_service& ios,
    tcp::endpoint peer_endpoint,
    torrent_rate_limiter& rate_limiter,
    const peer_session_settings& settings,
    torrent_frontend torrent
)
    : peer_session(ios, std::move(peer_endpoint), rate_limiter, settings)
{
    torrent_ = torrent;
    assert(torrent_);

    // Initialize peer's bitfield.
    info_.available_pieces = bitfield(torrent_.info().num_pieces);
    info_.is_outbound = true;
}

peer_session::peer_session(
    asio::io_service& ios,
    tcp::endpoint peer_endpoint,
    torrent_rate_limiter& rate_limiter,
    const peer_session_settings& settings,
    std::function<torrent_frontend(const sha1_hash&)> torrent_attacher
)
    : peer_session(ios, std::move(peer_endpoint), rate_limiter, settings)
{
    torrent_attacher_ = std::move(torrent_attacher);
    info_.is_outbound = false;

    assert(torrent_attacher_);
}

peer_session::~peer_session()
{
    // Note to self: we only need to remove downloads if session is destroyed; if it's
    // just disconnected, it may mean that we want to continue the session later, in
    // which case we want to have previous downloads (that may not have been finished).
    disconnect(peer_session_errc::stopped);
    for(auto& download : downloads_) { download->deregister_peer(remote_endpoint()); }
    // At this point we should have no more pending operations.
    assert(!has_pending_async_op());
}

void peer_session::start()
{
    if(is_disconnected())
    {
        if(!info_.was_started_before)
        {
            if(is_outbound())
                connect();
            else
                on_connected();
            info_.was_started_before = true;
        }
        else
        {
            info_.is_outbound = true;
            connect();
        }
    }
    else if(is_disconnecting() && socket_->is_open())
    {
        // If socket is still open, we can continue the session, but we may need to
        // reinstate the send and receive cycles and deadline timers.
        info_.state = state::connected;
        // If we're not receiving, and not writing to disk (in which case the disk write
        // handler would call receive), we need to resuscitate the receive cycle.
        if(!op_state_[op::receive] && !op_state_[op::disk_write]) { receive(); }
        // TODO verify; I don't think it's enough to check whether socket is open,
        // as it may be still connecting, in which case we can't just continue the
        // session, so stronger guarantees are necessary.
    }
}

void peer_session::stop()
{
    if(!is_stopped())
    {
        // If we don't have async ops, the session is dead, so this shouldn't happen.
        assert(has_pending_async_op());
        info_.state = state::disconnecting;
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
    socket_->open(info_.remote_endpoint.protocol(), ec);
    if(ec)
    {
        // TODO can we disconnect if we haven't even connected?
        disconnect(ec);
        return;
    }

    socket_->async_connect(info_.remote_endpoint,
        [SHARED_THIS](const std::error_code& error) { on_connected(error); });

    info_.state = state::connecting;
    info_.connection_started_time = cached_clock::now();
    if(torrent_) { ++torrent_.info().num_connecting_sessions; }

    start_timer(connect_timeout_timer_, settings_.peer_connect_timeout,
        [SHARED_THIS](const std::error_code& error) { on_connect_timeout(error); });
    log(log_event::connecting, log::priority::low, "started establishing connection");
}

void peer_session::on_connected(const std::error_code& error)
{
    if(torrent_) { --torrent_.info().num_connecting_sessions; }

    if(should_abort(error)) { return; }

    std::error_code ec;
    connect_timeout_timer_.cancel(ec);

    if(error || !socket_->is_open())
    {
        // TODO can we disconnect if we haven't even connected?
        disconnect(error ? error : std::make_error_code(std::errc::bad_file_descriptor));
        return;
    }

    log(log_event::connecting, log::priority::low, "setting non-blocking io mode");
    socket_->non_blocking(true, ec);
    if(ec)
    {
        disconnect(ec);
        return;
    }

    info_.connection_established_time = cached_clock::now();
    log(log_event::connecting, "connected in %lims",
        to_int<milliseconds>(info_.connection_established_time
            - info_.connection_started_time));
    info_.local_endpoint = socket_->local_endpoint(ec);
    if(ec)
    {
        disconnect(ec);
        return;
    }

    info_.state = state::handshaking;
    if(settings_.encryption_policy == peer_session_settings::no_encryption)
    {
        if(info_.is_outbound) { send_handshake(); }
        // Otherwise send_handshake() is called after we've received peer's handshake.
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
    connect_timeout_timer_.cancel(ec);
    request_timeout_timer_.cancel(ec);
    keep_alive_timer_.cancel(ec);
    inactivity_timeout_timer_.cancel(ec);

    // Free any bandwidth quota we may have left for others to use.
    rate_limiter_.add_download_quota(info_.receive_quota);
    rate_limiter_.add_upload_quota(info_.send_quota);
    rate_limiter_.unsubscribe(this);

    abort_outgoing_requests();
    if(parole_download_) { detach_parole_download(); }
    if(torrent_) { torrent_.piece_picker().decrease_frequency(info_.available_pieces); }

    socket_->shutdown(tcp::socket::shutdown_both, ec);
    socket_->close(ec);
    info_.state = state::disconnected;
    log(log_event::disconnecting, "closed socket");
    //TODO are there more outstanding bytes (disk etc) that we need to subtract here?
    //torrent_.info().num_outstanding_bytes -= info_.num_outstanding_bytes;
    if(torrent_) { ++torrent_.info().num_lingering_disconnected_sessions; }

    // If we have some block data in message buffer but are disconnecting,
    // we won't finish downloading it, so tally the wasted bytes.
    if(info_.in_transit_block != invalid_block)
    {
        info_.total_wasted_bytes += message_parser_.size();
        if(torrent_) torrent_.info().total_wasted_bytes += message_parser_.size();
    }

    ////TODO
    //send_buffer_.clear();
    //message_parser_.clear();

    log(log_event::disconnecting, "tore down connection");
    // TODO tell disk_io to stop serving peer's outstanding requests.
}

inline void peer_session::detach_parole_download()
{
    if(parole_download_->num_blocks_left() < parole_download_->blocks().size())
    {
        // We must NOT hold onto this piece because it's reserved in piece picker,
        // meaning no other peer would get it until it's released in the destructor
        // download of this piece has been begun, so we should take the chance and
        // assume peer hasn't sent bad data and put this download in the shared
        // downloads so as not to waste what we already have
        // note that we don't detach this session from the download, that's done in
        // the destructor.
        std::shared_ptr<piece_download> download = std::move(parole_download_);
        // We put this download in our shared_downloads so that we can deregister
        // this peer when the session destructs (we don't do that here as there is
        // a chance the piece has been finished but the verification handler is 
        // invoked only after disconnecting, meaning we can still ban this peer
        // so that we don't connect to it again.
        downloads_.emplace_back(download);
        torrent_.downloads().emplace_back(download);
    }
    else
    {
        // Otherwise we must free this piece from piece picker for other peers to
        // download this piece.
        torrent_.piece_picker().unreserve(parole_download_->piece_index());
        parole_download_.reset();
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
    s.torrent_id = torrent_ ? torrent_.info().id : -1;
    s.peer_id = info_.peer_id;
    s.client = info_.client;
    s.avg_request_rtt = milliseconds(avg_request_rtt_.mean());
    s.upload_rate = info_.upload_rate.rate();
    s.download_rate = info_.download_rate.rate();
    s.peak_upload_rate = info_.upload_rate.peak();
    s.peak_download_rate = info_.download_rate.peak();
    s.used_send_buffer_size = send_buffer_.size();
    s.total_send_buffer_size = send_buffer_.size();
    s.used_receive_buffer_size = message_parser_.size();
    s.total_receive_buffer_size = message_parser_.buffer_size();
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
    // TODO don't copy over string type elements as those have likely not changed.
    static_cast<info&>(s) = info_;
    s.piece_downloads.clear();
    s.piece_downloads.reserve(downloads_.size());
    for(const auto& d : downloads_)
    {
        s.piece_downloads.emplace_back(d->piece_index());
    }
}

bool peer_session::is_extension_enabled(const int extension) const noexcept
{
    return info_.extensions[extension] // Peer's extensions.
        && settings_.extensions[extension]; // Our extensions.
}

void peer_session::choke_peer()
{
    if(!is_connected() || is_peer_choked()) { return; }
    send_choke();
    for(const auto& block : incoming_requests_)
    {
        // TODO we should tell disk_io and other components of this
        // TODO if block is in the allowed fast set, don't reject.
        send_reject_request(block);
    }
    incoming_requests_.clear();
}

void peer_session::unchoke_peer()
{
    if(is_connected() && is_peer_choked())
    {
        send_unchoke();
        info_.upload_rate.clear();
    }
}

void peer_session::suggest_piece(const piece_index_t piece)
{
    if(is_connected()
       && is_extension_enabled(extensions::fast)
       && !info_.available_pieces[piece])
    {
        send_suggest_piece(piece);
    }
}

void peer_session::announce_new_piece(const piece_index_t piece)
{
    // No need to send a have message if we're shutting down, otherwise we're still
    // connecting or handshaking, in which case we'll send our piece availability after
    // this stage is done.
    if(is_connected())
    {
        // Don't send a have msg if peer already has the piece.
        if(!info_.available_pieces[piece]) { send_have(piece); }
        // Send_have() is called by torrent when a new piece is received, so recalculate
        // whether we're interested in this peer, for we may have received the only piece
        // peer has in which we were interested.
        update_interest();
#ifdef TIDE_ENABLE_DEBUGGING
        // If we've become a seeder we shouldn't have any downloads left then
        // (torrent should post hash results first, then announce to peers).
        if(torrent_.piece_picker().has_all_pieces() && !downloads_.empty())
        {
            // FIXME this branch executed (shouldn't).
            std::string s;
            for(const auto& d : downloads_)
            {
                s += util::format("dl(%i|%i/%i|%i)", d->piece_index(),
                    d->num_received_blocks(), d->num_blocks(), d->peers().size()) + " ";
            }
            log(log_event::info, log::priority::high,
                "became seeder but have %i downloads left: %s",
                downloads_.size(), s.c_str());
        }
#endif // TIDE_ENABLE_DEBUGGING
    }
}

void peer_session::update_interest()
{
    const bool was_interested = info_.am_interested;
    const bool am_interested = torrent_
        .piece_picker().am_interested_in(info_.available_pieces);
    if(!was_interested && am_interested)
    {
        info_.am_interested = true;
        std::error_code ec;
        inactivity_timeout_timer_.cancel(ec);
        send_interested();
        if(can_make_requests()) { make_requests(); }
        log(log_event::info, "became interested in peer");
    }
    else if(was_interested && !am_interested)
    {
        info_.am_interested = false;
        send_not_interested();
        // If peer isn't interested either, we enter a state of inactivity, so we must
        // guard against idling too long.
        if(!is_peer_interested())
        {
            start_timer(inactivity_timeout_timer_, minutes(5),
                [SHARED_THIS](const std::error_code& error)
                { on_inactivity_timeout(error); });
        }
        log(log_event::info, "no longer interested in peer (have: %i, has %i pieces)",
            torrent_.piece_picker().num_have_pieces(), info_.available_pieces.count());
    }
    if(torrent_.piece_picker().has_all_pieces() && is_peer_seed())
    {
        disconnect(peer_session_errc::both_seeders);
    }
}

// -------------
// -- sending --
// -------------

void peer_session::send()
{
    request_upload_quota();
    if(!can_send()) { return; }

    const int num_bytes_to_send = std::min(send_buffer_.size(), info_.send_quota);
    assert(num_bytes_to_send > 0);
    socket_->async_write_some(send_buffer_.get_buffers(num_bytes_to_send),
        [SHARED_THIS](const std::error_code& error, size_t num_bytes_sent)
        { on_sent(error, num_bytes_sent); });

    op_state_.set(op::send);

    log(log_event::outgoing, log::priority::low,
        "sending: %i; available: %i; quota: %i",
        num_bytes_to_send, send_buffer_.size(), info_.send_quota);
}

bool peer_session::can_send() const noexcept
{
    if(send_buffer_.empty())
    {
        log(log_event::outgoing, log::priority::low, "CAN'T SEND, buffer empty");
        return false;
    }
    else if(op_state_[op::send])
    {
        log(log_event::outgoing, log::priority::low, "CAN'T SEND, already sending");
        return false;
    }
    else if(info_.send_quota <= 0)
    {
        log(log_event::outgoing, log::priority::low, "CAN'T SEND, no quota left");
        return false;
    }
    return true;
}

void peer_session::request_upload_quota()
{
    info_.send_quota += rate_limiter_.request_upload_quota(send_buffer_.size());
    if(info_.send_quota == 0)
    {
        rate_limiter_.subscribe_for_upload_quota(
            this, send_buffer_.size(), [this](const int quota)
            {
                assert(quota > 0);
                info_.send_quota += quota;
                if(!is_stopped()) { send(); }
            });
    }
}

void peer_session::on_sent(const std::error_code& error, size_t num_bytes_sent)
{
    op_state_.unset(op::send);
    if(is_disconnecting())
    {
        try_finish_disconnecting();
        return;
    }
    else if(should_abort(error))
    {
        // We are aborting, so pending async ops were cancelled.
        return;
    }
    else if(error)
    {
        log(log_event::outgoing, "error while sending");
        disconnect(error);
        return;
    }

    update_send_stats(num_bytes_sent);
    send_buffer_.consume(num_bytes_sent);

    log(log_event::outgoing,
        "sent: %i; quota: %i; send buffer size: %i; total sent: %lli",
        num_bytes_sent, info_.send_quota, send_buffer_.size(),
        info_.total_uploaded_bytes);

    // This call to send() will only write to socket again if during the first write
    // there were more bytes in send buffer to send than we had quota for, and since the
    // first thing in send is asking for more bandwidth quota, we may be able to send
    // off the rest of the send buffer's contents.
    if(!send_buffer_.empty()) { send(); }
}

inline void peer_session::update_send_stats(const int num_bytes_sent) noexcept
{
    info_.send_quota -= num_bytes_sent;
    info_.last_send_time = cached_clock::now();
    info_.total_uploaded_bytes += num_bytes_sent;
    torrent_.info().total_uploaded_bytes += num_bytes_sent;
}

// ---------------
// -- receiving --
// ---------------

void peer_session::receive()
{
    assert(!is_stopped());

    if(op_state_[op::receive])
    {
        log(log_event::incoming, log::priority::low, "CAN'T RECEIVE, already receiving");
        return;
    }

    prepare_to_receive();
    const int num_to_receive = std::min(info_.receive_quota,
        message_parser_.free_space_size());
    if(num_to_receive == 0) { return; }

    view<uint8_t> buffer = message_parser_.get_receive_buffer(num_to_receive);
    socket_->async_read_some(asio::mutable_buffers_1(buffer.data(), buffer.size()),
        [SHARED_THIS](const std::error_code& error, size_t num_bytes_received)
        { on_received(error, num_bytes_received); });

    op_state_.set(op::receive);

    log(log_event::incoming, log::priority::low,
        "receiving: %i; receive buffer free space: %i; quota: %i",
        num_to_receive, message_parser_.free_space_size(), info_.receive_quota);
}

void peer_session::prepare_to_receive()
{
    const int buffer_capacity = receive_buffer_capacity();
    if(am_expecting_block())
    {
        // We're expecting block data, make sure we can accomodate it.
        assert(info_.receive_quota >= 0);
        const int quota_needed =
            std::min(info_.num_outstanding_bytes, buffer_capacity)
            - info_.receive_quota;
        // If we don't have enough quota to receive all expected message bytes, try to
        // request more.
        if(quota_needed > 0)
        {
            const int quota = rate_limiter_.request_download_quota(quota_needed);
            info_.receive_quota += quota;
            log(log_event::incoming, log::priority::low,
                "receive quota:: requested: %i, received: %i, total: %i",
                quota_needed, quota, info_.receive_quota);
        }
        // If we haven't been able to reserve quota, subscribe for more.
        if(info_.receive_quota == 0)
        {
            log(log_event::incoming, log::priority::low,
                "CAN'T RECEIVE, no receive quota, subscribing for more");
            rate_limiter_.subscribe_for_download_quota(
                this, quota_needed, [this](const int quota)
                {
                    assert(quota > 0);
                    info_.receive_quota += quota;
                    if(!is_stopped()) { receive(); }
                });
            return;
        }
        // If we don't have enough space in our buffer to receive all expected message
        // bytes, reserve more buffer space.
        const int space_needed = info_.receive_quota - message_parser_.free_space_size();
        if(space_needed > 0)
        {
            message_parser_.reserve(message_parser_.size() + space_needed);
        }
    }
    else if(message_parser_.is_full())
    {
        // If we don't expect piece payloads (in which case receive operations are
        // constrained by how fast we can write to disk, and resumed once disk writes
        // finished, in on_block_saved), we should always have enough space for protocol
        // chatter (non payload messages), otherwise the async receive cycle would stop,
        // i.e. there'd be no one reregistering the async receive calls.
        message_parser_.reserve(message_parser_.size() + 128);
    }
}

inline int peer_session::receive_buffer_capacity() const
{
    // The maximum number of bytes receive buffer is able to accommodate (with resizing).
    // Pending bytes written to disk are also counted as part of the receive buffer
    // until they are flushed to disk; this is used to throttle the download rate if
    // we're disk bound (so as not to further overwhelm disk).
    int buffer_capacity = settings_.max_receive_buffer_size
        - message_parser_.size() - info_.num_pending_disk_write_bytes;
    if((buffer_capacity <= 0) && (info_.num_pending_disk_read_bytes > 0))
    {
        // If we're stalled on the disk we still allow to receive one block as
        // otherwise downloads would crawl to a halt, and saving a block at a time
        // should not overwhelm disk_io too much.
        buffer_capacity = 0x4000;
        log(log_event::disk, log::priority::high,
            "session disk bound, receive buffer capacity reached, using reserves");
    }
    return buffer_capacity;
}

inline void peer_session::try_finish_disconnecting()
{
    if(!has_pending_async_op())
    {
        // We are gracefully stopping and there are no other pending async ops, so
        // we can shut down now.
        disconnect(peer_session_errc::stopped);
        torrent_.on_peer_session_stopped(*this);
    }
}

void peer_session::on_received(const std::error_code& error, size_t num_bytes_received)
{
    op_state_.unset(op::receive);
    if(is_disconnecting())
    {
        try_finish_disconnecting();
        return;
    }
    else if(should_abort(error))
    {
        // We have been disconnected, so pending async ops were cancelled.
        return;
    }
    else if(error)
    {
        log(log_event::incoming, "error while receiving");
        disconnect(error);
        return;
    }

    assert(num_bytes_received > 0);
    message_parser_.record_received_bytes(num_bytes_received);

    // Send response messages at the end of the function in one batch.
    send_cork _cork(*this);
    const bool was_choked = am_choked();
    // If we completely filled up receive buffer it may mean socket has more data.
    if(message_parser_.is_full())
    {
        // Handle whatever messages we already have before flushing the rest of socket's
        // buffer, to avoid reallocating receive buffer.
        handle_messages();
        // handle_messages() may have spurred a disconnect
        if(is_disconnected()) { return; }
        num_bytes_received += flush_socket();
    }
    update_receive_stats(num_bytes_received);
    log(log_event::incoming,
        "received: %i; receive buffer size: %i; quota: %i; total received: %lli",
        num_bytes_received, message_parser_.buffer_size(), info_.receive_quota,
        info_.total_downloaded_bytes);
    // flush_socket() may have spurred a disconnect.
    if(is_disconnected()) { return; }
    handle_messages();
    // handle_messages() may have spurred a disconnect
    if(is_disconnected()) { return; }

    adjust_receive_buffer(was_choked, num_bytes_received);
    receive();
}

inline int peer_session::flush_socket()
{
    assert(message_parser_.is_full());
    // We may not have read all of the available bytes buffered in socket:
    // try sync read remaining bytes.
    std::error_code ec;
    const auto num_available_bytes = socket_->available(ec);
    if(ec)
    {
        disconnect(ec);
    }
    else if(num_available_bytes > 0)
    {
        view<uint8_t> buffer = message_parser_.get_receive_buffer(num_available_bytes);
        const auto num_bytes_read = socket_->read_some(
            asio::mutable_buffers_1(buffer.data(), buffer.size()), ec);
        if((ec == asio::error::would_block) || (ec == asio::error::try_again))
        {
            // This is not an error, just ignore.
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
            message_parser_.record_received_bytes(num_bytes_read);
            return num_bytes_read;
        }
    }
    return 0;
}

inline void peer_session::update_receive_stats(const int num_bytes_received) noexcept
{
    info_.receive_quota -= num_bytes_received;
    info_.last_receive_time = cached_clock::now();
    info_.total_downloaded_bytes += num_bytes_received;
    torrent_.info().total_downloaded_bytes += num_bytes_received;
}

inline void peer_session::adjust_receive_buffer(
    const bool was_choked, const size_t num_bytes_received)
{
    const int old_buffer_size = message_parser_.buffer_size();
        if(old_buffer_size != message_parser_.buffer_size())
            log(log_event::incoming, log::priority::low,
                "grew receive buffer from %i to %i",
                old_buffer_size, message_parser_.buffer_size());
    /* this is experimental
    if(!am_choked()
       && (float(num_bytes_received) < message_parser_.buffer_size() * 0.10f
           && info_.num_outstanding_bytes < message_parser_.buffer_size()))
    {
        // We're not choked but we received so little and we're not expecting to
        // receive a lot of data, so decrease buffer size.
        // TODO verify that we're not too agressively shrinkign buffer here
        message_parser_.shrink_to_fit(info_.num_outstanding_bytes);
    }
    else */if(!was_choked && am_choked() && old_buffer_size > 1024)
    {
        // If we went from unchoked to choked (and if buffer is large enough, otherwise
        // don't bother), 100 bytes should suffice to receive further protocol chatter
        // (if we have unfinished messages in receive buffer it will not shrink below
        // the last valid message byte).
        message_parser_.shrink_to_fit(128);
        log(log_event::incoming, log::priority::low,
            "shrunk receive buffer from %i to %i",
            old_buffer_size, message_parser_.buffer_size());
    }
}

inline bool peer_session::am_expecting_block() const noexcept
{
    return (info_.num_outstanding_bytes > 0) && !am_choked();
}

// ----------------------
// -- message handling --
// ----------------------

inline void peer_session::handle_messages()
{
    if(info_.state == state::handshaking)
    {
        if(message_parser_.has_handshake())
        {
            handle_handshake();
            if(is_disconnected()) { return; }
            send_piece_availability();
        }
        else
        {
            // Otherwise we don't have the full handshake yet, so receive more bytes and
            // come back later to try again.
            return;
        }
    }
    // Fallthrough.
    if(info_.state == state::piece_availability_exchange
       && message_parser_.has_message())
    {
        if(message_parser_.type() == message::bitfield)
        {
            handle_bitfield();
            if(is_disconnected()) { return; }
        }
        else if(is_extension_enabled(extensions::fast))
        {
            // If the fast extension is set, peer MUST send a piece availability
            // related message after the handshake; otherwise this is optional.
            if(message_parser_.type() == message::have_all)
                handle_have_all();
            else if(message_parser_.type() == message::have_none)
                handle_have_none();
            else
                disconnect(peer_session_errc::no_piece_availability_message);
            if(is_disconnected()) { return; }
        }
        info_.state = state::connected;
    }
    // Fallthrough.
    while(!is_disconnected()
          && message_parser_.has_message()
          && send_buffer_.size() <= settings_.max_send_buffer_size)
    {
#define NOT_AFTER_HANDSHAKE(str) do { \
    log(log_event::invalid_message, str " not after handshake"); \
    disconnect(peer_session_errc::bitfield_not_after_handshake); } while(0)
        switch(message_parser_.type()) {
        // -- standard BitTorrent messages --
        // Bitfield messages may only be sent after the handshake.
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
        // Like bitfield, these messages may only be exchanged after the handshake.
        case message::have_all: NOT_AFTER_HANDSHAKE("HAVE ALL"); break;
        case message::have_none: NOT_AFTER_HANDSHAKE("HAVE NONE"); break;
        case message::reject_request: handle_reject_request(); break;
        case message::allowed_fast: handle_allowed_fast(); break;
        default: handle_unknown_message();
        }
#undef NOT_AFTER_HANDSHAKE
    }
    message_parser_.optimize_receive_space();
    if(info_.num_outstanding_bytes > 0) { probe_in_transit_block(); }
}

inline void peer_session::probe_in_transit_block() noexcept 
{
    // Now check if the next message we're expecting and have not fully received is
    // a block, and if so, record it.
    const_view<uint8_t> bytes = message_parser_.view_raw_bytes();
    if(bytes.length() >= 5)
    {
        const int type = bytes[4];
        if((type == message::block) && (bytes.length() >= 17))
        {
            // Trim off the first 5 bytes (msg_len(4) + msg_type(1)).
            info_.in_transit_block = parse_block_info(bytes.subview(5));
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
        handshake = message_parser_.extract_handshake();
    }
    catch(const std::runtime_error& error)
    {
        log(log_event::invalid_message, "couldn't parse HANDSHAKE");
        disconnect(peer_session_errc::invalid_handshake);
        return;
    }

    sha1_hash peer_info_hash;
    std::copy(handshake.info_hash.cbegin(),
        handshake.info_hash.cend(), peer_info_hash.begin());
    if(info_.is_outbound)
    {
        // We started the connection, so we already sent our handshake,
        // so just verify peer's info_hash.
        if(peer_info_hash != torrent_.info().info_hash)
        {
            disconnect(peer_session_errc::invalid_info_hash);
            return;
        }
    }
    else
    {
        torrent_frontend torrent = torrent_attacher_(peer_info_hash);
        torrent_attacher_ = decltype(torrent_attacher_)(); // no longer need it
        if(!torrent)
        {
            // This means we couldn't find a torrent to which we could be attached,
            // likely due to peer's bad info_hash.
            disconnect(peer_session_errc::invalid_info_hash);
            return;
        }
        // Initialize peer's bitfield now that we know the number of pieces this
        // torrent has.
        info_.available_pieces = bitfield(torrent_.info().num_pieces);
        // The connection was initiated by peer, we still need to send our handshake.
        send_handshake();
    }
    info_.extensions.assign(endian::parse<uint64_t>(handshake.reserved.cbegin()));
    std::copy(handshake.peer_id.cbegin(),
        handshake.peer_id.cend(), info_.peer_id.begin());
    try_identify_client();

    // BitComet clients have been observed to drop requests if we have more than
    // 50 outstanding outgoing requests, so cap this.
    if((info_.client == "BitComet") && (info_.max_outgoing_request_queue_size > 50))
    {
        info_.max_outgoing_request_queue_size = 50;
    }

#ifdef TIDE_ENABLE_LOGGING
    const auto extensions_str = extensions::to_string(info_.extensions);
    if(info_.client.empty())
    {
        log(log_event::incoming, log::priority::high,
            "HANDSHAKE (protocol: %s; extensions: %s; client_id: %s)",
            handshake.protocol.data(), extensions_str.c_str(), info_.peer_id.data());
    }
    else
    {
        log(log_event::incoming, log::priority::high,
            "HANDSHAKE (protocol: %s; extensions: %s; client_id: %s; client: %s)",
            handshake.protocol.data(), extensions_str.c_str(), info_.peer_id.data(),
            info_.client.c_str());
    }
#endif // TIDE_ENABLE_LOGGING

    // Only keep connection alive if connection was properly set up to begin with.
    start_timer(keep_alive_timer_, settings_.peer_timeout,
        [SHARED_THIS](const std::error_code& error) { on_keep_alive_timeout(error); });
}

// ----------------------------------
// BITFIELD <len=1+X><id=5><bitfield>
// ----------------------------------
inline void peer_session::handle_bitfield()
{
    assert(info_.state == state::piece_availability_exchange);

    message msg = message_parser_.extract_message();
    const int num_pieces = torrent_.info().num_pieces;
    if(!bitfield::is_bitfield_data_valid(msg.data, num_pieces))
    {
        // Peer sent an invalid bitfield, disconnect immediately.
        disconnect(peer_session_errc::invalid_bitfield_message);
        return;
    }

    info_.available_pieces = bitfield(msg.data, num_pieces);
    info_.is_peer_seed = info_.available_pieces.are_all_set();

    log(log_event::incoming, "BITFIELD (%s:%i)",
        is_peer_seed() ? "seed" : "leech",
        info_.available_pieces.count());

    // Check if we're interested in peer now that we know its piece availability.
    update_interest();
}

// ------------------
// KEEP-ALIVE <len=0>
// ------------------
inline void peer_session::handle_keep_alive()
{
    message_parser_.skip_message();
    log(log_event::incoming, "KEEP_ALIVE");
    if(!is_peer_choked() && is_peer_interested())
    {
        // Peer is unchoked and interested but it's not sending us requests so our
        // unchoke message may not have gotten through, send it again.
        send_unchoke();
    }
}

// -------------
// CHOKE <len=1>
// -------------
inline void peer_session::handle_choke()
{
    log(log_event::incoming, "CHOKE");
    if(message_parser_.extract_message().data.size() != 0)
    {
        log(log_event::invalid_message, "wrong CHOKE message length");
        disconnect(peer_session_errc::invalid_choke_message);
        return;
    }
    if(!am_choked())
    {
        info_.am_choked = true;
        op_state_.unset(op::slow_start);
        // The Fast extension modifies the choke semantics in that a choke message no
        // longer implicitly rejects requests, this is done explicitly.
        if(!is_extension_enabled(extensions::fast)) { abort_outgoing_requests(); }
    }
    info_.last_incoming_choke_time = cached_clock::now();
}

// ---------------
// UNCHOKE <len=1>
// ---------------
inline void peer_session::handle_unchoke()
{
    log(log_event::incoming, "UNCHOKE");
    if(message_parser_.extract_message().data.size() != 0)
    {
        log(log_event::invalid_message, "wrong UNCHOKE message length");
        disconnect(peer_session_errc::invalid_unchoke_message);
        return;
    }
    if(info_.am_choked)
    {
        // Reset these values so that they aren't biased towards earlier values
        // TODO needs more consideration.
        info_.per_second_downloaded_bytes.clear();
        info_.download_rate.clear();
        info_.am_choked = false;
    }
    info_.last_incoming_unchoke_time = cached_clock::now();
    if(can_make_requests()) { make_requests(); }
}

// ------------------
// INTERESTED <len=1>
// ------------------
inline void peer_session::handle_interested()
{
    log(log_event::incoming, "INTERESTED");
    if(message_parser_.extract_message().data.size() != 0)
    {
        log(log_event::invalid_message, "wrong INTERESTED message length");
        disconnect(peer_session_errc::invalid_interested_message);
        return;
    }
    if(!is_peer_interested())
    {
        info_.is_peer_interested = true;
        std::error_code ec;
        inactivity_timeout_timer_.cancel(ec);
    }
    info_.last_incoming_interest_time = cached_clock::now();
}

// ----------------------
// NOT INTERESTED <len=1>
// ----------------------
inline void peer_session::handle_not_interested()
{
    log(log_event::incoming, "NOT_INTERESTED");
    if(message_parser_.extract_message().data.size() != 0)
    {
        log(log_event::invalid_message, "wrong NOT_INTERESTED message length");
        disconnect(peer_session_errc::invalid_not_interested_message);
        return;
    }
    if(is_peer_interested())
    {
        info_.is_peer_interested = false;
        if(!info_.am_interested)
        {
            // We aren't interested either, so we enter a state of inactivity, so we must
            // guard against idling too long.
            start_timer(inactivity_timeout_timer_, minutes(10),
                [SHARED_THIS](const std::error_code& error)
                { on_inactivity_timeout(error); });
        }
    }
    info_.last_incoming_uninterest_time = cached_clock::now();
}

inline void peer_session::handle_have()
{
    message msg = message_parser_.extract_message();
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
    // Redundant have message (return so as not to falsely increase piece's frequency).
    if(info_.available_pieces[piece]) { return; }

    torrent_.piece_picker().increase_frequency(piece);
    info_.available_pieces.set(piece);
    // Only need to recalculate if we're not interested.
    if(!info_.am_interested) { update_interest(); }
}

// ---------------------------------------------
// REQUEST <len=13><id=6><index><offset><length>
// ---------------------------------------------
inline void peer_session::handle_request()
{
    message msg = message_parser_.extract_message();
    if(msg.data.size() != 3 * 4)
    {
        log(log_event::invalid_message, "wrong REQUEST message length");
        disconnect(peer_session_errc::invalid_request_message);
        return;
    }

    if(!is_peer_interested())
    {
        // Peer is not choked but according to our data it is not interested either, so
        // pretend that we got an interested message as peer's may have gotten lost.
        info_.is_peer_interested = true;
        info_.last_incoming_interest_time = cached_clock::now();
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

    // If block is in the allowed fast set, we can serve this request.
    if(is_peer_choked()
       && (!is_extension_enabled(extensions::fast)
           || std::find(outgoing_allowed_set_.begin(), outgoing_allowed_set_.end(),
                   block_info.index) == outgoing_allowed_set_.end()))
    {
        handle_illicit_request(block_info);
        return;
    }

    log(log_event::incoming, log::priority::high,
        "REQUEST (piece: %i, offset: %i, length: %i)",
        block_info.index, block_info.offset, block_info.length);

    if(should_accept_request(block_info))
    {
        // At this point we can serve the request
        // TODO don't issue request to disk if it's overwhelmed.
        info_.last_incoming_request_time = cached_clock::now();
        incoming_requests_.emplace_back(block_info);

        torrent_.fetch_block(block_info,
            [SHARED_THIS](const std::error_code& error, block_source block)
            { on_block_fetched(error, block); });

        op_state_.set(op::disk_read);
        info_.num_pending_disk_read_bytes += block_info.length;
        torrent_.info().num_pending_disk_read_bytes += block_info.length;

        log(log_event::disk, log::priority::high,
            "disk read launched, serving request (piece: %i, offset: %i, length: %i)",
            block_info.index, block_info.offset, block_info.length);
    }
}

inline bool peer_session::should_accept_request(const block_info& block) const noexcept
{
    // TODO check if max block size is still enforced
    // don't serve request if peer reached its max allowed outstanding requests or
    // if the requested block is larger than 16KiB.
    return incoming_requests_.size() < settings_.max_incoming_request_queue_size
        || block.length <= 0x4000;
}

// --------------------------------------------
// CANCEL <len=13><id=8><index><offset><length>
// --------------------------------------------
inline void peer_session::handle_cancel()
{
    message msg = message_parser_.extract_message();
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

    auto request = std::find(incoming_requests_.begin(),
        incoming_requests_.end(), block_info);
    if(request != incoming_requests_.cend())
    {
        // TODO we likely launched a disk read for this block, so cancel it.
        incoming_requests_.erase(request);
        log(log_event::disk, "disk abort launched, cancelling request");
        if(is_extension_enabled(extensions::fast)) { send_reject_request(block_info); }
    }
}

inline bool peer_session::is_request_valid(const block_info& request) const noexcept
{
    return is_block_info_valid(request)
        && torrent_.piece_picker().my_bitfield()[request.index];
}

// ------------------------------------------
// BLOCK <len=9+X><id=7><index><offset><data>
// ------------------------------------------
void peer_session::handle_block()
{
    std::error_code _ec;
    request_timeout_timer_.cancel(_ec);
    info_.num_consecutive_timeouts = 0;

    message msg = message_parser_.extract_message();
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

    auto request = std::find(outgoing_requests_.begin(),
        outgoing_requests_.end(), block_info);
    if(request == outgoing_requests_.cend())
    {
        handle_illicit_block(block_info);
        return;
    }

    if(block_info.length == 0)
    {
        // BitComet has been observed to use 0 length blocks to reject requests.
        handle_rejected_request(request);
        return;
    }

    // Erase request from queue as we either got it or no longer expect it
    // (handle_reject_request also erases it so no need to do this after invoking it).
    outgoing_requests_.erase(request);

    // NOTE: we must upload stats before adjusting request timeout and request queue
    // size as we adjust request timeout based on stats.
    update_download_stats(block_info.length);
    adjust_request_timeout();
    adjust_best_request_queue_size();
    info_.in_transit_block = invalid_block;

    if(torrent_.piece_picker().my_bitfield()[block_info.index])
    {
        // We already have this piece.
        log(log_event::incoming, "received block for piece we already have");
        info_.total_wasted_bytes += block_info.length;
        torrent_.info().total_wasted_bytes += block_info.length;
    }
    else
    {
        // We MUST have download, because at this point block is deemed valid, which
        // means its request entry in outgoing_requests_ was found, meaning we expect
        // this block, so its corresponding download instance must also be present.
        piece_download& download = find_download(block_info.index);
        download.got_block(remote_endpoint(), block_info);
        disk_buffer block = torrent_.get_disk_buffer(block_info.length);
        assert(block);
        // Exclude the block header (index and offset, both 4 bytes).
        std::copy(msg.data.begin() + 8, msg.data.end(), block.data());
        save_block(block_info, std::move(block), download);
    }

    if(can_make_requests())
        make_requests();
    else if(!outgoing_requests_.empty())
        start_timer(request_timeout_timer_, calculate_request_timeout(),
            [SHARED_THIS](const std::error_code& error) { on_request_timeout(error); });
}

inline void peer_session::update_download_stats(const int num_bytes)
{
    info_.last_incoming_block_time = cached_clock::now();
    info_.num_outstanding_bytes -= num_bytes;
    info_.total_downloaded_piece_bytes += num_bytes;
    info_.download_rate.update(num_bytes);
    info_.per_second_downloaded_bytes.update(num_bytes);
    torrent_.info().num_outstanding_bytes -= num_bytes;
    torrent_.info().total_downloaded_piece_bytes += num_bytes;
    torrent_.info().download_rate.update(num_bytes);
    num_downloaded_piece_bytes_ += num_bytes;
}

inline void peer_session::adjust_request_timeout() // TODO rename
{
    const auto request_rtt = cached_clock::now() - info_.last_outgoing_request_time;
    avg_request_rtt_.update(to_int<milliseconds>(request_rtt));
    log(log_event::request, log::priority::high, "request rtt: %lims",
        to_int<milliseconds>(request_rtt));

    const auto timeout = calculate_request_timeout();
    if((request_rtt < timeout) && info_.has_peer_timed_out)
    {
        // Peer has timed out before but managed to deliver this time.
        info_.has_peer_timed_out = false;
    }
    else if(request_rtt >= timeout)
    {
        info_.has_peer_timed_out = true;
    }
}

inline void peer_session::adjust_best_request_queue_size() noexcept
{
    if(info_.has_peer_timed_out)
    {
        info_.best_request_queue_size = 1;
        op_state_[op::slow_start] = false;
        return;
    }

    // Only adjust request queue size if at least a second has passed.
    const auto now = cached_clock::now();
    if(now - info_.last_request_queue_adjust_time < seconds(1)) { return; }
    info_.last_request_queue_adjust_time = now;

    const int old_best_request_queue_size = info_.best_request_queue_size;
    const int num_downloaded = info_.per_second_downloaded_bytes.value();
    const int deviation = info_.per_second_downloaded_bytes.deviation();

    log(log_event::request, log::priority::high,
        "downloaded this second: %i b (deviation: %i b)", num_downloaded, deviation);

    if(op_state_[op::slow_start])
    {
        // If our download rate is not increasing significantly anymore, exit slow start.
        if(deviation < 5000)
        {
            log(log_event::request, log::priority::high,
                "leaving slow start (per second deviation: %i b)", deviation);
            op_state_[op::slow_start] = false;
            return;
        }
        ++info_.best_request_queue_size;
    }
    else
    {
        // TODO figure out good formula, this is just a placeholder.
        info_.best_request_queue_size = (num_downloaded + (0x4000 - 1)) / 0x4000;
    }

    if(info_.best_request_queue_size > info_.max_outgoing_request_queue_size)
    {
        info_.best_request_queue_size = info_.max_outgoing_request_queue_size;
    }
    else if(info_.best_request_queue_size < settings_.min_outgoing_request_queue_size)
    {
        info_.best_request_queue_size = settings_.min_outgoing_request_queue_size;
    }

    if(info_.best_request_queue_size != old_best_request_queue_size)
    {
        log(log_event::request, log::priority::high,
            "best request queue size changed from %i to %i",
            old_best_request_queue_size, info_.best_request_queue_size);
    }
}

inline bool peer_session::is_block_info_valid(const block_info& block) const noexcept
{
    const int piece_length = get_piece_length(torrent_.info(), block.index);
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
    return (index >= 0) && (index < torrent_.info().num_pieces);
}

inline void peer_session::handle_illicit_request(const block_info& block)
{
    ++info_.num_illicit_requests;
    log(log_event::incoming, "%i illicit requests", info_.num_illicit_requests);

    // Don't mind request messages (though don't serve them) up to 2 seconds after
    // choking peer, to give it some slack.
    if(cached_clock::now() - seconds(2) <= info_.last_outgoing_choke_time) { return; }

    if((info_.num_illicit_requests % 10 == 0) && is_peer_choked())
    {
        // Every now and then remind peer that it is choked.
        send_choke();
    }
    else if(info_.num_illicit_requests > 300)
    {
        // Don't tolerate this forever.
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

    message msg = message_parser_.extract_message();
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

    if(!torrent_.piece_picker().my_bitfield()[piece])
    {
        // TODO check if we're alreayd downloading this piece from other peers
        // then decide whether we want to download this piece from peer.
    }
}

// -----------------------
// HAVE ALL <len=1><id=14>
// -----------------------
inline void peer_session::handle_have_all()
{
    assert(info_.state == state::piece_availability_exchange);

    if(!is_extension_enabled(extensions::fast))
    {
        log(log_event::invalid_message, "HAVE ALL message not supported");
        disconnect(peer_session_errc::unsupported_extension);
        return;
    }

    if(message_parser_.extract_message().data.size() != 0)
    {
        log(log_event::invalid_message, "wrong HAVE ALL message length");
        disconnect(peer_session_errc::invalid_have_all_message);
        return;
    }

    assert(info_.available_pieces.size() == torrent_.info().num_pieces);
    info_.available_pieces.fill();
    info_.is_peer_seed = true;

    log(log_event::incoming, "HAVE ALL");

    // Check if we're interested in peer now that we know its piece availability.
    update_interest();
}

// ------------------------
// HAVE NONE <len=1><id=15>
// ------------------------
inline void peer_session::handle_have_none()
{
    assert(info_.state == state::piece_availability_exchange);

    if(!is_extension_enabled(extensions::fast))
    {
        log(log_event::invalid_message, "HAVE NONE message not supported");
        disconnect(peer_session_errc::unsupported_extension);
        return;
    }

    if(message_parser_.extract_message().data.size() != 0)
    {
        log(log_event::invalid_message, "wrong HAVE NONE message length");
        disconnect(peer_session_errc::invalid_have_all_message);
        return;
    }

    assert(info_.available_pieces.size() == torrent_.info().num_pieces);
    info_.available_pieces.clear();
    info_.is_peer_seed = false;
    // We don't need to update interest as peer has no pieces and a connection starts
    // out as not interested, so.

    log(log_event::incoming, "HAVE NONE");
}

// -----------------------------------------------------
// REJECT REQUEST <len=13><id=16><index><offset><length>
// -----------------------------------------------------
inline void peer_session::handle_reject_request()
{
    message msg = message_parser_.extract_message();

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

    handle_rejected_request(std::find(outgoing_requests_.begin(),
        outgoing_requests_.end(), block_info));
}

inline void peer_session::handle_rejected_request(
    std::vector<pending_block>::iterator request)
{
    log(log_event::incoming, log::priority::high,
        "REJECT REQUEST (piece: %i, offset: %i, length: %i)",
        request->index, request->offset, request->length);
    if(request != outgoing_requests_.end())
    {
        // Find_download must not trigger the assertion as request is only valid as long
        // as no peer_session in torrent has downloaded it--as soon as we receive it
        // from another peer, we cancel the request from this peer, which removes the
        // request from outgoing_requests_ TODO verify.
        find_download(request->index).abort_request(remote_endpoint(), *request);
        outgoing_requests_.erase(request);
    }
    // We don't have other requests, so stop the timer.
    if(outgoing_requests_.empty())
    {
        std::error_code ec;
        request_timeout_timer_.cancel(ec);
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

    message msg = message_parser_.extract_message();
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

    //if(torrent_.piece_picker().my_bitfield()[piece]) { return; }

    if(std::find(outgoing_allowed_set_.begin(),
        outgoing_allowed_set_.end(), piece) == outgoing_allowed_set_.end())
    {
        outgoing_allowed_set_.emplace_back(piece);
        //// TODO if peer has this piece we may consider downloading it
        //if(info_.available_pieces[piece])
    }
}

inline void peer_session::handle_illicit_block(const block_info& block)
{
    // We don't want this block (give 2 second slack as it may be an old request).
    if(!info_.am_interested
       && cached_clock::now() - info_.last_outgoing_uninterest_time > seconds(2))
    {
        if(++info_.num_unwanted_blocks > 50)
        {
            disconnect(peer_session_errc::unwanted_blocks);
        }
        log(log_event::incoming, "%i unwanted blocks", info_.num_unwanted_blocks);
    }
    info_.total_wasted_bytes += block.length;
    torrent_.info().total_wasted_bytes += block.length;
    log(log_event::incoming, "%i wasted bytes", info_.total_wasted_bytes);
}

inline void peer_session::handle_unknown_message()
{
    // Later when we support custom extensions we'll first pass the current message
    // there and see if they can handle it.
    message_parser_.skip_message();
    log(log_event::invalid_message, "unknown message");
    disconnect(peer_session_errc::unknown_message);
}

// ----------
// -- disk --
// ----------

inline void peer_session::save_block(const block_info& block_info,
    disk_buffer block_data, piece_download& download)
{
    op_state_.set(op::disk_write);
    info_.num_pending_disk_write_bytes += block_info.length;
    torrent_.info().num_pending_disk_write_bytes += block_info.length;

    // Note that it's safe to pass a reference to download as only torrent may
    // remove a piece_download from shared_downloads_, and if download is 
    // parole_download_, it is added to shared_downloads_ if we disconnect before 
    // finishing the download.
    torrent_.save_block(block_info, std::move(block_data), download,
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
    const int n = std::count_if(outgoing_requests_.begin(),
        outgoing_requests_.end(), [&download](const auto& r)
        { return r.index == download.piece_index(); });
    if(n > 0)
    {
        log(log_event::info, log::priority::high,
            "%i blocks for piece(%i) in outgoing_requests_ after piece completion",
            n, download.piece_index());
        assert(0 && "remaining requests for complete piece!");
    }
#endif // TIDE_ENABLE_LOGGING

    // Despite joining this download, we may not have been successful in getting any
    // blocks from peer.
    if(num_bytes_downloaded > 0)
    {
        if(is_piece_good)
            handle_valid_piece(download);
        else
            handle_corrupt_piece(download);
    }

    const auto it = std::find_if(downloads_.begin(), downloads_.end(),
        [&download](const auto& d) { return d.get() == &download; });
    if(it != downloads_.end()) { downloads_.erase(it); }
#ifdef TIDE_ENABLE_DEBUGGING
    else log(log_event::info, log::priority::high, "not removing download(%i)",
            download.piece_index());
#endif // TIDE_ENABLE_DEBUGGING
}

inline void peer_session::handle_valid_piece(const piece_download& download)
{
    log(log_event::disk, log::priority::high,
        "piece(%i) passed hash test", download.piece_index());

    info_.total_verified_piece_bytes += get_piece_length(
        torrent_.info(), download.piece_index());

    if(is_peer_on_parole())
    {
        if(parole_download_ && (&download == parole_download_.get()))
        {
            // Peer cleared itself, so it's no longer on parole.
            parole_download_.reset();
            info_.is_peer_on_parole = false;
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
        download.piece_index(), info_.num_hash_fails);

    ++info_.num_hash_fails;
    info_.total_wasted_bytes += get_piece_length(
        torrent_.info(), download.piece_index());

    if(is_peer_on_parole()
       && parole_download_
       && &download == parole_download_.get())
    {
        log(log_event::parole, "confirmed suspicion through parole download");
        parole_download_.reset();
    }
    else if(download.is_exclusive())
    {
        log(log_event::parole, log::priority::high,
            "peer sent bad piece, disconnecting peer");
        if(parole_download_)
        {
            // Download is not the parole piece this peer was assigned, our suspicion
            // got confirmed by chance through another download which happend to involve
            // only this peer; free parole_download_ for others to request
            // TODO free from piece picker
            // TODO tell disk_io not to save these blocks; if it has, tell it to consider
            // them corrupt (so that it won't drop other blocks).
            //torrent_.piece_picker().unreserve(parole_download_->piece_index());
            parole_download_.reset();
        }
        disconnect(peer_session_errc::corrupt_piece);
        return;
    }
    else
    {
        log(log_event::parole, "peer on parole effective immediately");
        info_.is_peer_on_parole = true;
    }
}

void peer_session::on_block_saved(const std::error_code& error,
    const block_info& block, const time_point start_time)
{
    info_.num_pending_disk_write_bytes -= block.length;
    // There may be multiple concurrent disk operations, so we can only unset this state
    // if we don't expect more bytes to be written to disk.
    if(info_.num_pending_disk_write_bytes == 0) { op_state_.unset(op::disk_write); }
    torrent_.info().num_pending_disk_write_bytes -= block.length;
    assert(error != disk_io_errc::invalid_block);
    // It's not really an error if piece turned out to be bad or it was a duplicate block
    // (though the latter should happen very rarely).
    if(error && (error != disk_io_errc::corrupt_data_dropped
                 && error != disk_io_errc::duplicate_block))
    {
        // If block could not be saved we will have to redownload it at some point, so
        // tell its corresponding download instance to free this block for requesting.
        if(error == disk_io_errc::block_dropped)
        {
            // The assert in find_download must not fire as in this case (dropped block)
            // we could not advance the hashing, i.e. the completion of the piece, and a
            // piece_download may only be removed once we have fully hashed it.
            find_download(block.index).abort_request(remote_endpoint(), block);
        }
        ++info_.num_disk_io_failures;
        ++torrent_.info().num_disk_io_failures;
        const auto reason = error.message();
        log(log_event::disk, log::priority::high, "disk failure #%i (%s)",
            info_.num_disk_io_failures, reason.c_str());
        if(info_.num_disk_io_failures > 100) { disconnect(error); }
    }
    else
    {
        info_.num_disk_io_failures = 0;
        info_.total_bytes_written_to_disk += block.length;
        torrent_.info().total_bytes_written_to_disk += block.length;
        avg_disk_write_time_.update(to_int<milliseconds>(
            cached_clock::now() - start_time));

        log(log_event::disk, log::priority::high,
            "saved block to disk (piece: %i, offset: %i, length: %i) - "
            "disk write stats (total: %lli; pending: %lli)",
            block.index, block.offset, block.length, info_.total_bytes_written_to_disk,
            info_.num_pending_disk_write_bytes);
    }

    // Note: don't move this above, we still need to record stats for torrent,
    // but even more importantly, THIS ALWAYS HAS TO BE CALLED.
    if(is_disconnecting())
    {
        try_finish_disconnecting();
        return;
    }
    else if(should_abort(error))
    {
        return;
    }

    // We can likely receive more now that we finished writing to disk.
    receive();
}

void peer_session::on_block_fetched(const std::error_code& error,
    const block_source& block)
{
    if(error == disk_io_errc::operation_aborted)
    {
        // The block read was cancelled.
        log(log_event::disk, "block fetch aborted (piece: %i, offset: %i, length: %i)",
            block.index, block.offset, block.length);
    }
    else if(error)
    {
        ++info_.num_disk_io_failures;
        ++torrent_.info().num_disk_io_failures;
        log(log_event::disk, log::priority::high,
            "disk failure #%i", info_.num_disk_io_failures);
        if(info_.num_disk_io_failures > 100) { disconnect(error); }
    }
    else
    {
        // Reset disk failuires to 0 since it only counts consecutive failures.
        info_.num_disk_io_failures = 0;
        info_.total_bytes_read_from_disk += block.length;
        info_.num_pending_disk_read_bytes -= block.length;
        torrent_.info().total_bytes_read_from_disk += block.length;
        torrent_.info().num_pending_disk_read_bytes -= block.length;

        log(log_event::disk, log::priority::high,
            "read block from disk (piece: %i, offset: %i, length: %i) - "
            "disk read stats (total: %lli; pending: %lli)",
            block.index, block.offset, block.length, info_.total_bytes_read_from_disk,
            info_.num_pending_disk_read_bytes);
    }

    // There may be multiple concurrent disk operations, so we can only unset this state
    // if we don't expect more bytes to be written to disk.
    if(info_.num_pending_disk_read_bytes == 0) { op_state_.unset(op::disk_read); }

    // Note: don't move this above, we still need to record stats for torrent,
    // but even more importantly, THIS ALWAYS HAS TO BE CALLED.
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
    send_buffer_.append(fixed_payload<protocol_length + 49>()
        .i8(protocol_length)
        .range(protocol, protocol + protocol_length)
        .u64(settings_.extensions.data())
        .buffer(torrent_.info().info_hash)
        .buffer(settings_.client_id));
    send();

#ifdef TIDE_ENABLE_LOGGING
    const auto extensions_str = extensions::to_string(settings_.extensions);
    log(log_event::outgoing, "HANDSHAKE (protocol: %s; extensions: %s; client_id: %s)",
        protocol, extensions_str.c_str(), settings_.client_id.data());
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
    assert(torrent_);
    assert(!torrent_.piece_picker().has_no_pieces());

    const auto& my_pieces = torrent_.piece_picker().my_bitfield();
    const int msg_size = 1 + my_pieces.data().size();
    send_buffer_.append(payload(4 + msg_size)
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
    send_buffer_.append(payload);
    send();
    log(log_event::outgoing, "KEEP_ALIVE");
}

// -------------
// CHOKE <len=1>
// -------------
void peer_session::send_choke()
{
    static constexpr uint8_t payload[] = { 0,0,0,1, message::choke };
    send_buffer_.append(payload);
    info_.is_peer_choked = true;
    info_.last_outgoing_choke_time = cached_clock::now();
    send();
    log(log_event::outgoing, "CHOKE");
}

// ---------------
// UNCHOKE <len=1>
// ---------------
void peer_session::send_unchoke()
{
    static constexpr uint8_t payload[] = { 0,0,0,1, message::unchoke };
    send_buffer_.append(payload);
    info_.is_peer_choked = false;
    info_.last_outgoing_unchoke_time = cached_clock::now();
    send();
    log(log_event::outgoing, "UNCHOKE");
}

// ------------------
// INTERESTED <len=1>
// ------------------
void peer_session::send_interested()
{
    static constexpr uint8_t payload[] = { 0,0,0,1, message::interested };
    send_buffer_.append(payload);
    info_.am_interested = true;
    info_.last_outgoing_interest_time = cached_clock::now();
    send();
    log(log_event::outgoing, "INTERESTED");
}

// ----------------------
// NOT INTERESTED <len=1>
// ----------------------
void peer_session::send_not_interested()
{
    static constexpr uint8_t payload[] = { 0,0,0,1, message::not_interested };
    send_buffer_.append(payload);
    info_.am_interested = false;
    op_state_[op::slow_start] = false;
    info_.last_outgoing_uninterest_time = cached_clock::now();
    send();
    log(log_event::outgoing, "NOT_INTERESTED");
}

// -------------------------------
// HAVE <len=5><id=4><piece index>
// -------------------------------
inline void peer_session::send_have(const piece_index_t piece)
{
    send_buffer_.append(fixed_payload<9>()
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
    send_buffer_.append(fixed_payload<17>()
        .i32(13)
        .i8(message::request)
        .i32(block.index)
        .i32(block.offset)
        .i32(block.length));
    send();

    log(log_event::outgoing, "REQUEST (piece: %i, offset: %i, length: %i)",
        block.index, block.offset, block.length);

    info_.last_outgoing_request_time = cached_clock::now();
    info_.num_outstanding_bytes += block.length;
    torrent_.info().num_outstanding_bytes += block.length;
    ++torrent_.info().num_pending_blocks;

    start_timer(request_timeout_timer_, calculate_request_timeout(),
        [SHARED_THIS](const std::error_code& error) { on_request_timeout(error); });
}

// ------------------------------------------
// BLOCK <len=9+X><id=7><index><offset><data>
// ------------------------------------------
void peer_session::send_block(const block_source& block)
{
    static constexpr int header_size = 4 + 1 + 2 * 4;
    // Send_buffer is optimized for sending blocks so we don't need to copy it into a
    // separate buffer, just separate the block header (msg header and block info) and 
    // append the block separately.
    fixed_payload<header_size> block_header;
    block_header.i32(header_size + block.length)
                .i8(message::block)
                .i32(block.index)
                .i32(block.offset);
    send_buffer_.append(block_header);
    send_buffer_.append(block);
    outgoing_requests_.emplace_back(block.index, block.offset, block.length);

    update_upload_stats(block.length);

    send();

    log(log_event::outgoing, log::priority::high,
        "BLOCK (piece: %i, offset: %i, length: %i) -- upload rate: %i bytes/s",
        block.index, block.offset, block.length, info_.upload_rate.rate());

    // Now that we sent this block, remove it from incoming_requests_.
    auto it = std::find(incoming_requests_.begin(), incoming_requests_.end(), block);
    assert(it != incoming_requests_.end());
    incoming_requests_.erase(it);
}

inline void peer_session::update_upload_stats(const int num_bytes)
{
    info_.last_outgoing_block_time = cached_clock::now();
    info_.total_uploaded_piece_bytes += num_bytes;
    info_.upload_rate.update(num_bytes);
    torrent_.info().total_uploaded_piece_bytes += num_bytes;
    torrent_.info().upload_rate.update(num_bytes);
    log(log_event::outgoing, log::priority::high,
        "upload rate: %i bytes/s", info_.upload_rate.rate());
}

// --------------------------------------------
// CANCEL <len=13><id=8><index><offset><length>
// --------------------------------------------
void peer_session::send_cancel(const block_info& block)
{
    // If we're already receiving this block, we can't cancel it.
    if(block != info_.in_transit_block)
    {
        send_buffer_.append(fixed_payload<17>()
            .i32(13)
            .i8(message::cancel)
            .i32(block.index)
            .i32(block.offset)
            .i32(block.length));
        send();
        --torrent_.info().num_pending_blocks;
        auto it = std::find(outgoing_requests_.begin(),
            outgoing_requests_.end(), block);
        if(it != outgoing_requests_.end()) { outgoing_requests_.erase(it); }
        log(log_event::outgoing, "CANCEL (piece: %i, offset: %i, length: %i)",
            block.index, block.offset, block.length);
    }
}

// -------------------------------
// PORT <len=3><id=9><listen-port>
// -------------------------------
void peer_session::send_port(const int port)
{
    send_buffer_.append(fixed_payload<7>()
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
    send_buffer_.append(fixed_payload<9>()
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
    send_buffer_.append(payload);
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
    send_buffer_.append(payload);
    send();
    log(log_event::outgoing, "HAVE NONE");
}

// -----------------------------------------------------
// REJECT REQUEST <len=13><id=16><index><offset><length>
// -----------------------------------------------------
void peer_session::send_reject_request(const block_info& block)
{
    send_buffer_.append(fixed_payload<17>()
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
    send_buffer_.append(fixed_payload<9>()
        .i32(5)
        .i8(message::allowed_fast)
        .i32(piece));
    send();
    log(log_event::outgoing, "ALLOWED FAST (%i)", piece);
}

void peer_session::send_allowed_fast_set()
{
    generate_allowed_fast_set();
    for(const auto& p : outgoing_allowed_set_) { send_allowed_fast(p); }
}

inline void peer_session::send_piece_availability()
{
    info_.state = state::piece_availability_exchange;
    if(is_extension_enabled(extensions::fast))
    {
        // In the fast extension we MUST send a piece availability message.
        if(torrent_.piece_picker().has_all_pieces())
            send_have_all();
        else if(torrent_.piece_picker().has_no_pieces())
            send_have_none();
        else
            send_bitfield();
    }
    else if(!torrent_.piece_picker().has_no_pieces())
    {
        // Otherwise we only need to send the bitfield if we have any pieces
        // TODO if we only have a few pieces (i.e. not worth sending an entire bitfield)
        // send them in separate have messages.
        send_bitfield();
    }
}

// -------------------
// -- request logic --
// -------------------

inline bool peer_session::can_make_requests() const noexcept
{
    // TODO restrict requests if disk is overwhelmed...I think.?
    return am_interested()
        && num_to_request() > 0
        && (!am_choked() || !incoming_allowed_set_.empty());
}

void peer_session::make_requests()
{
    assert(torrent_);

    // TODO rework this.
    if(outgoing_requests_.size() == 1)
    {
        auto& lingering_block = outgoing_requests_[0];
        // We have a single pending block left, and it's a block that's supposed to
        // come before the block we received just now; even though peer is not required
        // to serve blocks in order, they have a tendency not to send the first
        // requested block.
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
        outgoing_requests_.size(), info_.best_request_queue_size);

    view<pending_block> new_requests = distpach_make_requests();
    if(new_requests.empty()) { return; }

    auto& torrent_info = torrent_.info();
    payload payload(new_requests.size() * 17);
    // Craft the payload for each block that was put in outgoing_requests_ by the
    // above functions.
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
        info_.num_outstanding_bytes += block.length;
        torrent_info.num_outstanding_bytes += block.length;
        ++torrent_info.num_pending_blocks;
    }
    log(log_event::outgoing, log::priority::high,
        "request queue length: %i", new_requests.size());
    send_buffer_.append(std::move(payload));
    send();

    if(torrent_info.num_pending_blocks >= torrent_info.num_blocks)
    {
    }

    info_.last_outgoing_request_time = cached_clock::now();
    start_timer(request_timeout_timer_, calculate_request_timeout(),
        [SHARED_THIS](const std::error_code& error) { on_request_timeout(error); });
}

inline view<pending_block> peer_session::distpach_make_requests()
{
    // TODO if we're on parole and it's also end-game mode, we should probably not
    // request from this peer (so as not to slow down the download), unless they are
    // the only ones that have some of the pieces.
    if(torrent_.info().state[torrent_info::end_game])
        return make_requests_in_endgame_mode();
    else if(is_peer_on_parole())
        return make_requests_in_parole_mode();
    else
        return make_requests_in_normal_mode();
}

inline view<pending_block> peer_session::make_requests_in_endgame_mode()
{
    // TODO for now.
    return make_requests_in_normal_mode();
}

inline view<pending_block> peer_session::make_requests_in_parole_mode()
{
    // Pick a parole piece for this peer if it hasn't been assigned one yet since it
    // participated in a failed hash test.
    if(parole_download_ == nullptr)
    {
        auto& piece_picker = torrent_.piece_picker();
        const auto piece = piece_picker.pick(info_.available_pieces);
        if(piece == invalid_piece_index)
        {
            return {};
        }
        else if(piece_picker.num_pieces_left() == 1
                && piece_picker.frequency(piece) > 1)
        {
            // If this is the last piece and other peers have this piece, we don't want
            // to stall completion by assigning only a single peer to it
            // FIXME if all peers that have this piece are put on parole this will
            // never dl.
            piece_picker.unreserve(piece);
            log(log_event::request, log::priority::high,
                "picked and released piece(%i) to not stall completion", piece);
            return {};
        }
        ++torrent_.info().num_pending_pieces;
        parole_download_ = std::make_unique<piece_download>(
            piece, get_piece_length(torrent_.info(), piece));
        // It's safe to pass only this instead of SHARED_THIS because we remove
        // these callbacks from download when we destruct.
        parole_download_->register_peer(remote_endpoint(),
            [this, &download = *parole_download_]
            (bool is_piece_good, int num_bytes_downloaded)
            { on_piece_hashed(download, is_piece_good, num_bytes_downloaded); },
            [this](const block_info& block) { send_cancel(block); });
        log(log_event::request, log::priority::high,
            "picked piece(%i) in parole mode", piece);
    }
    const int num_new_requests = parole_download_->pick_blocks(
        outgoing_requests_, remote_endpoint(), num_to_request());
    log(log_event::request, log::priority::high,
        "%i new parole requests", num_new_requests);
    return view_of_new_requests(num_new_requests);
}

inline view<pending_block> peer_session::make_requests_in_normal_mode()
{
    // If we have active downloads, prefer to finish those (this will result in less
    // peers per piece download, i.e. lower chance of a bad peer polluting many pieces).
    int num_new_requests = continue_downloads();

    // We try to join a download using shared_downloads_ as long as we need more
    // blocks and there are downloads to join.
    while(outgoing_requests_.size() < info_.best_request_queue_size)
    {
        const int num_blocks = join_download();
        if(num_blocks == 0) { break; }
        num_new_requests += num_blocks;
    }

    // While we still need blocks, we pick a piece and start a new download, and add it
    // to the shared downloads via shared_downloads_.
    while(outgoing_requests_.size() < info_.best_request_queue_size)
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
    assert(n <= outgoing_requests_.size());
    const int first_new_request_pos = outgoing_requests_.size() - n;
    return {&outgoing_requests_[first_new_request_pos], size_t(n)};
}

inline int peer_session::continue_downloads()
{
    int num_new_requests = 0;
    for(auto& download : downloads_)
    {
        if(outgoing_requests_.size() >= info_.best_request_queue_size) { break; }
        const int n = download->pick_blocks(
            outgoing_requests_, remote_endpoint(), num_to_request());
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
        // It's safe to pass only this instead of SHARED_THIS because we remove
        // our callback from download when we destruct.
        download->register_peer(remote_endpoint(), 
            [this, &download = *download](bool is_piece_good, int num_bytes_downloaded)
            { on_piece_hashed(download, is_piece_good, num_bytes_downloaded); },
            [this](const block_info& block) { send_cancel(block); });
        num_new_requests += download->pick_blocks(
            outgoing_requests_, remote_endpoint(), num_to_request());
        // Now we participated in this piece download as well.
        downloads_.emplace_back(download);
    }
    return num_new_requests;
}

inline std::shared_ptr<piece_download> peer_session::find_shared_download()
{
    for(auto& download : torrent_.downloads())
    {
        if(info_.available_pieces[download->piece_index()]
           && std::find(downloads_.begin(), downloads_.end(), download)
               == downloads_.end()
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
    const auto piece = torrent_.piece_picker().pick(info_.available_pieces);

#ifdef TIDE_ENABLE_EXPENSIVE_ASSERTS
    // Test whether piece picker returned a unique piece.
    const auto& downloads = torrent_.downloads();
    bool is_duplicate1 = std::find_if(downloads.begin(), downloads.end(),
        [piece](const auto& d) { return d->piece_index() == piece; }) != downloads.end();
    bool is_duplicate2 = std::find_if(downloads_.begin(), downloads_.end(),
        [piece](const auto& d) { return d->piece_index() == piece; }) != downloads_.end();
    bool is_duplicate3 = parole_download_
        ? parole_download_->piece_index() == piece : false;
    if(is_duplicate1 || is_duplicate2 || is_duplicate3)
    {
        const auto s = torrent_.piece_picker().to_string();
        log(log_event::info, log::priority::high,
            "FATAL: piece picker picked reserved piece(%i): %s", piece, s.c_str());
        assert(0 && "piece picker picked a reserved piece");
    }
#endif // TIDE_ENABLE_EXPENSIVE_ASSERTS

    if(piece != invalid_piece_index)
    {
        auto& info = torrent_.info();
        // We might need to enter end-game mode.
        if(++info.num_pending_pieces + info.num_downloaded_pieces == info.num_pieces)
        {
            info.state[torrent_info::end_game] = true;
            log(log_event::info, log::priority::high, "entered end-game mode");
        }

        log(log_event::request, log::priority::high, "picked piece(%i)", piece);

        auto download = std::make_shared<piece_download>(
            piece, get_piece_length(info, piece));
        // It's safe to pass only this instead of SHARED_THIS because we remove
        // these callbacks from download when we destruct.
        download->register_peer(remote_endpoint(), 
            [this, &download = *download](bool is_piece_good, int num_bytes_downloaded)
            { on_piece_hashed(download, is_piece_good, num_bytes_downloaded); },
            [this](const block_info& block) { send_cancel(block); });
        num_new_requests += download->pick_blocks(
            outgoing_requests_, remote_endpoint(), num_to_request());

        // Add download to shared database so other peer_sessions may join.
        torrent_.downloads().emplace_back(download);
        downloads_.emplace_back(download);
    }
    return num_new_requests;
}

inline int peer_session::num_to_request() const noexcept
{
    return std::max(info_.best_request_queue_size - int(outgoing_requests_.size()), 0);
}

inline void peer_session::abort_outgoing_requests()
{
    std::error_code ec;
    request_timeout_timer_.cancel(ec);

    auto& torrent_info = torrent_.info();
    piece_download* download = nullptr;
    // Tell each download that we won't get our requested blocks.
    for(const pending_block& block : outgoing_requests_)
    {
        // It is likely that most of these requests belong to one piece download, so 
        // cache it as much as possible.
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
    info_.num_outstanding_bytes = 0;
    torrent_.info().num_outstanding_bytes = 0;
    outgoing_requests_.clear();
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
        to_int<seconds>(cached_clock::now() - info_.last_outgoing_request_time),
        outgoing_requests_.size());

    info_.best_request_queue_size = 1;
    info_.has_peer_timed_out = true;
    ++info_.num_timed_out_requests;
    ++torrent_.info().num_timed_out_requests;

    if(++info_.num_consecutive_timeouts > 50)
    {
        disconnect(make_error_code(peer_session_errc::request_timeout));
        return;
    }

    if(outgoing_requests_.empty()) log(log_event::timeout,
        log::priority::high, "request queue is empty o.O");

    auto request = find_request_to_time_out();
    if(request != outgoing_requests_.end())
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
            outgoing_requests_.size());
    }

    if(can_make_requests())
        make_requests();
    else if(!outgoing_requests_.empty())
        start_timer(request_timeout_timer_, calculate_request_timeout(),
            [SHARED_THIS](const std::error_code& error) { on_request_timeout(error); });
}

inline
std::vector<pending_block>::iterator peer_session::find_request_to_time_out() noexcept
{
    for(int i = outgoing_requests_.size() - 1; i >= 0; --i)
    {
        const auto& r = outgoing_requests_[i];
        // Only time out a block if it hasn't been timed out before and its piece can be
        // downloaded from more than a single peer.
        if(!r.has_timed_out && (torrent_.piece_picker().frequency(r.index) > 1))
        {
            return outgoing_requests_.begin() + i;
        }
    }
    return outgoing_requests_.end();
}

seconds peer_session::calculate_request_timeout() const
{
    // Avg_request_rtt_ is in milliseconds.
    int t = avg_request_rtt_.mean() + 4 * avg_request_rtt_.deviation();
    // To avoid being timing out peer instantly, timeouts should never be less than two
    // seconds.
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
            cached_clock::now() - info_.connection_started_time);
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
    if(cached_clock::now() - info_.last_send_time > seconds(120)) { send_keep_alive(); }
    start_timer(keep_alive_timer_, settings_.peer_timeout,
        [SHARED_THIS](const std::error_code& error) { on_keep_alive_timeout(error); });
}

// -----------
// -- utils --
// -----------

void peer_session::generate_allowed_fast_set()
{
    const torrent_info& info = torrent_.info();
    const int n = std::min(info.num_pieces, settings_.allowed_fast_set_size);
    outgoing_allowed_set_.reserve(n);
    std::string x(24, 0);
    const address& ip = remote_endpoint().address();
    // TODO branch on ipv4/ipv6.
    endian::write<uint32_t>(0xff'ff'ff'00 & ip.to_v4().to_ulong(), &x[0]);
    std::copy(info.info_hash.begin(), info.info_hash.end(), x.begin() + 4);
    while(outgoing_allowed_set_.size() < n)
    {
        const sha1_hash hash = create_sha1_digest(x);
        x.assign(hash.begin(), hash.end());
        for(auto i = 0; (i < 5) && (outgoing_allowed_set_.size() < n); ++i)
        {
            const uint32_t index = endian::parse<uint32_t>(x.data() + (4 * i))
                % info.num_pieces;
            if(outgoing_allowed_set_.end() == std::find(
                outgoing_allowed_set_.begin(), outgoing_allowed_set_.end(), index))
            {
                outgoing_allowed_set_.push_back(index);
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
            cached_clock::now() - info_.connection_established_time);
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
    // We're not attached to any torrent yet.
    const torrent_id_t id = torrent_ ? torrent_.info().id : -1;
    log::log_peer_session(id, remote_endpoint(), header.str(),
        util::format(format, std::forward<Args>(args)...), priority);
#endif // TIDE_ENABLE_LOGGING
}

inline piece_download& peer_session::find_download(const piece_index_t piece) noexcept
{
    auto it = std::find_if(downloads_.begin(), downloads_.end(),
        [piece](const auto& download) { return download->piece_index() == piece; });
    // If we didn't find download among downloads_, we must be on parole and this must
    // be the parole download, however, parole_download_ must be valid at this point.
    if(it == downloads_.end())
    {
        // FIXME this fired.
        log(log_event::info, "piece(%i) not found in downloads_");
        assert(parole_download_);
        assert(parole_download_->piece_index() == piece);
        return *parole_download_;
    }
    assert(it->get());
    return **it;
}

void peer_session::try_identify_client()
{
    // https://wiki.theory.org/BitTorrentSpecification#peer_id
    info_.client = [this]
    {
        if(info_.peer_id[0] == '-')
        {
            // Azureus-style encoding.
            const auto matches = [this](const char* signature) -> bool
            {
                return info_.peer_id[1] == signature[0]
                    && info_.peer_id[2] == signature[1];
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
                // standard 4 for most other Azureus style peer ids.
                return info_.peer_id[1 + 2 + 6] == '-' ? "BitCometLite" : "BitBlinder";
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
            // Shad0w-style encoding.
            const auto matches = [this](const char client) -> bool
            {
                return info_.peer_id[0] == client;
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
    const auto index = endian::parse<piece_index_t>(it);
    const auto offset = endian::parse<int>(it += 4);

    if(data.size() == 3 * 4)
    {
        // It's a request/cancel message with fixed message length.
        return block_info(index, offset, endian::parse<int32_t>(it += 4));
    }
    else
    {
        // It's a block message, we get the block's length by subtracting the index and
        // offset fields' added length from the total message length.
        return block_info(index, offset, data.size() - 2 * 4);
    }
}

#undef SHARED_THIS

} // namespace tide
