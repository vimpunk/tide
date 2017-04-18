#ifndef TORRENT_PEER_SESSION_ERROR_HEADER
#define TORRENT_PEER_SESSION_ERROR_HEADER

#include <system_error>

/**
 * These are the types of errors that may occur in a peer connection, any of which result
 * in the peer being disconnected.
 */
enum class peer_session_error_t
{
    unknown = 1,
    duplicate_peer_id,
    torrent_removed,
    not_enough_memory,

    port_blocked,
    ip_blocked,

    both_seeders,

    // Peer is upload only and has no interesting pieces.
    not_interested_in_uploader_peer,

    // Peer connection timed out (generic timeout).
    timeout,
    // We could not set up the connection.
    connect_timeout,
    // the peers have not been interested in each other for a very long time.
    // disconnect
    uninterest_timeout,
    // The peer has not sent any message in a long time, not even a keepalive message.
    inactivity_timeout,
    // The handshake could not be completed.
    handshake_timeout,
    // Our requests timed out too often.
    request_timeout,
    // The peer became interested but never sent a request.
    no_request_timeout,
    // We disconnected the peer in the hopes of finding a better peer in the swarm.
    looking_for_other_peer,
    // We have too many peers connected.
    too_many_connections,
    // The info hash sent in the initial handshake was invalid.
    invalid_info_hash,

    // Used anytime the message is larger than what's expected or when the client sent
    // a larger block than what we requested.
    message_too_big,

    // Generic invalid BitTorrent messages.
    invalid_handshake,
    invalid_message_id,
    invalid_message,
    invalid_choke_message,
    invalid_unchoke_message,
    invalid_interested_message,
    invalid_not_interested_message,
    invalid_have_message,
    invalid_bitfield_message,
    invalid_request_message,
    invalid_block_message,
    invalid_cancel_message,
    invalid_dht_port_message,
    //invalid_reject_message,
    //invalid_allow_fast_message,
    //invalid_extended_message,

    // We could not identify the message so to be safe the connection was closed.
    unknown_message,

    // The peer sent more requests while being choked than allowed.
    sent_requests_when_choked,

    // The peer sent corrupt data.
    corrupt_piece,

    // The peer sent us too many blocks that we didn't request. This is used as DoS
    // mitigation.
    unwanted_blocks
};

inline bool operator==(const peer_session_error_t e, const int i) noexcept
{
    return static_cast<int>(e) == i;
}

inline bool operator!=(const int i, const peer_session_error_t e) noexcept
{
    return !(e == i);
}

struct peer_session_error_category : public std::error_category
{
    const char* name() const noexcept override
    {
        return "peer_session";
    }

    std::string message(int env) const override
    {
        switch(static_cast<peer_session_error_t>(env))
        {
        case peer_session_error_t::unknown:
            return "unknown error";
        case peer_session_error_t::duplicate_peer_id:
            return "duplicate peer id";
        case peer_session_error_t::torrent_removed:
            return "torrent removed";
        case peer_session_error_t::not_enough_memory:
            return "no more memory for buffers";
        case peer_session_error_t::port_blocked:
            return "peer's port blocked";
        case peer_session_error_t::ip_blocked:
            return "peer's ip blocked";
        case peer_session_error_t::both_seeders:
            return "both ends of the connection are seeders";
        case peer_session_error_t::not_interested_in_uploader_peer:
            return "peer is upload only and has no interesting pieces";
        case peer_session_error_t::timeout:
            return "generic peer time out";
        case peer_session_error_t::uninterest_timeout:
            return "neither endpoint is interested";
        case peer_session_error_t::inactivity_timeout:
            return "inactivity timeout";
        case peer_session_error_t::handshake_timeout:
            return "handshake timeout";
        case peer_session_error_t::request_timeout:
            return "too many request timeouts";
        case peer_session_error_t::no_request_timeout:
            return "no request received despite peer's interest";
        case peer_session_error_t::looking_for_other_peer:
            return "trying our fortune with other peers";
        case peer_session_error_t::invalid_info_hash:
            return "peer's torrent info hash was invalid";
        case peer_session_error_t::message_too_big:
            return "peer's message exceeded max message length";
        case peer_session_error_t::invalid_handshake:
            return "invalid handshake";
        case peer_session_error_t::invalid_message:
            return "invalid message (generic)";
        case peer_session_error_t::invalid_message_id:
            return "invalid message id";
        case peer_session_error_t::invalid_choke_message:
            return "invalid 'choke' message";
        case peer_session_error_t::invalid_unchoke_message:
            return "invalid 'unchoke' message";
        case peer_session_error_t::invalid_interested_message:
            return "invalid 'interested' message";
        case peer_session_error_t::invalid_not_interested_message:
            return "invalid 'uninterested' message";
        case peer_session_error_t::invalid_have_message:
            return "invalid 'have' message";
        case peer_session_error_t::invalid_bitfield_message:
            return "invalid 'bitfield' message";
        case peer_session_error_t::invalid_request_message:
            return "invalid 'request' message";
        case peer_session_error_t::invalid_block_message:
            return "invalid 'block' (or formally, 'piece') message";
        case peer_session_error_t::invalid_cancel_message:
            return "invalid 'cancel' message";
        case peer_session_error_t::unknown_message:
            return "could not identify message";
        case peer_session_error_t::sent_requests_when_choked:
            return "choked peer sent too many requests";
        case peer_session_error_t::corrupt_piece:
            return "peer sent corrupt piece(s)";
        case peer_session_error_t::unwanted_blocks:
            return "peer sent unwanted blocks";
        default:
            return "unknown error";
        }
    }

    std::error_condition default_error_condition(int ev) const noexcept override
    {
        switch(static_cast<peer_session_error_t>(ev))
        {
        case peer_session_error_t::not_enough_memory:
            return std::errc::not_enough_memory;
        case peer_session_error_t::timeout:
            return std::errc::host_unreachable;
        case peer_session_error_t::message_too_big:
            return std::errc::message_size;
        default:
            return std::error_condition(ev, *this);
        }
    }
};

const peer_session_error_category& peer_session_category()
{
    static peer_session_error_category instance;
    return instance;
}

std::error_code make_error_code(peer_session_error_t e)
{
    return std::error_code(
        static_cast<int>(e),
        peer_session_category()
    );
}

namespace std
{
    template<> struct is_error_code_enum<peer_session_error_t> : public true_type {};
}

// for more info:
// http://blog.think-async.com/2010/04/system-error-support-in-c0x-part-4.html

#endif // TORRENT_PEER_SESSION_ERROR_HEADER
