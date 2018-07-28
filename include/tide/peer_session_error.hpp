#ifndef TIDE_PEER_SESSION_ERROR_HEADER
#define TIDE_PEER_SESSION_ERROR_HEADER

#include "error_code.hpp"

#include <type_traits> // true_type
#include <string>

namespace tide {

/**
 * These are the types of errors that may occur in a peer connection, any of which result
 * in the peer being disconnected.
 */
enum class peer_session_errc
{
    unknown = 1,

    // peer_session was stopped by torrent.
    stopped,

    // The info hash sent in the initial handshake was invalid.
    invalid_info_hash,

    duplicate_peer_id,
    torrent_removed,
    not_enough_memory,

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

    // If peer sends us an extension message that we have disabled, peer is disconnected.
    unsupported_extension,

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
    invalid_suggest_piece_message,
    invalid_have_all_message,
    invalid_have_none_message,
    invalid_reject_request_message,
    invalid_allow_fast_message,
    invalid_extended_message,

    // We could not identify the message so to be safe the connection was closed.
    unknown_message,

    // If the Fast extension is enabled, some form of piece availability message must be
    // exchanged. This indicates that peer didn't send a bitfield, have_all, or have_none
    // message after the handshake.
    no_piece_availability_message,

    // As described above, piece availability messages may only be sent after
    // the handshake, so when a peer sends one at any other time, it is
    // disconnected.
    piece_availability_not_after_handshake,

    // The peer sent more requests while being choked than allowed.
    sent_requests_when_choked,

    // The peer sent corrupt data.
    corrupt_piece,

    // The peer sent us too many blocks that we didn't request. This is used as DoS
    // mitigation.
    unwanted_blocks
};

struct peer_session_error_category : public error_category
{
    const char* name() const noexcept override { return "peer_session"; }
    std::string message(int env) const override;
    error_condition default_error_condition(int ev) const noexcept override;
};

const peer_session_error_category& peer_session_category();
error_code make_error_code(peer_session_errc e);
error_condition make_error_condition(peer_session_errc e);

} // namespace tide

namespace TIDE_ERROR_CODE_NS {
    template<>
    struct is_error_code_enum<tide::peer_session_errc> : public std::true_type {};
}

// for more info:
// http://blog.think-async.com/2010/04/system-error-support-in-c0x-part-4.html

#endif // TIDE_PEER_SESSION_ERROR_HEADER
