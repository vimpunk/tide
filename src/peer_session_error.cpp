#include "peer_session_error.hpp"

#include <iostream>

std::string peer_session_error_category::message(int env) const
{
    switch(static_cast<peer_session_errc>(env))
    {
    case peer_session_errc::unknown:
        return "Unknown error";
    case peer_session_errc::duplicate_peer_id:
        return "Duplicate peer id";
    case peer_session_errc::torrent_removed:
        return "Torrent removed";
    case peer_session_errc::not_enough_memory:
        return "No more memory for buffers";
    case peer_session_errc::both_seeders:
        return "Both ends of the connection are seeders";
    case peer_session_errc::not_interested_in_uploader_peer:
        return "Peer is upload only and has no interesting pieces";
    case peer_session_errc::timeout:
        return "Generic peer time out";
    case peer_session_errc::connect_timeout:
        return "Timed out while connecting to peer";
    case peer_session_errc::uninterest_timeout:
        return "Neither endpoint is interested";
    case peer_session_errc::inactivity_timeout:
        return "Inactivity timeout";
    case peer_session_errc::handshake_timeout:
        return "Handshake timeout";
    case peer_session_errc::request_timeout:
        return "Too many request timeouts";
    case peer_session_errc::no_request_timeout:
        return "No request received despite peer's interest";
    case peer_session_errc::looking_for_other_peer:
        return "trying our fortune with other peers";
    case peer_session_errc::invalid_info_hash:
        return "Peer's torrent info hash was invalid";
    case peer_session_errc::message_too_big:
        return "Peer's message exceeded max message length";
    case peer_session_errc::invalid_handshake:
        return "Invalid handshake";
    case peer_session_errc::invalid_message:
        return "Invalid message (generic)";
    case peer_session_errc::invalid_message_id:
        return "Invalid message id";
    case peer_session_errc::invalid_choke_message:
        return "Invalid 'choke' message";
    case peer_session_errc::invalid_unchoke_message:
        return "Invalid 'unchoke' message";
    case peer_session_errc::invalid_interested_message:
        return "Invalid 'interested' message";
    case peer_session_errc::invalid_not_interested_message:
        return "Invalid 'uninterested' message";
    case peer_session_errc::invalid_have_message:
        return "Invalid 'have' message";
    case peer_session_errc::invalid_bitfield_message:
        return "Invalid 'bitfield' message";
    case peer_session_errc::invalid_request_message:
        return "Invalid 'request' message";
    case peer_session_errc::invalid_block_message:
        return "Invalid 'block' (or formally, 'piece') message";
    case peer_session_errc::invalid_cancel_message:
        return "Invalid 'cancel' message";
    case peer_session_errc::unknown_message:
        return "Could not identify message";
    case peer_session_errc::sent_requests_when_choked:
        return "Choked peer sent too many requests";
    case peer_session_errc::corrupt_piece:
        return "Peer sent corrupt piece(s)";
    case peer_session_errc::unwanted_blocks:
        return "Peer sent unwanted blocks";
    default:
        return "not peer_session related error";
    }
}

std::error_condition peer_session_error_category::default_error_condition(int ev) const noexcept
{
    switch(static_cast<peer_session_errc>(ev))
    {
    case peer_session_errc::not_enough_memory:
        return std::errc::not_enough_memory;
    case peer_session_errc::timeout:
        return std::errc::host_unreachable;
    case peer_session_errc::message_too_big:
        return std::errc::message_size;
    default:
        return std::error_condition(ev, *this);
    }
}

const peer_session_error_category& peer_session_category()
{
    static peer_session_error_category instance;
    return instance;
}

std::error_code make_error_code(peer_session_errc e)
{
    return std::error_code(static_cast<int>(e), peer_session_category());
}

std::error_condition make_error_condition(peer_session_errc e)
{
    return std::error_condition(static_cast<int>(e), peer_session_category());
}
