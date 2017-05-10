#ifndef TORRENT_PEER_INFO_HEADER
#define TORRENT_PEER_INFO_HEADER

#include "bt_bitfield.hpp"
#include "socket.hpp"
#include "units.hpp"

#include <string>
#include <vector>
#include <array>

struct peer_info
{
    // The unique torrent id to which this peer belongs.
    torrent_id_t torrent_id;

    // The 20 byte BitTorrent peer id.
    peer_id id;

    // A string representing the peer's software, if available (left empty if peer
    // could not be identified).
    std::string client;

    // These are the extensions peer supports.
    std::array<uint8_t, 8> extensions;

    // All pieces peer has.
    bt_bitfield available_pieces;

    tcp::endpoint local_endpoint;
    tcp::endpoint peer_endpoint;

    // The pieces we're currently downloading from this peer (those that have been
    // downloaded but not yet been verified count as well).
    std::vector<piece_index_t> piece_downloads;

    time_point connection_established_time;

    // The total number of piece bytes exchanged with this peer. Does not include
    // protocol overhead (both BitTorrent protocol and TCP/IP protocol).
    int64_t total_downloaded_piece_bytes = 0;
    int64_t total_uploaded_piece_bytes = 0;

    // The total number of all bytes, excluding the underlying network protocol overhead,
    // exchaned with this peer (i.e. total_piece_{up,down}loaded + BitTorrent protocol
    // overhead).
    int64_t total_downloaded_bytes = 0;
    int64_t total_uploaded_bytes = 0;

    // If we receive a piece that we already have, this is incremented.
    int64_t total_wasted_bytes = 0;

    // Latest payload (piece) upload and download rates in bytes/s.
    int upload_rate = 0;
    int download_rate = 0;

    // The highest upload and download rate recorded in this connection.
    int peak_upload_rate = 0;
    int peak_download_rate = 0;

    // The maximum number of bytes/s we are allowed to send to or receive from peer. No
    // limit is employed if the values are -1 (the default).
    int max_upload_rate = -1;
    int max_download_rate = -1;

    // The amount of message bytes in these buffers.
    int send_buffer_size = 0;
    int receive_buffer_size = 0;

    // The number of bad pieces in which this peer has participated.
    int num_hash_fails = 0;

    // The number of requests to which we haven't gotten any response.
    int num_timed_out_requests = 0;

    // The number of requests that peers hasn't served yet.
    //int download_queue_size = 0;
    // The number of requests from peer that haven't been answered yet.
    //int upload_queue_size = 0;

    int total_bytes_written_to_disk = 0;
    int total_bytes_read_from_disk = 0;

    // The number of bytes that are waiting to be written to and read from disk,
    // but are queued up.
    int num_pending_disk_write_bytes = 0;
    int num_pending_disk_read_bytes = 0;

    // The number of piece bytes we're expecting to receive from peer.
    int num_outstanding_bytes = 0;

    // The number of bytes this peer is allowed to send and receive until it is allotted
    // more (typically once per second) or requests more if it runs out.
    int send_quota = 0;
    int receive_quota = 0;

    bool am_interested = false;
    bool am_choked = true;
    bool is_peer_interested = false;
    bool is_peer_choked = true;

    bool am_seed = false;
    bool is_peer_seed = false;

    // If it's an outgoing connection, we initiated it, otherwise peer did.
    bool is_outbound;

    // Peer is on parole if it participated in a download that resulted in a corrupt
    // piece. Unless the peer was the sole contributor to this piece, the culprit cannot
    // be determined, so each participant goes on parole, which means that in the next
    // download
    bool is_on_parole = false;

    // If a peer does not manage to serve our request within the timeout limit, it is
    // marked and fewer requests are made subsequently.
    bool has_peer_timed_out = false;

    enum class state_t
    {
        stopped,
        connecting,
        in_handshake,
        // This state is optional, it is used to verify that the bitfield exchange
        // occurrs after the handshake and not later. It is set once the handshake is
        // done and changed to connected as soon as we receive the bitfield or the the
        // first message that is not a bitfield. Any subsequent bitfield messages are
        // rejected and the connection is dropped.
        bitfield_exchange,
        // This is the state in which the session is when it is ready to send and receive
        // regular messages, i.e. when the up/download actually begins.
        connected,
        // After this is done, the state is set back to stopped.
        disconnecting
    };

    state_t state = state_t::stopped;
};

#endif // TORRENT_PEER_INFO_HEADER
