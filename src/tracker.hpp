#ifndef TORRENT_TRACKER_HEADER
#define TORRENT_TRACKER_HEADER

#include "peer_entry.hpp"
#include "socket.hpp"

#include <utility>
#include <string>
#include <vector>
#include <string>

struct tracker_response
{
    // If present, no other keys may be present. A human-readable error message.
    std::string failure_reason;

    // Optional. Similar to failure_reason, but the response is still processed.
    std::string warning_message;

    // Optional.
    std::string tracker_id;

    // The number of seconds the client should wait before recontacting tracker.
    long interval;

    // If present, the client must not reannounce itself before the end of this interval.
    long min_interval;

    long num_seeders;
    long num_leechers;

    std::vector<peer_entry> peers;
    std::vector<tcp::endpoint> ipv4_peers;
    //std::vector<tcp::endpoint> ipv6_peers;
};

class tracker_request_builder
{
    std::vector<std::pair<std::string, std::string>> m_params;
    int m_required_data_counter = 0;

public:

    enum class event_t
    {
        // The first request to tracker must include this value.
        started,
        // Must be sent to tracker if the client is shutting down gracefully.
        stopped,
        // Must be sent to the tracker when the client becomes a seeder. Must not be
        // present if the client started as a seeder.
        completed
    };

    /** Returns the final request path. NOTE: it is _not_ urlencoded. */
    std::string build();

    // --------------
    // -- required --
    // --------------

    tracker_request_builder& info_hash(sha1_hash info_hash);
    tracker_request_builder& peer_id(sha1_hash peer_id);
    tracker_request_builder& port(uint16_t port);
    tracker_request_builder& uploaded(int64_t uploaded);
    tracker_request_builder& downloaded(int64_t downloaded);
    tracker_request_builder& left(int64_t left);

    // --------------
    // -- optional --
    // --------------

    /**
     * Indicates that client accepts a compact response (each peer takes up only 6 bytes
     * where the first four bytes constitute the IP address and the last 2 the port
     * number, in Network Byte Order.)
     */
    tracker_request_builder& compact(bool b);

    /**
     * Indicates that the tracker should omit the peer id fields in the peers dictionary
     * in non-compact mode (in compact mode this is ignored).
     */
    tracker_request_builder& no_peer_id(bool b);

    /**
     * Must be specified in the three specific cases in event_t, otherwise left empty,
     * which indicates a request performed at regular intervals.
     */
    tracker_request_builder& event(event_t event);

    /**
     * True IP address of the client in dotted quad format. This is only necessary if
     * the IP addresss from which the HTTP request originated is not the same as the
     * client's host address. This happens if the client is communicating through a
     * proxy, or when the tracker is on the same NAT'd subnet as peer (in which case it
     * is necessary that tracker not give out an unroutable address to peer).
     */
    tracker_request_builder& ip(std::string ip);

    /**
     * The number of peers the client wishes to receive from the tracker. If omitted,
     * typically defaults to 50.
     */
    tracker_request_builder& num_want(int num_want);

    /** If a previous annoucne contained a tracker_id, it should be included here */
    tracker_request_builder& tracker_id(std::string tracker_id);
};

class blist;

tracker_response parse_response(std::string response);
std::vector<tcp::endpoint> parse_peers(const std::string& peers_str);
std::vector<peer_entry> parse_peers(const blist& peers_list);

// NOTE: THIS IS JUST TEMPORARY FOR THE DURATION OF THE FIRST INTEGRATION TEST. EXPECT
// THE API TO CHANGE A GREAT DEAL.
class tracker
{
    std::string m_address;
    const std::vector<std::string> m_announce_list;

public:

    tracker(std::string address, std::vector<std::string> announce_list)
        : m_address(std::move(address))
        , m_announce_list(std::move(announce_list))
    {}

    void try_contact(
        const std::string& request_url,
        std::function<void(tracker_response)> handler
    )
    {
        handler(parse_response(contact(request_url)));
    }

private:

    std::string contact(const std::string& request_url) const;
};

#endif // TORRENT_TRACKER_HEADER
