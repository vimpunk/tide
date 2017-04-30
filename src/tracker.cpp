#include "tracker.hpp"
#include "bdecode.hpp"
#include "address.hpp"
#include "endian.hpp"

#include <iostream>

#include <Poco/Net/HTTPClientSession.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Path.h>
#include <Poco/URI.h>
#include <Poco/ByteOrder.h>

std::string tracker::contact(const std::string& request_url) const
{
    Poco::URI uri(m_address + request_url); 
    const std::string host = uri.getHost();

    Poco::Net::HTTPClientSession session(host, uri.getPort());
    
    std::string path = uri.getPathAndQuery();
    if(path.empty())
    {
        path = "/";
    }

    Poco::Net::HTTPRequest request(
        Poco::Net::HTTPRequest::HTTP_GET,
        path,
        Poco::Net::HTTPMessage::HTTP_1_1
    );
    request.setHost(host, uri.getPort());
    request.add("User-Agent", "RT");
    request.add("Connection", "close");
/*
	std::cerr << '\n';
	request.write(std::cerr);
	std::cerr << '\n';
*/
    session.sendRequest(request);

    Poco::Net::HTTPResponse response;
    std::istream& istream = session.receiveResponse(response);

    std::stringstream ss;
    ss << istream.rdbuf();
//	std::cerr << ss.str() << '\n';
    return ss.str();
}

tracker_response parse_response(std::string raw_response)
{
    tracker_response response;
    // some trackers don't bother with a bencode map on failure, they just return the
    // failure reason string
	if(raw_response.empty() || (raw_response[0] != 'd'))
	{
        response.failure_reason = std::move(raw_response);
        return response;
	}

	const bmap response_map = decode_bmap(std::move(raw_response));	
    // if there is a failure reason, return early
    if(response_map.try_find_string("failure reason", response.failure_reason))
    {
        return response;
    }
    // see also if a tracker_id is provided, as trackers don't necessarily send one
    response_map.try_find_string("tracker_id", response.tracker_id);
    response_map.try_find_string("warning message", response.warning_message);
    if(!response_map.try_find_number("interval", response.interval))
    {
        // default to 30 minutes
        response.interval = 1800;
    }
    response.num_seeders = response_map.find_number("complete");
    response.num_leechers = response_map.find_number("incomplete");

    blist peers_list;
    std::string peers_str;
    if(response_map.try_find_blist("peers", peers_list))
    {
        response.peers = parse_peers(peers_list);
    }
    else if(response_map.try_find_string("peers", peers_str))
    {
        response.ipv4_peers = parse_peers(peers_str);
    }
    else
    {
        assert(false && "TODO");
    }

    return response;
}

std::vector<peer_entry> parse_peers(const blist& peers_list)
{
	std::vector<peer_entry> peers;
    peers.reserve(peers_list.size());
	for(const bmap& peer_map : peers_list.all_bmaps()) 
	{
        peer_entry peer;
        std::string peer_id;
        if(peer_map.try_find_string("peer_id", peer_id))
        {
            for(auto i = 0; i < peer.id.size(); ++i)
            {
                peer.id[i] = peer_id[i];
            }
        }
        else
        {
            peer.id.fill(0);
        }
        // this will throw if no IP address is found
        address ip = address::from_string(peer_map.find_string("ip"));
        // this will throw if no port is found
        const uint16_t port = peer_map.find_number("port");
        peer.endpoint = tcp::endpoint(std::move(ip), port);
        peers.emplace_back(std::move(peer));
	}
	return peers;
}

std::vector<tcp::endpoint> parse_peers(const std::string& peers_str)
{
    if(peers_str.length() % 6 != 0) 
    {
        throw std::runtime_error("invalid 'peer' binary string encoding");
    }

	std::vector<tcp::endpoint> peers;
    peers.reserve(peers_str.length() / 6);
    for(auto i = 0; i < peers_str.length(); i += 6)
    {
        // these are IPv4 entries
        address_v4 ip(parse_u32(&peers_str[i]));
        const uint16_t port = parse_u16(&peers_str[i + 4]);
        peers.emplace_back(std::move(ip), port);
    }
	return peers;
}

// -----------------------------
// -- tracker request builder --
// -----------------------------

std::string tracker_request_builder::build()
{
    if(m_required_data_counter != 6)
    {
        throw std::runtime_error("missing required field(s) in tracker request");
    }

    std::string path = "?";
    auto it = m_params.cbegin();
    const auto last_valid = m_params.cend() - 1;

    while(it != last_valid)
    {
        path += it->first + '=' + it->second + '&';
        ++it;
    }
    path += last_valid->first + '=' + last_valid->second;
    return path;
}

// --------------
// -- required --
// --------------

tracker_request_builder& tracker_request_builder::info_hash(sha1_hash info_hash)
{
    std::string s;
    s.reserve(info_hash.size());
    for(auto b : info_hash)
    {
        s.push_back(b);
    }
    m_params.emplace_back("info_hash", std::move(s));
    ++m_required_data_counter;
    return *this;
}

tracker_request_builder& tracker_request_builder::peer_id(sha1_hash peer_id)
{
    std::string s;
    s.reserve(peer_id.size());
    for(auto b : peer_id)
    {
        s.push_back(b);
    }
    m_params.emplace_back("peer_id", std::move(s));
    ++m_required_data_counter;
    return *this;
}

tracker_request_builder& tracker_request_builder::port(uint16_t port)
{
    m_params.emplace_back("port", std::to_string(port));
    ++m_required_data_counter;
    return *this;
}

tracker_request_builder& tracker_request_builder::uploaded(int64_t uploaded)
{
    m_params.emplace_back("uploaded", std::to_string(uploaded));
    ++m_required_data_counter;
    return *this;
}

tracker_request_builder& tracker_request_builder::downloaded(int64_t downloaded)
{
    m_params.emplace_back("downloaded", std::to_string(downloaded));
    ++m_required_data_counter;
    return *this;
}

tracker_request_builder& tracker_request_builder::left(int64_t left)
{
    m_params.emplace_back("left", std::to_string(left));
    ++m_required_data_counter;
    return *this;
}

// --------------
// -- optional --
// --------------

tracker_request_builder& tracker_request_builder::compact(bool b)
{
    m_params.emplace_back("compact", b ? "1" : "0");
    return *this;
}

tracker_request_builder& tracker_request_builder::no_peer_id(bool b)
{
    m_params.emplace_back("no_peer_id", b ? "1" : "0");
    return *this;
}

tracker_request_builder& tracker_request_builder::event(event_t event)
{
    switch(event)
    {
    case event_t::started:
        m_params.emplace_back("event", "started");
        break;
    case event_t::stopped:
        m_params.emplace_back("event", "stopped");
        break;
    case event_t::completed:
        m_params.emplace_back("event", "completed");
        break;
    default:
        throw std::runtime_error("bad event in tracker_request_builder");
    }
    return *this;
}

tracker_request_builder& tracker_request_builder::ip(std::string ip)
{
    std::error_code ec;
    address::from_string(ip, ec);
    if(ec)
    {
        throw std::runtime_error("bad ip address in tracker_request_builder");
    }
    m_params.emplace_back("ip", std::move(ip));
    return *this;
}

tracker_request_builder& tracker_request_builder::num_want(int num_want)
{
    m_params.emplace_back("numwant", std::to_string(num_want));
    return *this;
}

tracker_request_builder& tracker_request_builder::tracker_id(std::string tracker_id)
{
    m_params.emplace_back("tracker_id", std::move(tracker_id));
    return *this;
}
