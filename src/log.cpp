#include "log.hpp"

#include <sstream>
#include <cassert>
#ifdef TIDE_ENABLE_STREAM_DEBUGGING
# include <iostream>
#endif // TIDE_ENABLE_STREAM_DEBUGGING

namespace tide {
namespace log {
namespace detail {

#define TIDE_FLUSH(f) do if(f.is_open()) f.flush(); while(0)

class engine_logger
{
    std::ofstream m_file;
public:
    void log(const std::string& header, const std::string& log,
        const priority priority = priority::normal);
    void flush() { TIDE_FLUSH(m_file); }
};

/** disk_io runs on muliple threads so this logger is thread-safe. */
class disk_io_logger
{
    std::ofstream m_file;
    std::mutex m_file_mutex;
public:
    void log(const std::string& header, const std::string& log,
        const bool concurrent, const priority priority);
    void flush() { TIDE_FLUSH(m_file); }
};

class torrent_logger
{
    std::map<torrent_id_t, std::ofstream> m_files;
public:
    void log(const torrent_id_t torrent, const std::string& header,
        const std::string& log, const priority priority);
    void flush()
    {
        for(auto& e : m_files) { TIDE_FLUSH(e.second); }
    }
};

class peer_session_logger
{
#ifdef TIDE_LOG_PEERS_SEPARATELY
    std::map<tcp::endpoint, std::ofstream> m_files;
#endif
    std::ofstream m_incoming_connections;
public:
    void log(const torrent_id_t torrent, const tcp::endpoint& endpoint,
        const std::string& header, const std::string& log, const priority priority);
    void flush()
    {
    #ifdef TIDE_LOG_PEERS_SEPARATELY
        for(auto& e : m_files) { TIDE_FLUSH(e.second); }
    #endif // TIDE_LOG_PEERS_SEPARATELY
        TIDE_FLUSH(m_incoming_connections);
    }
};

engine_logger engine_logger;
disk_io_logger disk_io_logger;
peer_session_logger peer_session_logger;
torrent_logger torrent_logger;

#ifndef TIDE_MIN_LOG_PRIORITY
# define TIDE_MIN_LOG_PRIORITY priority::low
#endif

constexpr auto g_open_mode = std::ios::app | std::ios::out;

template<typename String>
std::string make_log_path(const String& name)
{
#ifdef TIDE_LOG_PATH
    return std::string(TIDE_LOG_PATH) + '/' + name + "-log.txt";
#else
    throw "TIDE_LOG_PATH not defined";
#endif
}

#ifdef TIDE_ENABLE_LOGGING

# define TIDE_PRIORITY_CHAR(p) \
    char(p == priority::low ? 'l' : p == priority::normal ? 'n' : 'h')

# define TIDE_LOG(priority, stream, header, log) \
    stream << '[' << TIDE_PRIORITY_CHAR(priority) << '|' << header << "] " << log << '\n';

#define TIDE_STREAM std::clog

# ifdef TIDE_ENABLE_STREAM_DEBUGGING
#  define TIDE_CLOG(priority, file, header, log) do { \
    assert(file.is_open()); \
    TIDE_LOG(priority, file, header, log); \
    TIDE_LOG(priority, TIDE_STREAM, header, log); } while(0)
# else // TIDE_ENABLE_STREAM_DEBUGGING
#  define TIDE_CLOG(p, f, h, l) TIDE_LOG(p, f, h, l)
# endif // TIDE_ENABLE_STREAM_DEBUGGING

#endif // TIDE_ENABLE_LOGGING

void engine_logger::log(const std::string& header, const std::string& log, const priority priority)
{
#ifdef TIDE_ENABLE_LOGGING
    if(priority < TIDE_MIN_LOG_PRIORITY) { return; }
    if(!m_file.is_open())
    {
        m_file.open(make_log_path("engine"), g_open_mode);
    }
    TIDE_CLOG(priority, m_file, header, log);
#endif // TIDE_ENABLE_LOGGING
}

void disk_io_logger::log(const std::string& header, const std::string& log,
    const bool concurrent, const priority priority)
{
#ifdef TIDE_ENABLE_LOGGING
    if(priority < TIDE_MIN_LOG_PRIORITY) { return; }
    // if this is invoked from the network thread, we can write to stdout as well,
    // otherwise we can't use stream debugging/clog with disk_io when concurrent logging
    // is requested, as we'd need to mutually exclude clog each time some entity wanted
    // to do some logging, which is too expensive
    if(!concurrent) { TIDE_LOG(priority, TIDE_STREAM, header, log); }
    std::lock_guard<std::mutex> l(m_file_mutex);
    if(!m_file.is_open())
    {
        m_file.open(make_log_path("diskIO"), g_open_mode);
    }
    TIDE_LOG(priority, m_file, header, log);
#endif // TIDE_ENABLE_LOGGING
}

void torrent_logger::log(const torrent_id_t torrent, const std::string& header,
    const std::string& log, const priority priority)
{
#ifdef TIDE_ENABLE_LOGGING
    if(priority < TIDE_MIN_LOG_PRIORITY) { return; }
    auto it = m_files.find(torrent);
    if(it == m_files.end())
    {
        const auto path = make_log_path("torrent#" + std::to_string(torrent));
        it = m_files.emplace(torrent, std::ofstream(path.c_str(), g_open_mode)).first;
    }
    TIDE_CLOG(priority, it->second, header, log);
# ifdef TIDE_MERGE_TORRENT_LOGS
    const std::string new_header = "(torrent#" + std::to_string(torrent) + ')' + header;
    engine_logger.log(new_header, log, priority);
# endif // TIDE_MERGE_TORRENT_LOGS
#endif // TIDE_ENABLE_LOGGING
}

void peer_session_logger::log(const torrent_id_t torrent, const tcp::endpoint& endpoint,
    const std::string& header, const std::string& log, const priority priority)
{
#ifdef TIDE_ENABLE_LOGGING
    if(priority < TIDE_MIN_LOG_PRIORITY) { return; }

    const std::string ep_str = [&endpoint]
    {
        std::stringstream ss;
        ss << endpoint.address().to_string() << ':' << endpoint.port();
        return ss.str();
    }();
    const auto new_header = ep_str + '|' + header; 

# ifdef TIDE_LOG_PEERS_SEPARATELY
    auto it = m_files.find(endpoint);
    if(it == m_files.end())
    {
        const auto path = make_log_path("peer(" + ep_str + ")");
        it = m_files.emplace(endpoint, std::ofstream(path.c_str(), g_open_mode)).first;
    }
    TIDE_LOG(priority, it->second, new_header, log);
# endif // TIDE_LOG_PEERS_SEPARATELY

    if(torrent == -1)
    {
        // an incoming and as yet unattached peer requested logging, so can't put this
        // in any specific torrent log file, so put it in the incomming connections file
        if(!m_incoming_connections.is_open())
            m_incoming_connections.open(make_log_path("incoming_peers"), g_open_mode);
        TIDE_CLOG(priority, it->second, new_header, log);
    }
    else
    {
        torrent_logger.log(torrent, new_header, log, priority);
    }
#endif // TIDE_ENABLE_LOGGING
}

} // namespace detail

void log_torrent(const torrent_id_t torrent, const std::string& header,
    const std::string& log, const priority priority)
{
    detail::torrent_logger.log(torrent, header, log, priority);
}

void log_peer_session(const torrent_id_t torrent, const tcp::endpoint& endpoint,
    const std::string& header, const std::string& log, const priority priority)
{
    detail::peer_session_logger.log(torrent, endpoint, header, log, priority);
}

void log_engine(const std::string& header, const std::string& log,
    const priority priority)
{
    detail::engine_logger.log(header, log, priority);
}

void log_disk_io(const std::string& header, const std::string& log,
    const bool concurrent, const priority priority)
{
    detail::disk_io_logger.log(header, log, concurrent, priority);
}

void flush()
{
    detail::torrent_logger.flush();
    detail::peer_session_logger.flush();
    detail::engine_logger.flush();
    detail::disk_io_logger.flush();
}

} // namespace log
} // namespace tide
