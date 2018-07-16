#ifndef TIDE_LOG_HEADER
#define TIDE_LOG_HEADER

#include "socket.hpp"
#include "types.hpp"
#include "path.hpp"

#include <fstream>
#include <string>
#include <mutex>
#include <map>

namespace tide {
namespace log {

enum class priority
{
    low,
    normal,
    high
};

void log_torrent(const torrent_id_t torrent, const std::string& header,
        const std::string& log, const priority priority = priority::normal);
void log_peer_session(const torrent_id_t torrent, const tcp::endpoint& endpoint,
        const std::string& header, const std::string& log,
        const priority priority = priority::normal);
void log_engine(const std::string& header, const std::string& log,
        const priority priority = priority::normal);
void log_disk_io(const std::string& header, const std::string& log,
        const bool concurrent = false, const priority priority = priority::normal);

/**
 * Call this in a SIGABRT handler so that even when an assertion fires, everything
 * buffered is written to disk.
 */
void flush();

} // log
} // tide

#endif // TIDE_LOG_HEADER
