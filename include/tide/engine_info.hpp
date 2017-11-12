#ifndef TIDE_ENGINE_INFO_HEADER
#define TIDE_ENGINE_INFO_HEADER

#include "types.hpp"

namespace tide {

struct engine_info
{
    uint64_t update_counter = 0;

    int num_active_leeches = 0;
    int num_active_seeds = 0;

    int num_slow_leeches = 0;
    int num_slow_seeds = 0;

    int num_auto_managed_torrents = 0;
    int num_connections = 0;

    /* TODO comprehensive engine level stats aggregation?
    // The number of unserviced requests that all peer_sessions in torrent have issued.
    // It's decremented if we cancel or drop a request. This is used to determine when
    // to enter end-game mode. Note that some blocks may be requested by multiple peers,
    // so if this value reaches num_blocks, it may not mean that we have requested all
    // blocks in torrent, but it's a close enough approximation.
    int num_pending_blocks = 0;

    int num_seeders = 0;
    int num_leechers = 0;
    int num_unchoked_peers = 0;

    // The number of peers to which we're currently connecting but have as yet not been
    // connected. This is used to cap the number of "half-open" connections. This is
    // only for outbound connections.
    int num_connecting_sessions = 0;
    */
};

} // namespace tide

#endif // TIDE_ENGINE_INFO_HEADER
