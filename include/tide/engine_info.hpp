#ifndef TIDE_ENGINE_INFO_HEADER
#define TIDE_ENGINE_INFO_HEADER

#include "types.hpp"

namespace tide {

struct engine_info
{
    uint64_t update_counter = 0;

    // The number of active incomplete and complete torrents.
    int num_active_leeches = 0;
    int num_active_seeds = 0;

    // The number of active slow incomplete and complete torrents.
    int num_slow_leeches = 0;
    int num_slow_seeds = 0;

    int num_auto_managed_torrents = 0;

    int num_connections = 0;
};

} // namespace tide

#endif // TIDE_ENGINE_INFO_HEADER
