#ifndef TORRENT_UNITS_HEADER
#define TORRENT_UNITS_HEADER

#include <cstdint>
#include <array>

using piece_index_t = int32_t;
using torrent_id_t = int32_t;

using sha1_hash = std::array<uint8_t, 20>;
using peer_id = sha1_hash;

#endif // TORRENT_UNITS_HEADER
