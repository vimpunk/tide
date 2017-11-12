#ifndef TIDE_UNITS_HEADER
#define TIDE_UNITS_HEADER

#include <cstdint>
#include <array>

namespace tide {

// File index can be used to retrieve files from torrent_storage. This is to avoid
// referring to the files directly, which allows more flexibility for future changes
// and safety as well.
using file_index_t = int;
using piece_index_t = int32_t;

static constexpr int invalid_piece_index = -1;

// Each torrent has its own unique identifier that is used internally for torrent
// lookups and priority ordering so that we don't have to use a torrent's info hash
// which would be slower due to being 16 bytes longer.
using torrent_id_t = int;

using sha1_hash = std::array<uint8_t, 20>;
using peer_id_t = sha1_hash;

} // namespace tide

#endif // TIDE_UNITS_HEADER
