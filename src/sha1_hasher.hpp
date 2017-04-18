#ifndef TORRENT_SHA1_HASHER_HEADER
#define TORRENT_SHA1_HASHER_HEADER

#include "units.hpp"
#include "view.hpp"

#include <memory>

/**
 * This class is used to verify pieces using the SHA-1 hashing algorithm.
 *
 * The entire piece that is to be hashed need not be kept in memory, it can be hashed
 * incrementally by feeding the hasher with blocks using the update() method.  When all
 * blocks have been hashed, use the finish() method to return the final SHA-1 digest.
 */
class sha1_hasher
{
    struct sha1_context;

public:

    sha1_hasher() = default;

    sha1_hasher& update(const_view<uint8_t> data);
    template<typename Buffer> sha1_hasher& update(const Buffer& buffer);

    sha1_hash finish();
};

#endif // TORRENT_SHA1_HASHER_HEADER
