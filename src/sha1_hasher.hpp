#ifndef TORRENT_SHA1_HASHER_HEADER
#define TORRENT_SHA1_HASHER_HEADER

#include "units.hpp"
#include "view.hpp"

#include <utility> // declval
#include <memory>
#include <array>

#include <openssl/sha.h>

namespace tide {

/**
 * This class is used to verify pieces using the SHA-1 hashing algorithm.
 *
 * The entire piece that is to be hashed need not be kept in memory, it can be hashed
 * incrementally by feeding the hasher with blocks using the update() method.  When all
 * blocks have been hashed, use the finish() method to return the final SHA-1 digest.
 */
class sha1_hasher
{
    SHA_CTX m_context;

public:

    sha1_hasher();

    void reset();

    sha1_hasher& update(const_view<uint8_t> buffer);
    template<
        typename Container,
        typename = decltype(std::declval<Container>().data())
    > sha1_hasher& update(const Container& buffer);
    template<size_t N> sha1_hasher& update(const uint8_t (&buffer)[N]);
    template<size_t N> sha1_hasher& update(const std::array<uint8_t, N>& buffer);

    sha1_hash finish();
};

template<typename Container, typename>
sha1_hasher& sha1_hasher::update(const Container& buffer)
{
    return update(const_view<uint8_t>(
        reinterpret_cast<const uint8_t*>(buffer.data()),
        buffer.size()
    ));
}

template<size_t N>
sha1_hasher& sha1_hasher::update(const uint8_t (&buffer)[N])
{
    return update(const_view<uint8_t>(buffer));
}

template<size_t N>
sha1_hasher& sha1_hasher::update(const std::array<uint8_t, N>& buffer)
{
    return update(const_view<uint8_t>(buffer));
}

/**
 * This is a convenience method for when update would be called only once because all
 * the data is available.
 */
template<typename Buffer>
static sha1_hash create_sha1_digest(const Buffer& buffer)
{
    sha1_hasher hasher;
    hasher.update(buffer);
    return hasher.finish();
}

} // namespace tide

#endif // TORRENT_SHA1_HASHER_HEADER
