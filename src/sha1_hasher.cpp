#include "sha1_hasher.hpp"

namespace tide {

sha1_hasher::sha1_hasher()
{
    reset();
}

void sha1_hasher::reset()
{
    SHA1_Init(&context_);
}

sha1_hasher& sha1_hasher::update(const_view<uint8_t> buffer)
{
    SHA1_Update(&context_, buffer.data(), buffer.size());
    return *this;
}

sha1_hash sha1_hasher::finish()
{
    sha1_hash digest;
    SHA1_Final(digest.data(), &context_);
    return digest;
}

} // namespace tide
