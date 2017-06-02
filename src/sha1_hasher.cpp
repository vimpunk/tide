#include "sha1_hasher.hpp"

sha1_hasher::sha1_hasher()
{
    reset();
}

void sha1_hasher::reset()
{
    SHA1_Init(&m_context);
}

sha1_hasher& sha1_hasher::update(const_view<uint8_t> buffer)
{
    SHA1_Update(&m_context, buffer.data(), buffer.size());
    return *this;
}

sha1_hash sha1_hasher::finish()
{
    sha1_hash digest;
    SHA1_Final(digest.data(), &m_context);
    return digest;
}
