#ifndef TIDE_ENDIAN_HEADER
#define TIDE_ENDIAN_HEADER

#include <endian/endian.hpp>
#include <cstdint>

namespace tide {
namespace endian {

/**
 * Parses a byte sequence and reconstructs into an integer of type T, converting
 * from Network Byte Order to Host Byte Order. The byte sequence must have at
 * least sizeof(T) bytes.
 */
template <typename T, typename InputIt>
T read_network(InputIt it)
{
    return ::endian::read<::endian::order::network, T>(it);
}

/**
 * Writes an integer of type T to the byte sequence pointed to by it, converting
 * it from Host Byte Order to Network Byte Order. The byte sequence must have
 * space for sizeof(T) bytes.
 */
template <typename T, typename InputIt>
void write_network(InputIt it, const T& h)
{
    ::endian::write<::endian::order::network>(h, it);
}

} // endian
} // tide

#endif // TIDE_ENDIAN_HEADER
