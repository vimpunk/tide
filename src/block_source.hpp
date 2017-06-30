#ifndef TIDE_BLOCK_DISK_BUFFER_HEADER
#define TIDE_BLOCK_DISK_BUFFER_HEADER

#include "disk_buffer.hpp"
#include "block_info.hpp"

#include <vector>

namespace tide {

/**
 * This is a read only mapping into a memory mapped region of the file in which the
 * block, represented by this buffer, is mapped. Since a block may span several files, a
 * list of block 'chunks' is used in all cases. This is not to be confused with more
 * blocks, this object always represents a single block.
 *
 * The buffer is valid as long as at least one copy of it exists (like shared_ptr).
 *
 * This way the requested block can be copied directly into the socket's receive buffer
 * without any intermediate copies.
 */
struct block_source : public block_info
{
    std::vector<source_buffer> buffers;

    block_source() = default;

    block_source(block_info info, std::vector<source_buffer> buffers_)
        : block_info(std::move(info))
        , buffers(std::move(buffers_))
    {}

    block_source(block_info info, source_buffer buffer)
        : block_info(std::move(info))
    {
        buffers.emplace_back(std::move(buffer));
    }
};

// TODO make a specialization for when only a single buffer is used to represent block
// to avoid all the vector allocations

} // namespace tide

#endif // TIDE_BLOCK_DISK_BUFFER_HEADER
