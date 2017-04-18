#ifndef TORRENT_BLOCK_DISK_BUFFER_HEADER
#define TORRENT_BLOCK_DISK_BUFFER_HEADER

#include "block_info.hpp"
#include "mmap/mmap.hpp"

#include <vector>

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
    std::vector<mmap_source> chunks;

    block_source() = default;

    block_source(block_info info, std::vector<mmap_source>&& mmaps)
        : block_info(std::move(info))
        , chunks(std::move(mmaps))
    {}
};

/**
 * [WIP] This is not yet implemented but it is planned.
 *
 * This will be used to provde a writable buffer that maps directly to the file, to
 * avoid intermediate copies of the block to be written.
 */
struct block_sink : public block_info {};

#endif // TORRENT_BLOCK_DISK_BUFFER_HEADER
