#ifndef TIDE_DISK_BUFFER_HEADER
#define TIDE_DISK_BUFFER_HEADER

#include "mmap.hpp"

#include <iterator>
#include <cassert>
#include <memory>

#include <boost/pool/pool.hpp>

namespace tide {
namespace util {

struct buffer
{
    using value_type = uint8_t;
    using size_type = int;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type*;
    using const_pointer = const value_type*;
    using reference = value_type&;
    using const_reference = const value_type&;
    using iterator = pointer;
    using const_iterator = const_pointer;
    using iterator_tag = std::random_access_iterator_tag;

    buffer() = default;
    buffer(const buffer&) = default;
    buffer& operator=(const buffer&) = default;
    buffer(buffer&&) = default;
    buffer& operator=(buffer&&) = default;
    virtual ~buffer() = default;

    virtual pointer data() = 0;
    virtual const_pointer data() const = 0;
    virtual size_type size() const = 0;
};

} // namespace util

class mmap_source_buffer : public util::buffer
{
    mmap_source m_source;
public:
    explicit mmap_source_buffer(mmap_source source) : m_source(std::move(source)) {}

    pointer data() { return m_source.data(); }
    const_pointer data() const { return m_source.data(); }
    size_type size() const { return m_source.size(); }
};

using disk_buffer_pool = boost::pool<>;

/**
 * This is a fixed size 16KiB pool allocated buffer which is used for holding a block
 * copied from peer_session's receive buffer, then to buffer this block until it is
 * written to disk.
 * It is also used when we're not memory mapping blocks but instead copying the file
 * data from the kernel's page cache into our address space and pass that along to
 * peer_session for sending the block to its peer.
 *
 * It has shared_ptr semantics in that only the destruction of the last copy will free
 * the underlying resource (that is, give back the memory to the allocating pool). Thus,
 * ensuring thread-safety (not writing to the same buffer simultaneously) is the
 * responsibility of the user.
 *
 * The memory allocated is always 16KiB for efficiency purposes, but in certain cases,
 * such as a very small download, or the last block in a download (which almost certainly
 * is not 16KiB), the desired size is smaller. Thus, the functions size and length return
 * this desired size, not 16KiB, though in most cases the two will be the same.
 *
 * NOTE: the pool that allocates memory for disk_buffer must outlive disk_buffer.
 */
class disk_buffer : public util::buffer
{
    std::shared_ptr<value_type> m_data;
    // Reflects the desired size, not the amount of memory, which is always 16KiB.
    int m_size = 0;

public:

    disk_buffer() = default; // default is invalid buffer
    disk_buffer(pointer data, size_type size, disk_buffer_pool& pool)
        : m_data(data, [&pool](pointer p) { pool.free(p); })
        , m_size(size)
    {
        assert(size <= 0x4000);
    }

    operator bool() const noexcept { return m_data != nullptr; }

    size_type size() const noexcept override { return m_size; }
    size_type length() const noexcept { return m_size; }

    pointer data() noexcept override { return m_data.get(); }
    const_pointer data() const noexcept override { return m_data.get(); }

    iterator begin() noexcept { return data(); }
    const_iterator begin() const noexcept { return data(); }

    iterator end() noexcept { return data() + size(); }
    const_iterator end() const noexcept { return data() + size(); }
};

/**
 * This is a general abstraction for modeling a buffer that acts as a source (that is,
 * an immutable buffer). This is necessary because sometimes the portion of the file
 * that represents the requested block may be memory mapped, or it may be copied into
 * a disk_buffer, but in the end the usage and the purpose is the same.
 *
 * It has shared_ptr semantics because blocks are stored in the disk cache as
 * source_buffers as they too may be either memory mappings or disk_buffers.
 */
class source_buffer
{
public:

    using buffer_type = util::buffer;
    using value_type = buffer_type::value_type;
    using size_type = buffer_type::size_type;
    using difference_type = buffer_type::difference_type;
    //using pointer = buffer_type::pointer;
    using const_pointer = buffer_type::const_pointer;
    //using reference = buffer_type::reference;
    using const_reference = buffer_type::const_reference;
    //using iterator = buffer_type::iterator;
    using const_iterator = buffer_type::const_iterator;
    using iterator_tag = buffer_type::iterator_tag;

private:
    std::shared_ptr<buffer_type> m_buffer;
public:
    
    source_buffer(std::shared_ptr<buffer_type> buffer) : m_buffer(buffer) {}

    operator bool() const noexcept { return m_buffer != nullptr; }

    const_pointer data() const noexcept { return m_buffer->data(); }
    size_type size() const noexcept { return m_buffer->size(); }

    const_iterator begin() const noexcept { return data(); }
    const_iterator end() const noexcept { return data() + size(); }
};

} // namespace tide

#endif // TIDE_DISK_BUFFER_HEADER
