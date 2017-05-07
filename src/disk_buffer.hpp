#ifndef TORRENT_DISK_BUFFER_HEADER
#define TORRENT_DISK_BUFFER_HEADER

#include <iterator>
#include <cassert>

class disk_io;

/**
 * This is a page aligned, fixed size (16KiB, the size of the block) buffer which is
 * used to hold a block copied from the peer_session's receive buffer, then to buffer
 * the block until it's written to disk.
 *
 * Only a single entity may have ownership of a buffer (unique_ptr semantics), so
 * buffers have to be moved around to the entities that handle them.
 *
 * Only disk_io may instantiate and release the resources of a disk buffer.
 * TODO make disk_buffer clean up after itself RAII style to avoid accidental memory leaks
 */
struct disk_buffer
{
    using value_type = uint8_t;
    using size_type = int;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type*;
    using const_pointer = const value_type*;
    using reference = value_type&;
    using const_reference = const value_type&;
    using iterator = pointer;
    using iterator_tag = std::random_access_iterator_tag;

private:

    pointer m_data;

    // only disk_io may instantiate a disk_buffer object
    friend class disk_io;
    disk_buffer(pointer data) : m_data(data) {}

public:

    disk_buffer(const disk_buffer&) = delete;
    disk_buffer& operator=(const disk_buffer&) = delete;

    disk_buffer(disk_buffer&&) = default;
    disk_buffer& operator=(disk_buffer&&) = default;

    operator bool() const noexcept
    {
        return m_data != nullptr;
    }

    pointer data() noexcept
    {
        assert(*this);
        return m_data;
    }

    const_pointer data() const noexcept
    {
        assert(*this);
        return m_data();
    }

    iterator begin() noexcept
    {
        assert(*this);
        return data();
    }

    const_iterator begin() const noexcept
    {
        assert(*this);
        return data();
    }

    iterator end() noexcept
    {
        assert(*this);
        return data() + 0x4000;
    }

    const_iterator end() const noexcept
    {
        assert(*this);
        return data() + 0x4000;
    }
};

#endif // TORRENT_DISK_BUFFER_HEADER
