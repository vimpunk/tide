#include "mmap.hpp"

#include <sys/mman.h>

#if defined(_WIN32)
inline DWORD int64_high(int64_t n) noexcept
{
    return n >> 32;
}

inline DWORD int64_low(int64_t n) noexcept
{
    return n & 0xFF'FF'FF'FF;
}
#endif

namespace tide {
namespace detail {

/**
 * This is used to map values requested by user to values compatible with the
 * operating system, and store these values.
 * TODO verify this
 */
struct mmap_context
{
    using size_type = mmap_base::size_type;

    // This is the offset that the user requested.
    const size_type offset = 0;

    // This is the length that the user requested, which may be truncated to fit the
    // file size.
    const size_type length = 0;

    // This is the user's offset aligned to a page boundary.
    const size_type aligned_offset = 0;

    // This is the user's offset aligned to a page boundary.
    const size_type length_to_map = 0;

    mmap_context(size_type offset_, size_type length_, size_type file_size)
        : offset(offset_)
        , length(adjust_length_to_file_size(offset_, length_, file_size))
        , aligned_offset(get_aligned_offset(offset_))
        , length_to_map(offset - aligned_offset + length)
    {
        assert(length_to_map >= 0);
        assert(offset < file_size);
    }

    size_type requested_start_offset() const noexcept
    {
        return offset - aligned_offset;
    }

#ifdef _WIN32
    size_type max_file_size() const noexcept
    {
        return offset + length;
    }
#endif

private:

    static size_type adjust_length_to_file_size(size_type offset,
        size_type length, size_type file_size) noexcept
    {
        if(offset + length >= file_size)
            return file_size - offset;
        else
            return length;
    }

    static size_type get_aligned_offset(size_type offset) noexcept
    {
        const auto page_size = fs::page_size();
        // use integer division to round down to the nearest page alignment
        return offset / page_size * page_size;
    }
};

void mmap_base::map(fs::file_handle_type file_handle, size_type offset, size_type length,
    const access_mode mode, std::error_code& error)
{
    verify_file_handle(error);
    if(error) { return; }

    m_file_handle = file_handle;
    map(offset, length, mode, error);
}

void mmap_base::map(size_type offset, size_type length,
    const access_mode mode, std::error_code& error)
{
    mmap_context mmap_ctx(offset, length, query_file_size(error));
    if(error) { return; }
#if defined(_WIN32)
    m_file_mapping_handle = ::CreateFileMapping(
        m_file_handle,
        0,
        mode == access_mode::read_only ? PAGE_READONLY : PAGE_READWRITE,
        int64_high(mmap_ctx.max_file_size()),
        int64_low(mmap_ctx.max_file_size()),
        0);
    if(m_file_mapping_handle == INVALID_HANDLE_VALUE)
    {
        util::assign_errno(error);
        return;
    }

    pointer mapping_start = static_cast<pointer>(::MapViewOfFile(
        m_file_mapping_handle,
        mode == access_mode::read_only ? FILE_MAP_READ : FILE_MAP_WRITE,
        int64_high(mmap_ctx.aligned_offset),
        int64_low(mmap_ctx.aligned_offset),
        mmap_ctx.length_to_map));
    if(mapping_start == nullptr)
    {
        util::assign_errno(error);
        return;
    }
#else
    pointer mapping_start = static_cast<pointer>(::mmap(
        0, // don't give hint as to where to map
        mmap_ctx.length_to_map,
        mode == mmap_base::access_mode::read_only ? PROT_READ : PROT_WRITE,
        MAP_SHARED, // TODO do we want to share it?
        m_file_handle,
        mmap_ctx.aligned_offset));
    if(mapping_start == MAP_FAILED)
    {
        util::assign_errno(error);
        return;
    }
#endif
    m_data = mapping_start + mmap_ctx.requested_start_offset();
    m_length = mmap_ctx.length;
    m_mapped_length = mmap_ctx.length_to_map;
}

void mmap_base::sync(std::error_code& error)
{
    verify_file_handle(error);
    if(error) { return; }

    if(data() != nullptr)
    {
        pointer mapping_start = get_mapping_start();
#ifdef _WIN32
        if(::FlushViewOfFile(mapping_start, m_mapped_length) == 0
           || ::FlushFileBuffers(m_file_handle) == 0)
#else
        if(::msync(mapping_start, m_mapped_length, MS_SYNC) != 0)
#endif
        {
            util::assign_errno(error);
            return;
        }
    }
#ifdef _WIN32
    if(::FlushFileBuffers(m_file_handle) == 0) { util::assign_errno(error); }
#endif
}

void mmap_base::unmap()
{
    // TODO do we care about errors here?
    if(m_data != nullptr)
    {
        pointer mapping_start = get_mapping_start();
#ifdef _WIN32
        ::UnmapViewOfFile(mapping_start);
        ::CloseHandle(m_file_mapping_handle);
        m_file_mapping_handle = INVALID_HANDLE_VALUE;
#else
        ::munmap(const_cast<pointer>(mapping_start), m_mapped_length);
#endif
    }
    m_data = nullptr;
    m_length = m_mapped_length = 0;
}

inline mmap_base::size_type mmap_base::query_file_size(std::error_code& error) noexcept
{
#ifdef _WIN32
    PLARGE_INTEGER file_size;
    if(::GetFileSizeEx(m_file_handle, &file_size) == 0)
    {
        util::assign_errno(error);
        return 0;
    }
    return file_size;
#else
    struct stat sbuf;
    if(::fstat(m_file_handle, &sbuf) == -1)
    {
        util::assign_errno(error);
        return 0;
    }
    return sbuf.st_size;
#endif
}

inline mmap_base::pointer mmap_base::get_mapping_start() noexcept
{
    if(!m_data) { return nullptr; }
    const auto offset = m_mapped_length - m_length;
    return m_data - offset;
}

inline void mmap_base::verify_file_handle(std::error_code& error) const noexcept
{
    error.clear();
    if(!is_open() || !is_mapped())
    {
        error = std::make_error_code(std::errc::bad_file_descriptor);
    }
}

} // namespace detail
} // namespace tide
