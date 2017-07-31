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

inline size_t make_page_aligned(size_t offset) noexcept
{
    const static size_t page_size = sys::page_size();
    // use integer division to round down to the nearest page alignment
    return offset / page_size * page_size;
}

mmap_base::mmap_base(mmap_base&& other)
    : m_data(std::move(other.m_data))
    , m_length(std::move(other.m_length))
    , m_mapped_length(std::move(other.m_mapped_length))
    , m_file_handle(std::move(other.m_file_handle))
#ifdef _WIN32
    , m_file_mapping_handle(std::move(other.m_file_mapping_handle))
#endif
{
    other.m_data = nullptr;
    other.m_length = other.m_mapped_length = 0;
    other.m_file_handle = INVALID_HANDLE_VALUE;
#ifdef _WIN32
    other.m_file_mapping_handle = INVALID_HANDLE_VALUE;
#endif
}

mmap_base& mmap_base::operator=(mmap_base&& other)
{
    if(this != &other)
    {
        m_data = std::move(other.m_data);
        m_length = std::move(other.m_length);
        m_mapped_length = std::move(other.m_mapped_length);
        m_file_handle = std::move(other.m_file_handle);
#ifdef _WIN32
        m_file_mapping_handle = std::move(other.m_file_mapping_handle);
#endif
        other.m_data = nullptr;
        other.m_length = other.m_mapped_length = 0;
        other.m_file_handle = INVALID_HANDLE_VALUE;
#ifdef _WIN32
        other.m_file_mapping_handle = INVALID_HANDLE_VALUE;
#endif
    }
    return *this;
}

void mmap_base::map(const handle_type handle, const size_type offset,
    const size_type length, const access_mode mode, std::error_code& error)
{
    error.clear();
    if(handle == INVALID_HANDLE_VALUE)
    {
        error = std::make_error_code(std::errc::bad_file_descriptor);
        return;
    }
    m_file_handle = handle;

    // TODO we might not want to query the file size with every mapping... maybe make
    // it an optional parameter?
    if(offset + length > query_file_size(error))
    {
        if(!error) { error = std::make_error_code(std::errc::invalid_argument); }
    }
    if(error) { return; }

    map(offset, length, mode, error);
}

void mmap_base::map(const size_type offset, const size_type length,
    const access_mode mode, std::error_code& error)
{
    const size_type aligned_offset = make_page_aligned(offset);
    const size_type length_to_map = offset - aligned_offset + length;
#if defined(_WIN32)
    const size_type max_file_size = offset + length;
    m_file_mapping_handle = ::CreateFileMapping(
        m_file_handle,
        0,
        mode == access_mode::read_only ? PAGE_READONLY : PAGE_READWRITE,
        int64_high(max_file_size),
        int64_low(max_file_size),
        0);
    if(m_file_mapping_handle == INVALID_HANDLE_VALUE)
    {
        error = sys::latest_error();
        return;
    }

    const pointer mapping_start = static_cast<pointer>(::MapViewOfFile(
        m_file_mapping_handle,
        mode == access_mode::read_only ? FILE_MAP_READ : FILE_MAP_WRITE,
        int64_high(aligned_offset),
        int64_low(aligned_offset),
        length_to_map));
    if(mapping_start == nullptr)
    {
        error = sys::latest_error();
        return;
    }
#else
    const pointer mapping_start = static_cast<pointer>(::mmap(
        0, // don't give hint as to where to map
        length_to_map,
        mode == mmap_base::access_mode::read_only ? PROT_READ : PROT_WRITE,
        MAP_SHARED, // TODO do we want to share it?
        m_file_handle,
        aligned_offset));
    if(mapping_start == MAP_FAILED)
    {
        error = sys::latest_error();
        return;
    }
#endif
    m_data = mapping_start + offset - aligned_offset;
    m_length = length;
    m_mapped_length = length_to_map;
}

void mmap_base::sync(std::error_code& error)
{
    error.clear();
    verify_file_handle(error);
    if(error) { return; }

    if(data() != nullptr)
    {
#ifdef _WIN32
        if(::FlushViewOfFile(get_mapping_start(), m_mapped_length) == 0
           || ::FlushFileBuffers(m_file_handle) == 0)
#else
        if(::msync(get_mapping_start(), m_mapped_length, MS_SYNC) != 0)
#endif
        {
            error = sys::latest_error();
            return;
        }
    }
#ifdef _WIN32
    if(::FlushFileBuffers(m_file_handle) == 0)
    {
        error = sys::latest_error();
    }
#endif
}

void mmap_base::unmap()
{
    // TODO do we care about errors here?
    if((m_data != nullptr) && (m_file_handle != INVALID_HANDLE_VALUE))
    {
#ifdef _WIN32
        ::UnmapViewOfFile(get_mapping_start());
        ::CloseHandle(m_file_mapping_handle);
        m_file_mapping_handle = INVALID_HANDLE_VALUE;
#else
        ::munmap(const_cast<pointer>(get_mapping_start()), m_mapped_length);
#endif
    }
    m_data = nullptr;
    m_length = m_mapped_length = 0;
    m_file_handle = INVALID_HANDLE_VALUE;
#ifdef _WIN32
    m_file_mapping_handle = INVALID_HANDLE_VALUE;
#endif
}

inline mmap_base::size_type mmap_base::query_file_size(std::error_code& error) noexcept
{
#ifdef _WIN32
    PLARGE_INTEGER file_size;
    if(::GetFileSizeEx(m_file_handle, &file_size) == 0)
    {
        error = sys::latest_error();
        return 0;
    }
    return file_size;
#else
    struct stat sbuf;
    if(::fstat(m_file_handle, &sbuf) == -1)
    {
        error = sys::latest_error();
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
    if(!is_open() || !is_mapped())
    {
        error = std::make_error_code(std::errc::bad_file_descriptor);
    }
}

} // namespace detail
} // namespace tide
