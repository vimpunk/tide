#include "mmap.hpp"

#if defined(_WIN32)
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
#else
# include <fcntl.h>
# include <unistd.h>
# include <sys/mman.h>
# include <sys/stat.h>
#endif

#include <stdexcept>
#include <iostream>
#include <cassert>

// TODO
// universal file paths (boost has one but let's decrease dependencies)

inline size_t get_page_size()
{
#if defined(_WIN32)
    SYSTEM_INFO SystemInfo;
    GetSystemInfo(&SystemInfo);
    return SystemInfo.dwAllocationGranularity;
#else
    return sysconf(_SC_PAGE_SIZE);
#endif
}

size_t os_page_size()
{
    static const size_t page_size = get_page_size();
    return page_size;
}

#if defined(_WIN32)
inline DWORD get_int64_high(int64_t n) noexcept
{
    return n >> 32;
}

inline DWORD get_int64_low(int64_t n) noexcept
{
    return n & 0xFF'FF'FF'FF;
}
#endif

/** This is the concrete mmap implementation. */
struct mmap_impl
{
    using value_type = mmap_base::value_type;
    using size_type = mmap_base::size_type;
    using reference = mmap_base::reference;
    using const_reference = mmap_base::const_reference;
    using pointer = mmap_base::pointer;
    using const_pointer = mmap_base::const_pointer;
    using difference_type = mmap_base::difference_type;
    using iterator = mmap_base::iterator;
    using const_iterator = mmap_base::const_iterator;
    using iterator_category = mmap_base::iterator_category;

private:

#if defined(_WIN32)
    using handle_t = void*;
#else
    using handle_t = int;
#endif

    // Points to the first requested byte, and NOT to the actual start of the mapping!
    pointer m_data = nullptr;

    // Requested length, i.e. not the length of the full mapping.
    size_type m_length = 0;
    size_type m_mapped_length = 0;

    handle_t m_file_handle;
#if defined(_WIN32)
    handle_t m_file_mapping_handle;
#endif

public:

    mmap_impl()
#if defined(_WIN32)
        : m_file_handle(INVALID_HANDLE_VALUE)
        , m_file_mapping_handle(INVALID_HANDLE_VALUE)
#else
        : m_file_handle(-1)
#endif
    {}

    mmap_impl(
        const std::string& path,
        size_type offset,
        size_type length,
        mmap_base::access_mode mode
    )
        : mmap_impl()
    {
        map(path, offset, length, mode);
    }

    ~mmap_impl()
    {
        unmap();
    }

    void map(
        const std::string& path,
        size_type offset,
        size_type length,
        mmap_base::access_mode mode
    )
    {
        assert(!is_open());
        open_file(path, mode);
        const mmap_context ctx(offset, length, query_file_size());
        m_data = mmap(ctx, mode);
        m_length = ctx.length;
        m_mapped_length = ctx.length_to_map;
    }

    void unmap()
    {
        if(is_open())
        {
            munmap();
            close_file();
        }
    }

    bool is_open() const noexcept
    {
        return m_file_handle !=
#if defined(_WIN32)
            INVALID_HANDLE_VALUE
#else
            -1
#endif
        ;
    }        

    bool is_empty() const noexcept { return length() == 0; }
    size_type size() const noexcept { return length(); }
    size_type length() const noexcept { return m_length; }
    size_type mapped_length() const noexcept { return m_mapped_length; }

    pointer data() noexcept { return m_data; }
    const_pointer data() const noexcept { return m_data; }

    const_iterator begin() const noexcept { return data(); }
    const_iterator cbegin() const noexcept { return data(); }
    const_iterator end() const noexcept { return begin() + length(); }
    const_iterator cend() const noexcept { return end(); }

    size_type query_file_size()
    {
        if(!is_open())
        {
            return 0;
        }
#if defined(_WIN32)
        DWORD high_size;
        DWORD low_size = GetFileSize(m_file_handle, &high_size);
        return (size_t(high_size) << 32) | low_size;
#else
        struct stat sbuf;
        if(::fstat(m_file_handle, &sbuf) == -1)
        {
            return 0;
        }
        return sbuf.st_size;
#endif
    }

    pointer get_mapping_start() const noexcept
    {
        if(!m_data)
        {
            return nullptr;
        }
        return m_data - (m_mapped_length - m_length);
    }

    void flush()
    {
        if(!is_open())
        {
            return;
        }
        if(m_data != nullptr)
        {
            pointer mapping_start = get_mapping_start();
#if defined(_WIN32)
            if(::FlushViewOfFile(mapping_start, m_mapped_length) == 0
               || ::FlushFileBuffers(m_file_handle) == 0)
#else
            if(::msync(mapping_start, m_mapped_length, MS_SYNC) != 0)
#endif
            {
                throw std::runtime_error("could not flush memory mapped region");
            }
        }
#if defined(_WIN32)
        if(::FlushFileBuffers(m_file_handle) == 0)
        {
            throw std::runtime_error("could not flush memory mapped region");
        }
#endif
    }

private:

    /**
     * This is used to map values requested by user to values compatible with the
     * operating system, and store these values.
     */
    struct mmap_context
    {
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

        size_type offset_till_requested_start() const noexcept
        {
            return offset - aligned_offset;
        }

#if defined(_WIN32)
        size_type max_file_size() const noexcept
        {
            return offset + length;
        }
#endif

        std::string str() const noexcept
        {
            return
                "{length: " + std::to_string(length)
                + ", offset: " + std::to_string(offset)
                + ", length_to_map: " + std::to_string(length_to_map)
                + ", aligned_offset: " + std::to_string(aligned_offset)
                + '}';
        }

    private:

        static size_type adjust_length_to_file_size(
            size_type offset,
            size_type length,
            size_type file_size
        ) noexcept
        {
            return offset + length >= file_size ? file_size - offset
                                                : length;
        }

        static size_type get_aligned_offset(size_type offset) noexcept
        {
            const auto page_size = os_page_size();
            // use integer division to round down to the nearest page alignment
            return offset / page_size * page_size;
        }
    };

    void open_file(const std::string& path, mmap_base::access_mode mode)
    {
        if(path.empty())
        {
            return;
        }
        if(is_open())
        {
            throw std::runtime_error("memory mapped file already open");
        }
#if defined(_WIN32)
        m_file_handle = ::CreateFile(
            path.c_str(),
            (mode == mmap_base::access_mode::read_only ? GENERIC_READ
                                                       : GENERIC_READ | GENERIC_WRITE),
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            0,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0
        );
        if(m_file_handle == INVALID_HANDLE_VALUE)
        {
            throw std::runtime_error("invalid file handle for: " + path);
        }
#else
        m_file_handle = ::open(
            path.c_str(),
            (mode == mmap_base::access_mode::read_only ? O_RDONLY
                                                       : O_RDWR)
        );
        if(m_file_handle == -1)
        {
            throw std::runtime_error("invalid file handle for: " + path);
        }
#endif
    }

    void close_file()
    {
#if defined(_WIN32)
        ::CloseHandle(m_file_handle);
        m_file_handle = INVALID_HANDLE_VALUE;
#else
        ::close(m_file_handle);
        m_file_handle = -1;
#endif
    }

    pointer mmap(const mmap_context& mmap_ctx, mmap_base::access_mode mode)
    {
#if defined(_WIN32)
        m_file_mapping_handle = ::CreateFileMapping(
            m_file_handle,
            0,
            (mode == mmap_base::access_mode::read_only ? PAGE_READONLY
                                                       : PAGE_READWRITE),
            get_int64_high(mmap_ctx.max_file_size()),
            get_int64_low(mmap_ctx.max_file_size()),
            0
        );
        if(m_file_mapping_handle == INVALID_HANDLE_VALUE)
        {
            throw std::runtime_error("error while mapping file");
        }

        pointer mapping_start = static_cast<pointer>(::MapViewOfFile(
            m_file_mapping_handle,
            (mode == mmap_base::access_mode::read_only ? FILE_MAP_READ
                                                       : FILE_MAP_WRITE),
            get_int64_high(mmap_ctx.aligned_offset),
            get_int64_low(mmap_ctx.aligned_offset),
            mmap_ctx.length_to_map
        ));
        if(mapping_start == nullptr)
        {
            throw std::runtime_error("error while mapping file");
        }
#else
        pointer mapping_start = static_cast<pointer>(::mmap(
            0,
            mmap_ctx.length_to_map,
            (mode == mmap_base::access_mode::read_only ? PROT_READ
                                                       : PROT_WRITE),
            MAP_SHARED,
            m_file_handle,
            mmap_ctx.aligned_offset
        ));
        if(mapping_start == MAP_FAILED)
        {
            throw std::runtime_error("error while mapping file");
        }
#endif
        return mapping_start + mmap_ctx.offset_till_requested_start();
    }

    void munmap()
    {
        if(m_data != nullptr)
        {
            pointer mapping_start = get_mapping_start();
#if defined(_WIN32)
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
};

// ---------------
// -- mmap base -- 
// ---------------

bool mmap_base::is_open() const noexcept
{
    return m_impl && m_impl->is_open();
}        

void mmap_base::map(
    const std::string& path,
    size_type offset,
    size_type length,
    access_mode mode
)
{
    if(!m_impl)
    {
        m_impl = std::make_shared<mmap_impl>();
    }
    m_impl->map(path, offset, length, mode);
}

void mmap_base::unmap()
{
    if(m_impl)
    {
        m_impl->unmap();
    }
}

mmap_base::size_type mmap_base::length() const noexcept
{
    return m_impl ? m_impl->length()
                  : 0;
}

mmap_base::size_type mmap_base::mapped_length() const noexcept
{
    return m_impl ? m_impl->mapped_length()
                  : 0;
}

mmap_base::size_type mmap_base::query_file_size()
{
    return m_impl ? m_impl->query_file_size()
                  : 0;
}

mmap_base::pointer mmap_base::data() noexcept
{
    return m_impl ? m_impl->data()
                  : nullptr;
}

mmap_base::const_pointer mmap_base::data() const noexcept
{
    return m_impl ? m_impl->data()
                  : nullptr;
}

// ---------------
// -- mmap sink -- 
// ---------------

void mmap_sink::flush()
{
    if(m_impl)
    {
        m_impl->flush();
    }
}
