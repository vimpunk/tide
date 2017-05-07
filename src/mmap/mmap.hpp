#ifndef MMAP_HEADER
#define MMAP_HEADER

#include "../path.hpp"

#include <iterator>
#include <cstdint>
#include <string>
#include <memory>

class mmap_impl;
size_t os_page_size();

/**
 * Defines functions common to read only and read write memory mappings. In either
 * case, the client need not adjust the offset to be aligned with the system's page
 * alignment, this is taken care of by mmap_base.
 */
struct mmap_base
{
    using value_type = uint8_t;
    using size_type = int64_t;
    using reference = value_type&;
    using const_reference = const reference;
    using pointer = value_type*;
    using const_pointer = const pointer;
    using difference_type = std::ptrdiff_t;
    using iterator = pointer;
    using const_iterator = const_pointer;
    using iterator_category = std::random_access_iterator_tag;

    enum class access_mode
    {
        read_only,
        read_write
    };

protected:

    std::shared_ptr<mmap_impl> m_impl;

public:

    void unmap();

    /** NOTE: this operation invokes a system call. */
    size_type query_file_size();

    bool is_open() const noexcept;
    bool is_empty() const noexcept;
    size_type length() const noexcept;
    size_type size() const noexcept;
    size_type mapped_length() const noexcept;

    const_iterator begin() const noexcept;
    const_iterator cbegin() const noexcept;
    const_iterator end() const noexcept;
    const_iterator cend() const noexcept;

    const_pointer data() const noexcept;

protected:

    pointer data() noexcept;

    void map(
        const path& path,
        size_type offset,
        size_type length,
        access_mode mode
    );

    void map(

    );
};

/**
 * These are the mmap classes that can be used. There are read-only and read-write
 * versions.
 *
 * When specifying a file to map, there is no need to worry about providing
 * offsets that are aligned with the operating system's page granularity, this is taken
 * care of within the class in both cases.
 *
 * Both classes have std::shared_ptr<> semantics, thus the instances may be copied and
 * sued as the file will not be unmapped (and in the case of mmap_sink the file flushed
 * to disk) until the last copy is destructed.
 *
 * Remapping a file is possible, but unmap must be called before that.
 */

/** A read-only file memory mapping. */
struct mmap_source: public mmap_base
{
    mmap_source() = default;
    mmap_source(const path& path, size_type offset, size_type length);
    void map(const path& path, size_type offset, size_type length);
};

/** A read-write file memory mapping. */
struct mmap_sink: public mmap_base
{
    mmap_sink() = default;
    mmap_sink(const path& path, size_type offset, size_type length);
    ~mmap_sink();

    void map(const path& path, size_type offset, size_type length);
    void flush();

    pointer data() noexcept;
    iterator begin() noexcept;
    iterator end() noexcept;
};

// ---------------
// -- mmap base --
// ---------------

inline bool mmap_base::is_empty() const noexcept
{
    return length() == 0;
}

inline mmap_base::size_type mmap_base::size() const noexcept
{
    return length();
}

inline mmap_base::const_iterator mmap_base::begin() const noexcept
{
    return data();
}

inline mmap_base::const_iterator mmap_base::cbegin() const noexcept
{
    return data();
}

inline mmap_base::const_iterator mmap_base::end() const noexcept
{
    return begin() + length();
}

inline mmap_base::const_iterator mmap_base::cend() const noexcept
{
    return end();
}

// -----------------
// -- mmap source --
// -----------------

inline
mmap_source::mmap_source(const path& path, size_type offset, size_type length)
{
    map(path, offset, length);
}

inline void mmap_source::map(const path& path, size_type offset, size_type length)
{
    mmap_base::map(path, offset, length, access_mode::read_only);
}

// ---------------
// -- mmap sink --
// ---------------

inline mmap_sink::mmap_sink(const path& path, size_type offset, size_type length)
{
    map(path, offset, length);
}

inline mmap_sink::~mmap_sink()
{
    flush();
}

inline void mmap_sink::map(const path& path, size_type offset, size_type length)
{
    mmap_base::map(path, offset, length, access_mode::read_write);
}

inline mmap_base::iterator mmap_sink::data() noexcept
{
    return mmap_base::data();
}

inline mmap_base::iterator mmap_sink::begin() noexcept
{
    return data();
}

inline mmap_base::iterator mmap_sink::end() noexcept
{
    return data() + length();
}

#endif
