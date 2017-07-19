#ifndef TIDE_MMAP_HEADER
#define TIDE_MMAP_HEADER

#include "filesystem.hpp"

#include <iterator>

namespace tide {
namespace detail {

/**
 * Most of the logic in establishing a memory mapping is the same for both read-only and
 * read-write mappings, so they both inherit from mmap_base.
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
    //using reverse_iterator = std::reverse_iterator<iterator>;
    //using const_reverse_iterator = std::reverse_iterator<const_iterator>;
    using iterator_category = std::random_access_iterator_tag;
    using handle_type = fs::file_handle_type;

protected:

    // Points to the first requested byte, and not to the actual start of the mapping.
    pointer m_data = nullptr;

    // Requested length, i.e. not the length of the full mapping.
    size_type m_length = 0;
    size_type m_mapped_length = 0;

    handle_type m_file_handle;
#if defined(_WIN32)
    handle_type m_file_mapping_handle;
#endif

    enum class access_mode
    {
        read_only,
        read_write
    };

public:

    mmap_base() = default;
    mmap_base(const mmap_base&) = delete;
    mmap_base& operator=(const mmap_base&) = delete;
    mmap_base(mmap_base&&);
    mmap_base& operator=(mmap_base&&);
    ~mmap_base();

    void unmap();

    /**
     * On *nix systems is_open and is_mapped are the same and don't actually say if
     * the file itself is open or closed, they only refer to the mapping. This is
     * because a mapping remains valid (as long as it's not unmapped) even if another
     * entity closes the file which is being mapped.
     * TODO investigate Windows
     */
    bool is_open() const noexcept;
    bool is_mapped() const noexcept;
    bool is_empty() const noexcept;

    /**
     * size/length returns the logical length (i.e. the one user requested), while
     * mapped_length returns the actual mapped length, which is usually a multiple of
     * the OS' page size.
     */
    size_type size() const noexcept;
    size_type length() const noexcept;
    size_type mapped_length() const noexcept;

    const_pointer data() const noexcept;

    const_iterator begin() const noexcept;
    const_iterator cbegin() const noexcept;
    const_iterator end() const noexcept;
    const_iterator cend() const noexcept;

    const_reference operator[](const size_type i) const noexcept;

protected:

    void map(const handle_type handle, const size_type offset, const size_type length,
        const access_mode mode, std::error_code& error);
    void sync(std::error_code& error);

private:

    pointer get_mapping_start() noexcept;

    /** NOTE: m_file_handle must be valid. */
    size_type query_file_size(std::error_code& error) noexcept;

    void map(const size_type offset, const size_type length,
        const access_mode mode, std::error_code& error);

    void verify_file_handle(std::error_code& error) const noexcept;
};

} // namespace detail

/**
 * When specifying a file to map, there is no need to worry about providing
 * offsets that are aligned with the operating system's page granularity, this is taken
 * care of within the class in both cases.
 *
 * Both classes have std::unique_ptr<> semantics, thus only a single entity may own
 * a mapping to a file at any given time.
 *
 * Remapping a file is possible, but unmap must be called before that.
 *
 * For now, both classes may only be used with an existing open file by providing the 
 * file's handle.
 *
 * Both classes' destructors unmap the file. However, mmap_sink's destructor does not
 * sync the mapped file view to disk, this has to be done manually with sink.
 */

/** A read-only file memory mapping. */
struct mmap_source: public detail::mmap_base
{
    mmap_source() = default;
    mmap_source(const handle_type handle, const size_type offset, const size_type length);
    void map(const handle_type handle, const size_type offset,
        const size_type length, std::error_code& error);
};

/** A read-write file memory mapping. */
struct mmap_sink: public detail::mmap_base
{
    mmap_sink() = default;
    mmap_sink(const handle_type handle, const size_type offset, const size_type length);

    void map(const handle_type handle, const size_type offset,
        const size_type length, std::error_code& error);

    /** Flushes the memory mapped page to disk. */
    void sync(std::error_code& error);

    pointer data() noexcept;
    iterator begin() noexcept;
    iterator end() noexcept;

    reference operator[](const size_type i) noexcept;
};

// ---------------
// -- mmap_base --
// ---------------

namespace detail {

inline mmap_base::~mmap_base()
{
    unmap();
}

inline bool mmap_base::is_open() const noexcept
{
    return m_file_handle != INVALID_HANDLE_VALUE;
}

inline bool mmap_base::is_mapped() const noexcept
{
#ifdef _WIN32
    return m_file_mapping_handle != INVALID_HANDLE_VALUE;
#else
    return is_open();
#endif
}

inline bool mmap_base::is_empty() const noexcept
{
    return length() == 0;
}

inline mmap_base::size_type mmap_base::size() const noexcept
{
    return length();
}

inline mmap_base::size_type mmap_base::length() const noexcept
{
    return m_length;
}

inline mmap_base::size_type mmap_base::mapped_length() const noexcept
{
    return m_mapped_length;
}

inline mmap_base::const_pointer mmap_base::data() const noexcept
{
    return m_data;
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

inline mmap_base::const_reference mmap_base::operator[](const size_type i) const noexcept
{
    return m_data[i];
}

} // namespace detail

// -----------------
// -- mmap_source --
// -----------------

inline mmap_source::mmap_source(const handle_type handle,
    const size_type offset, const size_type length)
{
    std::error_code error;
    map(handle, offset, length, error);
    if(error) { throw error; }
}

inline void mmap_source::map(const handle_type handle, const size_type offset,
    const size_type length, std::error_code& error)
{
    mmap_base::map(handle, offset, length, access_mode::read_only, error);
}

// ---------------
// -- mmap_sink --
// ---------------

inline mmap_sink::mmap_sink(const handle_type handle,
    const size_type offset, const size_type length)
{
    std::error_code error;
    map(handle, offset, length, error);
    if(error) { throw error; }
}

inline void mmap_sink::map(const handle_type handle, const size_type offset,
    const size_type length, std::error_code& error)
{
    mmap_base::map(handle, offset, length, access_mode::read_write, error);
}

inline void mmap_sink::sync(std::error_code& error) { mmap_base::sync(error); }

inline mmap_sink::pointer mmap_sink::data() noexcept { return m_data; }
inline mmap_sink::iterator mmap_sink::begin() noexcept { return data(); }
inline mmap_sink::iterator mmap_sink::end() noexcept { return data() + length(); }

inline mmap_sink::reference mmap_sink::operator[](const size_type i) noexcept
{
    return m_data[i];
}

} // namespace tide

#endif // TIDE_MMAP_HEADER
