#ifndef TIDE_FILE_HEADER
#define TIDE_FILE_HEADER

#include "flag_set.hpp"
#include "system.hpp"
#include "iovec.hpp"
#include "view.hpp"
#include "time.hpp"
#include "path.hpp"
#include "mmap.hpp"

#include <system_error>
#include <cstdint>

#ifdef _WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif // WIN32_LEAN_AND_MEAN
# include <windows.h>
#else // _WIN32
# include <fcntl.h>
# include <unistd.h>
# include <sys/mman.h>
# include <sys/stat.h>
# include <sys/uio.h>
# define INVALID_HANDLE_VALUE -1 // this is the macro used on Windows
#endif // _WIN32

namespace tide {

enum class file_errc
{
    // We tried to read/block from a file that we marked as not downloaded (i.e.
    // we don't have its data written to disk).
    tried_unwanted_file_read,
    tried_unwanted_file_write,
    tried_unallocated_file_read,
    tried_unallocated_file_write,
    tried_read_only_file_write,
    invalid_file_offset,
    null_transfer,
};

inline bool operator==(const file_errc e, const int i) noexcept
{
    return static_cast<int>(e) == i;
}

inline bool operator!=(const int i, const file_errc e) noexcept
{
    return !(e == i);
}

struct file_error_category : public std::error_category
{
    const char* name() const noexcept override { return "file"; }
    std::string message(int env) const override;
    std::error_condition default_error_condition(int ev) const noexcept override;
};

const file_error_category& file_category();
std::error_code make_error_code(file_errc e);
std::error_condition make_error_condition(file_errc e);

struct file
{
    enum open_mode : uint8_t
    {
        read_only,
        write_only,
        read_write,
        // Don't update the access timestamps, which should improve performance.
        no_atime,
        // Tell OS not to read ahead.
        random,
        // Tell OS to read ahead aggressively.
        sequential, // TODO currently unimplemented
        // Don't allow other process to access while we're working with it.
        lock_file, // TODO currently unimplemented
        // Don't put file into the OS' page cache.
        no_os_cache,
        // When creating the file, set the executabe attribute.
        executable,
        max
    };

    using handle_type = sys::file_handle_type;
    using open_mode_flags = flag_set<open_mode, open_mode::max>;
    using size_type = int64_t;

private:

    handle_type m_file_handle = INVALID_HANDLE_VALUE;
    path m_absolute_path;
    bool m_is_allocated = false;
    size_type m_length;
    open_mode_flags m_open_mode;

public:

    /**
     * Default constructed file is invalid (i.e. its handler is invalid).
     *
     * Sets the attributes of the file but does not open or initialize its storage.
     * This is to allow on demand execution of those functions, so call open() and then
     * allocate() separately, in this order.
     */
    file() = default;
    file(path path, size_type length, open_mode_flags open_mode);
    file(const file&) = delete;
    file& operator=(const file&) = delete;
    file(file&& other) = default;
    file& operator=(file&& other) = default;
    ~file();

    /**
     * Open, with no argument, opens the file with the current open_mode, while open
     * with a supplied open_mode (re)opens the file if the open_mode differs from the
     * current settings.
     *
     * Closing a file does NOT sync the file page with the one on disk, so make sure to
     * all sync_with_disk if needed.
     */
    void open(std::error_code& error);
    void open(open_mode_flags open_mode, std::error_code& error);
    void close();

    /**
     * This should be called when the directory in which this file is located has been
     * moved, because the internal path member needs to be updated to match file's path
     * in the filesystem. file_path is an absolute path to the new location of the file.
     */
    void set_path(path file_path);

    /**
     * Instructs the OS to allocate length number of bytes on the hardware for this
     * file, if file hasn't been allocated the correct size yet. If the reallocation
     * caused it to shrink, the truncated data is lost, but the rest is the same as
     * before, and if file grew, the new bytes are 0.
     */
    void allocate(std::error_code& error);
    void allocate(const size_type length, std::error_code& error);

    /**
     * Removes the data associated with this file from disk. After the successful
     * execution of this function, is_allocated() returns false.
     *
     * NOTE: file must be closed before issueing this call.
     */
    void erase(std::error_code& error);
    void move(const path& new_path, std::error_code& error);

    /**
     * Note that the returned value is not the one retrieved from the OS, but the
     * one that was supplied in the constructor, so if another process changes the
     * underlying file, the returned value will not reflect the actual file size.
     */
    size_type size() const noexcept;
    size_type length() const noexcept;

    const path& absolute_path() const;
    std::string filename() const;

    bool is_open() const noexcept;
    bool is_read_only() const noexcept;
    bool is_write_only() const noexcept;
    bool is_allocated() const noexcept;

    /**
     * Returns a memory mapping of the portion of the file specified by file_offset and
     * length. This is useful to map entire pieces and keep them in cache for repeated
     * reads.
     *
     * Memory mapping should only be used if repeated reads/writes to the mapped region
     * are expected, otherwise the overhead the kernel has to do to negotiate the
     * mapping might not make it worthwhile and in that case the read/write functions
     * below are more appropriate.
     *
     * An exception is thrown if file_offset and/or length are invalid. Any other IO
     * errors are reported via error. In both cases the returned mmap object is invalid/
     * uninitialized.
     */
    mmap_source create_mmap_source(const size_type file_offset,
        const size_type length, std::error_code& error);
    mmap_sink create_mmap_sink(const size_type file_offset,
        const size_type length, std::error_code& error);

    /**
     * Reads or writes a single buffer and returns the number of bytes read/written, or
     * 0 if no reading/writing occured (whether due to an error or EOF is not specified,
     * as details can be retrieved from error).
     * The number of bytes written is min(length() - file_offset, buffer.length()).
     *
     * An exception is thrown if file_offset is invalid.
     */
    size_type read(view<uint8_t> buffer, size_type file_offset, std::error_code& error);
    size_type read(iovec buffer, size_type file_offset, std::error_code& error);
    size_type write(view<uint8_t> buffer, size_type file_offset, std::error_code& error);
    size_type write(iovec buffer, size_type file_offset, std::error_code& error);

    /**
     * These two functions are scatter-gather operations in that multiple buffers may
     * be provided which are treated as a single contiguous buffer.
     *
     * The number of bytes transferred to or from disk is guaranteed to be
     * min(num_bytes_in_buffers, file.length() - file_offset), as the syscalls the 
     * implementation uses don't usually guarantee the transfer of the requested number 
     * of bytes, but these operations are repeated until succeeding or until an error 
     * occurs.
     *
     * The number of bytes that were successfully read/written are returned, or 0 if no
     * reading/writing occured (whether due to an error or EOF is not specified, as
     * details can be retrieved from error).
     *
     * For writing, if the open_mode_t::no_disk_cache flag is set, changes are
     * immediately written to disk, that is, the OS is instructed to flush the file's 
     * contents from its page cache to disk. Otherwise this should be done manually with
     * sync_with_disk in order to guarantee that changes are written to disk.
     *
     * An exception is thrown if file_offset is invalid.
     * Any other IO errors are reported via error.
     *
     * If an error occurs while reading, the contents of the destination buffer is
     * undetermined.
     *
     * NOTE: the number of bytes that have been read/written are trimmed from the iovec
     * buffers view. It's effectively used as a byte pointer/cursor that is advanced
     * by the number of bytes transferred, which can be useful when buffers is meant to
     * be written to/filled with by the contents of several consecutive files, so when 
     * these functions return, the buffers view can just be passed to the next file.
     */
    size_type read(view<iovec>& buffers,
        const size_type file_offset, std::error_code& error);
    size_type write(view<iovec>& buffers,
        const size_type file_offset, std::error_code& error);

    /** If we're in write mode, syncs the file buffer in the OS page cache with disk. */
    void sync_with_disk(std::error_code& error);

private:

    void before_mapping_source(const size_type file_offset,
        const size_type length, std::error_code& error) const noexcept;
    void before_mapping_sink(const size_type file_offset,
        const size_type length, std::error_code& error) const noexcept;
    void before_reading(const size_type file_offset,
        std::error_code& error) const noexcept;
    void before_writing(const size_type file_offset,
        std::error_code& error) const noexcept;
    void verify_handle(std::error_code& error) const;
    void verify_file_offset(const size_type file_offset, std::error_code& error) const;

    /**
     * Abstracts away the plumbing behind a single pread/pwrite operation: repeatedly
     * calls fn until it transfers min(buffer.iov_len, length() - file_offset) number
     * of bytes.
     *
     * fn needs to have the following signature:
     * size_type fn(void* buffer, size_type length, size_type file_offset);
     * where the return value is the number of bytes that were transferred.
     */
    template<typename PIOFunction>
    size_type single_buffer_io(iovec buffer, size_type file_offset,
        std::error_code& error, PIOFunction fn);

    /**
     * Abstracts away scatter-gather IO by repeatedly calling the supplied pread or
     * pwrite (like) function. Use this if preadv/pwritev is slower than repeated calls
     * on the current system.
     *
     * fn will be called for every buffer processed, and its signature must be:
     * size_type fn(void* buffer, size_type length, size_type file_offset);
     * where the return value is the number of bytes transferred.
     *
     * Note that unlike preadv/pwritev, this is not atomic, so other processes may be
     * able to write to a file between calls to fn.
     */
    template<typename PIOFunction>
    size_type repeated_positional_io(view<iovec>& buffers, size_type file_offset,
        std::error_code& error, PIOFunction fn);

    /**
     * Abstraction around preadv/writev functions, which imparts the responsibility of
     * doing scatter-gather IO on the kernel. This should be preferred over repeated
     * calls to single buffer IO operations in almost all cases. Writing all buffers in
     * one is an atomic operation, unless the io function transfers less bytes than
     * requested, in which case this function calls it again with the remaining bytes.
     *
     * pvio_fn will be called until it transfers all the bytes requested, usually once.
     * It must have the following signature:
     * size_type vpo_fn(view<iovec>& buffers, size_type file_offset);
     * where the return value is the number of bytes transferred.
     */
    template<typename PVIOFunction>
    size_type positional_vector_io(view<iovec>& buffers, size_type file_offset,
        std::error_code& error, PVIOFunction pvio_fn);
};

namespace util {

/**
 * Trims the front of buffers by num_to_trim bytes by removing the buffers that were
 * fully used and trimming the last buffer that was used by the number of bytes that
 * were extracted or written to it, like so:
 *
 * remove these two buffers
 * |      |      num_to_trim
 * v      v      V
 * ====|=====|===-----|---
 *             ^ and trim this buffer's front
 */
void trim_buffers_front(view<iovec>& buffers, int num_to_trim) noexcept;

} // namespace util

inline void file::set_path(path file_path)
{
    m_absolute_path = file_path;
}

inline file::size_type file::size() const noexcept
{
    return length();
}

inline file::size_type file::length() const noexcept
{
    return m_length;
}

inline const path& file::absolute_path() const
{
    return m_absolute_path;
}

inline std::string file::filename() const
{
    return m_absolute_path.filename().native();
}

inline bool file::is_open() const noexcept
{
    return m_file_handle != INVALID_HANDLE_VALUE;
}

inline bool file::is_read_only() const noexcept
{
    return m_open_mode[read_only];
}

inline bool file::is_write_only() const noexcept
{
    return m_open_mode[write_only];
}

inline bool file::is_allocated() const noexcept
{
    return m_is_allocated;
}

} // namespace tide

namespace std
{
    template<> struct is_error_code_enum<tide::file_errc> : public true_type {};
}

#endif // TIDE_FILE_HEADER
