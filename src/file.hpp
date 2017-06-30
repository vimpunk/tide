#ifndef TIDE_FILE_HEADER
#define TIDE_FILE_HEADER

#include "flag_set.hpp"
#include "iovec.hpp"
#include "view.hpp"
#include "time.hpp"
#include "path.hpp"

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
# include <sys/uio.h> // TODO might need io.h
# define INVALID_HANDLE_VALUE -1 // this is the macro used on Windows
#endif // _WIN32

namespace tide {
namespace fs { // filesystem utilities

struct file_status
{
    enum
    {
#ifdef _WIN32
        // TODO
        fifo,
        character_device,
        directory,
        regular_file,
#else // _WIN32
        socket = 0140000,
        symbolic_link = 0120000,
        regular_file = 0100000,
        block_device = 0060000,
        directory = 0040000,
        character_device = 0020000,
        fifo = 001000
#endif // _WIN32
    };

    int64_t length;
    int mode;
    time_point last_access_time;
    time_point last_modification_time;
    time_point last_status_change_time;
};

file_status status(const path& path, std::error_code& error);

bool exists(const path& path);
bool exists(const path& path, std::error_code& error);
bool is_directory(const path& path, std::error_code& error);

int64_t file_length(const path& path, std::error_code& error);

void create_directory(const path& path, std::error_code& error);
void create_directories(const path& path, std::error_code& error);

/** On Linux open file descriptors for old_path are unaffected. TODO check on Windows. */
void move(const path& old_path, const path& new_path, std::error_code& error);
void rename(const path& old_path, const path& new_path, std::error_code& error);

} // namespace fs

// TODO currently only linux is supported
// TODO add optimization where user can tell file that only page aligned 16KiB blocks
// will be written at a time as an open_mode flag or something
// TODO think about the situation where we've given out mmap objects but the file is
// closed. do we pass the responsibility of disposing of those mmap instances to user?
// plus files will periodically be flushed and perhaps closed (on windows there might
// be issues with syncing to disk but look into this)
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

#ifdef _WIN32
    using handle_type = HANDLE;
#else
    using handle_type = int;
#endif
    using open_mode_flags = flag_set<open_mode, open_mode::max>;

private:

    handle_type m_file_handle = INVALID_HANDLE_VALUE;
    path m_absolute_path;
    bool m_is_allocated = false;
    open_mode_flags m_open_mode;
    int64_t m_length;

public:

    /**
     * Default constructed file is invalid (i.e. its handler is invalid).
     *
     * Sets the attributes of the file but does not open or initialize its storage.
     * This is to allow on demand execution of those functions, so call open() and then
     * allocate() separately, in this order.
     */
    file() = default;
    file(path path, int64_t length, open_mode_flags open_mode);
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
    void on_parent_moved(path file_path);

    /**
     * Instructs the OS to allocate length number of bytes on the hardware for this
     * file, if file hasn't been allocated the correct size yet. If the reallocation
     * caused it to shrink, the truncated data is lost, but the rest is the same as
     * before, and if file grew, the new bytes are 0.
     *
     * NOTE: this must be called before the first time any operation is done on
     * file and the file must already be opened.
     */
    void allocate(std::error_code& error);
    void reallocate(const int64_t length, std::error_code& error);

    /**
     * Removes the data associated with this file from disk. After the successful
     * execution of this function, is_allocated() returns false.
     *
     * NOTE: file must be closed before issueing this call.
     */
    void erase(std::error_code& error);
    void move(const path& new_path, std::error_code& error);

    int64_t size() const noexcept;
    int64_t length() const noexcept;

    path absolute_path() const;
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
    mmap_source create_mmap_source(const int64_t file_offset,
        const int length, std::error_code& error);
    mmap_sink create_mmap_sink(const int64_t file_offset,
        const int length, std::error_code& error);
     */

    /**
     * Reads or writes a single buffer and returns the number of bytes read/written, or
     * 0 if no reading/writing occured (whether due to an error or EOF is not specified,
     * as details can be retrieved from error).
     * The number of bytes written is min(length() - file_offset, buffer.length()).
     *
     * An exception is thrown if file_offset is invalid.
     */
    int read(view<uint8_t> buffer, const int64_t file_offset, std::error_code& error);
    int read(iovec buffer, const int64_t file_offset, std::error_code& error);
    int write(view<uint8_t> buffer, const int64_t file_offset, std::error_code& error);
    int write(iovec buffer, const int64_t file_offset, std::error_code& error);

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
    int read(view<iovec>& buffers, const int64_t file_offset, std::error_code& error);
    int write(view<iovec>& buffers, const int64_t file_offset, std::error_code& error);

    /** If we're in write mode, syncs the file buffer in the OS page cache with disk. */
    void sync_with_disk(std::error_code& error);

private:

    void check_read_preconditions(
        const int64_t file_offset, std::error_code& error) const noexcept;
    void check_write_preconditions(
        const int64_t file_offset, std::error_code& error) const noexcept;
    void verify_handle(std::error_code& error) const;
    void verify_file_offset(const int64_t file_offset) const;

    /**
     * Abstracts away scatter-gather IO by repeatedly calling the supplied pread or
     * pwrite (like) function. Use this if preadv/pwritev is slower than repeated calls
     * on the current system.
     *
     * pio_fn will be called for every buffer processed, and its signature must be:
     * int pio_fn(void* buffer, int64_t file_offset, int64_t length);
     * where the return value is the number of bytes transferred.
     *
     * Note that unlike preadv/pwritev, this is not atomic, so other processes may be
     * able to write to a file between calls to pio_fn.
     */
    template<typename PIOFunction>
    int repeated_positional_io(PIOFunction pio_fn, view<iovec>& buffers,
        int64_t file_offset, std::error_code& error);

    /**
     * Abstraction around preadv/writev functions, which imparts the responsibility of
     * doing scatter-gather IO on the kernel. This should be preferred over repeated
     * calls to single buffer IO operations in almost all cases. Writing all buffers in
     * one is an atomic operation, unless the io function transfers less bytes than
     * requested, in which case this function calls it again with the remaining bytes.
     *
     * pvio_fn will be called until it transfers all the bytes requested, usually once.
     * It must have the following signature:
     * int vpo_fn(view<iovec>& buffers, int64_t file_offset);
     * where the return value is the number of bytes transferred.
     */
    template<typename PVIOFunction>
    int positional_vector_io(PVIOFunction pvio_fn, view<iovec>& buffers,
        int64_t file_offset, std::error_code& error);
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

/**
 * Assigns errno on UNIX and GetLastError() on Windows to error after a failed
 * operation.
 */
void assign_errno(std::error_code& error) noexcept;

} // namespace util

inline void file::on_parent_moved(path file_path)
{
    m_absolute_path = file_path;
}

inline int64_t file::size() const noexcept
{
    return length();
}

inline int64_t file::length() const noexcept
{
    return m_length;
}

inline path file::absolute_path() const
{
    return m_absolute_path;
}

inline std::string file::filename() const
{
    m_absolute_path.filename().native();
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

#endif // TIDE_FILE_HEADER
