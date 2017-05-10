#ifndef TORRENT_FILE_HEADER
#define TORRENT_FILE_HEADER

#include "view.hpp"
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
#endif // _WIN32

// TODO
struct mmap_source {};
struct mmap_sink {};

// TODO currently only linux is supported
// TODO think about the situation where we've given out mmap objects but the file is
// closed. do we pass the responsibility of disposing of those mmap instances to user?
// plus files will periodically be flushed and perhaps closed (on windows there might
// be issues with syncing to disk but look into this)
struct file
{
    enum open_mode : uint8_t
    {
        read_only     = 0,
        write_only    = 1,
        read_write    = 2,
        // Don't update the access timestamps, which should improve performane.
        no_atime      = 4,
        // Tell OS not to read ahead.
        random        = 8,
        // Tell OS to read ahead aggressively.
        sequential    = 16, // TODO currently unimplemented
        // Don't allow other process to access while we're working with it.
        lock_file     = 32, // TODO currently unimplemented
        // Don't put file into the OS' page cache.
        no_os_cache   = 64,
        // When creating the file, set the executabe attribute.
        executable    = 128
    };

private:

#if defined(_WIN32)
    using handle_type = HANDLE;
# define TORRENT_INVALID_FILE_HANDLE INVALID_HANDLE_VALUE
#else
    using handle_type = int;
# define TORRENT_INVALID_FILE_HANDLE -1
#endif

    handle_type m_file_handle = TORRENT_INVALID_FILE_HANDLE;

    path m_absolute_path;

    bool m_is_allocated = false;

    // This is set every time we (re)open file.
    uint8_t m_open_mode;
    int64_t m_length;

public:

    /**
     * Default constructed file is invalid.
     *
     * Sets the attributes of the file but does not open or initialize its storage.
     * This is to allow on demand execution of those functions, so call open() and then
     * allocate_storage() separately, in this order.
     */
    file();
    file(path path, int64_t length, uint8_t open_mode);
    file(const file&) = delete;
    file& operator=(const file&) = delete;
    file(file&& other) = default;
    file& operator=(file&& other) = default;
    ~file();

    /**
     * Instructs the OS to allocate length() number of bytes on the hardware for this
     * file.
     * Allocation is deferred until first access, so torrent_storage has to call this
     * before doing any operations on file. This is useful because user may stop torrent
     * halfway through in which case we may have wastefully spent time to preallocate
     * a file that was never accessed.
     */
    void allocate_storage(std::error_code& error);

    int64_t length() const noexcept;
    path absolute_path() const noexcept;
    bool is_open() const noexcept;
    bool is_read_only() const noexcept;
    bool is_allocated() const noexcept;

    /**
     * Open, with no argument, opens the file with the current open_mode, while open
     * with a supplied open_mode (re)opens the file if the open_mode differs from the
     * current settings.
     *
     * Closing a file does NOT sync the file page with the one on disk, so make sure to
     * do that manually.
     */
    void open(std::error_code& error);
    void open(uint8_t open_mode, std::error_code& error);
    void close();

    /**
     * Returns a memory mapping of the portion of the file specified by offset and
     * length. This is useful to map entire pieces and keep them in cache for repeated
     * reads. Memory mapping should only be used if repeated reads/writes to the mapped
     * region are expected, otherwise the overhead the kernel has to do to negotiate the
     * mapping might not make it worth it and in that case the read/write functions
     * below are more appropriate.
     *
     * An exception is thrown if offset and/or length are invalid. Any other IO errors
     * are reported via error. In the latter case the returned mmap object is invalid/
     * uninitialized.
     */
    mmap_source create_ro_mmap(
        const int64_t offset, const int64_t length, std::error_code& error
    );
    mmap_sink create_rw_mmap(
        const int64_t offset, const int64_t length, std::error_code& error
    );

    /**
     * The two functions are similar in their function to the syscalls pread and pwrite.
     * They are scatter-gather operations in that multiple buffers may be provided which
     * are treated as a single contiguous buffer.
     *
     * The number of bytes transferred to or from disk is guaranteed to be
     * min(num_bytes_in_buffers, length), as the syscalls the implementation uses do not
     * usually guarantee the transfer of the requested number of bytes, so these
     * operations are repeated until succeeding or until an error occurs.
     *
     * For writing, if the no_disk_cache flag from open_mode is set, changes are
     * immediately written to disk, i.e. OS is instructed to flush the file's contents
     * from its page buffer to disk. This can be done manually with sync_with_disk().
     *
     * An exception is thrown if offset and/or length are invalid. Any other IO errors
     * are reported via error. TODO consider only asserting the input values
     */
    int read(
        view<view<uint8_t>> buffers,
        const int64_t offset,
        const int64_t length,
        std::error_code& error
    );
    int write(
        view<view<uint8_t>> buffers,
        const int64_t offset,
        const int64_t length,
        std::error_code& error
    );

    /** If we're in write mode, syncs the file buffer in the OS page cache with disk. */
    void sync_with_disk(std::error_code& error);

private:

    void verify_file_handle(std::error_code& error) const;
    void verify_args(const int64_t offset, const int64_t length) const;

    /**
     * These are the low level IO functions that wrap the platform dependent syscall
     * and return the syscall's value, which is the number of writes read/written or
     * some indication of an error. This means that any errors that occured are turned
     * into error_codes in the functions that use them.
     */
    int write_at(uint8_t* buffer, const int64_t offset, const int64_t length);
    int read_at(uint8_t* buffer, const int64_t offset, const int64_t length);

    /**
     * Abstracts away scatter-gather io operations, as reading and writing have the
     * same signature, and most of the work lies in managing the list of buffers and
     * redoing io operations until the desired length number of bytes has been
     * transferred.
     */
    template<typename IOFunction>
    int do_io_operation(
        IOFunction io_fn,
        view<view<uint8_t>> buffers,
        const int64_t offset,
        const int64_t length,
        std::error_code& error
    );
};

inline int64_t file::length() const noexcept
{
    return m_length;
}

inline path file::absolute_path() const noexcept
{
    return m_absolute_path;
}

inline bool file::is_open() const noexcept
{
    return m_file_handle != TORRENT_INVALID_FILE_HANDLE;
}

inline bool file::is_read_only() const noexcept
{
    return m_open_mode & read_only;
}

inline bool file::is_allocated() const noexcept
{
    return m_is_allocated;
}

#endif // TORRENT_FILE_HEADER
