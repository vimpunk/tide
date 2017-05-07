#ifndef TORRENT_FILE_HEADER
#define TORRENT_FILE_HEADER

#include "units.hpp"
#include "view.hpp"
#include "path.hpp"

#include <system_error>
#include <cstdint>

#ifdef _WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif // WIN32_LEAN_AND_MEAN
# include <windows.h>
#else // ifdef _WIN32
# include <fcntl.h>
# include <unistd.h>
# include <sys/mman.h>
# include <sys/stat.h>
#endif // ifdef _WIN32

// TODO
struct mmap_source {};
struct mmap_sink {};

// TODO currently only linux is supported
// TODO think about the situation where we've given out mmap objects but the file is
// closed. do we pass the responsibility of disposing of those mmap instances to user?
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
    uint8_t m_open_mode = 0;
    int64_t m_length = 0;

    piece_index_t m_first_overlapped_piece = 0;
    piece_index_t m_last_overlapped_piece = 0;
    piece_index_t m_first_full_piece = 0;
    piece_index_t m_last_full_piece = 0;

public:

    /**
     * Sets the attributes of the file but does not open or initialize its storage.
     * This is to allow on demand execution of those functions, so call open() and then
     * allocate_storage() separately, in this order.
     */
    file(
        path path,
        int64_t length,
        uint8_t open_mode,
        piece_index_t first_overlapped_piece,
        piece_index_t last_overlapped_piece,
        piece_index_t first_full_piece,
        piece_index_t last_full_piece
    );
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
    std::error_code allocate_storage();

    int64_t length() const noexcept;
    path absolute_path() const noexcept;
    bool is_open() const noexcept;
    bool is_read_only() const noexcept;
    bool is_allocated() const noexcept;

    /**
     * These functions return the indices of the pieces at the edges of the file;
     * "full piece" means that the piece is fully contained in this file while
     * "overlapped piece" means that the piece overlaps into another file and this file
     * only has some portion of it. If the file boundaries are aligned with the piece
     * length, then the two types of functions are identical.
     */
    piece_index_t first_full_piece() const noexcept;
    piece_index_t last_full_piece() const noexcept;
    piece_index_t first_overlapped_piece() const noexcept;
    piece_index_t last_overlapped_piece() const noexcept;

    /** Returns the number of pieces this file fully contains. */
    int num_full_pieces() const noexcept;

    /** Returns the number of pieces this file contains, even if only partially. */
    int num_all_pieces() const noexcept;

    /**
     * Open, with no argument, opens the file with the current open_mode, while open
     * with a supplied open_mode (re)opens the file if the open_mode differs from the
     * current settings.
     *
     * Closing a file does NOT sync the file page with the one on disk, so make sure to
     * do that manually.
     */
    std::error_code open();
    std::error_code open(uint8_t open_mode);
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
        std::error_code& error,
        const int64_t offset,
        const int64_t length
    );
    mmap_sink create_rw_mmap(
        std::error_code& error,
        const int64_t offset,
        const int64_t length
    );

    /**
     * Similar to the low level syscall pread(2) (and the equivalent on Windows).
     * It's a scatter operation in that multiple buffers may be provided which are
     * treated as if they were a single contiguous buffer. The number of bytes that
     * were successfully read into buffers is returned.
     *
     * An exception is thrown if offset and/or length are invalid. Any other IO errors
     * are reported via error.
     */
    int read(
        std::error_code& error,
        view<view<uint8_t>> buffers,
        const int64_t offset,
        const int64_t length
    );

    /**
     * Similar to the the low level syscall pwrite(2) (and the equivalent on Windows).
     * It's a gather operation in that multiple buffers may be provided which are
     * treated as if they were a single contiguous buffer. The number of bytes that
     * were successfully written to disk is returned.
     *
     * If the no_disk_cache flag from open_mode is set, changes are immediately written
     * to disk.
     *
     * An exception is thrown if offset and/or length are invalid. Any other IO errors
     * are reported via error.
     */
    int write(
        std::error_code& error,
        view<view<uint8_t>> buffers,
        const int64_t offset,
        const int64_t length
    );

    /** If we're in write mode, syncs the file buffer in the OS page cache with disk. */
    std::error_code sync_with_disk();

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

    template<typename IOFunction>
    int do_io_operation(
        std::error_code& error,
        IOFunction io_fn,
        view<view<uint8_t>> buffers,
        const int64_t offset,
        const int64_t length
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

inline int file::num_full_pieces() const noexcept
{
    return last_full_piece() - first_full_piece() + 1;
}

inline int file::num_all_pieces() const noexcept
{
    return last_overlapped_piece() - first_overlapped_piece() + 1;
}

#endif // TORRENT_FILE_HEADER
