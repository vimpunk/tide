#include "file.hpp"

file::file(
    path path,
    int64_t length,
    uint8_t open_mode,
    piece_index_t first_overlapped_piece,
    piece_index_t last_overlapped_piece,
    piece_index_t first_full_piece,
    piece_index_t last_full_piece
)
    : m_absolute_path(std::move(path))
    , m_length(length)
    , m_open_mode(open_mode)
    , m_first_overlapped_piece(first_overlapped_piece)
    , m_last_overlapped_piece(last_overlapped_piece)
    , m_first_full_piece(first_full_piece)
    , m_last_full_piece(last_full_piece)
{}

file::~file()
{
    close();
}

std::error_code file::allocate_storage()
{
    std::error_code ec;
    verify_file_handle(ec);
    if(ec)
    {
        return ec;
    }

#ifdef _WIN32
    LARGE_INTEGER size;
    if(GetFileSizeEx(m_file_handle, &size) == FALSE)
    {
        ec.assign(GetLastError(), std::system_category());
        return ec;
    }
    if(size.QuadPart != length())
    {
        LARGE_INTEGER distance;
        distance.QuadPart = length();
        if(SetFilePointerEx(m_file_handle, distance, &distance, FILE_BEGIN) == FALSE)
        {
            ec.assign(GetLastError(), std::system_category());
            return ec;
        }
        if(SetEndOfFile(m_file_handle) == FALSE)
        {
            ec.assign(GetLastError(), std::system_category());
            return ec;
        }
    }
#else
    struct stat stat;
    if(fstat(m_file_handle, &stat) != 0)
    {
        ec.assign(errno, std::system_category());
        return ec;
    }

    // don't truncate file if it's already truncated (has the correct length)
    if(stat.st_size == length())
    {
        return ec;
    }

    if(ftruncate(m_file_handle, length()) < 0)
    {
        ec.assign(errno, std::system_category());
        return ec;
    }

    // only allocate file blocks if it isn't allocated yet (check if the correct number
    // of blocks (we have to round of the number of blocks relative to the file length
    // here) are allocated)
    if(stat.st_blocks < (length() + stat.st_blksize - 1) / stat.st_blksize)
    {
        const int ret = posix_fallocate(m_file_handle, 0, length());
        if(ret != 0)
        {
            ec.assign(ret, std::system_category());
            return ec;
        }
    }
#endif
    return ec;
}

std::error_code file::open()
{
    return open(m_open_mode);
}

std::error_code file::open(uint8_t open_mode)
{
    std::error_code ec;
    if(is_open())
    {
        if(open_mode == m_open_mode)
        {
            return ec;
        }
        // close file because we want to open it in a different mode
        close();
    }

#ifdef _WIN32
    // TODO
#else
    int permissions = S_IRUSR  // 00400 user has read permission
                    | S_IWUSR  // 00200 user has write permission
                    | S_IRGRP  // 00040 group has read permission
                    | S_IWGRP  // 00020 group has write permission
                    | S_IROTH  // 00004 other has read permission
                    | S_IWOTH; // 00002 other has write permission
    if(open_mode & executable)
    {
        // give executable permission for all groups
        permissions |= S_IXUSR | S_IXGRP | S_IXOTH;
    } 

    // the final open mode flag that is passed to open(2)
    int mode = 0;

# ifdef O_NOATIME
    mode |= ((open_mode & no_atime) ? O_NOATIME : 0);
# endif // O_NOATIME

# ifdef O_SYNC
    mode |= ((open_mode & no_os_cache) ? O_SYNC : 0);
# endif // O_SYNC

    switch(open_mode & (read_only | write_only | read_write))
    {
    case read_write:
        mode |= O_RDWR | O_CREAT;
        break;
    case write_only:
        mode |= O_WRONLY | O_CREAT;
        break;
    case read_only:
        mode |= O_RDONLY | O_CREAT;
        break;
    };

    m_file_handle = ::open(m_absolute_path.c_str(), mode, permissions);

    if((m_file_handle == TORRENT_INVALID_FILE_HANDLE)
        && ((mode & no_atime) && (errno == EPERM)))
    {
        // O_NOATIME is not allowed for files we don't own, so try again without it
        mode &= ~O_NOATIME;
        open_mode &= ~no_atime;
        m_file_handle = ::open(m_absolute_path.c_str(), mode, permissions);
    }

    if(m_file_handle == TORRENT_INVALID_FILE_HANDLE)
    {
        ec.assign(errno, std::system_category());
        return ec;
    }
#endif // ifdef _WIN32

    m_open_mode = open_mode;
    return ec;
}

void file::close()
{
    if(!is_open())
    {
        return;
    }
#ifdef _WIN32
    ::CloseHandle(m_file_handle);
#else
    ::close(m_file_handle);
#endif
    m_file_handle = TORRENT_INVALID_FILE_HANDLE;
}

mmap_source file::create_ro_mmap(
    std::error_code& error,
    const int64_t offset,
    const int64_t length)
{
    verify_args(offset, length);
    verify_file_handle(error);
    if(error && !is_allocated())
    {
        //return mmap_source(m_file_handle);
    }
    error.clear();
}

mmap_sink file::create_rw_mmap(
    std::error_code& error,
    const int64_t offset,
    const int64_t length)
{
    verify_args(offset, length);
    verify_file_handle(error);
    if(error && !is_allocated())
    {
        //return mmap_sink(m_file_handle);
    }
    if(is_read_only())
    {
        error = std::make_error_code(std::errc::read_only_file_system);
    }
    error.clear();
}

int file::read(
    std::error_code& error,
    view<view<uint8_t>> buffers,
    const int64_t offset,
    const int64_t length)
{
    verify_args(offset, length);
    verify_file_handle(error);
    if(error && !is_allocated())
    {
        return 0;
    }
    error.clear();
    return do_io_operation(
        error,
        [this](uint8_t* buffer, int64_t offset, int64_t length) -> int
        {
            return read_at(buffer, offset, length);
        },
        buffers,
        offset,
        length
    );
}

int file::write(
    std::error_code& error,
    view<view<uint8_t>> buffers,
    const int64_t offset,
    const int64_t length)
{
    verify_args(offset, length);
    verify_file_handle(error);
    if(error && !is_allocated())
    {
        return 0;
    }
    if(is_read_only())
    {
        error = std::make_error_code(std::errc::read_only_file_system);
        return 0;
    }

    error.clear();
    const int total_written = do_io_operation(
        error,
        [this](uint8_t* buffer, int64_t offset, int64_t length) -> int
        {
            return write_at(buffer, offset, length);
        },
        buffers,
        offset,
        length
    );
    if(m_open_mode & no_os_cache)
    {
        sync_with_disk();
    }

    return total_written;
}

std::error_code file::sync_with_disk()
{
    std::error_code error;
    if(is_read_only())
    {
        // don't sync if we're not in write mode
        return error;
    }
#ifdef _WIN32
    // TODO find windows equivalent
#else
    if(fdatasync(m_file_handle) != 0)
    {
        error.assign(errno, std::system_category());
    }
#endif
    return error;
}

inline int file::write_at(uint8_t* buffer, const int64_t offset, const int64_t length)
{
#ifdef _WIN32
#else
    // watch out, posix syscalls have offset and length positions swapped
    return ::pwrite(m_file_handle, reinterpret_cast<void*>(buffer), length, offset);
#endif
}

inline int file::read_at(uint8_t* buffer, const int64_t offset, const int64_t length)
{
#ifdef _WIN32
#else
    return ::pread(m_file_handle, reinterpret_cast<void*>(buffer), length, offset);
#endif
}

template<typename IOFunction>
int file::do_io_operation(
    std::error_code& error,
    IOFunction io_fn,
    view<view<uint8_t>> buffers,
    const int64_t offset,
    const int64_t length)
{
    int total_transferred = 0;
    int64_t file_offset = offset;

    for(view<uint8_t> buffer : buffers)
    {
        while(!buffer.is_empty())
        {
            int num_to_transfer = buffer.size();
            // take care not to transfer more than the requested length
            const int excess = total_transferred + num_to_transfer - length;
            if(excess > 0)
            {
                // this is the last round, because we're approaching the requested
                // length to write, so don't transfer the whole buffer
                num_to_transfer -= excess;
            }

            int num_transferred = io_fn(buffer.data(), file_offset, num_to_transfer);

            if(num_transferred < 0)
            {
#ifdef _WIN32
                error.assign(GetLastError(), std::system_category());
#else
                error.assign(errno, std::system_category());
#endif
                return num_transferred;
            }

            total_transferred += num_transferred;
            file_offset += num_transferred;
            buffer.trim_front(num_transferred);

            if(total_transferred >= length)
            {
                // TODO this is ugly
                return total_transferred;
            }
        }
    }
    return total_transferred;
}

inline void file::verify_file_handle(std::error_code& error) const
{
    if(m_file_handle == TORRENT_INVALID_FILE_HANDLE)
    {
#ifdef _WIN32
        error.assign(TORRENT_INVALID_FILE_HANDLE, std::system_category());
#else
        error = std::make_error_code(std::errc::bad_file_descriptor);
#endif
    }
}

inline void file::verify_args(const int64_t offset, const int64_t length) const
{
    if((offset > file::length()) || (offset + length > file::length()))
    {
        throw std::invalid_argument("wrong offset and/or length given to file");
    }
}