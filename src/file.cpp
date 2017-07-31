#include "disk_io_error.hpp"
#include "file.hpp"

#include <cmath>

#ifdef _WIN32
// emulate UNIX syscalls on windows so we can use the same api
// TODO
// TODO currently only linux is supported

int pread(handle_type file_handle, void* buffer,
    const int count, const int64_t file_offset)
{
}

int pwrite(handle_type file_handle, void* buffer,
    const int count, const int64_t file_offset)
{
}

int preadv(handle_type file_handle, iovec* buffers, int iovec_count, int64_t file_offset)
{
}

int pwritev(handle_type file_handle, iovec* buffers, int iovec_count, int64_t file_offset)
{
}
#endif // _WIN32

namespace tide {

// ----------
// -- file --
// ----------

file::file(path path, size_type length, open_mode_flags open_mode)
    : m_absolute_path(std::move(path))
    , m_length(length)
    , m_open_mode(open_mode)
{}

file::~file()
{
    close();
}

void file::allocate(std::error_code& error)
{
    allocate(length(), error);
}

void file::allocate(const size_type length, std::error_code& error)
{
    error.clear();
    verify_handle(error);
    // only (re)allocate if we're not allocated, or if we are if the requested length
    // to allocate is not equal to the currently allocated amount
    if(error || (is_allocated() && (length == this->length()))) { return; }

#ifdef _WIN32
    LARGE_INTEGER size;
    if(GetFileSizeEx(m_file_handle, &size) == FALSE)
    {
        error = sys::latest_error();
        return;
    }

    if(size.QuadPart != length)
    {
        LARGE_INTEGER distance;
        distance.QuadPart = length;
        if(SetFilePointerEx(m_file_handle, distance, &distance, FILE_BEGIN) == FALSE)
        {
            error = sys::latest_error();
            return;
        }
        if(SetEndOfFile(m_file_handle) == FALSE)
        {
            error = sys::latest_error();
            return;
        }
    }
#else // _WIN32
    struct stat stat;
    if(fstat(m_file_handle, &stat) != 0)
    {
        error = sys::latest_error();
        return;
    }

    // don't truncate file if it's already truncated (has the correct length)
    if(stat.st_size == length)
    {
        m_is_allocated = true;
        return;
    }

    if(ftruncate(m_file_handle, length) < 0)
    {
        error = sys::latest_error();
        return;
    }

    // only allocate file blocks if it isn't allocated yet (check if the correct number
    // of blocks (we have to round of the number of blocks relative to the file length
    // here) are allocated)
    if(stat.st_blocks < (length + stat.st_blksize - 1) / stat.st_blksize)
    {
        const int ret = posix_fallocate(m_file_handle, 0, length);
        if(ret != 0)
        {
            error.assign(ret, std::system_category());
            return;
        }
    }
#endif // _WIN32
    m_is_allocated = true;
    m_length = length;
}

void file::erase(std::error_code& error)
{
    error.clear();
    verify_handle(error);
    if(error) { return; }
    if(is_open())
    {
        // we shouldn't delete the file out from under us, even if the file is kept
        // alive as long as a file descriptor is referring to it (we probably don't 
        // want this but TODO)
        error = std::make_error_code(std::errc::device_or_resource_busy);
        return;
    }
#ifdef _WIN32
    // TODO filepath name might be restricted
    if(DeleteFile(m_absolute_path.c_str()) == 0) { error = sys::latest_error(); }
#else // _WIN32
    if(unlink(m_absolute_path.c_str()) != 0) { error = sys::latest_error(); }
#endif // _WIN32
}

void file::move(const path& new_path, std::error_code& error)
{
    sys::move(m_absolute_path, new_path, error);
    if(!error)
    {
        m_absolute_path = new_path;
    }
}

void file::open(std::error_code& error)
{
    return open(m_open_mode, error);
}

void file::open(open_mode_flags open_mode, std::error_code& error)
{
    error.clear();
    if(is_open())
    {
        if(open_mode == m_open_mode) { return; }
        // close file because we want to open it in a different mode
        close();
    }

#ifdef _WIN32
    // TODO
#else
    // use default permissions and let the OS decide the rest
    int permissions = S_IRUSR | S_IWUSR  // user: read, write (00600)
                    | S_IRGRP | S_IWGRP  // group: read, write (00060)
                    | S_IROTH | S_IWOTH; // other: read, write (00006)
    if(open_mode[executable])
    {
        // give executable permission for all groups
        permissions |= S_IXUSR | S_IXGRP | S_IXOTH;
    } 

    // the final open mode flag that is passed to open(2)
    int mode = 0;
# ifdef O_NOATIME
    mode |= (open_mode[no_atime] ? O_NOATIME : 0);
# endif // O_NOATIME

# ifdef O_SYNC
    mode |= (open_mode[no_os_cache] ? O_SYNC : 0);
# endif // O_SYNC

    if(open_mode[read_write])
    {
        mode |= O_RDWR | O_CREAT;
    }
    else if(open_mode[read_only])
    {
        mode |= O_RDONLY;
    }
    else if(open_mode[write_only])
    {
        mode |= O_WRONLY | O_CREAT;
    }

    m_file_handle = ::open(m_absolute_path.c_str(), mode, permissions);

    if(m_file_handle == INVALID_HANDLE_VALUE
       && open_mode[no_atime]
       && errno == EPERM)
    {
        // O_NOATIME is not allowed for files we don't own, so try again without it
        mode &= ~O_NOATIME;
        open_mode.unset(no_atime);
        m_file_handle = ::open(m_absolute_path.c_str(), mode, permissions);
    }

    if(m_file_handle == INVALID_HANDLE_VALUE)
    {
        error = sys::latest_error();
        return;
    }
#endif // _WIN32
    m_open_mode = open_mode;
}

void file::close()
{
    if(!is_open()) { return; }
#ifdef _WIN32
    ::CloseHandle(m_file_handle);
#else
    ::close(m_file_handle);
#endif
    m_file_handle = INVALID_HANDLE_VALUE;
}

mmap_source file::create_mmap_source(const size_type file_offset,
    const int length, std::error_code& error)
{
    error.clear();
    before_mapping_source(file_offset, length, error);
    if(error) { return {}; }

    mmap_source mmap;
    mmap.map(m_file_handle, file_offset, length, error);
    return mmap;
}

mmap_sink file::create_mmap_sink(const size_type file_offset,
    const int length, std::error_code& error)
{
    error.clear();
    before_mapping_sink(file_offset, length, error);
    if(error) { return {}; }

    mmap_sink mmap;
    mmap.map(m_file_handle, file_offset, length, error);
    return mmap;
}

int file::read(view<uint8_t> buffer, size_type file_offset, std::error_code& error)
{
    return read(iovec{buffer.data(), buffer.length()}, file_offset, error);
}

int file::read(iovec buffer, size_type file_offset, std::error_code& error)
{
    error.clear();
    before_reading(file_offset, error);
    if(!error)
    {
        return single_buffer_io(buffer, file_offset, error,
            [this](void* buffer, int length, size_type offset) -> int
            { return pread(m_file_handle, buffer, length, offset); });
    }
    return 0;
}

int file::write(view<uint8_t> buffer, size_type file_offset, std::error_code& error)
{
    return write(iovec{buffer.data(), buffer.length()}, file_offset, error);
}

int file::write(iovec buffer, size_type file_offset, std::error_code& error)
{
    error.clear();
    before_writing(file_offset, error);
    if(!error)
    {
        return single_buffer_io(buffer, file_offset, error,
            [this](void* buffer, int length, size_type offset) -> int
            { return pwrite(m_file_handle, buffer, length, offset); });
    }
    return 0;
}

template<typename PIOFunction>
int file::single_buffer_io(iovec buffer, size_type file_offset,
    std::error_code& error, PIOFunction fn)
{
    int total_transferred = 0;
    while(buffer.iov_len > 0)
    {
        // make sure not to transfer more than what's left in file because if this is
        // a write operation, we'll enlarge file
        assert(length() - file_offset > 0);
        const int num_to_transfer = std::min(
            buffer.iov_len, size_t(length() - file_offset));
        assert(num_to_transfer > 0);
        const int num_transferred = fn(buffer.iov_base, num_to_transfer, file_offset);
        if(num_transferred < 0)
        {
            const std::error_code ec = sys::latest_error();
            if(ec == std::errc::interrupted) { continue; }
            error = ec;
            break;
        }
        else if(num_transferred == 0)
        {
            const std::error_code ec = sys::latest_error();
            if(ec)
                error = ec;
            else
                error = make_error_code(disk_io_errc::null_transfer);
            break;
        }
        file_offset += num_transferred;
        total_transferred += num_transferred;
        util::trim_iovec_front(buffer, num_transferred);
    }
    return total_transferred;
}

int file::read(view<iovec>& buffers, const size_type file_offset, std::error_code& error)
{
    error.clear();
    return positional_vector_io(buffers, file_offset, error,
        [this](view<iovec>& buffers, size_type file_offset) -> int
        { return preadv(m_file_handle, buffers.data(), buffers.size(), file_offset); });
}

int file::write(view<iovec>& buffers, const size_type file_offset, std::error_code& error)
{
    error.clear();
    before_writing(file_offset, error);
    if(error) { return 0; }

    // TODO this is an ugly hack, try to find a better way as it's error prone and
    // difficult to maintain
    // an alternative would be to just copy input buffers into a deque and modify that
    // or let caller promise not to supply a larger file and refuse to write if buffers
    // has more bytes than we can write to file, by setting error

    // pwritev unfortunately extends the file if the input buffer is larger than the
    // file's size, so we must trim buffers' back by finding the last buffer to keep and
    // trimming everything after it, like so:
    //
    // buffers: |-----|----x|xxxxx|
    //                    ^-file_end
    //
    // trim everything after file_end, but save this partial buffer because it will
    // ruin the caller's iovec
    const int adjusted_file_length = length() - file_offset;
    int buff_offset = file_offset;
    auto it = buffers.begin();
    const auto end = buffers.end();
    // if buffers has more bytes than adjusted_file_length, then find the last buffer
    // that can be written to file without extending file's size
    for(; it != end; ++it)
    {
        const int buff_end = buff_offset + it->iov_len;
        if((adjusted_file_length >= buff_offset) && (adjusted_file_length <= buff_end))
        {
            break;
        }
        buff_offset = buff_end;
    }

    int num_written = 0;
    if(it != end)
    {
        // we were stopped from iterating all the way through buffers, so buffers has
        // more bytes than file
        // -1 because we don't want to trim off buffer pointed to by 'it'
        const int num_buffs_to_trim = end - it - 1;
        buffers.trim_back(num_buffs_to_trim);
        // but before trimming, we need to save some state so that we can restore the
        // buffers that we don't use, otherwise we'd leave buffers invalid (the buffer
        // after we're done writing should begin one past the last byte written, and not
        // stop there)
        // now trim the excess bytes in the partial buffer
        const int num_bytes_to_trim = buff_offset + it->iov_len - adjusted_file_length;
        it->iov_len -= num_bytes_to_trim;

        num_written = positional_vector_io(buffers, file_offset, error,
            [this](view<iovec>& buffers, size_type file_offset) -> int
            {
                return pwritev(m_file_handle, buffers.data(),
                    buffers.size(), file_offset);
            });

        if(num_bytes_to_trim > 0)
        {
            // since buffers was trimmed to have as many bytes as can be written to
            // file, and since positional_vector_io trims off from the front of buffers 
            // the number of bytes written, the result is an empty buffers sequence, so
            // we need to get back the last buffer by decrementing the internal pointer
            // in buffers, unless the last buffer was fully drained, i.e. 
            // num_bytes_to_trim is 0, which means we don't need to restore this buffer
            assert(buffers.empty());
            buffers = view<iovec>(buffers.data() - 1, 1);

            // now that we have the last buffer back from which we wrote, we need to 
            // restore it, like so:
            // |xxxx---|
            //      ^-file_end
            // up until file_end everything was trimmed, so restore the rest of the
            // buffer after file_end by the same amount that was trimmed from it
            buffers.back().iov_len += num_bytes_to_trim;
        }
        // and by "attaching" back the full buffers we trimmed off before writing
        buffers = view<iovec>(buffers.data(), buffers.size() + num_buffs_to_trim);
    }
    else
    {
        num_written = positional_vector_io(buffers, file_offset, error,
            [this](view<iovec>& buffers, size_type file_offset) -> int
            {
                return pwritev(m_file_handle, buffers.data(),
                    buffers.size(), file_offset);
            });
    }

    if(!error && m_open_mode[no_os_cache]) { sync_with_disk(error); }
    return num_written;
}

// this is currently unused as positional_vector_io is assumed to perform better but do
// profile and maybe add compile time branching depending on the system that's known
// to perform better under repeated calls to pread/pwrite (some personal anecdotes
// indicated that this seems to be the case)
template<typename PIOFunction>
int file::repeated_positional_io(view<iovec>& buffers, size_type file_offset,
    std::error_code& error, PIOFunction fn)
{
    int file_length_left = length() - file_offset;
    int total_transferred = 0;
    for(iovec& buffer : buffers)
    {
        // fn is not guaranteed to transfer all of buffer, so retry until everything
        // has been sent
        while(buffer.iov_len > 0)
        {
            const int num_to_transfer = std::min(file_length_left, int(buffer.iov_len));
            const int num_transferred = fn(buffer.iov_base,
                num_to_transfer, file_offset);
            if(num_transferred < 0)
            {
                const std::error_code ec = sys::latest_error();
                if(ec == std::errc::interrupted) { continue; }
                error = ec;
                return total_transferred;
            }
            else if(num_transferred == 0)
            {
                const std::error_code ec = sys::latest_error();
                if(ec)
                    error = ec;
                else
                    error = make_error_code(disk_io_errc::null_transfer);
                return total_transferred;
            }

            total_transferred += num_transferred;
            file_offset += num_transferred;
            file_length_left -= num_transferred;
            if(file_length_left == 0) { return total_transferred; }

            util::trim_iovec_front(buffer, num_transferred);
        }
    }
    return total_transferred;
}

template<typename PVIOFunction>
int file::positional_vector_io(view<iovec>& buffers, size_type file_offset,
    std::error_code& error, PVIOFunction fn)
{
    size_type file_length_left = length() - file_offset;
    int total_transferred = 0;
    // ideally this will loop once but preadv/pwritev are not guaranteed to transfer
    // the requested bytes so we have to call it again until all requested bytes are
    // transferred
    while(!buffers.empty() && (file_length_left > 0))
    {
        const int num_transferred = fn(buffers, file_offset);
        if(num_transferred < 0)
        {
            const std::error_code ec = sys::latest_error();
            if(ec == std::errc::interrupted) { continue; }
            error = ec;
            break;
        }
        else if(num_transferred == 0)
        {
            const std::error_code ec = sys::latest_error();
            if(ec)
                error = ec;
            else
                error = make_error_code(disk_io_errc::null_transfer);
            break;
        }
        total_transferred += num_transferred;
        file_offset += num_transferred;
        file_length_left -= num_transferred;
        util::trim_buffers_front(buffers, num_transferred);
    }
    return total_transferred;
}

void file::sync_with_disk(std::error_code& error)
{
    error.clear();
    // no need to sync if we're not in write mode
    if(is_read_only()) { return; }
#ifdef _WIN32
    if(!FlushFileBuffers(m_file_handle))
    {
        error = sys::latest_error();
    }
#else
    if(fdatasync(m_file_handle) != 0)
    {
        error = sys::latest_error();
    }
#endif
}

inline void file::before_mapping_source(const size_type file_offset,
    const int length, std::error_code& error) const noexcept
{
    before_reading(file_offset, error);
    if(!error)
    {
        if(file_offset + length > m_length)
        {
            error = std::make_error_code(std::errc::invalid_argument);
        }
    }
}

inline void file::before_mapping_sink(const size_type file_offset,
    const int length, std::error_code& error) const noexcept
{
    before_writing(file_offset, error);
    if(!error)
    {
        if(file_offset + length > m_length)
        {
            error = std::make_error_code(std::errc::invalid_argument);
        }
    }
}

inline void file::before_reading(const size_type file_offset,
    std::error_code& error) const noexcept
{
    verify_file_offset(file_offset, error);
    if(error) { return; }
    verify_handle(error);
    if(error) { return; }

    else if(!is_allocated())
    {
        error = make_error_code(disk_io_errc::tried_unallocated_file_read);
    }
}

inline void file::before_writing(const size_type file_offset,
    std::error_code& error) const noexcept
{
    verify_file_offset(file_offset, error);
    if(error) { return; }
    verify_handle(error);
    if(error) { return; }

    else if(!is_allocated())
    {
        error = make_error_code(disk_io_errc::tried_unallocated_file_write);
    }
    else if(is_read_only())
    {
        error = make_error_code(disk_io_errc::tried_read_only_file_write);
    }
}

inline void file::verify_handle(std::error_code& error) const
{
    if(!is_open())
    {
        error = std::make_error_code(std::errc::bad_file_descriptor);
    }
}

inline void file::verify_file_offset(const size_type file_offset,
    std::error_code& error) const
{
    if((file_offset >= length()) || (file_offset < 0))
    {
        error = make_error_code(disk_io_errc::invalid_file_offset);
    }
}

namespace util {

void trim_buffers_front(view<iovec>& buffers, int num_to_trim) noexcept
{
    while(num_to_trim > 0)
    {
        const int buff_len = buffers.front().iov_len;
        if(buff_len > num_to_trim) { break; }
        num_to_trim -= buff_len;
        buffers.trim_front(1);
    }
    if(num_to_trim > 0)
    {
        assert(num_to_trim < int(buffers.front().iov_len));
        trim_iovec_front(buffers.front(), num_to_trim);
    }
}

} // namespace util
} // namespace tide
