#include "file.hpp"

// TODO delete logging from here
#include "log.hpp"
#include "string_utils.hpp"

#include <cmath>

#ifdef _WIN32
// emulate UNIX syscalls on windows so we can use the same api
// TODO
// TODO currently only linux is supported

file::size_typepread(handle_type file_handle, void* buffer, const file::size_type count,
        const int64_t file_offset)
{}

file::size_type pwrite(handle_type file_handle, void* buffer, const file::size_type count,
        const int64_t file_offset)
{}

file::size_type preadv(handle_type file_handle, iovec* buffers,
        file::size_type iovec_count, int64_t file_offset)
{}

file::size_type pwritev(handle_type file_handle, iovec* buffers,
        file::size_type iovec_count, int64_t file_offset)
{}
#endif // _WIN32

namespace tide {

std::string file_error_category::message(int env) const
{
    switch(static_cast<file_errc>(env)) {
    case file_errc::tried_unwanted_file_read: return "Tried unwanted file read";
    case file_errc::tried_unwanted_file_write: return "Tried unwanted file write";
    case file_errc::tried_unallocated_file_read: return "Tried unallocated file read";
    case file_errc::tried_unallocated_file_write: return "Tried unallocated file write";
    case file_errc::tried_read_only_file_write: return "Tried read only file write";
    case file_errc::invalid_file_offset: return "Invalid file offset";
    case file_errc::null_transfer: return "Transfer of 0 bytes";
    default: return "Unknown";
    }
}

error_condition file_error_category::default_error_condition(int ev) const noexcept
{
    switch(static_cast<file_errc>(ev)) {
        /*
    case file_errc::tried_unwanted_file_read:
    case file_errc::tried_unwanted_file_write:
    case file_errc::tried_unallocated_file_read:
    case file_errc::tried_unallocated_file_write:
    case file_errc::tried_read_only_file_write:
    case file_errc::invalid_file_offset:
    case file_errc::null_transfer:
        */
    default: return error_condition(ev, *this);
    }
}

const file_error_category& file_category()
{
    static file_error_category instance;
    return instance;
}

error_code make_error_code(file_errc e)
{
    return error_code(static_cast<int>(e), file_category());
}

error_condition make_error_condition(file_errc e)
{
    return error_condition(static_cast<int>(e), file_category());
}

// ----------
// -- file --
// ----------

file::file(path path, size_type length, open_mode_flags open_mode)
    : absolute_path_(std::move(path)), length_(length), open_mode_(open_mode)
{}

file::~file()
{
    close();
}

void file::erase(error_code& error)
{
    error.clear();
    verify_handle(error);
    if(error) {
        return;
    }
    if(is_open()) {
        // We shouldn't delete the file out from under us, even if the file is kept
        // alive as long as a file descriptor is referring to it (we probably don't
        // want this but TODO).
        error = std::make_error_code(std::errc::device_or_resource_busy);
        return;
    }
#ifdef _WIN32
    // TODO filepath name might be restricted
    if(DeleteFile(absolute_path_.c_str()) == 0) {
        error = system::last_error();
    }
#else // _WIN32
    if(unlink(absolute_path_.c_str()) != 0) {
        error = system::last_error();
    }
#endif // _WIN32
}

void file::move(const path& new_path, error_code& error)
{
    system::rename(absolute_path_, new_path, error);
    if(!error) {
        absolute_path_ = new_path;
    }
}

file::size_type file::query_size(error_code& error) const noexcept
{
    return system::file_size(path(), error);
}

void file::open(error_code& error)
{
    return open(open_mode_, error);
}

void file::open(open_mode_flags open_mode, error_code& error)
{
#ifdef TIDE_ENABLE_DEBUGGING
    log::log_disk_io("{FILE}", util::format("opening file %s", absolute_path().c_str()),
            true, log::priority::high);
#endif // TIDE_ENABLE_DEBUGGING
    error.clear();
    if(is_open()) {
        if(open_mode == open_mode_) {
            return;
        }
        // close file because we want to open it in a different mode
        close();
    }

#ifdef _WIN32
    // TODO
#else
    // use default permissions and let the OS decide the rest
    int permissions = S_IRUSR | S_IWUSR // user: read, write (00600)
            | S_IRGRP | S_IWGRP // group: read, write (00060)
            | S_IROTH | S_IWOTH; // other: read, write (00006)
    if(open_mode[executable]) {
        // give executable permission for all groups
        permissions |= S_IXUSR | S_IXGRP | S_IXOTH;
    }

    // the final open mode flag that is passed to open(2)
    int mode = 0;
#ifdef O_NOATIME
    mode |= (open_mode[no_atime] ? O_NOATIME : 0);
#endif // O_NOATIME

#ifdef O_SYNC
    mode |= (open_mode[no_os_cache] ? O_SYNC : 0);
#endif // O_SYNC

    if(open_mode[read_write])
        mode |= O_RDWR | O_CREAT;
    else if(open_mode[read_only])
        mode |= O_RDONLY;
    else if(open_mode[write_only])
        mode |= O_WRONLY | O_CREAT;

    file_handle_ = ::open(absolute_path_.c_str(), mode, permissions);

    if(file_handle_ == INVALID_HANDLE_VALUE && open_mode[no_atime] && errno == EPERM) {
        // O_NOATIME is not allowed for files we don't own, so try again without it
        mode &= ~O_NOATIME;
        open_mode.unset(no_atime);
        file_handle_ = ::open(absolute_path_.c_str(), mode, permissions);
    }

    if(file_handle_ == INVALID_HANDLE_VALUE) {
        error = system::last_error();
        return;
    }
#endif // _WIN32
    open_mode_ = open_mode;
}

void file::close()
{
    if(!is_open()) {
        return;
    }
#ifdef _WIN32
    ::CloseHandle(file_handle_);
#else
    ::close(file_handle_);
#endif
    file_handle_ = INVALID_HANDLE_VALUE;
}

void file::allocate(error_code& error)
{
    allocate(length(), error);
}

void file::allocate(const size_type length, error_code& error)
{
#ifdef TIDE_ENABLE_DEBUGGING
    log::log_disk_io("{FILE}",
            util::format("allocating file %s", absolute_path().c_str()), true,
            log::priority::high);
#endif // TIDE_ENABLE_DEBUGGING
    error.clear();
    verify_handle(error);
    // only (re)allocate if we're not allocated, or if we are if the requested length
    // to allocate is not equal to the currently allocated amount
    if(error || (is_allocated() && (length == this->length()))) {
        return;
    }

#ifdef _WIN32
    LARGE_INTEGER size;
    if(GetFileSizeEx(file_handle_, &size) == FALSE) {
        error = system::last_error();
        return;
    }

    if(size.QuadPart != length) {
        LARGE_INTEGER distance;
        distance.QuadPart = length;
        if(SetFilePointerEx(file_handle_, distance, &distance, FILE_BEGIN) == FALSE) {
            error = system::last_error();
            return;
        }
        if(SetEndOfFile(file_handle_) == FALSE) {
            error = system::last_error();
            return;
        }
    }
#else // _WIN32
    struct stat stat;
    if(fstat(file_handle_, &stat) != 0) {
        error = system::last_error();
        return;
    }

    // don't truncate file if it has the correct length
    if(stat.st_size == length) {
        is_allocated_ = true;
        length_ = length;
        return;
    }

    if(ftruncate(file_handle_, length) < 0) {
        error = system::last_error();
        return;
    }

    // only allocate file blocks if it isn't allocated yet (check if the correct number
    // of blocks (we have to round of the number of blocks relative to the file length
    // here) are allocated)
    if(stat.st_blocks < (length + stat.st_blksize - 1) / stat.st_blksize) {
        const int ret = posix_fallocate(file_handle_, 0, length);
        if(ret != 0) {
            error.assign(ret, std::system_category());
            return;
        }
    }
#endif // _WIN32
    is_allocated_ = true;
    length_ = length;
}

mmap_source file::create_mmap_source(
        const size_type file_offset, const size_type length, error_code& error)
{
    error.clear();
    before_mapping_source(file_offset, length, error);
    if(error) {
        return {};
    }

    mmap_source mmap;
    mmap.map(file_handle_, file_offset, length, error);
    return mmap;
}

mmap_sink file::create_mmap_sink(
        const size_type file_offset, const size_type length, error_code& error)
{
    error.clear();
    before_mapping_sink(file_offset, length, error);
    if(error) {
        return {};
    }

    mmap_sink mmap;
    mmap.map(file_handle_, file_offset, length, error);
    return mmap;
}

file::size_type file::read(view<uint8_t> buffer, size_type file_offset, error_code& error)
{
    return read(iovec{buffer.data(), buffer.length()}, file_offset, error);
}

file::size_type file::read(iovec buffer, size_type file_offset, error_code& error)
{
    error.clear();
    before_reading(file_offset, error);
    if(!error) {
        return single_buffer_io(buffer, file_offset, error,
                [this](void* buffer, size_type length, size_type offset) -> size_type {
                    return pread(file_handle_, buffer, length, offset);
                });
    }
    return 0;
}

file::size_type file::write(
        view<uint8_t> buffer, size_type file_offset, error_code& error)
{
    return write(iovec{buffer.data(), buffer.length()}, file_offset, error);
}

file::size_type file::write(iovec buffer, size_type file_offset, error_code& error)
{
    error.clear();
    before_writing(file_offset, error);
    if(!error) {
        return single_buffer_io(buffer, file_offset, error,
                [this](void* buffer, size_type length, size_type offset) -> size_type {
                    return pwrite(file_handle_, buffer, length, offset);
                });
    }
    return 0;
}

template <typename PIOFunction>
file::size_type file::single_buffer_io(
        iovec buffer, size_type file_offset, error_code& error, PIOFunction fn)
{
    size_type total_transferred = 0;
    while(buffer.iov_len > 0) {
        // make sure not to transfer more than what's left in file because if this is
        // a write operation, we'll enlarge file
        assert(length() - file_offset > 0);
        const size_type num_to_transfer
                = std::min(buffer.iov_len, size_t(length() - file_offset));
        assert(num_to_transfer > 0);
        const size_type num_transferred
                = fn(buffer.iov_base, num_to_transfer, file_offset);
        if(num_transferred < 0) {
            const error_code ec = system::last_error();
            if(ec == std::errc::interrupted) {
                continue;
            }
            error = ec;
            break;
        } else if(num_transferred == 0) {
            const error_code ec = system::last_error();
            if(ec)
                error = ec;
            else
                error = make_error_code(file_errc::null_transfer);
            break;
        }
        file_offset += num_transferred;
        total_transferred += num_transferred;
        util::trim_iovec_front(buffer, num_transferred);
    }
    return total_transferred;
}

file::size_type file::read(
        view<iovec>& buffers, const size_type file_offset, error_code& error)
{
    error.clear();
    return positional_vector_io(buffers, file_offset, error,
            [this](view<iovec>& buffers, size_type file_offset) -> size_type {
                return preadv(file_handle_, buffers.data(), buffers.size(), file_offset);
            });
}

file::size_type file::write(
        view<iovec>& buffers, const size_type file_offset, error_code& error)
{
    error.clear();
    before_writing(file_offset, error);
    if(error) {
        return 0;
    }

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
    const size_type adjusted_file_length = length() - file_offset;
    size_type buff_offset = 0;
    auto it = buffers.begin();
    const auto end = buffers.end();
    // if buffers has more bytes than adjusted_file_length, then find the last buffer
    // that can be written to file without extending file's size
    for(; it != end; ++it) {
        const size_type buff_end = buff_offset + it->iov_len;
        if((adjusted_file_length >= buff_offset) && (adjusted_file_length <= buff_end)) {
            break;
        }
        buff_offset = buff_end;
    }

    size_type num_written = 0;
    if(it != end) {
        // we were stopped from iterating all the way through buffers, so buffers has
        // more bytes than file
        // -1 because we don't want to trim off buffer pointed to by 'it'
        const size_type num_buffs_to_trim = end - it - 1;
        buffers.trim_back(num_buffs_to_trim);
        // but before trimming, we need to save some state so that we can restore the
        // buffers that we don't use, otherwise we'd leave buffers invalid (the buffer
        // after we're done writing should begin one past the last byte written, and not
        // stop there)
        // now trim the excess bytes in the partial buffer
        const size_type num_bytes_to_trim
                = buff_offset + it->iov_len - adjusted_file_length;
        it->iov_len -= num_bytes_to_trim;

        num_written = positional_vector_io(buffers, file_offset, error,
                [this](view<iovec>& buffers, size_type file_offset) -> size_type {
                    return pwritev(
                            file_handle_, buffers.data(), buffers.size(), file_offset);
                });

        if(num_bytes_to_trim > 0) {
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
    } else {
        num_written = positional_vector_io(buffers, file_offset, error,
                [this](view<iovec>& buffers, size_type file_offset) -> size_type {
                    return pwritev(
                            file_handle_, buffers.data(), buffers.size(), file_offset);
                });
    }

    if(!error && open_mode_[no_os_cache]) {
        sync_with_disk(error);
    }
    return num_written;
}

// this is currently unused as positional_vector_io is assumed to perform better but do
// profile and maybe add compile time branching depending on the system that's known
// to perform better under repeated calls to pread/pwrite (some personal anecdotes
// indicated that this seems to be the case)
template <typename PIOFunction>
file::size_type file::repeated_positional_io(
        view<iovec>& buffers, size_type file_offset, error_code& error, PIOFunction fn)
{
    size_type file_length_left = length() - file_offset;
    size_type total_transferred = 0;
    for(iovec& buffer : buffers) {
        // fn is not guaranteed to transfer all of buffer, so retry until everything
        // has been sent
        while(buffer.iov_len > 0) {
            const size_type num_to_transfer
                    = std::min(file_length_left, size_type(buffer.iov_len));
            const size_type num_transferred
                    = fn(buffer.iov_base, num_to_transfer, file_offset);
            if(num_transferred < 0) {
                const error_code ec = system::last_error();
                if(ec == std::errc::interrupted) {
                    continue;
                }
                error = ec;
                return total_transferred;
            } else if(num_transferred == 0) {
                const error_code ec = system::last_error();
                if(ec)
                    error = ec;
                else
                    error = make_error_code(file_errc::null_transfer);
                return total_transferred;
            }

            total_transferred += num_transferred;
            file_offset += num_transferred;
            file_length_left -= num_transferred;
            if(file_length_left == 0) {
                return total_transferred;
            }

            util::trim_iovec_front(buffer, num_transferred);
        }
    }
    return total_transferred;
}

template <typename PVIOFunction>
file::size_type file::positional_vector_io(
        view<iovec>& buffers, size_type file_offset, error_code& error, PVIOFunction fn)
{
    size_type file_length_left = length() - file_offset;
    size_type total_transferred = 0;
    // ideally this will loop once but preadv/pwritev are not guaranteed to transfer
    // the requested bytes so we have to call it again until all requested bytes are
    // transferred
#ifdef TIDE_ENABLE_DEBUGGING
    log::log_disk_io("{FILE}",
            util::format("buffers.size() = %i, file_length_left = %lli", buffers.size(),
                    file_length_left),
            false, log::priority::high);
#endif // TIDE_ENABLE_DEBUGGING
    int loop_counter = 0;
    while(!buffers.empty() && (file_length_left > 0)) {
#ifdef TIDE_ENABLE_DEBUGGING
        log::log_disk_io("{FILE}",
                util::format("%ith loop in trying to transfer data from/to file",
                        loop_counter),
                false, log::priority::high);
#endif // TIDE_ENABLE_DEBUGGING
        const size_type num_transferred = fn(buffers, file_offset);
        if(num_transferred < 0) {
            const error_code ec = system::last_error();
            if(ec == std::errc::interrupted) {
                continue;
            }
            error = ec;
            break;
        } else if(num_transferred == 0) {
            const error_code ec = system::last_error();
            if(ec)
                error = ec;
            else
                error = make_error_code(file_errc::null_transfer);
            break;
        }
        total_transferred += num_transferred;
        file_offset += num_transferred;
        file_length_left -= num_transferred;
        util::trim_buffers_front(buffers, num_transferred);
        ++loop_counter;
    }
    return total_transferred;
}

void file::sync_with_disk(error_code& error)
{
    error.clear();
    // no need to sync if we're not in write mode
    if(is_read_only()) {
        return;
    }
#ifdef _WIN32
    if(!FlushFileBuffers(file_handle_)) {
        error = system::last_error();
    }
#else
    if(fdatasync(file_handle_) != 0) {
        error = system::last_error();
    }
#endif
}

inline void file::before_mapping_source(const size_type file_offset,
        const size_type length, error_code& error) const noexcept
{
    before_reading(file_offset, error);
    if(!error) {
        if(file_offset + length > length_) {
            error = make_error_code(errc::invalid_argument);
        }
    }
}

inline void file::before_mapping_sink(const size_type file_offset, const size_type length,
        error_code& error) const noexcept
{
    before_writing(file_offset, error);
    if(!error) {
        if(file_offset + length > length_) {
            error = std::make_error_code(std::errc::invalid_argument);
        }
    }
}

inline void file::before_reading(const size_type file_offset, error_code& error) const
        noexcept
{
    verify_file_offset(file_offset, error);
    if(error) {
        return;
    }
    verify_handle(error);
    if(error) {
        return;
    }

    else if(!is_allocated()) {
        error = make_error_code(file_errc::tried_unallocated_file_read);
    }
}

inline void file::before_writing(const size_type file_offset, error_code& error) const
        noexcept
{
    verify_file_offset(file_offset, error);
    if(error) {
        return;
    }
    verify_handle(error);
    if(error) {
        return;
    }

    if(!is_allocated()) {
        error = make_error_code(file_errc::tried_unallocated_file_write);
    } else if(is_read_only()) {
        error = make_error_code(file_errc::tried_read_only_file_write);
    }
}

inline void file::verify_handle(error_code& error) const
{
    if(!is_open()) {
        error = std::make_error_code(std::errc::bad_file_descriptor);
    }
}

inline void file::verify_file_offset(const size_type file_offset, error_code& error) const
{
    if((file_offset >= length()) || (file_offset < 0)) {
        error = make_error_code(file_errc::invalid_file_offset);
    }
}

namespace util {

void trim_buffers_front(view<iovec>& buffers, int num_to_trim) noexcept
{
    while(num_to_trim > 0) {
        const int buff_len = buffers.front().iov_len;
        if(buff_len > num_to_trim) {
            break;
        }
        num_to_trim -= buff_len;
        buffers.trim_front(1);
    }
    if(num_to_trim > 0) {
        assert(num_to_trim < int(buffers.front().iov_len));
        trim_iovec_front(buffers.front(), num_to_trim);
    }
}

} // namespace util
} // namespace tide
