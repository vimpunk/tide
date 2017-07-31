#ifndef TIDE_DISK_IO_ERROR_HEADER
#define TIDE_DISK_IO_ERROR_HEADER

#include <system_error>
#include <string>

namespace tide {

enum class disk_io_errc
{
    unknown = 1,
    // We tried to read/block from a file that we marked as not downloaded (i.e.
    // we don't have its data written to disk).
    tried_unwanted_file_read,
    tried_unwanted_file_write,
    tried_unallocated_file_read,
    tried_unallocated_file_write,
    tried_read_only_file_write,
    invalid_file_offset,
    null_transfer,
    // Used when we abort a block read.
    operation_aborted
};

inline bool operator==(const disk_io_errc e, const int i) noexcept
{
    return static_cast<int>(e) == i;
}

inline bool operator!=(const int i, const disk_io_errc e) noexcept
{
    return !(e == i);
}

struct disk_io_error_category : public std::error_category
{
    const char* name() const noexcept override { return "disk_io"; }
    std::string message(int env) const override;
    std::error_condition default_error_condition(int ev) const noexcept override;
};

const disk_io_error_category& disk_io_category();
std::error_code make_error_code(disk_io_errc e);
std::error_condition make_error_condition(disk_io_errc e);

} // namespace tide

namespace std
{
    template<> struct is_error_code_enum<tide::disk_io_errc> : public true_type {};
}

// for more info:
// http://blog.think-async.com/2010/04/system-error-support-in-c0x-part-4.html

#endif // TIDE_DISK_IO_ERROR_HEADER
