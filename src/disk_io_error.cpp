#include "disk_io_error.hpp"

namespace tide {

std::string disk_io_error_category::message(int env) const
{
    switch(static_cast<disk_io_errc>(env))
    {
    case disk_io_errc::unknown: return "Unknown";
    case disk_io_errc::tried_unwanted_file_read: return "Tried unwanted file read";
    case disk_io_errc::tried_unwanted_file_write: return "Tried unwanted file write";
    case disk_io_errc::tried_unallocated_file_read: return "Tried unallocated file read";
    case disk_io_errc::tried_unallocated_file_write: return "Tried unallocated file write";
    case disk_io_errc::tried_read_only_file_write: return "Tried read only file write";
    case disk_io_errc::invalid_file_offset: return "Invalid file offset";
    case disk_io_errc::null_transfer: return "Transfer of 0 bytes";
    case disk_io_errc::operation_aborted: return "Operation aborted";
    default: return "Unknown";
    }
}

std::error_condition
disk_io_error_category::default_error_condition(int ev) const noexcept
{
    switch(static_cast<disk_io_errc>(ev))
    {
    default:
        return std::error_condition(ev, *this);
    }
}

const disk_io_error_category& disk_io_category()
{
    static disk_io_error_category instance;
    return instance;
}

std::error_code make_error_code(disk_io_errc e)
{
    return std::error_code(static_cast<int>(e), disk_io_category());
}

std::error_condition make_error_condition(disk_io_errc e)
{
    return std::error_condition(static_cast<int>(e), disk_io_category());
}

} // namespace tide
