#ifndef TORRENT_DISK_IO_ERROR_HEADER
#define TORRENT_DISK_IO_ERROR_HEADER

#include <system_error>

enum class disk_io_error_t
{
    unknown = 1,
};

inline bool operator==(const disk_io_error_t e, const int i) noexcept
{
    return static_cast<int>(e) == i;
}

inline bool operator!=(const int i, const disk_io_error_t e) noexcept
{
    return !(e == i);
}

struct disk_io_error_category : public std::error_category
{
    const char* name() const noexcept override
    {
        return "disk_io";
    }

    std::string message(int env) const override
    {
        switch(static_cast<disk_io_error_t>(env))
        {
        default:
            return "unknown error";
        }
    }

    std::error_condition default_error_condition(int ev) const noexcept override
    {
        switch(static_cast<disk_io_error_t>(ev))
        {
        default:
            return std::error_condition(ev, *this);
        }
    }
};

const disk_io_error_category& disk_io_category()
{
    static disk_io_error_category instance;
    return instance;
}

std::error_code make_error_code(disk_io_error_t e)
{
    return std::error_code(
        static_cast<int>(e),
        disk_io_category()
    );
}

namespace std
{
    template<> struct is_error_code_enum<disk_io_error_t> : public true_type {};
}

// for more info:
// http://blog.think-async.com/2010/04/system-error-support-in-c0x-part-4.html

#endif // TORRENT_DISK_IO_ERROR_HEADER
