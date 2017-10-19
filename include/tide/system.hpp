#ifndef TIDE_FILE_SYSTEM_HEADER
#define TIDE_FILE_SYSTEM_HEADER

#include "path.hpp"
#include "time.hpp"

#include <system_error>
#include <cstdint>

#ifdef _WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif // WIN32_LEAN_AND_MEAN
# include <windows.h>
#else // _WIN32
// TODO check what we need and delete unused includes
# include <fcntl.h>
# include <unistd.h>
# include <sys/stat.h>
# include <sys/uio.h>
# define INVALID_HANDLE_VALUE -1 // this is the macro used on Windows
#endif // _WIN32

namespace tide {
namespace sys {

using file_handle_type =
#ifdef _WIN32
    HANDLE
#else
    int
#endif
;

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

int64_t file_size(const path& path, std::error_code& error);

void create_directory(const path& path, std::error_code& error);
void create_directories(const path& path, std::error_code& error);

/** On Linux open file descriptors for old_path are unaffected. TODO check on Windows. */
void move(const path& old_path, const path& new_path, std::error_code& error);
void rename(const path& old_path, const path& new_path, std::error_code& error);

/**
 * Returns the operating system's page granularity. Since this value is not expected
 * to change, only the first invocation of this function makes a syscall, caches the
 * returned value, enabling all other invocations to serve the cached value.
 */
size_t page_size();

/** Returns errno on UNIX and GetLastError() on Windows. */
std::error_code latest_error() noexcept;

} // namespace sys
} // namespace tide

#endif // TIDE_FILE_SYSTEM_HEADER
