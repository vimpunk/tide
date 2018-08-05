#ifndef TIDE_SYSTEM_HEADER
#define TIDE_SYSTEM_HEADER

#include "path.hpp"
#include "time.hpp"

#include <cstdint>
#include <filesystem>
#include <system_error>

#include <mio/page.hpp>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif // WIN32_LEAN_AND_MEAN
#include <windows.h>
#else // _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#define INVALID_HANDLE_VALUE -1 // This is the macro used on Windows.
#endif // _WIN32

namespace tide {
namespace system {

using namespace std::filesystem;

using file_handle_type =
#ifdef _WIN32
        HANDLE
#else
        int
#endif
        ;

/**
 * Returns the operating system's page granularity. Since this value is not expected
 * to change, only the first invocation of this function makes a syscall, caches the
 * returned value, enabling all other invocations to serve the cached value.
 */
using mio::page_size;

/** Returns `errno` on UNIX and the result of calling `GetLastError` on Windows. */
std::error_code last_error() noexcept;

struct ram
{
    int64_t physical_size;
    int64_t physical_free_space;
    // int64_t shared;
    int64_t virtual_size;
    int64_t virtual_free_space;
};

/**
 * Returns a `ram` instance describing info about this system's RAM. If `error` is set,
 * the values in the returned `ram` are undefined.
 */
ram ram_status(std::error_code& error);

} // namespace system
} // namespace tide

#endif // TIDE_SYSTEM_HEADER
