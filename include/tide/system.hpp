#ifndef TIDE_SYSTEM_HEADER
#define TIDE_SYSTEM_HEADER

#include "path.hpp"
#include "time.hpp"

#include <system_error>
#include <cstdint>

#include <mio/page.hpp>

#ifdef _WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif // WIN32_LEAN_AND_MEAN
# include <windows.h>
#else // _WIN32
# include <fcntl.h>
# include <unistd.h>
# include <sys/stat.h>
# include <sys/uio.h>
# define INVALID_HANDLE_VALUE -1 // This is the macro used on Windows.
#endif // _WIN32

#if defined(TIDE_USE_BOOST_FILESYSTEM)
# error "Not implemented." // TODO

# include <boost/filesystem.hpp>

namespace tide {
namespace system {

bool exists(const path& path);
bool exists(const path& path, std::error_code& error);
bool is_directory(const path& path, std::error_code& error);

int64_t file_size(const path& path, std::error_code& error);

void create_directory(const path& path, std::error_code& error);
void create_directories(const path& path, std::error_code& error);

/** On Linux open file descriptors for old_path are unaffected. TODO check on Windows. */
void rename(const path& old_path, const path& new_path, std::error_code& error);
void rename(const path& old_path, const path& new_path, std::error_code& error);

} // namespace system
} // namespace tide

#elif __cplusplus >= 201406L

# include <filesystem>

namespace tide {
namespace system {
using namespace std::filesystem;
} // namespace system
} // namespace tide

#elif defined(TIDE_USE_EXPERIMENTAL_FILESYSTEM)

# include <experimental/filesystem>

namespace tide {
namespace system {
using namespace std::experimental::filesystem;
} // namespace system
} // namespace tide

#endif // defined(TIDE_USE_EXPERIMENTAL_FILESYSTEM)

namespace tide {
namespace system {

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

/** Returns errno on UNIX and GetLastError() on Windows. */
std::error_code last_error() noexcept;

struct ram
{
    int64_t physical_size;
    int64_t physical_free_space;
    //int64_t shared;
    int64_t virtual_size;
    int64_t virtual_free_space;
};

/**
 * Returns a `ram` instance describing info about this system's RAM. Note that if
 * `error` is set, the values in the returned `ram` are undefined.
 */
ram ram_status(std::error_code& error);

} // namespace system
} // namespace tide

#endif // TIDE_SYSTEM_HEADER
