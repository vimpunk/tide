#include "system.hpp"

#ifndef _WIN32
# include <sys/sysinfo.h>
#endif

namespace tide {
namespace system {

#ifdef TIDE_USE_BOOST_FILESYSTEM

bool exists(const path& path, std::error_code& error)
{
    boost::filesystem::error_code ec;
    const auto result = boost::filesystem::exists(path, ec);
    if(ec) error = std::make_error_code(ec.value(), std::system_category());
    return result;
}

bool exists(const path& path)
{
    std::error_code ec;
    return exists(path, ec);
}

int64_t file_size(const path& path, std::error_code& error)
{
    boost::filesystem::error_code ec;
    const auto result = boost::filesystem::file_size(path, ec);
    if(ec) error = std::make_error_code(ec.value(), std::system_category());
    return result;
}

bool is_directory(const path& path, std::error_code& error)
{
    boost::filesystem::error_code ec;
    const auto result = boost::filesystem::is_directory(path, ec);
    if(ec) error = std::make_error_code(ec.value(), std::system_category());
    return result;
}

void create_directory(const path& path, std::error_code& error)
{
    boost::filesystem::error_code ec;
    boost::filesystem::create_directory(path, ec);
    if(ec) error = std::make_error_code(ec.value(), std::system_category());
}

void create_directories(const path& path, std::error_code& error)
{
    boost::filesystem::error_code ec;
    boost::filesystem::create_directories(path, ec);
    if(ec) error = std::make_error_code(ec.value(), std::system_category());
}

void rename(const path& old_path, const path& new_path, std::error_code& error)
{
    boost::filesystem::error_code ec;
    boost::filesystem::move(old_path, new_path, ec);
    if(ec) error = std::make_error_code(ec.value(), std::system_category());
}

void rename(const path& old_path, const path& new_path, std::error_code& error)
{
    rename(old_path, new_path, error);
}

#endif // defined(TIDE_USE_BOOST_FILESYSTEM)

std::error_code last_error() noexcept
{
    std::error_code error;
#ifdef _WIN32
    error.assign(GetLastError(), std::system_category());
#else
    error.assign(errno, std::system_category());
#endif
    return error;
}

ram ram_status(std::error_code& error)
{
    ram ram;
#ifdef _WIN32
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof ms;
    if(GlobalMemoryStatusEx(&ms) == 0)
    {
        error = last_error();
        return {};
    }
    ram.physical_size = ms.ullTotalPhys;
    ram.physical_free_space = ms.ullAvailPhys;
    ram.virtual_size = ms.ullTotalVirtual;
    ram.virtual_free_space = ms.ullAvailVirtual;
#else
    struct sysinfo si;
    if(sysinfo(&si) != 0)
    {
        error = last_error();
        return {};
    }
    ram.physical_size = si.totalram;
    ram.physical_free_space = si.freeram;
    //ram.shared = si.sharedram;
    ram.virtual_size = si.totalswap;
    ram.virtual_free_space = si.totalswap;
#endif
    return ram;
}

} // namespace system
} // namespace tide
