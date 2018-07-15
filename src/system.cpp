#include "system.hpp"

#ifndef _WIN32
# include <sys/sysinfo.h>
#endif

namespace tide {
namespace system {

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
