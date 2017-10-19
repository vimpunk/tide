#ifndef TIDE_IOVEC_HEADER
#define TIDE_IOVEC_HEADER

/**
 * iovec is used for scatter gather IO operations, where the list is some list of iovec
 * structs specifying the individual buffers. This is also what the UNIX file IO
 * syscalls use. For convenience this structure is used in the entire app, and as for
 * Windows syscalls this is converted to the native requirements at the last step.
 */

#ifdef _WIN32
# include <cstddef> // size_t

struct iovec
{
    void* iov_base; /* Starting address. */
    size_t iov_len; /* Number of bytes to transfer. */
};

#else // _WIN32
# include <sys/uio.h>
#endif // _WIN32

namespace tide {
namespace util {

/** NOTE: if n is larger than iov.iov_len, using the iovec after this function is UB. */
inline void trim_iovec_front(iovec& iov, const int n) noexcept
{
    iov.iov_base = reinterpret_cast<char*>(iov.iov_base) + n;
    iov.iov_len -= n;
}

} // namespace util
} // namespace tide

#endif // TIDE_IOVEC_HEADER
