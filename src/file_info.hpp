#ifndef TORRENT_FILE_INFO_HEADER
#define TORRENT_FILE_INFO_HEADER

#include "path.hpp"

struct file_info
{
    // At this point path has been sanitized, so it is safe to use.
    class path path;
    // In bytes.
    int64_t length;
    // User may choose not to download a file, in which case this must be marked false.
    bool is_wanted = true;

    file_info() = default;
    file_info(class path p, int64_t l)
        : path(std::move(p))
        , length(l)
    {}
};

#endif // TORRENT_TORRENT_INFO_HEADER
