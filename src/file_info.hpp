#ifndef TORRENT_FILE_INFO_HEADER
#define TORRENT_FILE_INFO_HEADER

#include "path.hpp"

struct file_info
{
    class path path;
    int64_t length;
    // User may choose not to download a file, in which case this must be marked false.
    bool is_wanted = true;

    file_info(std::string p, int64_t l)
        : path(std::move(p))
        , length(l)
        , is_wanted(w)
    {}

    file_info(class path p, int64_t l)
        : path(std::move(p))
        , length(l)
        , is_wanted(w)
    {}
};

#endif // TORRENT_TORRENT_INFO_HEADER

