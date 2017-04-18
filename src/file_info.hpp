#ifndef TORRENT_FILE_INFO_HEADER
#define TORRENT_FILE_INFO_HEADER

#include <string>

struct file_info
{
    std::string path;
    int64_t length;

    file_info(std::string p, int64_t l)
        : path(std::move(path))
        , length(l)
    {}
};

#endif // TORRENT_TORRENT_INFO_HEADER

