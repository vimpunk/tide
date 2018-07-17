#ifndef TIDE_FILE_INFO_HEADER
#define TIDE_FILE_INFO_HEADER

#include <cstdint>
#include <filesystem>

namespace tide {

struct file_info
{
    // A relative path. This is so that when user moves torrent, no file data has to
    // be changed, only a single internal root path field.
    // At this point path has been sanitized, so it is safe to use.
    std::filesystem::path path;
    // In bytes.
    int64_t length;
    // How many bytes of the file we have downloaded.
    int64_t downloaded_length = 0;
    // User may choose not to download a file, in which case this must be marked false.
    bool is_wanted = true;

    file_info() = default;
    file_info(std::filesystem::path p, int64_t l)
        : path(std::move(p))
        , length(l)
    {}
};

} // namespace tide

#endif // TIDE_TORRENT_INFO_HEADER
