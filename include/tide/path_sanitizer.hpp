#ifndef TIDE_PATH_SANITIZER_HEADER
#define TIDE_PATH_SANITIZER_HEADER

#include "bdecode.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace tide {

/**
 * This is used primarily to sanitize the file paths specified in the .torrent
 * metainfo file, as due to the metainfo format's leniency, paths may not
 * conform the rules of the host's OS and/or may have path elements considered
 * insecure. All paths must first be sanitized before using them.
 */
std::filesystem::path create_and_sanitize_path(const blist& path_elements);
std::filesystem::path sanitize_path(std::string_view path);

} // namespace tide

#endif // TIDE_PATH_SANITIZER_HEADER
