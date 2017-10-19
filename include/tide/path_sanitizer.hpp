#ifndef TIDE_PATH_SANITIZER_HEADER
#define TIDE_PATH_SANITIZER_HEADER

#include "string_view.hpp"
#include "bdecode.hpp"
#include "view.hpp"
#include "path.hpp"

#include <string>
#include <vector>

namespace tide {

/**
 * This is used primarily to sanitize the file paths specified in the .torrent metainfo
 * file, as due to the metainfo format's leniency, paths may not conform the rules of
 * the host's OS and/or may have path elements considered insecure. All paths must first
 * be sanitized before using them.
 */
path create_and_sanitize_path(const blist& path_elements);

} // namespace tide

#endif // TIDE_PATH_SANITIZER_HEADER
