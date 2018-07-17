#ifndef TIDE_TORRENT_ARGS_HEADER
#define TIDE_TORRENT_ARGS_HEADER

#include "file_info.hpp"
#include "metainfo.hpp"
#include "settings.hpp"
#include "bdecode.hpp"
#include "types.hpp"
#include "path.hpp"

#include <string>
#include <vector>

namespace tide {

/**
 * These are the arguments with which a torrent can be started.
 * If the mandatory fields are erroneous, the torrent instantiation will fail.
 */
struct torrent_args
{
    // This is required for files, piece SHA-1 hashes and various other
    // parameters, see metainfo.hpp for more details.
    struct metainfo metainfo;

    // These must be indices into the file list in metainfo (need not have all
    // files, only the ones that have higher priority than normal). It should be
    // ordered by highest to lowest priority. By default no file has priority
    // over the other, the piece picker picks pieces that are the rarest (or
    // it's in sequential mode, in which case this list is still taken into
    // consideration). This has the same effect as calling
    // `torrent::prioritize_file` for each file index in this list.
    std::vector<file_index_t> priority_files;

    // This must be specified, and must be an absolute path.
    path save_path;

    // This is optional. If torrent is multi-file, this will be the name of the
    // root directory, and if it's not specified the `name` field in
    // `metainfo::source` is used, if it exists.
    std::string name;

    // See settings.hpp.
    torrent_settings settings;

    // Instructs engine not to start the download but to merely create a torrent
    // entry.
    bool start_in_paused = false;
};

} // namespace tide

#endif // TIDE_TORRENT_ARGS_HEADER
