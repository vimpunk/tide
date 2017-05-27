#ifndef TORRENT_TORRENT_ARGS_HEADER
#define TORRENT_TORRENT_ARGS_HEADER

#include "file_info.hpp"
#include "metainfo.hpp"
#include "settings.hpp"
#include "bdecode.hpp"
#include "path.hpp"

#include <string>
#include <vector>

/**
 * These are the arguments with which a torrent can be started.
 * If the mandatory fields are erroneous, the torrent instantiation will fail.
 */
struct torrent_args
{
    // This is required for files, piece SHA-1 hashes and various other parameters,
    // see metainfo.hpp for more details.
    struct metainfo metainfo;

    // These must be indices into the file list in metainfo (need not have all files,
    // only the ones that have higher priority than normal). It should be ordered by
    // highest to lowest priority. By default no file has priority over the other, the
    // piece picker picks pieces that are the rarest (or it's in sequential mode, in
    // which case this list is still taken into consideration). This has the same effect
    // as calling torrent::prioritize_file() with the specified file.
    std::vector<int> file_priorities;

    // This must be specified, and must be an absolute path.
    path save_path;

    // This is optional. If torrent is multi-file, this will be the name of the root
    // directory.
    std::string name;

    // See settings.hpp.
    torrent_settings settings;

    // Does not start the download, it merely creates a torrent entry in engine.
    bool start_in_paused = 0;
};

#endif // TORRENT_TORRENT_ARGS_HEADER
