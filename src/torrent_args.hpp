#ifndef TORRENT_TORRENT_ARGS_HEADER
#define TORRENT_TORRENT_ARGS_HEADER

#include "file_info.hpp"
#include "settings.hpp"
#include "bdecode.hpp"
#include "path.hpp"

#include <vector>

/**
 * These are the arguments with which a torrent can be started. All fields must be
 * present, unless otherwise specified, and if the mandatory fields are erroneous, the
 * torrent instantiation will fail.
 */
struct torrent_args
{
    // This is the decoded .torrent file, it's necessary to provide this for the
    // SHA-1 piece hashes and other info. Which files will actually be downloaded is
    // specified in files.
    bmap metainfo;

    // A position in this vector corresponds to the files specified in metainfo. This
    // vector must contain all the files listed in metainfo, but user may choose which
    // files to download. The files not wanted should be marked with file.is_wanted set
    // to false.
    std::vector<file_info> files;

    // These must be indices into the file list in metainfo (need not have all files,
    // only the ones that have higher priority than normal). It should be ordered by
    // highest to lowest priority. By default no file has priority over the other, the
    // piece picker picks pieces that are the rarest (or it's in sequential mode, in
    // which case this list is still taken into consideration). This has the same effect
    // as calling torrent::prioritize_file() with the specified file.
    std::vector<int> file_priorities;

    // This must be specified, and must be an absolute path.
    path save_path;

    // See settings.hpp.
    torrent_settings settings;

    // Does not start the download, it merely creates a torrent entry in engine.
    bool start_in_paused = 0;
};

#endif // TORRENT_TORRENT_ARGS_HEADER
