#ifndef TORRENT_METAINFO_HEADER
#define TORRENT_METAINFO_HEADER

#include "string_view.hpp"
#include "file_info.hpp"
#include "bdecode.hpp"

#include <vector>

namespace tide {

struct metainfo
{
    // This must not be destroyed, for all the below collections point into its source
    // buffer.
    bmap source;

    // This must be present. TODO check if this is true
    string_view announce;
    string_view piece_hashes;

    // http://bittorrent.org/beps/bep_0012.html
    // If this is not empty, only this list will be used. Note that tiers, as described
    // in the protocol extension, are not actually implemented, as trackers in announce
    // list are simply placed in here in the correct order they are tiered. This is to
    // save some dynamic allocation that would be inherent with the extra vectors that
    // comprise the tiers.
    std::vector<string_view> announce_list;

    // A position in this vector corresponds to the file(s) specified in metainfo. This
    // vector must contain all the files listed in metainfo, but user may choose which
    // files to download. The files not wanted should be marked with file.is_wanted set
    // to false.
    //
    // The reason for providing a separate files list and not using the one in metainfo
    // is that the file paths in metainfo are specified with path elements and may be
    // incorrect, while all file_info.paths here are reconstructed to conform to the
    // host's OS, and more importantly, sanitized (invalid path elements are changed or
    // removed, security hazards eliminated etc), which means that the path here might
    // be different to the one specified in metainfo.
    //
    // The number of files here and in metainfo must match, i.e. unwanted files must not
    // be removed.
    std::vector<file_info> files;

    int64_t piece_length;
    int64_t total_length;
    int num_pieces;
};

/**
 * This function extracts all commonly used data from the "raw" bmap representing the
 * .torrent/metainfo file, and more importantly, takes care of sanitizing file paths.
 * The rest of the (optional) information may be manually extracted from metainfo.source.
 *
 * An exception is thrown if any of the required fields are not in source.
 */
metainfo parse_and_sanitize_metainfo(bmap source);

} // namespace tide

#endif //TORRENT_METAINFO_HEADER 
