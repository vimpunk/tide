#ifndef TORRENT_TORRENT_STORAGE_HEADER
#define TORRENT_TORRENT_STORAGE_HEADER

#include "torrent_state.hpp"
#include "torrent_info.hpp"
#include "units.hpp"
#include "path.hpp"
#include "file.hpp"
#include "bdecode.hpp"

#include <system_error>
#include <vector>

// File index can be used to retrieve files from torrent_storage. This is to avoid
// referring to the files directly, which allows more flexibility for future changes
// and safety as well.
using file_index_t = int;

/**
 * A file_slice is used to represent the part of the file that contains a piece or
 * some fragment of it, denoted in an interval.
 * TODO
 */
struct file_slice
{
    // Files are accessed via file indices in torrent_storage for fast, cheap and
    // abstracted away file handling.
    file_index_t file_index;
    int64_t piece_start;
    int64_t piece_end;
};

/**
 * This class that is associated with a torrent, is an abstraction around everything
 * that is necessary to interact with the files we have or will download for the torrent.
 * All operations run synchronously, i.e. in the caller's thread. Therefore all methods
 * should be executed on a separate disk thread, such as in disk_io.
 */
class torrent_storage
{
    // torrent_storage takes ownership of the original metainfo bencode dictionary that
    // was parsed from the .torrent file. This is used to extract information about all
    // the files that will be in the torrent and to extract piece SHA-1 hashes (and
    // avoid making copies of them which could be quite expensive).
    // TODO or maybe let user pass in those values? like a view into the hashes?
    // we already use a reference which could just as well be invalidated so maybe we
    // should do that because otherwise torrent_storage has no use for the metainfo map
    bmap m_metainfo;

    std::vector<file> m_files;

    // The expected hashes of eall pieces, each hash's index in the vector implicitly
    // maps to its piece's index.
    // TODO perhaps only keep those that are necessary,
    // for user may not want to download the entire torrent. in that case a std::map
    // needs to be used with explicit piece indices
    // TODO also, perhaps these could be string_views into the original metainfo buffer
    // to avoid that many copies
    std::vector<sha1_hash> m_piece_hashes;

    // A reference to the corresponding torrent's stats & info. torrent_storage
    // may not outlive the matching torrent instance.
    const torrent_info& m_info;

    path m_save_path;

    // Torrent's name and the name of the root directory if it has more than one file.
    std::string m_name;

    // The summed lengths of all files in m_files.
    int64_t m_size = 0;

public:

    torrent_storage(
        const torrent_info& info,
        const std::vector<file_info>& files,
        std::vector<sha1_hash> hashes,
        path save_path,
        std::string name,
    );

    /**
     * This is the name of the torrent which, if the torrent has multiple files, is also
     * the root directory's name.
     */
    const std::string& name() const noexcept;

    /**
     * These return the root path of the torrent, which is the file itself for single
     * file torrents.
     */
    path absolute_path() const noexcept;
    path relative_path() const noexcept;

    /** Returns the number of files we're downloading (as user may not want all files). */
    const int num_files() const noexcept;

    /** Returns the total number of bytes of all files we're downloading. */
    const int64_t size() const noexcept;

    std::error_code move(path path);
    std::error_code rename(std::string name);
    std::error_code save_torrent_state(const torrent_state& state);
    bool is_state_up_to_date(const torrent_state& state);

    /**
     * Returns a list of memory mapped objects that fully covers the specified portion
     * of the piece (pieces may span multiple files).
     */
    std::vector<mmap_source> create_ro_mmap(
        std::error_code& error,
        const piece_index_t piece,
        const int64_t offset,
        const int64_t length
    );
    std::vector<mmap_sink> create_rw_mmap(
        std::error_code& error,
        const piece_index_t piece,
        const int64_t offset,
        const int64_t length
    );

    /**
     * Blocking scatter-gather IO implemented using low-level syscalls.
     * TODO comment
     */
    void write(
        std::error_code& error,
        const piece_index_t piece,
        view<view<uint8_t>> buffers,
        const int64_t piece_offset,
        const int64_t piece_length
    );
    void read(
        std::error_code& error,
        const piece_index_t piece,
        view<view<uint8_t>> buffers,
        const int64_t piece_offset,
        const int64_t piece_length
    );

private:

    /** Returns a range of files that contain some portion of the piece. */
    view<file> files_containing_piece(const piece_index_t piece);
};

#endif // TORRENT_TORRENT_STORAGE_HEADER
