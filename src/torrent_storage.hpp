#ifndef TORRENT_TORRENT_STORAGE_HEADER
#define TORRENT_TORRENT_STORAGE_HEADER

#include "torrent_state.hpp"
#include "torrent_info.hpp"
#include "string_view.hpp"
#include "block_info.hpp"
#include "bdecode.hpp"
#include "units.hpp"
#include "path.hpp"
#include "file.hpp"

#include <system_error>
#include <vector>

// File index can be used to retrieve files from torrent_storage. This is to avoid
// referring to the files directly, which allows more flexibility for future changes
// and safety as well.
using file_index_t = int;

/**
 * This class that is associated with a torrent, is an abstraction around everything
 * that is necessary to interact with the files we have or will download for the torrent.
 * All operations run synchronously, i.e. in the caller's thread. Therefore all methods
 * should be executed on a separate disk thread, such as in disk_io.
 *
 * NOTE: torrent_storage may not outlive its corresponding torrent instance.
 */
class torrent_storage
{
    struct file_entry
    {
        file storage;

        // If all files were regarded as a single continous byte stream, this file's
        // first byte would be at offset in that stream. This is used get the portion
        // in a piece that overlaps into this file.
        int64_t offset;

        // The range of pieces [first, last] that are covered by this file, even if
        // only partially.
        piece_index_t first_piece;
        piece_index_t last_piece;

        file_entry(path path, int64_t length, uint8_t open_mode)
            : storage(std::move(path), length, open_mode)
        {}
    };

    // Relevant info (such as piece length, wanted files etc) about storage's
    // corresponding torrent.
    const torrent_info& m_info;

    // All files listed in the metainfo are stored here, but files are lazily/ allocated
    // on disk, i.e. when they are first accessed. This way it is easy to mark a file,
    // which user had originally not wanted to download, as desired during the download.
    //
    // NOTE:
    // Despite lazy allocation preventing creating files that are never accessed, a
    // downloaded piece may still overlap into an unwanted file. In that case we don't
    // want to write those extra bytes to disk. Thus, before writing to a file, we must
    // check in m_info whether user actually wants that file, and discard those bytes
    // that overlap into the unwanted file.
    std::vector<file_entry> m_files;

    // The expected hashes of eall pieces, each hash's index in the vector implicitly
    // maps to its piece's index. This vector is allocated to be the size of all pieces.
    // Hash values are never actually copied out of the metainfo located in the torrent
    // to which whis storage belongs, these are just views into the original string.
    // (Thus, torrent must keep at least one instance of metainfo alive.)
    // TODO delete hash entries for pieces that we already have, do decrease memory usage
    std::vector<string_view> m_piece_hashes;

    path m_save_path;

    // Torrent's name and the name of the root directory if it has more than one file.
    std::string m_name;

    // The summed lengths of all files that are in this torrent, regardless if we're
    // downloading them.
    int64_t m_total_size = 0;

    // The summed lengths of all files that we are downloading.
    int64_t m_size = 0;

public:

    torrent_storage(
        const torrent_info& info,
        std::vector<string_view> piece_hashes,
        path save_path,
        std::string name
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

    /** Deletes file from disk. */
    std::error_code erase_file(const file_index_t file);
    std::error_code move(path path);
    std::error_code rename(std::string name);

    std::error_code update_torrent_state(const torrent_state& state);
    std::error_code save_torrent_state(const torrent_state& state);
    bool is_state_up_to_date(const torrent_state& state);

    /**
     * Returns a list of memory mapped objects that fully cover the specified portion
     * of the piece (pieces may span multiple files).
     */
    std::vector<mmap_source> create_ro_mmap(
        const block_info& info, std::error_code& error
    );
    std::vector<mmap_sink> create_rw_mmap(
        const block_info& info, std::error_code& error
    );

    /**
     * Blocking scatter-gather IO implemented using low-level syscalls.
     *
     * block_info specifies which piece, at which offset in the piece and how much in
     * the piece we should read from disk/write to buffer. Though the number of bytes
     * in buffer will be transferred at most.
     */
    void write(
        view<view<uint8_t>> buffers,
        const block_info& info,
        std::error_code& error
    );
    void read(
        view<view<uint8_t>> buffers,
        const block_info& info,
        std::error_code& error
    );

private:

    /**
     * Maps each file in m_info.files to a file_entry with correct data set up. Does not
     * allocate files (that's done on first access).
     */
    void initialize_file_entries();

    /**
     * Abstracts away scatter-gather io operations across multiple files, as reading and
     * writing are largely the same, and most of the effort is finding the files that
     * contain the block, finding the block's offset in file and how many of block's
     * bytes a file contains, managing the input buffer etc.
     *
     * Unless an error occurs, min(num_bytes_in_buffers, info.length) bytes are
     * guaranteed to be transferred.
     *
     * Also, if any of the files that are being written to/read from have not been
     * allocated on disk, this is done here before writing to them.
     *
     * Unwanted files are not actually touched.
     */
    template<typename FileIOFunction>
    void torrent_storage::do_file_io(
        FileIOFunction file_io_fn,
        view<view<uint8_t>> buffers,
        const block_info& info,
        std::error_code& error
    );
    void before_file_op(file_entry& file, std::error_code& error);

    /** Returns a range of files that contain some portion of the block or piece. */
    view<file_entry> find_files_containing_block(const block_info& block);
    view<file_entry> find_files_containing_piece(const piece_index_t piece);
};

#endif // TORRENT_TORRENT_STORAGE_HEADER
