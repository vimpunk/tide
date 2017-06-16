#ifndef TORRENT_TORRENT_STORAGE_HEADER
#define TORRENT_TORRENT_STORAGE_HEADER

#include "torrent_info.hpp"
#include "string_view.hpp"
#include "block_info.hpp"
#include "interval.hpp"
#include "bdecode.hpp"
#include "bencode.hpp"
#include "units.hpp"
#include "iovec.hpp"
#include "path.hpp"
#include "file.hpp"

#include <system_error>
#include <memory>
#include <vector>

namespace tide {

/**
 * Denotes where in the file the requested block is (offset) and how much of block
 * is in file (length).
 */
struct file_slice
{
    int64_t offset = 0;
    int64_t length = 0;
};

// TODO stats collection: avg read-write times
// idea: alternate between preadv and repeated pread calls depending on average time
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
        // first byte would be at this offset in the stream. This is used find the files
        // that map to a piece.
        // TODO perhaps rename to stream_offset to better illustrate this
        int64_t offset;

        // The range of pieces [first, last] that are covered by this file, even if
        // only partially.
        piece_index_t first_piece;
        piece_index_t last_piece;

        // Despite lazy allocation preventing creating files that are never accessed, a 
        // downloaded piece may still overlap into an unwanted file. In that case we
        // don't want to write those extra bytes to disk. Thus, before writing to a
        // file, we must check whether user actually wants that file, and discard those 
        // bytes that overlap into the unwanted file.
        bool is_wanted;
    };

    // All files listed in the metainfo are stored here, but files are lazily/ allocated
    // on disk, i.e. when they are first accessed.
    std::vector<file_entry> m_files;

    // Relevant info (such as piece length, wanted files etc) about storage's
    // corresponding torrent. Fields currently used:
    // files
    // TODO consider putting these in a torrent_storage_args fields so as not to
    // refer to torrent_info to avoid potential race conditions
    std::shared_ptr<torrent_info> m_info;

    // The expected hashes of all pieces, represented as a single block of memory for
    // optimal storage (this is a direct view into the original metainfo's encoded source
    // buffer). To retrieve a piece's hash:
    // string_view(m_piece_hashes.data() + piece_index * m_info->piece_length, 20)
    // NOTE: the metainfo into which this points must be kept alive.
    string_view m_piece_hashes;

    // This is the file where torrent resume data is stored.
    file m_resume_data;

    // This is an absolute path.
    path m_save_path;

    // The name of the root directory if this is a multi-file torrent.
    std::string m_name;

    const int m_piece_length;
    // This is the total number of pieces in torrent, and  may not be the same as the
    // number of pieces we actually want to download.
    // TODO this may not be needed
    const int m_num_pieces;

    // This is the number of bytes we download, which may not be the same as the sum of
    // each file's length, as we may not download all files.
    int64_t m_size_to_download = 0;

public:

    torrent_storage(std::shared_ptr<torrent_info> info,
        string_view piece_hashes, std::string resume_data_path);

    /**
     * This is the name of the torrent which, if the torrent has multiple files, is also
     * the root directory's name.
     */
    const std::string& name() const noexcept { return m_name; }

    /**
     * These return the root path of the torrent, which is the file itself for single
     * file torrents.
     */
    const path& save_path() const noexcept { return m_save_path; }

    /**
     * Returns the total number of bytes of all files we'll have once all the wanted
     * files are downloaded (that is, if we're not downloading all files, then this
     * value won't match the summed lengths of all files in metainfo.
     */
    int64_t size_to_download() const noexcept { return m_size_to_download; }

    /**
     * Returns an interval of piece indices of the pieces that are, even if partially,
     * in file. The range is left inclusive, i.e. the valid pieces are in the range 
     * [interval.begin, interval.end).
     */
    interval pieces_in_file(const file_index_t file_index) const noexcept;

    /**
     * The opposite of pieces_in_file: returns the range of files (in the form of file
     * indices into torrent_info::files) that cover part of piece. The range is left
     * inclusive, i.e. the valid files are in the range [interval.begin, interval.end).
     */
    interval files_containing_piece(const piece_index_t piece) const noexcept;

    /**
     * Returns where in file block resides. The return value is invalid if both
     * fields in file_slice are 0. This can happen if the block is not in file.
     */
    file_slice get_file_slice(const file_index_t file,
        const block_info& block) const noexcept;

    /** Returns the expected 20 byte SHA-1 hash for this piece. */
    string_view expected_hash(const piece_index_t piece) const noexcept;

    /**
     * User can change which files they wish to download during the download. These
     * merely mark the internal file_entry as wanted or not, but if the file is already
     * downloaded, it is not deleted (for that use erase_file). 
     */
    void want_file(const file_index_t file) noexcept;
    void dont_want_file(const file_index_t file) noexcept;

    void erase_file(const file_index_t file, std::error_code& error);

    /**
     * The torrent's current path, stored in torrent's torrent_info, must not be changed
     * from anywhere but here. If this operation is sucessful, the torrent_info.save_path
     * is updated to the new path.
     */
    void move_file(path path, std::error_code& error);

    bmap read_resume_data(std::error_code& error);
    void write_resume_data(const bmap_encoder& resume_data, std::error_code& error);

    /**
     * Returns a list of memory mapped objects that fully cover the specified portion
     * of the piece (pieces may span multiple files).
     *
     * info specifies which piece, at which offset in the piece and how much in the
     * piece we should map into memory.
     *
     * Files that are mapped must be allocated in read only-mode (we can't verify
     * whether the actual data is valid, so this is a best effort check), and if they
     * are not, error is set and no mappings are returned.
     * In the case of read-write mode, files are opened and allocated if they haven't
     * already been.
    std::vector<mmap_source> create_mmap_source(
        const block_info& info, std::error_code& error);
    std::vector<mmap_sink> create_mmap_sink(
        const block_info& info, std::error_code& error);
     */

    /**
     * Blocking scatter-gather IO implemented using syscalls.
     *
     * info specifies which piece, at which offset in the piece and how much in the
     * piece we should read from disk/write to buffer. Though buffer size number of
     * bytes will be transferred at most.
     * Unless an error occurs, min(num_bytes_in_buffers, info.length) bytes are
     * guaranteed to be read/written.
     *
     * In case of writing, if any of the files that are being written to have not been
     * allocated on disk, this is done here before writing to them.
     * In the case of reading, a file is opened if it's not open, but if it's not
     * allocated, the operation ends in an error.
     *
     * NOTE: the number of bytes that have been read/written are trimmed from the iovec
     * buffers view. Thus it should not be used to refer to the original/resulting data
     * after this function.
     */
    void read(view<iovec>& buffers, const block_info& info, std::error_code& error);
    void read(std::vector<iovec> buffers, const block_info& info, std::error_code& error);
    void write(view<iovec>& buffers, const block_info& info, std::error_code& error);
    void write(std::vector<iovec> buffers, const block_info& info, std::error_code& error);

private:

    void verify_file_index(const file_index_t index);

    /**
     * Maps each file in torrent_info::files to a file_entry with correct data set up. 
     * Does not allocate files in the download directory (that's done on first access).
     */
    void initialize_file_entries(const_view<file_info> files);

    /**
     * In case of multi file mode and if there are files nested in directories, the
     * directories are created, but not the files.
     *
     * NOTE: muste be called after m_files has been initialized.
     */
    void create_directory_tree();
    void create_directory(const path& path, std::error_code& error);
    void create_directories(const path& path, std::error_code& error);

    /**
     * The first time we write to a file, it's neither opened nor allocated, so this
     * function checks and takes care of doing so if necessary. If otherwise it's
     * allocated just not open, it is opened.
     */
    void before_writing(file& file, std::error_code& error);

    /**
     * When reading, files must already be allocated, so if they aren't, an error is
     * set. If otherwise it's allocated just not open, it is opened.
     */
    void before_reading(file_entry& file, std::error_code& error);
    void before_reading(file& file, std::error_code& error);

    /**
     * Both reading from, writing to and mapping files (the portions of them that
     * correspond to the block as described by info) involve the same plumbing
     * to keep track of where in the file we want to do the io operation, so this
     * function serves as an abstraction around the common parts.
     *
     * io_fn is called for every file that is processed (since blocks may span
     * several files), and must have the following signature:
     *
     * int io_fn(
     *     file_entry&,     // the current file on which to operate
     *     file_slice&      // the offset into the file where block starts and the
     *                      // number of bytes that block occupies in file
     *     std::error_code& // this must be set to any io error that occured
     * )
     */
    template<typename IOFunction> void do_file_io(
        IOFunction io_fn, const block_info& info, std::error_code& error);

    /**
     * Returns the position where in file offset, which refers to the offset in
     * all files combined, is and how much of length is contained in file.
     */
    file_slice get_file_slice(const file_entry& file,
        int64_t offset, int64_t length) const noexcept;

    /** Returns a range of files that contain some portion of the block or piece. */
    view<file_entry> files_containing_block(const block_info& block);
    //view<file_entry> files_containing_piece(const piece_index_t piece);

    bool is_valid_file_index(const file_index_t index) const noexcept;
};

} // namespace tide

#endif // TORRENT_TORRENT_STORAGE_HEADER
