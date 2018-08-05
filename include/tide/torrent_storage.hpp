#ifndef TIDE_TORRENT_STORAGE_HEADER
#define TIDE_TORRENT_STORAGE_HEADER

#include "bdecode.hpp"
#include "bencode.hpp"
#include "block_info.hpp"
#include "error_code.hpp"
#include "file.hpp"
#include "interval.hpp"
#include "iovec.hpp"
#include "string_view.hpp"
#include "torrent_info.hpp"
#include "types.hpp"

#include <filesystem>
#include <memory>
#include <vector>

namespace tide {

class bitfield;
class disk_buffer;

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
 * NOTE: for now this is not thread-safe but we might want to prevent multiple threads
 * accessing the same files. TODO
 */
class torrent_storage
{
    struct file_entry
    {
        file storage;

        // The offset of this file in the torrent, i.e. the offset in all files
        // conceptually concatenated in one contiguous byte array.
        int64_t torrent_offset; // const

        // The range of pieces [first, last] that are covered by this file, even if
        // only partially.
        piece_index_t first_piece; // const
        piece_index_t last_piece; // const

        // Despite lazy allocation preventing creating files that are never accessed, a
        // downloaded piece may still overlap into an unwanted file. In that case we
        // don't want to write those extra bytes to disk. Thus, before writing to a
        // file, we must check whether user actually wants that file, and discard those
        // bytes that overlap into the unwanted file.
        bool is_wanted;
    };

    // All files listed in the metainfo are stored here, but files are lazily/ allocated
    // on disk, i.e. when they are first accessed. The vector itself is never changed
    // (resize/reallocation), therefore the buffer's memory remains intact, which can be
    // relied upon when ensuring thread-safety.
    std::vector<file_entry> files_;

    // This is the file where torrent resume data is stored.
    file resume_data_;

    // The expected hashes of all pieces, represented as a single block of memory for
    // optimal memory layout. To retrieve a piece's hash:
    // string_view(piece_hashes_.data() + piece_index * piece_length_, 20)
    // TODO make this const to semantically ensure thread safety
    std::string piece_hashes_;

    // This is an absolute path to the root directory in which torrent is saved. If
    // torrent is multi-file, the root directory is save path / torrent name, otherwise
    // it's just save path.
    std::filesystem::path root_path_;

    // The name of the root directory if this is a multi-file torrent.
    std::string name_;

    int piece_length_; // const

    // This is the total number of pieces in torrent, but may not be the same as the
    // number of pieces we actually want to download.
    int num_pieces_; // const

    // This is the number of bytes we download, which may not be the same as the sum of
    // each file's length, as we may not download all files.
    int64_t size_to_download_ = 0;
    int64_t size_ = 0; // const

public:
    /**
     * Initializes internal file entries, and if torrent is multi-file, establishes
     * the final directory structure (but does not allocate any files).
     */
    torrent_storage(const torrent_info& info, string_view piece_hashes,
            std::filesystem::path resume_data_path);
    torrent_storage(const torrent_storage&) = delete;
    torrent_storage& operator=(const torrent_storage&) = delete;
    torrent_storage(torrent_storage&&) = default;
    torrent_storage& operator=(torrent_storage&&) = default;

    /**
     * These return the root path of the torrent, which is save path / torrent name for
     * multi-file torrents and save path for single file torrents.
     */
    const std::filesystem::path& root_path() const noexcept { return root_path_; }
    const std::string name() const noexcept { return name_; }

    /**
     * Returns the total number of bytes of all files we'll have once all the wanted
     * files are downloaded (that is, if we're not downloading all files, then this
     * value won't match the summed lengths of all files in metainfo).
     */
    int64_t size_to_download() const noexcept { return size_to_download_; }
    int64_t size() const noexcept { return size_; }

    int num_pieces() const noexcept { return num_pieces_; }
    int piece_length(const piece_index_t index) const noexcept;

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
    interval files_containing_pieces(const interval& pieces) const noexcept;

    /**
     * Returns where in file block resides. The return value is invalid if both
     * fields in file_slice are 0. This can happen if the block is not in file.
     */
    file_slice get_file_slice(const file_index_t file, const block_info& block) const
            noexcept;

    /** Returns the expected 20 byte SHA-1 hash for this piece. */
    sha1_hash expected_piece_hash(const piece_index_t piece) const noexcept;

    /**
     * User can change which files they wish to download during the download. These
     * merely mark the internal file_entry as wanted or not, but if the file is already
     * downloaded, it is not deleted (for that use erase_file).
     */
    void want_file(const file_index_t file) noexcept;
    void dont_want_file(const file_index_t file) noexcept;

    void erase_file(const file_index_t file, error_code& error);

    /**
     * Moves the entire download, that is, if torrent is multi-file, moves the root
     * directory and all its nested entries to the new path.
     * path has to be directory in which torrent's root_path is to be moved, but must
     * not include torrent's root directory in multi-file mode, or the single torrent
     * file in single-file mode. The new root directory will be at path / torrent name
     * for multi-file and at path for single-file.
     */
    void move(std::filesystem::path path, error_code& error);

    void move_resume_data(std::filesystem::path path, error_code& error);
    bmap read_resume_data(error_code& error);
    void write_resume_data(const bmap_encoder& resume_data, error_code& error);

    /**
     * Hashes every downloaded piece and compares them to their expected values, if they
     * exist at all (which means each file that was downloaded is read into memory for
     * the duration of the hashing). If any errors occurred, error will be set to the
     * corresponding disk_io_errc. If any pieces are missing (but otherwise no storage
     * error occurred), those pieces will be erased from the pieces bitfield.
     * pieces.size() must be the same as num_pieces.
     *
     * NOTE: this may be a very expensive operation, and in case of large/many files it
     * should be parallelized using the second overload, partitioning the number of
     * pieces as necessary.
     */
    void check_storage_integrity(bitfield& pieces, error_code& error);
    void check_storage_integrity(bitfield& pieces, int first_piece,
            int num_pieces_to_check, error_code& error);

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
     */
    std::vector<mmap_source> create_mmap_sources(
            const block_info& info, error_code& error);
    // std::vector<mmap_sink> create_mmap_sink( // TODO
    // const block_info& info, error_code& error);

    /**
     * Blocking scatter-gather IO.
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
     * TODO ensure atomicity for these operations
     */
    void read(iovec buffer, const block_info& info, error_code& error);
    void read(std::vector<iovec> buffers, const block_info& info, error_code& error);
    void read(view<disk_buffer> buffers, const block_info& info, error_code& error);
    void write(iovec buffer, const block_info& info, error_code& error);
    void write(std::vector<iovec> buffers, const block_info& info, error_code& error);
    void write(view<disk_buffer> buffers, const block_info& info, error_code& error);

private:
    /**
     * We don't expose these as buffers' iovecs are modified during both calls, which
     * would lead to surprises (iovecs at file boundaries are modified to align with
     * the boundaries, for simpler implementation). However, it is necessary for the
     * single iovec read/write functions, in order not to allocate a std::vector.

     TODO an error will occur if buffer(s) has less bytes than info.length, because we
     map files to a block according to info, not num bytes in buffers. so maybe we
     should add a check to ensure that num_bytes_in_buffers == info.length or we
     should map files according to the length of the buffers
     */
    void read(view<iovec> buffers, const block_info& info, error_code& error);
    void write(view<iovec> buffers, const block_info& info, error_code& error);

    /**
     * Maps each file in torrent_info::files to a file_entry with correct data set up.
     * Does not allocate files in the download directory (that's done on first access).
     */
    void initialize_file_entries(const_view<file_info> files);

    /**
     * In case of multi file mode and if there are files nested in directories, the
     * directories are created, but not the files.
     *
     * NOTE: muste be called after initialize_file_entries.
     */
    void create_directory_tree();

    /**
     * The first time we write to a file, it's neither opened nor allocated, so this
     * function checks and takes care of doing so if necessary. If otherwise it's
     * allocated just not open, it is opened.
     */
    void before_writing(file& file, error_code& error);

    /**
     * When reading, files must already be allocated, so if they aren't, an error is
     * set. If otherwise it's allocated just not open, it is opened.
     */
    void before_reading(file_entry& file, error_code& error);
    void before_reading(file& file, error_code& error);

    /**
     * Both reading from, writing to and mapping files (the portions of them that
     * corresponds to the block as described by info) involve the same plumbing
     * to keep track of where in the file we want to do the IO operation, so this
     * function serves as an abstraction around the common parts.
     *
     * fn is called for every file that maps to block (since a block may span
     * several files), and must have the following signature:
     *
     * int(file_entry&,     // the current file on which to operate
     *     file_slice&      // the offset into the file where block starts and the
     *                      // number of bytes that block occupies in file
     *     error_code& // this must be set to any io error that occured, after
     *                      // this function will stop immediately
     * )
     */
    template <typename Function>
    void for_each_file(Function fn, const block_info& block, error_code& error);

    /**
     * Returns the position where in file offset, which refers to the offset in
     * all files combined, is and how much of length is contained in file.
     */
    file_slice get_file_slice(const file_entry& file, int64_t torrent_offset,
            int64_t length) const noexcept;

    /** Returns a range of files that contain some portion of the block or piece. */
    view<file_entry> files_containing_block(const block_info& block);
    // view<file_entry> files_containing_piece(const piece_index_t piece);

    bool is_file_index_valid(const file_index_t index) const noexcept;
};

inline int torrent_storage::piece_length(const piece_index_t index) const noexcept
{
    if(index == num_pieces() - 1)
        return size() - index * piece_length_;
    else
        return piece_length_;
}

} // namespace tide

#endif // TIDE_TORRENT_STORAGE_HEADER
