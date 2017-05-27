#ifndef TORRENT_TORRENT_STORAGE_HEADER
#define TORRENT_TORRENT_STORAGE_HEADER

#include "torrent_state.hpp"
#include "torrent_info.hpp"
#include "string_view.hpp"
#include "block_info.hpp"
#include "interval.hpp"
#include "units.hpp"
#include "iovec.hpp"
#include "path.hpp"
#include "file.hpp"

#include <system_error>
#include <memory>
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
        // first byte would be at this offset in the stream. This is used find the files
        // that map to a piece.
        int64_t offset;

        // This is a reference to the attribute in the file_info in m_info.files
        // corresponding to this file. We use a reference so that whenever user changes
        // whether they wish to download a file, we can immediately learn about this.
        // (It's not changed from within torrent_storage though.)
        //
        // NOTE: Despite lazy allocation preventing creating files that are never
        // accessed, a downloaded piece may still overlap into an unwanted file. In that
        // case we don't want to write those extra bytes to disk. Thus, before writing
        // to a file, we must check in whether user actually wants that file, and
        // discard those bytes that overlap into the unwanted file.
        const bool& is_wanted;

        file_entry(path path, int64_t length, uint8_t open_mode, const bool& is_wanted_)
            : storage(std::move(path), length, open_mode)
            , is_wanted(is_wanted_)
        {}
    };

    // All files listed in the metainfo are stored here, but files are lazily/ allocated
    // on disk, i.e. when they are first accessed.
    std::vector<file_entry> m_files;

    // Relevant info (such as piece length, wanted files etc) about storage's
    // corresponding torrent. Fields currently used:
    // save_path, name, piece_length, files
    // TODO consider putting these in a torrent_storage_args fields so as not to
    // refer to torrent_info to avoid potential race conditions
    std::shared_ptr<torrent_info> m_info;

    // The expected hashes of all pieces, represented as a single block of memory for
    // optimal storage (this is a direct view into the original metainfo's encoded source
    // buffer). To retrieve a piece's hash:
    // string_view(m_piece_hashes.data() + piece_index * m_info.piece_length, 20)
    string_view m_piece_hashes;

    // This is an absolute path.
    path m_save_path;

public:

    torrent_storage(std::shared_ptr<torrent_info> info, string_view piece_hashes);

    /**
     * This is the name of the torrent which, if the torrent has multiple files, is also
     * the root directory's name.
     */
    const std::string& name() const noexcept;

    /**
     * These return the root path of the torrent, which is the file itself for single
     * file torrents.
     */
    path save_path() const noexcept;

    /**
     * Returns the total number of bytes of all files we're downloading (that is, if
     * we're not downloading all files, then this value won't match the summed lengths
     * of all files in metainfo.
     */
    int64_t size() const noexcept;

    /**
     * Returns which pieces map to this file, including those that are only partially
     * in file.
     */
    interval pieces_in_file(const file_index_t file_index) const;

    /** Returns the expected 20 byte SHA-1 hash for this piece. */
    string_view expected_hash(const piece_index_t piece) const noexcept;

    void erase_file(const file_index_t file, std::error_code& error);

    /**
     * The torrent's current path, stored in torrent's torrent_info, must not be changed
     * from anywhere but here. If this operation is sucessful, the torrent_info.save_path
     * is updated to the new path.
     */
    void move(path path, std::error_code& error);

    void update_torrent_state(const torrent_state& state, std::error_code& error);
    void save_torrent_state(const torrent_state& state, std::error_code& error);
    bool is_state_up_to_date(const torrent_state& state);

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
    std::vector<mmap_source> create_mmap_source(
        const block_info& info, std::error_code& error
    );
    std::vector<mmap_sink> create_mmap_sink(
        const block_info& info, std::error_code& error
    );

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

    /**
     * Maps each file in m_info.files to a file_entry with correct data set up. Does not
     * create files in the download directory (that's done on first access).
     */
    void initialize_file_entries();

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
    void before_writing(file_entry& file, std::error_code& error);

    /**
     * When reading, files must already be allocated, so if they aren't, an error is
     * set. If otherwise it's allocated just not open, it is opened.
     */
    void before_reading(file_entry& file, std::error_code& error);

    /**
     * Both reading from, writing to and mapping files (the portions of them that
     * correspond to the block as described by info) involve the same plumbing
     * to keep track of where in the file we want to do the io operation, so this
     * function serves as an abstraction around the common parts.
     *
     * IOFunction is called for every file that is processed (since blocks may span
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
        IOFunction io_fn, const block_info& info, std::error_code& error
    );

    /**
     * Denotes where in the file the requested block is (offset) and how much of block
     * is in file (length).
     */
    struct file_slice
    {
        int64_t offset;
        int64_t length;
    };

    /**
     * Returns the position where in file offset, which refers to the offset in
     * all files combined, is and how much of length is contained in file.
     */
    file_slice get_file_slice(
        file_entry& file, int64_t offset, int64_t length
    ) const noexcept;

    /** Returns a range of files that contain some portion of the block or piece. */
    view<file_entry> find_files_containing_block(const block_info& block);
    view<file_entry> find_files_containing_piece(const piece_index_t piece);
};

inline const std::string& torrent_storage::name() const noexcept
{
    return m_info.name;
}

inline int64_t torrent_storage::size() const noexcept
{
    return m_info.size;
}

#endif // TORRENT_TORRENT_STORAGE_HEADER
