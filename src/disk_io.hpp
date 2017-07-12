#ifndef TIDE_DISK_IO_HEADER
#define TIDE_DISK_IO_HEADER

#include "torrent_storage_handle.hpp"
#include "average_counter.hpp"
#include "torrent_storage.hpp"
#include "disk_io_error.hpp"
#include "block_source.hpp"
#include "disk_buffer.hpp"
#include "thread_pool.hpp"
#include "string_view.hpp"
#include "sha1_hasher.hpp"
#include "bitfield.hpp"
#include "interval.hpp"
#include "bdecode.hpp"
#include "time.hpp"
#include "path.hpp"

#include <unordered_map>
#include <system_error>
#include <functional>
#include <utility> // pair
#include <memory>
#include <atomic>
#include <vector>
#include <map>

#include <asio/io_service.hpp>

namespace tide {

class metainfo;
class bmap_encoder;
struct torrent_info;
struct disk_io_settings;

/**
 * All operations run asynchronously.
 * TODO more commentz
 */
class disk_io
{
public:

    struct stats
    {
        int num_blocks_written = 0;
        int num_blocks_read = 0;

        int num_write_cache_hits = 0;
        int num_read_cache_hits = 0;

        // Includes both the read and write caches. In bytes.
        int cache_capacity = 0;
        //int write_buffer_size = 0;
        int read_cache_size = 0;

        int write_queue_size = 0;
        int read_queue_size = 0;
        int peak_write_queue_size = 0;
        int peak_read_queue_size = 0;

        // How many of each jobs are currently being performed by threads.
        int num_hashing_threads = 0;
        int num_writing_threads = 0;
        int num_reading_threads = 0;

        int num_threads = 0;

        // The average number of milliseconds a job is queued up (is waiting to be 
        // executed).
        milliseconds avg_wait_time{0};
        milliseconds avg_write_time{0};
        milliseconds avg_read_time{0};
        milliseconds avg_hash_time{0};

        milliseconds total_job_time{0};
        milliseconds total_write_time{0};
        milliseconds total_read_time{0};
        milliseconds total_hash_time{0};
    };

private:

    // This is the io_service that runs the network thread. It is used to post handlers
    // on the network thread so that no syncing is required between the two threads, as
    // io_service is thread-safe.
    asio::io_service& m_network_ios;

    // All disk jobs are posted to and executed by this thread pool. Note that anything
    // posted to this that accesses fields in disk_io will need to partake in mutual
    // exclusion.
    thread_pool m_thread_pool;

    const disk_io_settings& m_settings;

    // Statistics are gathered here. One copy persists throughout the entire application
    // and copies for other modules are made on demand.
    stats m_stats;

    // Only disk_io can instantiate disk_buffers so that instances can be reused. All
    // buffers made by pool are 16KiB in size.
    disk_buffer_pool m_disk_buffer_pool;

    /**
     * This class represents an in-progress piece. It is used to store the hash context
     * (blocks are incrementally hashed) and to buffer blocks so that they may be 
     * processed (hashed and written to disk) in batches.
     *
     * For optimal performance, blocks should be supplied in contiguous batches (need
     * not be in order within the batch) of settings::write_cache_line_size, so that
     * these blocks can be hashed and written to disk by a single thread. However, 
     * this is the optimum, otherwise  at most settings::max_write_cache_line_size blocks
     * are kept in memory, after which they are flushed to disk, hashed or not. This 
     * means that most of them (unless some follow the last hashed block) won't be
     * hashed and thus need to be pulled back for hashing later, when the missing blocks 
     * have been downloaded.
     *
     TODO revise in accordance to threading changes
     * Crucially, only a single thread may work on a piece at any given time. When piece
     * has enough blocks for hashing and saving, those blocks are extracted from
     * partial_piece::blocks, and once done, unhashed_offset is updated with the amount
     * of blocks hashed.
     *
     * If an error occurs while trying to write to disk, i.e. blocks could not be saved,
     * they are placed back into blocks for future reattempt.
     *
     * Once the piece is completed, its hashing is finished, and the resulting hash is 
     * compared to the piece's expected hash, and this result is passed along to 
     * completion_handler. If the hash test was passed, the remaining blocks are written
     * to disk. (If the piece is large, that is, it has to be written to disk in several
     * settings::write_cache_line_size chunks, it means that even if a piece turns out
     * to be bad, some blocks will inevitably be persisted to disk. This is of no concern
     * as they will be overwritten once valid data is received.)
     *
     * Note, however, that while a thread is hashing and saving the current write buffer,
     * the network thread might fill up blocks with another batch ready to be hashed,
     * but since unhashed_offset is only updated once the hasher thread is finished, the 
     * network thread will not initiate another hash job (since it assumes that there is
     * a gap in blocks, due to the mismatch between blocks[0].offset and unhashed_offset,
     * (which is the desired behaviour)). 
     * Therefore, once the current hasher finishes, it must check whether another batch 
     * needs hashing.
     TODO decide if you want this or we should introduce atomic variables for this
     */
    struct partial_piece
    {
        struct block
        {
            // The actual data. This must always be valid.
            disk_buffer buffer;

            // The offset (a multiple of 16KiB) where this block starts in piece.
            int offset;

            // Invoked once the block could be saved to disk.
            std::function<void(const std::error_code&)> save_handler;

            block(disk_buffer buffer_, int offset_, 
                std::function<void(const std::error_code&)> save_handler_);
        };

        // buffer is used to buffer blocks so that they may be written to disk in
        // batches. The batch size varies, for in the optimal case we try to wait for
        // disk_io_settings::write_cache_line_size contiguous, or even better, hashable
        // (which means contiguous and follows the last hashed block) blocks, but if
        // this is not fulfilled, blocks are buffered until the buffer size reaches
        // disk_io_settings::max_write_cache_line_size blocks, after which the entire
        // buffer is flushed.
        // work_buffer is used to hold blocks that are being processed by a worker
        // thread.
        //
        // In the case of disk errors, blocks that we couldn't save are put back into 
        // buffer and kept there until successfully saved to disk.
        //
        // Blocks in both buffer and processing_buffer are ordered by their offsets.
        //
        // To avoid race conditions and mutual exclusion, network thread only handles
        // buffer, and when we want to flush its blocks, before launching the async
        // operation (i.e. still on the network thread) the to-be-flushed blocks are 
        // transferred to work_buffer. This may only be done while is_busy is not set, 
        // because the worker thread does access work_buffer.
        std::vector<block> buffer;
        std::vector<block> work_buffer;

        // Blocks may be saved to disk without being hashed, so unhashed_offset is not
        // sufficient to determine how many blocks we have. Thus each block that was
        // saved is marked as 'true' in this list.
        //
        // Only handled on the worker thread.
        std::vector<bool> save_progress;

        // Only one thread may process a partial_piece at a time, so this is set before
        // such a thread is launched, and unset on the network thread as well, once
        // thread calls the completion handler (i.e. it need not be atomic since it's
        // only accessed from the network thread).
        //
        // Only handled on the network thread.
        bool is_busy = false;

        // A cached value of the number of true bits in m_blocks_saved.
        int num_saved_blocks = 0;

        // This is always the first byte of the first unhashed block (that is, one past
        // the last hashed block's last byte). It's used to check if we can hash blocks
        // since they must be passed to m_hasher.update() in order.
        //
        // It's handled on both network and worker threads, but never at the same time.
        // This is done by synchronizing using the is_busy field, i.e. if piece is busy,
        // we don't bother this field (and piece in general), so while this flag is set
        // worker thread may freely update this field without further syncing.
        int unhashed_offset = 0;

        const piece_index_t index;
        // The length of this piece in bytes.
        const int length;
        // The number of blocks this piece has in total (i.e. how many blocks we expect).
        // TODO this is no longer needed, number of blocks: save_progress.size()
        const int num_blocks;

        // This is invoked once the piece has been hashed, which means that the piece
        // may not have been written to disk by the time of the invocation.
        //
        // Only used by the network thread.
        std::function<void(bool)> completion_handler;

        // This contains the sha1_context that holds the current hashing progress and is
        // used to incrementally hash blocks.
        //
        // NOTE: blocks may only be hashed in order.
        //
        // Only used by the worker threads.
        sha1_hasher hasher;

        // This enforces an upper bound on how long blocks may stay in memory. This is
        // to avoid lingering blocks, which may occur if the client started downloading
        // a piece from the only peer that has it, then disconnected.
        deadline_timer buffer_expiry_timer;

        /** Initializes the const fields, buffer_expiry_timer and calculates num_blocks. */
        partial_piece(piece_index_t index_, int length_, int max_write_buffer_size,
            std::function<void(bool)> completion_handler, asio::io_service& ios);

        /**
         * Determines whether all blocks have been received, regardless if they are 
         * already hashed and saved to disk or are still in blocks buffer.
         */
        bool is_complete() const noexcept;

        /**
         * The number of contiguous blocks following the last hashed block.
         * We can only hash the blocks that are in order and have no gaps, so this will
         * be 0 if buffer[0].offset > unhashed_offset, or it will be the number of
         * blocks until the first gap in buffer.
         */
        int num_hashable_blocks() const noexcept;

        /**
         * Returns a left-inclusive interval that represents the range of the largest
         * contiguous block sequence within buffer.
         */
        interval largest_contiguous_range() const noexcept;

        /**
         * Moves n blocks or the blocks in the range [begin, end) from buffer to 
         * work_buffer.
         */
        void move_blocks_to_work_buffer(const int n);
        void move_blocks_to_work_buffer(int begin, int end);

        /**
         * This is used when, after extracting blocks from buffer to work_buffer, we
         * fail to save them to disk, in which case we need to put them back in buffer
         * so that they may be saved later. The reason blocks are put back from
         * write_buffer to buffer is because it simplifies working with work_buffer and
         * even though it's sligthly expensive to do this, we don't expect to need this
         * frequently, and when we do, we have bigger problems.
         */
        void restore_buffer();
    };

    struct torrent_entry
    {
        // Each torrent is associated with a torrent_storage instance which encapsulates
        // the implementation of instantiating the storage, saving and loading blocks
        // from disk, renaming/moving/deleting files etc. Higher level logic, like
        // buffering writes or executing these functions concurrently is done in
        // disk_io, as torrent_storage only takes care of the low level functions.
        torrent_storage storage;

        // Received blocks are not immediately written to disk, but are buffered in this
        // list until the number of blocks reach disk_io_settings::write_cache_line_size
        // or the piece is finished, after which the blocks are hashed and written to
        // disk. This defers write jobs as much as possible so as to batch them together
        // to increase the amount of work performed within a context switch.
        //
        // unique_ptr is used to ensure that a thread referring to a piece does not
        // end up accessing invalid memory when write_buffer is reallocated upon adding
        // new entires from the network thread.
        std::vector<std::unique_ptr<partial_piece>> write_buffer;

        struct piece_fetch_subscriber
        {
            std::function<void(const std::error_code&, block_source)> handler;
            int requested_offset;
        };

        // Each time a block fetch is issued, which usually pulls in more blocks or,
        // if the piece is not too large, the entire piece, it is registered here, so
        // that if other requests for the same block or for any of the blocks that are
        // pulled in with the first one (if read ahead is not disabled), which is common
        // when a peer sends us a request queue, they don't launch their own fetch ops,
        // but instead wait for the first operation to finish and notify them of their
        // block. The piece_fetch_subscriber list has to be ordered by the requested
        // offset.
        //
        // After the operation is finished and all waiting requests are served, the
        // entry is removed from this map.
        //
        // Thus only the first block fetch request is recorded here, the rest are
        // attached to the subscriber queue.
        //
        // The original request handler is not stored in the subscriber list (so if only
        // a single request is issued for this block, we don't have to allocate torrent).
        std::vector<std::pair<block_info,
            std::vector<piece_fetch_subscriber>>> block_fetches;

        // Every time a thread is launched to do some operation on torrent_entry, this
        // counter is incremented, and when the operation finished, it's decreased. It
        // is used to keep torrent_entry alive until the last async operation.
        std::atomic<int> num_pending_ops{0};

        torrent_entry(std::shared_ptr<torrent_info> info,
            string_view piece_hashes, path resume_data_path);
        torrent_entry(torrent_entry&& other);
        torrent_entry& operator=(torrent_entry&& other);
    };

    // All torrents in engine have a corresponding torrent_entry.
    std::map<torrent_id_t, torrent_entry> m_torrents;

public:

    disk_io(asio::io_service& network_ios, const disk_io_settings& settings);
    ~disk_io();

    void change_cache_size(const int64_t n);

    void read_metainfo(const path& path,
        std::function<void(const std::error_code&, metainfo)> handler);

    /**
     * As opposed to most other operations, allocating a torrent is not done on
     * another thread as this operation only creates an internal torrent entry within
     * disk_io and it creates the directory tree for the torrent, the cost of which
     * should be little (TODO verify this claim). Files are only allocated once actual
     * data needs to be written to them.
     *
     * If the operation results in an error, error is set and an invalid
     * torrent_storage_handle is returned.
     */
    torrent_storage_handle allocate_torrent(std::shared_ptr<torrent_info> info,
        std::string piece_hashes, std::error_code& error);
    void move_torrent(const torrent_id_t id, std::string new_path,
        std::function<void(const std::error_code&)> handler);
    void rename_torrent(const torrent_id_t id, std::string name,
        std::function<void(const std::error_code&)> handler);

    /** Completely removes the torrent (files + metadata). */
    void erase_torrent_files(const torrent_id_t id,
        std::function<void(const std::error_code&)> handler);

    /**
     * Only erases the torrent's resume data, which is useful when user no longer wants
     * to seed it but wishes to retain the file.
     */
    void erase_torrent_resume_data(const torrent_id_t id,
        std::function<void(const std::error_code&)> handler);
    void save_torrent_resume_data(const torrent_id_t id, const bmap_encoder& resume_data,
        std::function<void(const std::error_code&)> handler);
    void load_torrent_resume_data(const torrent_id_t id,
        std::function<void(const std::error_code&, bmap)> handler);

    /**
     * Reads the state of every torrent whose state was saved to disk and returns a list
     * of all torrent states through the handler. This should be used when starting the
     * application.
     */
    void load_all_torrent_resume_data(
        std::function<void(const std::error_code&, std::vector<bmap>)> handler);

    /**
     * Verifies that all pieces downloaded in torrent exist and are valid by hashing
     * each piece in the downloaded files and comparing them to their expected values.
     */
    void check_storage_integrity(const torrent_id_t id, bitfield pieces,
        std::function<void(const std::error_code&, bitfield)> handler);

    /**
     * This can be used to hash any generic data, but for hashing pieces/blocks, use
     * save_block which incrementally hashes a piece with each additional block.
     * The lifetime of data must be ensured until the invocation of the handler.
     */
    void create_sha1_digest(const_view<uint8_t> data,
        std::function<void(sha1_hash)> handler);

    /**
     * This creates a page aligend disk buffer into which peer_session can receive or
     * copy blocks. This is necessary to save blocks (save_block takes a disk_buffer as
     * argument), as better performance can be achieved this way.
     * This method is always guaranteed to return a valid disk_buffer, but peer_session
     * must make sure that it doesn't abuse disk performance and its receive buffer
     * capacity which includes its outstanding bytes being written to disk.
     * TODO create a stronger constraint on this

     // TODO this is muddy explanation
     * disk_buffers have a fix size of 16KiB (0x4000), but the caller may request that
     * the size be less than that, in which case the true buffer size will remain the
     * same but the conceptual buffer size will the be requested number of bytes.
     */
    disk_buffer get_disk_buffer(const int length = 0x4000);

    /**
     * Asynchronously hashes and saves a block to disk. However, unless configured
     * otherwise, blocks are buffered until a suitable number of adjacent blocks have
     * been downloaded so as to process them in bulk. This means that for the best
     * performance, settings::write_cache_line_size number of adjacent blocks should
     * be downloaded in quick succession.
     *
     * If by adding this block the piece to which it belongs is completed, the hasher
     * finalizes the incremental hashing and produces a SHA-1 hash of the piece. Then,
     * this hash is compared to the expected hash, and the result is passed onto the
     * piece_completion_handler. A true value means the piece passed, while a false
     * value indicates a corrupt piece.
     *
     * save_handler is always invoked after the save operation has finished.
     *
     * The piece_completion_handler is only stored once per piece, i.e. the handler
     * supplied with the first block in piece that was saved.
     */
    void save_block(const torrent_id_t id,
        const block_info& block_info, disk_buffer block_data,
        std::function<void(const std::error_code&)> save_handler,
        std::function<void(bool)> piece_completion_handler);

    /**
     * Requests are queued up and those that ask for pieces that are cached are served
     * first over those whose requested pieces need to be pulled in from disk.
     * If multiple peers request the same uncached piece, only the first will launch a
     * disk read operation, while the others will be queued up and notified when the
     * piece is available.
     */
    void fetch_block(const torrent_id_t id, const block_info& block_info,
        std::function<void(const std::error_code&, block_source)> handler);

private:

    // -------------
    // -- writing --
    // -------------

    /**
     * Depending on the state of the piece, invokes handle_complete_piece or
     * flush_buffer, and takes care of setting up those operations.
     TODO better name
     */
    void dispatch_write(torrent_entry& torrent, partial_piece& piece);

    /**
     * This is callend when we have write_cache_line_size number of contiguous blocks
     * in piece, but they are not hashable (don't follow the last hashed block), so as
     * an optimization we try to wait for the blocks that fill the gap between the last
     * hashed block and the beginning of the contiguous sequence, which would help us to
     * avoid reading them back later.
     * This is calculated by checking if the number of blocks needed to fill the gap
     * and the current number of blocks in buffer is within write buffer capacity.
     */
    bool should_wait_for_hashing(const partial_piece& piece,
        const int num_contiguous_blocks) const noexcept;

    /**
     * This is called when piece has been completed by the most recent block that was
     * issued to be saved to disk. First, it checks whether some blocks have been
     * written to disk without being hashed (this happens when we don't receive blocks
     * in order, write buffer becomes fragmented, eventually reaching capacity, after 
     * which it needs to be flushed), and if there are any, it reads them back for
     * hashing. After all blocks have been hashed, it compares the hash result to the 
     * expected value, then user is notified of the result, and if piece is good, the 
     * remaining blocks in piece's write buffer are written to disk, after which the 
     * save handler is invoked.
     */
    void handle_complete_piece(torrent_entry& torrent, partial_piece& piece);

    /**
     * Called by handle_complete_piece, hashes all unhashed blocks in piece, which means
     * it may need to read back some blocks from disk. blocks in piece::work_buffer need 
     * not be contiguous.
     */
    sha1_hash finish_hashing(torrent_entry& torrent, partial_piece& piece,
        std::error_code& error);

    /**
     * This is called when piece has settings::write_cache_line_size or more hashable
     * blocks (which means contiguous and following the last hashed block in piece), in
     * which case these blocks are extracted from the piece's write buffer, hashed and
     * saved in one batch.
     */
    void hash_and_save_blocks(torrent_entry& torrent, partial_piece& piece);

    /**
     * This is called when piece is not yet complete (otherwise handle_complete_piece
     * is used) or when piece does not have hashable blocks (then hash_and_save_blocks
     * would be called), but piece has accrued so many blocks as to necessitate flushing 
     * them to disk. Blocks don't have to be contiguous. If some of the blocks in the
     * beginning of blocks are hashable, they are hashed as well, to decrease the amount
     * needed to be read back (if all blocks are hashable, hash_and_save_blocks is used).
     */
    void flush_buffer(torrent_entry& torrent, partial_piece& piece);

    /**
     * Utility function that saves to disk the blocks in piece::work_buffer, which may
     * or may not be contiguous to disk.
     * The less fragmented the block sequence, the more efficient the operation.
     */
    void save_maybe_contiguous_blocks(torrent_entry& torrent,
        partial_piece& piece, std::error_code& error);

    /** The completion handler for hash_and_save_blocks and flush_buffer. */
    void on_blocks_saved(const std::error_code& error,
        torrent_entry& torrent, partial_piece& piece);

    /**
     * Saving blocks entails the same plumbing: preparing iovec buffers, the block_info
     * indicating where to save the blocks and calling storage's appropriate function.
     */
    void save_contiguous_blocks(torrent_storage& storage, const piece_index_t piece_index,
        view<partial_piece::block> blocks, std::error_code& error);

    // -------------
    // -- reading --
    // -------------

    /**
     * NOTE: these functions are executed by m_thread_pool.
     */
    void fetch_block(torrent_entry& torrent, const block_info& block_info, 
        std::function<void(const std::error_code&, block_source)> handler);
    void read_ahead(torrent_entry& torrent, const block_info& block_info,
        std::function<void(const std::error_code&, block_source)> handler);

    // -----------
    // -- utils --
    // -----------

    /**
     * Creates a vector of iovecs and counts the total number of bytes in blocks,
     * and returns buffers and the number of bytes as a pair.
     */
    std::pair<std::vector<iovec>, int> prepare_iovec_buffers(
        view<partial_piece::block> blocks);

    static int count_contiguous_blocks(const_view<partial_piece::block> blocks) noexcept;

    torrent_entry& find_torrent_entry(const torrent_id_t id);

    enum class log_event
    {
        cache,
        metainfo,
        torrent,
        piece,
        resume_data,
        integrity_check
    };

    template<typename... Args>
    void log(const log_event event, const char* format, Args&&... args) const;
};

} // namespace tide

#endif // TIDE_DISK_IO_HEADER
