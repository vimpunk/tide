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

        int num_threads = 0;

        // The average number of milliseconds a job is queued up (is waiting to be 
        // executed).
        milliseconds avg_wait_time;
        milliseconds avg_write_time;
        milliseconds avg_read_time;
        milliseconds avg_hash_time;

        milliseconds total_job_time;
        milliseconds total_write_time;
        milliseconds total_read_time;
        milliseconds total_hash_time;

        stats()
            : avg_wait_time(0)
            , avg_write_time(0)
            , avg_read_time(0)
            , avg_hash_time(0)
            , total_job_time(0)
            , total_write_time(0)
            , total_read_time(0)
            , total_hash_time(0)
        {}
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

    const settings& m_settings;

    // Statistics are gathered here. One copy persists throughout the entire application
    // and copies for other modules are made on demand.
    stats m_stats;

    // Only disk_io can instantiate disk_buffers so that instances can be reused. All
    // buffers made by pool are 16KiB in size.
    disk_buffer_pool m_disk_buffer_pool;

    /**
     * This class represents an in-progress piece. It is used to buffer blocks and
     * incrementally hash them and store the hash context.
     *
     * min(settings::write_cache_line_size blocks, num_blocks_in_piece) blocks are kept
     * in memory (bufferred) before being hashed and written to disk. Once this threshold
     * is reached, the currently available number of consecutive blocks (i.e. blocks
     * following, without gaps, one another) are posted to m_thread_pool for hashing and 
     * are subsequently written to disk.
     *
     * It is crucial that blocks only be hashed in order, regardless of the amount of 
     * blocks that have been accrued (e.g. if we have all but the first block, we have
     * to wait for the first block to be downloaded before hashing can be begun).
     * Therefore the above statement about the number of blocks kept in memory is only
     * an aim, not a guarantee. TODO we may want to do sth about this so as not to
     * hike memory usage unexpectedly
     *
     * Once the piece is completed, its hashing is finished, and the resulting hash is 
     * compared to the piece's expected hash, and this result is passed along to 
     * completion_handler. If the hash test was passed, the remaining blocks are written
     * to disk. (If the piece is large, that is, it has to be written to disk in several
     * settings::write_cache_line_size chunks, it means that even if a piece turns out
     * to be bad, some blocks will inevitably be persisted to disk. This is no concern
     * as they will be overwritten once valid data is received.)
     *
     * Crucially, only a single thread may hash a piece at any given time. When piece
     * has enough blocks for hashing and saving, those blocks are extracted from
     * partial_piece::blocks, and once done, unhashed_offset is updated with the amount
     * of blocks hashed. This is because otherwise new blocks may be added to blocks on
     * the network thread, which may cause blocks to reallocate, and by doing so
     * invalidating any reference to it on the hasher's thread. If a disk error occurs,
     * that is, blocks could not be saved (although hashing should never fail), they
     * are placed back into blocks for future reattempt.
     *
     * Note, however, that while a thread is hashing and saving the current write buffer,
     * the network thread might fill up blocks with another batch ready to be hashed,
     * but since unhashed_offset is only updated once the hasher thread is finished, the 
     * network thread will not initiate another hash job (since it assumes that there is
     * a gap in blocks, due to the mismatch between blocks[0].offset and unhashed_offset,
     * (which is the desired behaviour)). 
     * Therefore, once the current hasher finishes, it must check whether another batch 
     * needs hashing.
     */
    struct partial_piece
    {
        struct block
        {
            disk_buffer buffer;
            // The offset within piece (a multiple of 16KiB) where this block begins.
            int offset;
            // Invoked once the block could be saved to disk.
            std::function<void(const std::error_code&)> save_handler;

            block(disk_buffer buffer_, int offset_, 
                std::function<void(const std::error_code&)> save_handler_);
        };

    private:

        // These are the actual blocks that we have in this piece. The vector is
        // preallocated for the number of blocks that can be stored in memory (this is
        // a minimum of settings::write_cache_line_size and the number of blocks in
        // piece).
        // Note that if we receive blocks out of order in such a way that we cannot
        // hash them, the number of blocks may exceed settings::write_cache_line_size.
        std::vector<block> m_blocks;

        // The number of contiguous blocks following the last hashed and saved block.
        // We can only hash and write to disk the blocks that are in order and have no
        // gaps, so this will be 0 if blocks[0].offset > unhashed_offset, or it will be 
        // the number of blocks until the first gap.
        //
        // It's decreased as soon as a hash & write op is launched, but this number
        // is added back if the block could not be saved to disk.
        int m_num_writeable_blocks = 0;

        // This is always the first byte of the first unhashed block (that is, one past
        // the last hashed block's last byte). It's used to check if we can hash blocks
        // since they must be passed to m_hasher.update() in order.
        int m_unhashed_offset = 0;

    public:

        const piece_index_t index;
        // The length of this piece in bytes.
        const int length;
        // The number of blocks this piece has in total (i.e. how many blocks we expect).
        const int num_blocks;

        // Only one thread may work with partial_piece at a time, so this is set before
        // such a thread is launched, and unset once thread calls the completion handler
        // (i.e. it need not be atomic since it's only accessed from the network thread).
        // TODO it may be enough to "mutually exclude" only hashing, i.e. rename to
        // is_hashing
        bool is_busy = false;

        // This is invoked once the piece has been hashed, which means that the piece
        // may not have been written to disk by the time of the invocation.
        std::function<void(bool)> completion_handler;

        // This contains the sha1_context that holds the current hashing progress and is
        // used to incrementally hash blocks. NOTE: blocks may only be hashed in order,
        // otherwise out of order blocks must be buffered until the next block to be
        // hashed is downloaded.
        sha1_hasher hasher;

        /** Initializes the const fields and calculates num_blocks. */
        partial_piece(piece_index_t index_, int length_, int max_write_buffer_size,
            std::function<void(bool)> completion_handler);

        /**
         * Determines whether all blocks have been received, regardless if they are 
         * already hashed and saved to disk or are still in blocks buffer.
         */
        bool is_complete() const noexcept;

        int first_unhashed_byte() const noexcept { return m_unhashed_offset; }
        int num_writeable_blocks() const noexcept { return m_num_writeable_blocks; }

        /**
         * Inserts a new block into blocks such that the resulting set of blocks
         * remains sorted by block offset.
         */
        void insert_block(block block);
        void insert_block(disk_buffer block_data, const int offset,
            std::function<void(const std::error_code&)> save_handler);

        /**
         * This is used when, after extracting all writeable blocks, we fail to save
         * them to disk, in which case we need to put them back in piece so that they
         * may be saved later. Conceptually the same as repeatedly calling insert_block
         * for each block, but this is optimized since all blocks are contiguous, i.e.
         * they may be inserted in bulk.
         */
        void insert_blocks(std::vector<block> contiguous_blocks);

        /** Removes and returns num_writeable_blocks blocks. */
        std::vector<block> extract_writeable_blocks();

        /** Incremets unhashed_offset and updates the number of writeable blocks. */
        void record_hashed_bytes(const int n);

    private:

        /**
         * This is called when a new block has been received or when we hashed some
         * blocks--both events that may affect how many blocks we can write.
         */
        void update_num_writeable_blocks();
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
        std::atomic<int> num_pending_ops;

        torrent_entry(std::shared_ptr<torrent_info> info,
            string_view piece_hashes, path resume_data_path);
        torrent_entry(torrent_entry&& other);
        torrent_entry& operator=(torrent_entry&& other);
    };

    // All torrents in engine have a corresponding torrent_entry.
    std::map<torrent_id_t, torrent_entry> m_torrents;

public:

    disk_io(asio::io_service& network_ios, const settings& settings);
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
    //buffer get_buffer();

    /**
     * This launches two disk_jobs. It saves the block to disk and it also hashes it,
     * usually simultaneously on two separate threads, but this may vary.
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

    torrent_entry& find_torrent_entry(const torrent_id_t id);

    /**
     * Depending on the state of the piece, invokes handle_complete_piece or
     * flush_write_buffer, and takes care of setting up those operations.
     TODO better name
     */
    void dispatch_block_write(torrent_entry& torrent, partial_piece& piece);

    /**
     * Blocks are passed in separately, because they are extracted from piece on the
     * network thread to avoid races, for this function is executed on another thread.
     *
     * NOTE: this function is executed by m_thread_pool.
     */
    void handle_complete_piece(torrent_entry& entry, partial_piece& piece,
        std::vector<partial_piece::block> blocks);

    /**
     * This is called when piece is not yet complete (otherwise handle_complete_piece
     * is used), but piece has accrued so many blocks as to necessitate flushing them
     * to disk.
     *
     * Blocks are passed in separately, because they are extracted from piece on the
     * network thread to avoid races, for this function is executed on another thread.
     *
     * NOTE: this function is executed by m_thread_pool.
     */
    void flush_write_buffer(torrent_entry& entry, partial_piece& piece,
        std::vector<partial_piece::block> blocks);

    /**
     * NOTE: this function is executed by m_thread_pool.
     */
    int hash_blocks(sha1_hasher& hasher, const int unhashed_offset,
        std::vector<partial_piece::block>& blocks);

    /**
     * Creates a vector of iovecs and counts the total number of bytes in blocks,
     * and returns buffers and the number of bytes as a pair.
     */
    std::pair<std::vector<iovec>, int> prepare_iovec_buffers(
        std::vector<partial_piece::block>& blocks);

    /**
     * NOTE: this function is executed by m_thread_pool.
     */
    void fetch_block(torrent_entry& torrent, const block_info& block_info, 
        std::function<void(const std::error_code&, block_source)> handler);
    void read_ahead(torrent_entry& torrent, const block_info& block_info,
        std::function<void(const std::error_code&, block_source)> handler);

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
