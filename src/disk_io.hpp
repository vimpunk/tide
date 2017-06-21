#ifndef TORRENT_DISK_IO_HEADER
#define TORRENT_DISK_IO_HEADER

#include "torrent_storage_handle.hpp"
#include "block_disk_buffer.hpp"
#include "average_counter.hpp"
#include "torrent_storage.hpp"
#include "disk_io_error.hpp"
#include "disk_buffer.hpp"
#include "string_view.hpp"
#include "thread_pool.hpp"
#include "time.hpp"
#include "path.hpp"
#include "sha1_hasher.hpp"
#include "bdecode.hpp"
#include "bitfield.hpp"

#include <system_error>
#include <unordered_map>
#include <functional>
#include <memory>
#include <vector>

#include <asio/io_service.hpp>
#include <boost/pool/pool.hpp>

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

    struct info
    {
        int num_blocks_written = 0;
        int num_blocks_read = 0;

        int num_write_cache_hits = 0;
        int num_read_cache_hits = 0;

        // Includes both the read and write caches. In bytes.
        int cache_capacity = 0;
        int write_cache_size = 0;
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

        info()
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

    const disk_io_settings& m_settings;

    // Statistics are gathered here. One copy persists throughout the entire application
    // and copies for other modules are made on demand.
    info m_info;

    // Only disk_io can instantiate disk_buffers so that instances can be reused.
    boost::pool<> m_disk_buffer_pool;

    struct partial_piece
    {
        // This contains the sha1_context that holds the current hashing progress and is
        // used to incrementally hash blocks. NOTE: you can only hash blocks in order,
        // otherwise out of order blocks must be buffered until the next block to be
        // hashed is downloaded.
        sha1_hasher hasher;

        // This is always the first byte of the first unhashed block (or one past the
        // last hashed block's last byte). This is used to check if we can hash blocks
        // since they must passed to m_hasher.update() in order.
        int unhashed_offset = 0;

        torrent_id_t torrent;
        piece_index_t piece_index;

        // These are the actual blocks that we have in this piece. The vector is
        // preallocated for the number of blocks that we expect to receive (disk_buffer
        // only stores a pointer so it shouldn't take up much space). This way blocks
        // can be immediately placed in their correct position (block.offset / 16KiB).
        std::vector<disk_buffer> blocks;
    };

    // This effectively acts as a "write cache" where blocks that we have received go
    // into their respective partial_piece. The blocks of a piece are kept in memory
    // until their number satisfies the minimum write cache line size and they have all
    // been hashed (though hashing and writing to disk migth be pipelined so as to be
    // performed by a single thread).
    // This essentially defers write jobs as much as possible to increase the amount of
    // work a thread can do in one job.
    // TODO will blocks be kept in memory until we have enogh blocks or will they be
    // flusehd to disk should circumstances demand it?
    // TODO explain how they relate to cache size, i.e. are they part of the cache size
    // limit do we ever flush it even if the target write cache line size is not reached etc
    std::vector<partial_piece> m_write_buffer;

    // Each torrent is associated with a torrent_storage instance which encapsulates the
    // implementation of instantiating the storage, saving and loading blocks from disk,
    // renaming/moving/deleting files etc. Higher level logic, like buffering writes is
    // done in disk_io, as torrent_storage only takes care of the low level functions.
    std::unordered_map<torrent_id_t, torrent_storage> m_torrents;

public:

    disk_io(asio::io_service& network_ios, const disk_io_settings& settings);
    ~disk_io();

    void change_cache_size(const int64_t n);

    void read_metainfo(const path& path,
        std::function<void(const std::error_code&, metainfo)> handler);

    void allocate_torrent(std::shared_ptr<torrent_info> info, string_view piece_hashes,
        std::function<void(const std::error_code&, torrent_storage_handle)> handler);
    void move_torrent(const torrent_id_t torrent, std::string new_path,
        std::function<void(const std::error_code&)> handler);
    void rename_torrent(const torrent_id_t torrent, std::string name,
        std::function<void(const std::error_code&)> handler);

    /** Completely removes the torrent (files + metadata). */
    void erase_torrent_files(const torrent_id_t torrent,
        std::function<void(const std::error_code&)> handler);

    /**
     * Only erases the torrent's resume data, which is useful when user no longer wants
     * to seed it but wishes to retain the file.
     */
    void erase_torrent_resume_data(const torrent_id_t torrent,
        std::function<void(const std::error_code&)> handler);
    void save_torrent_resume_data(
        const torrent_id_t torrent, const bmap_encoder& resume_data,
        std::function<void(const std::error_code&)> handler);
    void load_torrent_resume_data(const torrent_id_t torrent,
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
    void check_storage_integrity(const torrent_id_t torrent, bitfield pieces,
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
     */
    disk_buffer get_write_buffer();
    void return_write_buffer(disk_buffer buffer);

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
    void save_block(const torrent_id_t torrent,
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
    void fetch_block(const torrent_id_t torrent, const block_info& block_info,
        std::function<void(const std::error_code&, block_source)> handler);
};

} // namespace tide

#endif // TORRENT_DISK_IO_HEADER
