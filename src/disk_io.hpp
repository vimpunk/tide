#ifndef TORRENT_DISK_IO_HEADER
#define TORRENT_DISK_IO_HEADER

#include "block_disk_buffer.hpp"
#include "average_counter.hpp"
#include "torrent_state.hpp"
#include "disk_io_error.hpp"
#include "disk_buffer.hpp"
#include "time.hpp"

#include <system_error>
#include <unordered_map>
#include <functional>
#include <memory>
#include <vector>

#include <asio/io_service.hpp>
#include <boost/pool/pool.hpp>

class metainfo;
class torrent_storage;
struct torrent_info;
struct disk_io_settings;

struct disk_io_info
{
    int num_blocks_written = 0;
    int num_blocks_read = 0;

    int num_write_cache_hits = 0;
    int num_read_cache_hits = 0;

    // Includes both the read and write caches. In bytes.
    int cache_capacity = 0;
    int write_cache_size = 0;
    int read_cache_size = 0;

    // The average number of milliseconds a job is queued up (is waiting to be executed).
    int avg_wait_time_ms = 0;
    // The average number of milliseconds it takes to write to and read from disk.
    // TODO use chrono duration types for these
    int avg_write_time_ms = 0;
    int avg_read_time_ms = 0;
    int avg_hash_time_ms = 0;

    int total_job_time_ms = 0;
    int total_write_time_ms = 0;
    int total_read_time_ms = 0;
    int total_hash_time_ms = 0;

    int write_queue_size = 0;
    int read_queue_size = 0;
    int peak_write_queue_size = 0;
    int peak_read_queue_size = 0;

    int num_threads = 0;
};

/**
 * All operations run asynchronously.
 * TODO more commentz
 */
class disk_io
{
    struct disk_job
    {
        enum class priority_t { high, normal, low };
        virtual ~disk_job() = default;
        virtual void execute() = 0;
        virtual priority_t priority() { return priority_t::normal; }
    };

    // This is the io_service that runs the network thread. It is used to post handlers
    // on the network thread so that no syncing is required between the two threads, as
    // io_service is thread-safe.
    asio::io_service& m_network_ios;

    const disk_io_settings& m_settings;

    // Statistics are gathered here. One copy persists throughout the entire application
    // and copies for other modules are made on demand.
    disk_io_info m_info;

    // Only disk_io can instantiate disk_buffers so that instances can be resued.
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
        // since they may only be passed to m_hasher.update() in order.
        int hash_offset = 0;

        torrent_id_t torrent;
        piece_index_t piece_index;

        // These are the actual blocks that we have in this piece.
        std::vector<disk_buffer> blocks;
    };

    // This effectively acts as a "write cache" where blocks that we hvae received go
    // into their respective partial_pieces. The blocks of a piece are kept in memory
    // until their number satisfies the minimum write cache line size and they have all
    // been hashed (though hashing and writing to disk migth be pipelined so as to be
    // performed by a single thread).
    // This essentially defers write jobs as much as possible to increase the amount of
    // work a thread can do in one job.
    // TODO will blocks be kept in memory until we have enogh blocks or will they be
    // flusehd to disk should circumstances demand it?
    // TODO explain how they relate to cache size
    std::vector<partial_piece> m_write_buffer;

    // Each torrent is associated with a torrent_storage instance which encapsulates the
    // implementation of instantiating the storage, saving and loading blocks from disk,
    // renaming/moving/deleting files etc.
    std::unordered_map<torrent_id_t, std::unique_ptr<torrent_storage>> m_torrents;

    // TODO record pending disk reads: this is necessary if multiple requests are issued
    // for blocks in the same piece to avoid multiple disk jobs for the same piece
    //std::deque<std::shared_ptr<disk_job>> m_outstanding_read_jobs;

    average_counter m_avg_hash_time;
    average_counter m_avg_write_time;
    average_counter m_avg_read_time;
    average_counter m_avg_job_time;

public:

    disk_io(asio::io_service& network_ios, const disk_io_settings& settings);
    ~disk_io();

    /**
     * If there are more disk jobs running than what disk_io can keep up with, we should
     * slow down the downloads. This function can be used for determining this condition.
     */
    bool is_overwhelmed() const noexcept;

    /** Does not move current downloads to new save path. */
    void change_default_save_path(std::string path);
    void change_cache_size(const int64_t n);

    /**
     * Reads the state of every torrent whose state was saved to disk and returns a list
     * of all torrent states through the handler. This should be used when starting the
     * application.
     */
    void read_all_torrent_states(
        std::function<void(const std::error_code&, std::vector<torrent_state>)> handler,
        const std::string& app_metadata_path = ""
    );

    void read_metainfo(
        const std::string& metainfo_path,
        std::function<void(const std::error_code&, metainfo)> handler
    );

    void allocate_torrent(
        const torrent_id_t torrent,
        const torrent_info& info,
        //const metainfo& metainfo,
        std::function<void(const std::error_code&)> handler,
        std::string save_path = ""
    );

    void move_torrent(
        const torrent_id_t torrent,
        std::function<void(const std::error_code&)> handler,
        std::string new_path
    );

    void rename_torrent(
        const torrent_id_t torrent,
        std::function<void(const std::error_code&)> handler,
        std::string name
    );

    /** Completely removes the torrent (files + metadata). */
    void erase_torrent_files(
        const torrent_id_t torrent,
        std::function<void(const std::error_code&)> handler
    );

    /**
     * Only erases the torrent's metadata, which is useful when user no longer wants
     * to seed it but wishes to retain the file.
     */
    void erase_torrent_metadata(
        const torrent_id_t torrent,
        std::function<void(const std::error_code&)> handler
    );

    void save_torrent_state(
        const torrent_id_t torrent,
        const torrent_state& state,
        std::function<void(const std::error_code&)> handler
    );

    void read_torrent_state(
        const torrent_id_t torrent,
        std::function<void(const std::error_code&, torrent_state)> handler
    );

    /**
     * Verifies that all currently downloaded torrents' files are where they should be.
     */
    void check_storage_integrity(std::function<void(const std::error_code&)> handler);

    /**
     * This can be used to hash any generic data, but for hashing pieces/blocks, use
     * save_block which incrementally hashes a piece with each additional block.
     * The lifetime of data must be ensured until the invocation of the handler.
     */
    void create_sha1_digest(
        const_view<uint8_t> data,
        std::function<void(sha1_hash)> handler
    );

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
    void save_block(
        const torrent_id_t torrent,
        const block_info& block_info,
        disk_buffer block_data,
        std::function<void(const std::error_code&)> save_handler,
        std::function<void(bool)> piece_completion_handler
    );

    /**
     * Requests are queued up and those that ask for pieces that are cached are served
     * first over those whose requested pieces need to be pulled in from disk.
     * If multiple peers request the same uncached piece, only the first will launch a
     * disk read operation, while the others will be queued up and notified when the
     * piece is available.
     */
    void fetch_block(
        const torrent_id_t torrent,
        const block_info& block_info,
        std::function<void(const std::error_code&, block_source)> handler
    );

    /**
     * This should be called when we no longer need a previously requested block (we
     * choked peer or they cancelled the request). This only has an effect if the fetch
     * operation it's attempting to abort hasn't been started yet.
     */
    void abort_block_fetch(const torrent_id_t torrent, const block_info& block_info);
};

#endif // TORRENT_DISK_IO_HEADER
