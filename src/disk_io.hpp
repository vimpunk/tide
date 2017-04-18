#ifndef TORRENT_DISK_IO_HEADER
#define TORRENT_DISK_IO_HEADER

#include "block_disk_buffer.hpp"
#include "torrent_state.hpp"
#include "disk_io_error.hpp"

#include <system_error>
#include <functional>
#include <vector>
#include <map>

#include <asio/io_service.hpp>

class metainfo;
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
 */
class disk_io
{
    struct disk_job
    {
        enum class priority_t { high, normal, low };
        virtual ~disk_job() = default;
        virtual void execute() = 0;
        virtual priority_t priority() = 0;
    };

    class torrent_entry;

    // This is the io_service that runs the network thread. It is used to post handlers
    // on the network thread so that no syncing is required between the two threads.
    asio::io_service& m_network_ios;

    const disk_io_settings& m_settings;

    // Statistics are gathered here. One copy persists throughout the entire application
    // and copies are made on demand.
    disk_io_info m_info;

    // disk_io retains information about each torrent in the torrent engine. A torrent
    // entry is created when a torrent is allocated or resume data read.
    std::map<torrent_id_t, torrent_entry> m_torrents;

public:

    disk_io(asio::io_service& network_ios, const disk_io_settings& settings);

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
        const block_info& block_info,
        const std::vector<uint8_t>& data,
        std::function<void(const std::error_code&, sha1_hash)> handler
    );

    /**
     * This launches two disk_jobs. It saves the block to disk and it also hashes it,
     * usually simultaneously on two separate threads, but this may vary.
     *
     * If by adding this block the piece to which it belongs is completed, the hasher
     * finalizes the incremental hashing and produces a SHA-1 hash of the piece. Then,
     * this hash is compared to the expected hash, and the result is passed onto the
     * completion_handler. A true value means the piece passed, while a false value
     * indicates a corrupt piece.
     *
     * The regular handler is always invoked after the save operation is done.
     */
    void save_block(
        const torrent_id_t torrent,
        const block_info& block_info,
        std::vector<uint8_t>&& data,
        std::function<void(const std::error_code&)> handler,
        std::function<void(bool)> completion_handler
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
