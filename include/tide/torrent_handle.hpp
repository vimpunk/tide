#ifndef TIDE_TORRENT_HANDLE_HEADER
#define TIDE_TORRENT_HANDLE_HEADER

#include "torrent_info.hpp"
#include "string_view.hpp"
#include "types.hpp"

#include <vector>
#include <memory>
#include <mutex>

namespace asio { class io_service; }

namespace tide {

class torrent_settings;
class torrent;

/**
 * This is the means through which torrents are accessed by the public API. Since
 * networking is done on a different thread, all methods here are blocking in that
 * they need to wait till torrent's mutex is acquired.
 *
 * User needs to store this class somewhere, as this is the only way to handle
 * individual torrents.
 *
 * Note that torrent_handle cannot outlive the torrent it is referring to, so it must
 * be ensured by user that when a torrent is shut down, this handle is disposed of as
 * well.
 */
class torrent_handle
{
    std::weak_ptr<torrent> torrent_;
    // This is remains valid for the lifetime of the engine instance, which owns ios_.
    asio::io_service* ios_;

public:

    torrent_handle() = default;
    explicit torrent_handle(std::weak_ptr<torrent> t);

    /** Returns whether the handle is valid, i.e. if it refers to a valid torrent. */
    bool is_valid() const noexcept { return !torrent_.expired(); }
    operator bool() const noexcept { return is_valid(); }

    friend bool operator==(const torrent_handle& a, const torrent& b);
    friend bool operator==(const torrent& a, const torrent_handle& b);
    friend bool operator!=(const torrent_handle& a, const torrent& b);
    friend bool operator!=(const torrent& a, const torrent_handle& b);

    void pause();
    void resume();

    /** file_index must be the position of the file in the original .torrent metainfo. */
    void prioritize_file(const int file_index);
    void deprioritize_file(const int file_index);
    void prioritize_piece(const piece_index_t piece);
    void deprioritize_piece(const piece_index_t piece);

    void apply_settings(const torrent_settings& settings);

    void force_tracker_announce(string_view url);

    // TODO {
    /**
     * This saves torrent's current state to disk. This is done automatically if a
     * change to torrent's state occurs, but user may request it manually. It will not
     * issue a disk_io job if torrent's state has not changed since the last save.
     * /
    void save_state();

    void force_storage_integrity_check();
    void force_resume_data_check();

    /**
     * If torrent is multi-file, the root directory in which the files are stored is
     * renamed, otherwise nothing happens.
     *
     * Upon completing the operation, an alert is posted.
     * /
    void rename_torrent(std::string name);
    void move_torrent(std::string new_path);

    /** This will erase all downloaded data and metadata (resume state) as well. * /
    void erase_torrent_files();
    void erase_file(const file_index_t file);
    */
    // } TODO

    /**
     * Invoking any of the below accessor methods when is_valid is false results in
     * an undefined return value.
     */

    torrent_info info() const;

    void set_max_upload_slots(const int n);
    void set_max_upload_rate(const int n);
    void set_max_download_rate(const int n);
    void set_max_connections(const int n);

    int max_upload_slots() const noexcept;
    int max_upload_rate() const noexcept;
    int max_download_rate() const noexcept;
    int max_connections() const noexcept;

    torrent_id_t id() const noexcept;;
    sha1_hash info_hash() const noexcept;

    seconds total_seed_time() const noexcept;
    seconds total_leech_time() const noexcept;
    seconds total_active_time() const noexcept;

    time_point download_started_time() const noexcept;
    time_point download_finished_time() const noexcept;

    /** Total peers includes connected and available (i.e. not connected) peers. */
    int total_peers() const noexcept;
    int num_connected_peers() const noexcept;
    int num_seeders() const noexcept;
    int num_leechers() const noexcept;

    bool is_stopped() const noexcept;
    bool is_running() const noexcept;
    bool is_leech() const noexcept;
    bool is_seed() const noexcept;

private:

    /**
     * Executes function in a thread-safe manner, if torrent_ is still valid.
     * F must be a callable that takes a reference to torrent.
     */
    template<typename Function>
    void thread_safe_execution(Function function);
};

} // namespace tide

#endif // TIDE_TORRENT_HANDLE_HEADER
