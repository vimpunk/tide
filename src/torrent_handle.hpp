#ifndef TORRENT_TORRENT_HANDLE_HEADER
#define TORRENT_TORRENT_HANDLE_HEADER

#include "units.hpp"

#include <vector>
#include <memory>

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
    std::weak_ptr<torrent> m_torrent;

public:

    torrent_handle() = default;
    explicit torrent_handle(torrent* t);

    /** Returns whether the handle is valid, i.e. it refers to a valid torrent. */
    bool is_valid() const noexcept;
    operator bool() const noexcept;

    bool is_paused() const noexcept;
    bool is_running() const noexcept;

    torrent_info info() const;
    void piece_availability(std::vector<int>& piece_map);

    void pause();
    void resume();

    /** file_index must be the position of the file in the original .torrent metainfo. */
    void prioritize_file(const int file_index);
    void deprioritize_file(const int file_index);
    void prioritize_piece(const piece_index_t piece);
    void deprioritize_piece(const piece_index_t piece);

    void change_settings(const torrent_settings& settings);

    void force_tracker_reannounce();
};

} // namespace tide

#endif // TORRENT_TORRENT_HANDLE_HEADER
