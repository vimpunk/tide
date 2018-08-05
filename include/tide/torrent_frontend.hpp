#ifndef TIDE_TORRENT_FRONTEND_HEADER
#define TIDE_TORRENT_FRONTEND_HEADER

#include "block_source.hpp"
#include "disk_buffer.hpp"

#include <functional>
#include <memory>
#include <system_error>

namespace tide {

class piece_download;
class piece_picker;
class peer_session;
class torrent_info;
class block_info;
class torrent;

/**
 * This class is used by peer_sessions and it represents the torrent to which a
 * peer_session is attached. It exposes only the limited functionality that a
 * peer_session needs from torrent, which allows it to avoid directly referring to it.
 *
 * It is also used to mediate the communication of piece download completions and
 * disk_io errors between a single peer_session (meaning each peer_session will have its
 * own torrent_disk_io_frontend instance), torrent and disk_io. It faciliates and
 * abstracts away the coupling that would otherwise occur when peer_session would need
 * to tell torrent of a new piece (of which torrent needs to be notified in order to
 * tell all peers in the swarm that a new piece is available, among other things), or
 * of a disk_io error (and the alternate solution of providing a handler for every such
 * occurence is neither elegant, nor performant (std::function)).
 * The hierarchy with this class looks as follows:
 *
 *    [torrent]<---(2) piece completion---[disk_io]
 *        |  |                                A
 *        |  `------------------.             |
 * (3) post hash result         |             |
 * to participants              |             |
 *        |                     | (1.2) save blocks & pass
 *        V                     | torrent's completion handler
 * [piece_download]<--.         |             |
 *        |           |         |             |
 * (4) invoke handler |         `-----[torrent_frontend]
 *        |           |                       A
 *        |    (1.0) register blocks          |
 *        |    & completion handler   (1.1) save blocks
 *        |           |                       |
 *        `---->[peer_session]----------------'
 *
 * Thus peer_session need only interact with this class instead of torrent and disk_io.
 *
 * Moreover, this also safely abstracts away another crucial part: peer_session must
 * not provide any of its methods (thus, a std::shared_ptr to itself) as a piece
 * completion handler, for if peer_session is stopped earlier than the piece could be
 * downloaded, the completion handler would then prolong its lifetime, possibly
 * indefinitely, if piece could not be downloaded (e.g. peers owning it left the swarm).
 */
class torrent_frontend
{
    std::shared_ptr<torrent> torrent_;

public:
    torrent_frontend() = default;
    explicit torrent_frontend(torrent& t);

    /** Tests whether this instance is valid, i.e. whether it refers to a torrent. */
    operator bool() const noexcept { return torrent_ != nullptr; }

    class piece_picker& piece_picker() noexcept;
    const class piece_picker& piece_picker() const noexcept;

    torrent_info& info() noexcept;
    const torrent_info& info() const noexcept;

    const sha1_hash& info_hash() const noexcept;
    torrent_id_t id() const noexcept;

    std::vector<std::shared_ptr<piece_download>>& downloads() noexcept;
    const std::vector<std::shared_ptr<piece_download>>& downloads() const noexcept;

    disk_buffer get_disk_buffer(const int length);

    /**
     * This saves a block to disk and once done, gives back disk_io the disk_buffer
     * holding the block data, invokes handler, and passes to disk_io torrent's
     * piece completion handler, which when invoked, posts the piece's hash result to
     * all the peers attached to piece_download, to which the saved block belongs.
     */
    void save_block(const block_info& block_info, disk_buffer block_data,
            piece_download& download,
            std::function<void(const std::error_code&)> handler);

    void fetch_block(const block_info& block_info,
            std::function<void(const std::error_code&, block_source)> handler);

    /**
     * If we're gracefully stopping, which is an async operation, torrent needs to know
     * when peer_session finished the shutdown.
     */
    void on_peer_session_stopped(peer_session& session);
};

} // namespace tide

#endif // TIDE_TORRENT_FRONTEND_HEADER
