#ifndef TORRENT_PIECE_DOWNLOAD_HEADER
#define TORRENT_PIECE_DOWNLOAD_HEADER

#include "units.hpp"
#include "block_info.hpp"

#include <functional>
#include <vector>
#include <map>

namespace tide {

/**
 * This represents an ongoing piece download. It tracks piece completion, the peers who
 * participate in the download, handles block timeout logic, and acts as a mediator for
 * distributing the result of a finished piece's hash test, so that entities that need
 * otherwise not interact with one another can continue to do so.
 */
class piece_download
{
public:

    using completion_handler = std::function<void(bool)>;
    using cancel_handler = std::function<void(const block_info&)>;

private:

    /**
     * If a peer timed out on a request and if the requested block is freed for others
     * to download, the timed out peer is registered as a "cancel candidate" so that
     * when the block eventually arrives, and not from the original timed out peer, a
     * cancel message for this block can be sent. If the block arrives from the same
     * peer, the cancel handler is not invoked.
     */
    struct cancel_candidate
    {
        cancel_handler handler;
        const peer_id_t& peer;

        cancel_candidate(cancel_handler h, const peer_id_t& p)
            : handler(std::move(h))
            , peer(p)
        {}
    };

    // TODO check whether unordered maps are a better fit!

    // All peers from whom we've downloaded blocks in this piece are saved so that when
    // a piece is finished downloading each participant can be let know.
    std::map<peer_id_t, completion_handler> m_participants;

    // All pending blocks that have timed out and were made free to be downloaded from
    // other peers are placed here.
    std::map<block_info, cancel_candidate> m_timed_out_blocks;

    enum class block_status
    {
        free,
        requested,
        received
    };

    // A block is either free or not. The latter may mean that it has been received or
    // that it's being downloaded, while free blocks are those that we don't have yet.
    // TODO use block_status instead as we need the distinction between picked and reserved
    std::vector<bool> m_completion;

    const piece_index_t m_index;
    const int m_piece_length;

    // NOTE: this number does not correspond with the number of free slots in
    // m_completion, as blocks that have been requested but haven't arrived also have
    // a slot reserve in m_completion.
    // Thus this is only decremented on a call to got_block().
    int m_num_blocks_left;

    // This is incremented with every block request that was made and only decremented
    // if a request times out. This means that even if we receive the block this is not
    // decremented. This is used to check if we can make requests for this piece or we
    // should move on to another.
    int m_num_blocks_picked = 0;

    // A peer may be disconnected, so it's important not to rely on the current number
    // of participants to determine whether we downloaded the block from a single peer
    // or several peers, even if some were disconnected. This is because if we download
    // from more than a single peer, but then all but one are disconnected, and
    // if the remaining peer completes the download, it would be marked as the culprit,
    // even though any one of the other peers may have sent bad data.
    int m_all_time_num_participants = 0;

public:

    /**
     * Note that only downloads with the same m_index and m_piece_length can be
     * assigned to another.
     */
    piece_download(const piece_index_t index, const int piece_length);
    piece_download(const piece_download& other);
    piece_download(piece_download&& other);
    piece_download& operator=(const piece_download& other);
    piece_download& operator=(piece_download&& other);

    /** Tests whether there are blocks left to request. */
    bool can_request() const noexcept;

    /**
     * Exclusive means that we downloaded this piece from a single peer, even if we
     * disconnected that peer and detached it from this download since.
     */
    bool is_exclusive() const noexcept;

    /** Checks if we already downloaded block. */
    bool has_block(const block_info& block) const noexcept;

    int num_participants() const noexcept;
    int num_blocks() const noexcept;
    int num_blocks_left() const noexcept;
    piece_index_t piece_index() const noexcept;

    /**
     * Returns the peers that participated in this download and haven't been disconnected
     * (i.e. removed by remove_peer).
     */
    std::vector<peer_id_t> peers() const;

    const std::vector<bool>& downloaded_blocks() const;

    /**
     * When a part of the piece is received, it must be registered. The completion
     * handler is invoked in post_hash_result, which should be called when the
     * piece has been verified. This indirection is necessary because it's always a
     * single entity that saves the final block, so it will perform the hashing, so it
     * must propagate the results to other participants of this download.
     */
    void got_block(const peer_id_t& peer, const block_info& block,
        completion_handler completion_handler);

    /**
     * This should be called once the piece is complete and it has been hashed. It calls
     * each participating peer's completion_handler to notify them of the piece's hash
     * test.
     */
    // alternate name: invoke_completion_handlers
    void post_hash_result(const bool is_piece_good);

    /**
     * Timeouts are handled differently depending on the completion of the piece. E.g.
     * when we only have a single block in the piece missing, waiting for the timed out
     * peer to send its block would defer completion, so the requested block is freed so
     * that it may be downloaded from another peer sooner. If on the other hand there
     * are more blocks left, it doesn't make sense to handoff the request, so wait for
     * the timed out peer's block and let others request different blocks in the piece.
     *
     * So depending on the above, the block may remain as reserved or be changed to free
     * for others to request. If the block is freed, the peer's cancel handler is saved,
     * which is stored so that when block is downloaded from someone other than the
     * original timed out peer, the timed out peer can be sent a cancel message.
     *
     * NOTE: must not time out the block if peer is the only one that has this piece.
     * This is the caller's responsibility.
     */
    void time_out(const peer_id_t& peer, const block_info& block, cancel_handler handler);

    /**
     * This should be called when it is known that a block requested from a peer is not
     * going to be downloaded, such as when we disconnect or when we're choked (although
     * in the latter case peer may still decide to serve our requests).
     * This makes sure that the block is immediately freed for others to download.
     */
    // TODO rename cancel_request
    void abort_request(const block_info& block);
    
    /**
     * A peer may be disconnected before the download finishes, so it must be removed
     * on destruction so as not to call its handler, which after destructing would point
     * to invalid memory.
     */
    void remove_peer(const peer_id_t& peer);

    /** Returns n or less blocks to request. */
    // TODO make user request blocks one by one so we don't have to allocate a vector
    // for this
    std::vector<block_info> make_request_queue(const int n);

private:

    void verify_block(const block_info& block) const;
    int block_index(const block_info& block) const noexcept;
    int num_blocks(const int piece_length) const noexcept;
    int block_length(const int offset) const noexcept;
};

inline bool piece_download::is_exclusive() const noexcept
{
    return m_all_time_num_participants > 1;
}

inline int piece_download::num_participants() const noexcept
{
    return m_participants.size();
}

inline bool piece_download::can_request() const noexcept
{
    return m_num_blocks_picked < m_completion.size();
}

inline int piece_download::num_blocks() const noexcept
{
    return m_completion.size();
}

inline int piece_download::num_blocks_left() const noexcept
{
    return m_num_blocks_left;
}

inline piece_index_t piece_download::piece_index() const noexcept
{
    return m_index;
}

inline const std::vector<bool>& piece_download::downloaded_blocks() const
{
    return m_completion;
}

} // namespace tide

#endif // TORRENT_PIECE_DOWNLOAD_HEADER
