#ifndef TIDE_PIECE_DOWNLOAD_HEADER
#define TIDE_PIECE_DOWNLOAD_HEADER

#include "block_info.hpp"
#include "types.hpp"
#include "time.hpp"

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
struct piece_download
{
    using completion_handler = std::function<void(bool)>;
    using cancel_handler = std::function<void(const block_info&)>;

    /**
     * All peers from whom we've downloaded blocks in this piece are saved so that when
     * a piece is finished downloading each participant can be let know of the piece's
     * hash test result.
     */
    struct peer
    {
        peer_id_t id;
        completion_handler handler;
    };

    struct block
    {
        enum class status : uint8_t
        {
            free,
            requested,
            received
        };

        enum status status = status::free;
        bool was_timed_out = false;
        time_point request_time;
    };

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
        const peer_id_t& peer;
        cancel_handler handler;

        cancel_candidate(const peer_id_t& p, cancel_handler h)
            : peer(p)
            , handler(std::move(h))
        {}
    };

    // All pending blocks that have timed out and were made free to be downloaded from
    // other peers are placed here.
    std::map<block_info, cancel_candidate> m_timed_out_blocks;

    std::vector<peer> m_peers;
    std::vector<block> m_blocks;

    piece_index_t m_index;
    int m_piece_length;

    // This is only decremented on a call to got_block().
    int m_num_blocks_left;

    // This is decremented with every requested and received block, and incremented once
    // a block times out and becomes pickable. This means that once the piece is fully 
    // downloaded this will equal m_num_blocks_left. It's used to check if we can make 
    // requests for this piece or we should move on to another.
    int m_num_pickable_blocks;

    // A peer may be disconnected, so it's important not to rely on the current number
    // of participants to determine whether we downloaded the block from a single peer
    // or several peers, even if some were disconnected. This is because if we download
    // from more than a single peer, but then all but one are disconnected, and if the
    // remaining peer completes the download and the piece turns out to be corrupt, the 
    // remaining peer would be marked as the culprit, even though any one of the other 
    // peers may have sent the bad data.
    int m_all_time_num_participants = 0;

    // Every time got_block is called, this is updated. This is because timing out
    // blocks is handled by peer_sessions, not by piece_download itself (because each
    // peer_session tailors the timeout value to its peer's performance). However, we
    // don't always release timed out blocks for other peers to download (when we're not
    // close to completion, see time_out comment), which means that if a block that a
    // peer_session has timed out but piece_download didn't release never arrived in the
    // end, it would be stuck as `requested` forever, barring other peer_sessions from
    // downloading it. Since any number of blocks may behave like this, we must enforce
    // an upper bound on the time a block can remain in the `requested` state. This is
    // achieved by measuring average block round trip times and adjusting the upper
    // limit using this value.
    milliseconds m_avg_request_rtt;

public:

    piece_download(const piece_index_t index, const int piece_length);

    /** Tests whether there are blocks left to request. */
    bool can_request() const noexcept;

    /** Checks if we already downloaded block. */
    bool has_block(const block_info& block) const noexcept;

    /**
     * Exclusive means that no more than a single peer participated in this download,
     * even if that peer has been disconnected and detached from this download since.
     */
    bool is_exclusive() const noexcept;

    int num_blocks_left() const noexcept;

    int piece_length() const noexcept;
    piece_index_t piece_index() const noexcept;

    /**
     * Returns the peers that participated in this download and haven't been disconnected
     * (i.e. removed by remove_peer).
     */
    const std::vector<peer>& peers() const noexcept;
    const std::vector<block>& blocks() const noexcept;

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
     * So depending on the above, the block may remain as requested or be changed to
     * free for others to request. However, the peer's cancel handler is saved in either 
     * case, as peer may never send its block, in which case we request it from another
     * peer. When block is downloaded from someone other than the original timed out
     * peer, the timed out peer can be sent a cancel message.
     *
     * NOTE: peer_session must not time out the block if its peer is the only one that
     * has this piece.
     */
    void time_out(const peer_id_t& peer, const block_info& block, cancel_handler handler);

    /**
     * This should be called when it is known that a block requested from a peer is not
     * going to be downloaded, such as when we disconnect or when we're choked, or peer
     * rejects our request.
     * This makes sure that the block is immediately freed for others to download.
     */
    void cancel_request(const block_info& block);
    
    /**
     * A peer may be disconnected before the download finishes, so it must be removed
     * on destruction so as not to call its handler, which after destructing would point
     * to invalid memory.
     */
    void remove_peer(const peer_id_t& peer);

    /**
     * Picks a single block to download next. This should be used over make_request_queue 
     * to avoid the vector allocation. If no blocks could be requested, invalid_block is 
     * returned.
     *
     * If this function is called in quick succession in order to create a request queue
     * of several blocks, offset_hint can be used to hint at the next block in order to 
     * avoid looping over all blocks. This should be the next block's offset, that is, a
     * multiple of 0x4000.
     */
    block_info pick_block(int offset_hint = 0);

    /** Returns n or less blocks to request. */
    std::vector<block_info> make_request_queue(const int n);

private:

    bool has_timed_out(const block& block) const noexcept;

    void verify_block(const block_info& block) const;
    int block_index(const block_info& block) const noexcept;
    int num_blocks(const int piece_length) const noexcept;
    int block_length(const int offset) const noexcept;
};

inline bool piece_download::is_exclusive() const noexcept
{
    return m_all_time_num_participants == 1;
}

inline int piece_download::num_blocks_left() const noexcept
{
    return m_num_blocks_left;
}

inline int piece_download::piece_length() const noexcept
{
    return m_piece_length;
}

inline piece_index_t piece_download::piece_index() const noexcept
{
    return m_index;
}

inline const std::vector<piece_download::peer>& piece_download::peers() const noexcept
{
    return m_peers;
}

inline const std::vector<piece_download::block>& piece_download::blocks() const noexcept
{
    return m_blocks;
}

} // namespace tide

#endif // TIDE_PIECE_DOWNLOAD_HEADER
