#ifndef TIDE_PIECE_DOWNLOAD_HEADER
#define TIDE_PIECE_DOWNLOAD_HEADER

#include "block_info.hpp"
#include "socket.hpp"
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
    using peer_id_type = tcp::endpoint;
    class peer;

    struct block
    {
        enum class status : uint8_t
        {
            free,
            requested,
            received
        };

        enum status status = status::free;
        time_point request_time;

        // These are the peers from whom we've requested this block.
        std::vector<peer_id_type> peers;

        void remove_peer(const peer_id_type& id);
    };

    /**
     * All peers from whom we've downloaded blocks in this piece are saved so that when
     * a piece is finished downloading each participant can be let know of the piece's
     * hash test result, or when multiple peers download the same block, the first to
     * download it can notify the rest to cancel their request.
     */
    struct peer
    {
        peer_id_type id;

        // A peer must registered when it joins the download, but we may not be
        // successful in downloading anything from it, so this value is used passed to
        // completion_handler and is used to indicate whether peer has partaken in the
        // download.
        int num_bytes_downloaded = 0;

        std::function<void(bool, int)> completion_handler;
        std::function<void(const block_info&)> cancel_handler;

        // Stores the references to the entries in blocks_ which this peer has
        // requested. (blocks_ is never reallocated so it's OK to store a reference.)
        std::vector<std::reference_wrapper<block>> blocks;

        peer(peer_id_type id, std::function<void(bool, int)> completion_handler,
            std::function<void(const block_info&)> cancel_handler);

        void remove_block(const block& block);
        bool is_requesting_block(const block& block) const noexcept;
    };

private:

    std::vector<peer> peers_;
    std::vector<block> blocks_;

    // To determine whether we can request blocks in this piece we must loop through
    // all blocks to see whether any have timed out. This is expensive for an
    // operation meant to be cheap and invoked often. So the oldest request made is
    // cached here until it arrives, in which case we look for the second oldest
    // request, or nullptr if none are found.
    block* oldest_request_ = nullptr;

    piece_index_t index_;
    int piece_length_;

    // This is only decremented when we receive a block, i.e. on a call to got_block().
    int num_blocks_left_;

    // This is decremented with every requested and received block, and incremented once
    // a block times out and becomes pickable. This means that once the piece is fully 
    // downloaded this will equal num_blocks_left_. It's used to check if we can make 
    // requests for this piece or we should move on to another.
    int num_pickable_blocks_;

    // A peer may be disconnected, so it's important not to rely on the current number
    // of participants to determine whether we downloaded the block from a single peer
    // or several peers, even if some were disconnected. (If we download from more than
    // a single peer, but then all but one are disconnected, and if the remaining peer 
    // completes the download and the piece turns out to be bad, the remaining peer 
    // would be marked as the culprit, even though any one of the other peers may have 
    // sent the corrupt data.)
    int num_downloaders_ = 0;

    // Every time got_block is called, this is updated. This is because timing out
    // blocks is handled by peer_sessions, not by piece_download itself (because each
    // peer_session tailors the timeout value to its peer's performance). However, we
    // don't always release timed out blocks for other peers to download (when we're not
    // close to completion, see time_out_request comment), which means that if a block 
    // that a peer_session has timed out but piece_download didn't release never arrived 
    // in the end, it would be stuck as `requested` forever, barring other peer_sessions 
    // from downloading it. Since any number of blocks may behave like this, we must 
    // enforce an upper bound on the time a block may remain in the `requested` state. 
    // This is achieved by measuring average request round trip times and deriving the 
    // upper limit from this value.
    milliseconds avg_request_rtt_{0};

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

    int num_blocks() const noexcept;
    int num_received_blocks() const noexcept;
    int num_blocks_left() const noexcept;

    int piece_length() const noexcept;
    piece_index_t piece_index() const noexcept;

    const std::vector<peer>& peers() const noexcept;
    const std::vector<block>& blocks() const noexcept;

    milliseconds average_request_rtt() const noexcept;

    /**
     * When we have downloaded a block from a peer, we must register it with the
     * piece_download so that the completion handler can be invoked in post_hash_result
     * (which should be called by torrent when the piece has been verified; this 
     * indirection is necessary because it's always a single entity that saves the final
     * block, so it will perform the hashing, so it must propagate the results to other
     * participants of this download). The cancel_handler is invoked when another peer
     * downloads a block faster than this peer (important in end-game mode).
     *
     * completion_handler takes two arguments: the first indicates whether the piece
     * was good or not, the second indicates how many bytes the peer has downloaded in
     * this piece (we may not download anything from a registered peer, but we still
     * need to invoke the completion handlers).
     */
    void register_peer(const peer_id_type& id,
        std::function<void(bool, int)> completion_handler,
        std::function<void(const block_info&)> cancel_handler);

    /**
     * A peer may be disconnected before the download finishes, so it must be removed
     * on destruction so as not to call its handler, which after destructing would point
     * to invalid memory.
     */
    void deregister_peer(const peer_id_type& id);


    void got_block(const peer_id_type& id, const block_info& block);

    /**
     * This should be called once the piece is complete and it has been hashed. It calls
     * each participating peer's completion_handler to notify them of the piece's hash
     * test.
     */
    void post_hash_result(const bool is_piece_good);

    /**
     * Timeouts are handled differently depending on the completion of the piece. E.g.
     * when piece has only a single missing block, waiting for the timed out peer to
     * send that block would defer completion, so the requested block is freed in hopes
     * that it can be downloaded faster from other peers.
     * If on the other hand there are more blocks left, it doesn't make sense to handoff
     * the request, so wait for the timed out peer's block and let others request 
     * different blocks in the piece.
     * Depending on the above, true is returned if peer should consider the request
     * timed out, or false if it has not been timed out.
     *
     * NOTE: peer_session must not time out the block if its peer is the only one that
     * has this piece.
     */
    bool time_out_request(const block_info& block);

    /**
     * This should be called when it is known that a block requested from a peer is not
     * going to be downloaded, such as when a peer is disconnected, chokes us, or
     * rejects our request.
     * This makes sure that the block is immediately freed for others to download.
     */
    void abort_request(const peer_id_type& id, const block_info& block_info);

    /**
     * Picks a single block to download next. If no blocks could be requested, 
     * invalid_block is returned.
     *
     * If this function is called in quick succession in order to create a request queue
     * of several blocks, offset_hint can be used to hint at the next block in order to 
     * avoid looping over all blocks. This should be the next block's offset, that is, a
     * multiple of 0x4000.
     */
    block_info pick_block(const peer_id_type& id, int offset_hint = 0);

    /** Returns n or less blocks to request. */
    std::vector<block_info> pick_blocks(const peer_id_type& id, const int n);

    template<typename RequestQueue>
    int pick_blocks(RequestQueue& queue, const peer_id_type& id, const int n);

private:

    void update_average_request_rtt(const duration& rtt);
    block_info pick_block(peer& peer, int offset_hint);

    void set_oldest_request();

    /**
     * m and avg_request_rtt_ are used to derive the maximum time a request can go
     * unanswered.
     */
    bool has_lingered_too_long(const block& b, const int m = 3) const noexcept;

    peer& find_peer(const peer_id_type& id) noexcept;

    void verify_block(const block_info& block) const;
    int block_index(const block_info& block) const noexcept;
    int block_index(const int offset) const noexcept;
    int block_length(const int offset) const noexcept;
};

inline bool piece_download::is_exclusive() const noexcept
{
    return num_downloaders_ == 1;
}

inline int piece_download::num_blocks() const noexcept
{
    return blocks_.size();
}

inline int piece_download::num_blocks_left() const noexcept
{
    return num_blocks_left_;
}

inline int piece_download::num_received_blocks() const noexcept
{
    return num_blocks() - num_blocks_left();
}

inline int piece_download::piece_length() const noexcept
{
    return piece_length_;
}

inline piece_index_t piece_download::piece_index() const noexcept
{
    return index_;
}

inline const std::vector<piece_download::peer>& piece_download::peers() const noexcept
{
    return peers_;
}

inline const std::vector<piece_download::block>& piece_download::blocks() const noexcept
{
    return blocks_;
}

inline milliseconds piece_download::average_request_rtt() const noexcept
{
    return avg_request_rtt_;
}

template<typename RequestQueue>
int piece_download::pick_blocks(RequestQueue& queue,
    const peer_id_type& id, const int n)
{
    if(num_blocks_left() == 0) { return 0; }
    queue.reserve(queue.size() + std::min(n, num_pickable_blocks_));
    auto& peer = find_peer(id);
    int num_picked = 0;
    for(auto hint = 0; num_picked < n;)
    {
        const auto block = pick_block(peer, hint);
        if(block == invalid_block) { break; }
        queue.emplace_back(block);
        hint = block.offset + 0x4000;
        ++num_picked;
    }
    return num_picked;
}

} // namespace tide

#endif // TIDE_PIECE_DOWNLOAD_HEADER

