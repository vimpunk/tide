#include "piece_download.hpp"
#include "num_utils.hpp"

#include <algorithm>
#include <cassert>
#include <cmath>

#ifdef TIDE_ENABLE_DEBUGGING
# include "string_utils.hpp"
# include "log.hpp"
# include <iostream>
#endif // TIDE_ENABLE_DEBUGGING

namespace tide {

inline void piece_download::block::remove_peer(const peer_id_type& id)
{
    auto it = std::find(peers.begin(), peers.end(), id);
    // FIXME it fired
    assert(it != peers.end());
    peers.erase(it);
}

piece_download::peer::peer(peer_id_type id_,
    std::function<void(bool, int)> completion_handler_,
    std::function<void(const block_info&)> cancel_handler_
)
    : id(std::move(id_))
    , completion_handler(std::move(completion_handler_))
    , cancel_handler(std::move(cancel_handler_))
{}

inline void piece_download::peer::remove_block(const block& block)
{
    auto it = std::find_if(blocks.begin(), blocks.end(),
        [&block](const auto& b) { return &b.get() == &block; });
    assert(it != blocks.end());
    blocks.erase(it);
}

inline bool piece_download::peer::is_requesting_block(const block& block) const noexcept
{
    return std::find_if(blocks.begin(), blocks.end(),
        [&block](const auto& b) { return &b.get() == &block; }) != blocks.end();
}

piece_download::piece_download(const piece_index_t index, const int piece_length)
    : m_blocks((piece_length + (0x4000 - 1)) / 0x4000)
    , m_index(index)
    , m_piece_length(piece_length)
    , m_num_blocks_left(m_blocks.size())
    , m_num_pickable_blocks(m_blocks.size())
{}

bool piece_download::has_block(const block_info& block) const noexcept
{
    const int index = block_index(block);
    if(index >= m_blocks.size()) { return false; }
    return m_blocks[index].status == block::status::received;
}

void piece_download::register_peer(const peer_id_type& id,
    std::function<void(bool, int)> completion_handler,
    std::function<void(const block_info&)> cancel_handler)
{
#ifdef TIDE_ENABLE_EXPENSIVE_ASSERTS
    // only register it if we haven't already
    assert(std::find_if(m_peers.begin(), m_peers.end(),
        [&id](const auto& p) { return p.id == id; }) == m_peers.end());
#endif // TIDE_ENABLE_EXPENSIVE_ASSERTS
    m_peers.emplace_back(id, std::move(completion_handler), std::move(cancel_handler));
}

void piece_download::got_block(const peer_id_type& id, const block_info& block_info)
{
    verify_block(block_info);

    block& block = m_blocks[block_index(block_info)];
    if(block.status == block::status::received) { return; }

    update_average_request_rtt(cached_clock::now() - block.request_time);

    auto& peer = find_peer(id);
    if(peer.num_bytes_downloaded == 0) { ++m_num_downloaders; }
    peer.num_bytes_downloaded += block_info.length;

    block.status = block::status::received;
    --m_num_blocks_left;

    //if(m_oldest_request && (&block == m_oldest_request)) { set_oldest_request(); }

    // check whether other peers were also downloading this block, if so,
    // invoke their cancel handlers
    for(const auto& id2 : block.peers)
    {
        // don't invoke the cancel handler of this peer
        if(id2 != id)
        {
            // TODO this is a bit slow, can we optimize?
            auto& peer2 = find_peer(id2);
            peer2.cancel_handler(block_info);
            peer2.remove_block(block);
        }
    }
    block.peers.clear();
    peer.remove_block(block);
}

inline void piece_download::set_oldest_request()
{
    assert(m_oldest_request);
    auto it = std::lower_bound(m_blocks.begin(), m_blocks.end(),
        m_oldest_request->request_time, [](const auto& b, const auto& t)
        { return (b.status == block::status::requested) && (b.request_time < t); });
    /*
    auto it = [this]
    {
        auto oldest = m_blocks.end();
        for(auto it = m_blocks.begin(); it != m_blocks.end(); ++it)
        {
            if(it->status == block::status::requested
               && &*it != m_oldest_request
               && (oldest == m_blocks.end()
                   || it->request_time < oldest->request_time))
            {
                oldest = it;
            }
            ++it;
        }
        return oldest;
    }();
    */
    if(it != m_blocks.end())
        m_oldest_request = &*it;
    else
        m_oldest_request = nullptr;
}

inline void piece_download::update_average_request_rtt(const duration& rtt)
{
    const milliseconds elapsed = duration_cast<milliseconds>(rtt);
    if(m_avg_request_rtt == milliseconds(0))
        m_avg_request_rtt = elapsed;
    else
        m_avg_request_rtt = (m_avg_request_rtt / 10) * 7 + (elapsed / 10) * 3;
}

void piece_download::post_hash_result(const bool is_piece_good)
{
#ifdef TIDE_ENABLE_DEBUGGING
    if(num_blocks_left() != 0)
    {
        std::cout << "piece(" << piece_index() << ") FATAL! num_blocks_left("
            << num_blocks_left() << ") != 0!\n";
        int i = 0;
        for(const auto b : m_blocks)
        {
            std::cout << "b" << i << "(" << (b.status == block::status::free
                ? "free" : b.status == block::status::requested
                    ? "requested" : "received") << ") ";
            ++i;
        }
        std::cout << '\n';
    }
#endif // TIDE_ENABLE_DEBUGGING
    assert(num_blocks_left() == 0);
    for(auto& peer : m_peers)
    {
        peer.completion_handler(is_piece_good, peer.num_bytes_downloaded);
    }
}

bool piece_download::time_out_request(const block_info& block)
{
    verify_block(block);
    const int index = block_index(block);
    // only time out request if it is for the last block in piece, or if it lingered far
    // too long, otherwise wait for it and let other peers request different blocks
    // (for more info: http://blog.libtorrent.org/2011/11/block-request-time-outs/)
    if(m_blocks[index].status == block::status::requested)
    {
        if((num_blocks_left() == 1) || has_lingered_too_long(m_blocks[index], 4))
        {
            m_blocks[index].status = block::status::free;
            ++m_num_pickable_blocks;
            return true;
        }
    }
    return false;
}

void piece_download::abort_request(const peer_id_type& id, const block_info& block_info)
{
    verify_block(block_info);
    block& block = m_blocks[block_index(block_info)];
    if(block.status == block::status::requested)
    {
        // remove peer from block's registry
        block.remove_peer(id);
        // remove block from peer's registry
        find_peer(id).remove_block(block);
        // TODO is this correct/needed?
        block.request_time = time_point();
        block.status = block::status::free;
        ++m_num_pickable_blocks;
    }
}

void piece_download::deregister_peer(const peer_id_type& id)
{
    auto peer = std::find_if(m_peers.begin(), m_peers.end(),
        [&id](const auto& p) { return p.id == id; });
    if(peer == m_peers.end()) { return; }
    // dissasociate peer from the blocks it had requested
    for(auto& block : peer->blocks) { block.get().remove_peer(id); }
    m_peers.erase(peer);
}

bool piece_download::can_request() const noexcept
{
    if(num_blocks_left() == 0) { return false; }
    // if all blocks were requested but not all arrived, check if any timed out
    if((num_blocks_left() > 0) && (m_num_pickable_blocks == 0))
    {
        for(const auto& b : m_blocks)
        {
            if(has_lingered_too_long(b)) { return true; }
        }
        //assert(m_oldest_request);
        //return has_lingered_too_long(*m_oldest_request);
    }
    return m_num_pickable_blocks > 0;
}

block_info piece_download::pick_block(const peer_id_type& id, int offset_hint)
{
    assert(offset_hint % 0x4000 == 0);
    assert(offset_hint >= 0);

    if(num_blocks_left() > 0)
    {
        if((offset_hint >= m_piece_length) || (offset_hint < 0))
        {
            offset_hint = 0;
        }
        return pick_block(find_peer(id), offset_hint);
    }
    return invalid_block;
}

std::vector<block_info> piece_download::pick_blocks(const peer_id_type& id, const int n)
{
    std::vector<block_info> request_queue;
    pick_blocks(request_queue, id, n);
    return request_queue;
}

block_info piece_download::pick_block(peer& peer, int offset_hint)
{
    for(auto offset = offset_hint; offset < piece_length(); offset += 0x4000)
    {
        const int index = block_index(offset);
        block& block = m_blocks[index];
        if(has_lingered_too_long(block))
        {
            block.status = block::status::free;
            ++m_num_pickable_blocks;
        }
        if(block.status == block::status::free)
        {
            if(!peer.is_requesting_block(block))
            {
                peer.blocks.emplace_back(std::ref(block));
                block.peers.emplace_back(peer.id);
                block.status = block::status::requested;
                block.request_time = cached_clock::now();
                /*
                if(!m_oldest_request)
                {
                    m_oldest_request = &block;
                }
                */
                --m_num_pickable_blocks;
                return {piece_index(), offset, block_length(offset)};
            }
        }
    }
    return invalid_block;
}

inline
bool piece_download::has_lingered_too_long(const block& block, const int m) const noexcept
{
    // you can't linger if you're not requested c: <insert meme>
    if(block.status != block::status::requested) { return false; }
    // if not a single block was received in this piece then we don't have a sample on
    // which to base our timeout cap value, so use the multiplier as the default value
    // if only a single block is missing, we want to finish the piece asap
    const seconds min(num_blocks_left() == 1 ? 2 : 4);
    const milliseconds t = util::clamp(m_avg_request_rtt * m,
        milliseconds(min), milliseconds(seconds(20))); 
    return block.request_time != time_point()
        && cached_clock::now() - block.request_time >= t;
}

inline piece_download::peer& piece_download::find_peer(const peer_id_type& id) noexcept
{
    auto it = std::find_if(m_peers.begin(), m_peers.end(),
        [&id](const auto& p) { return p.id == id; });
    // peer must be registered when joining this download, so this must not fire
    assert(it != m_peers.end());
    return *it;
}

inline void piece_download::verify_block(const block_info& block) const
{
    // use asserts as peer_session verifies block; this is really just a sanity check
    assert(block.index == m_index);
    assert(block.offset % 0x4000 == 0);
    assert(block.offset < m_piece_length);
    assert(block.length <= m_piece_length - block.offset);
}

inline int piece_download::block_index(const block_info& block) const noexcept
{
    return block_index(block.offset);
}

inline int piece_download::block_index(const int offset) const noexcept
{
    return offset / 0x4000;
}

inline int piece_download::block_length(const int offset) const noexcept
{
    return std::min(m_piece_length - offset, 0x4000);
}

} // namespace tide
