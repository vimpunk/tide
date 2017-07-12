#include "piece_download.hpp"

#include <algorithm>
#include <cassert>
#include <cmath>

namespace tide {

piece_download::piece_download(const piece_index_t index, const int piece_length)
    : m_blocks(num_blocks(piece_length))
    , m_index(index)
    , m_piece_length(piece_length)
    , m_num_blocks_left(m_blocks.size())
    , m_num_pickable_blocks(m_blocks.size())
{}

bool piece_download::has_block(const block_info& block) const noexcept
{
    const int index = block_index(block);
    if(index >= num_blocks()) { return false; }
    return m_blocks[index].status == block::status::received;
}

void piece_download::got_block(const peer_id_t& peer, const block_info& block,
    completion_handler completion_handler)
{
    verify_block(block);

    const int elapsed = total_milliseconds(
        cached_clock::now() - m_last_received_request_time);
    if(m_avg_request_rtt_ms == 0)
        m_avg_request_rtt_ms = elapsed;
    else
        m_avg_request_rtt_ms = m_avg_request_rtt_ms * 0.7 + elapsed * 0.3;

    const int index = block_index(block);
    if(m_blocks[index].status == block::status::received) { return; }

    m_blocks[index].status = block::status::received;
    --m_num_blocks_left;

    // register this peer as a participant if we haven't already
    if(std::find_if(m_peers.begin(), m_peers.end(),
        [&peer](const auto& p) { return p.id == peer; }) == m_peers.end())
    {
        m_peers.emplace_back(piece_download::peer{peer, std::move(completion_handler)});
        ++m_all_time_num_participants;
    }

    auto it = m_timed_out_blocks.find(block);
    if(it != m_timed_out_blocks.end())
    {
        // this block has been timed out before, check if the original timed out peer
        // is the same as this one who dowloaded it; if not, notify it to cancel it
        auto& cancel_candidate = it->second;
        if(cancel_candidate.peer != peer) { cancel_candidate.handler(block); }
        m_timed_out_blocks.erase(it);
    }
}

void piece_download::post_hash_result(const bool is_piece_good)
{
    assert(num_blocks_left() == 0);
    for(auto& p : m_peers) { p.handler(is_piece_good); }
}

void piece_download::time_out(const peer_id_t& peer,
    const block_info& block, cancel_handler handler)
{
    verify_block(block);
    // only time out block if we're close to completion; if we're not, let other peers 
    // download other blocks in the hopes that this block will eventually arrive
    // TODO more advanced heuristic
    if(num_blocks_left() == 1)
    {
        // we consider this block free so that other peers can request it
        const int index = block_index(block);
        m_blocks[index].status = block::status::free;
        m_blocks[index].was_timed_out = true;
        ++m_num_pickable_blocks;
    }
    // we still register the timeout handler as block may never arrive in which case
    // we'll rerequest it
    m_timed_out_blocks.emplace(block, cancel_candidate(peer, std::move(handler)));
}

void piece_download::cancel_request(const block_info& block)
{
    verify_block(block);
    const int index = block_index(block);
    if(m_blocks[index].status == block::status::requested)
    {
        m_blocks[index].status = block::status::free;
        ++m_num_pickable_blocks;
        m_timed_out_blocks.erase(m_timed_out_blocks.find(block));
    }
}

void piece_download::remove_peer(const peer_id_t& peer)
{
    auto pit = std::find_if(m_peers.begin(), m_peers.end(),
        [&peer](const auto& p) { return p.id == peer; });
    if(pit == m_peers.end()) { return; }
    m_peers.erase(pit);
    // remove any cancel handlers this peer might have registered
    auto bit = m_timed_out_blocks.begin();
    const auto bend = m_timed_out_blocks.end();
    while(bit != bend)
    {
        auto tmp = bit++;
        if(tmp->second.peer == peer)
        {
            m_timed_out_blocks.erase(tmp);
        }
    }
}

bool piece_download::can_request() const noexcept
{
    if(num_blocks_left() == 0) { return false; }
    // if there is only a single block left and it's in the beginning of the piece,
    // it likely timed out before but we didn't time it out because there were other 
    // blocks to pick, but it still hasn't been downloaded, we want to re-request it
    if((num_blocks_left() > 0) && (m_num_pickable_blocks == 0))
    {
        //if(num_blocks_left() == 1)
            //return true;
        //else
            return cached_clock::now() - m_last_eviction_time
                 > milliseconds(m_avg_request_rtt_ms);
    }
    else
    {
        return m_num_pickable_blocks > 0;
    }
}

block_info piece_download::pick_block(int offset_hint)
{
    assert(offset_hint % 0x4000 == 0);
    assert(offset_hint >= 0);

    if(!can_request()) { return invalid_block; }

    // see comment in can_request
    if((num_blocks_left() == 1) && (m_num_pickable_blocks == 0))
    {
        auto it = std::find_if(m_blocks.begin(), m_blocks.end(),
            [](const auto& b) { return b.status == block::status::requested; });
        // since we have a block left but none are pickable, it means we must have a
        // single requested block left
        assert(it != m_blocks.end());
        const int offset = (it - m_blocks.begin()) * 0x4000;
        return {piece_index(), offset, block_length(offset)};
    }

    if(offset_hint >= m_piece_length)
    {
        offset_hint = 0;
    }

    for(auto i = offset_hint / 0x4000; i < num_blocks(); ++i)
    {
        if(m_blocks[i].status == block::status::free)
        {
            m_blocks[i].status = block::status::requested;
            --m_num_pickable_blocks;
            const int offset = i * 0x4000;
            if(num_blocks_left() == num_blocks())
            {
                m_last_received_request_time = cached_clock::now();
            }
            return {piece_index(), offset, block_length(offset)};
        }
    }
    return invalid_block;
}

std::vector<block_info> piece_download::make_request_queue(const int n)
{
    std::vector<block_info> request_queue;
    for(auto i = 0, hint = 0;
        (i  < num_blocks()) && (int(request_queue.size()) < n);
        ++i, hint += 0x4000)
    {
        auto block = pick_block(hint);
        if(block == invalid_block) { break; }
        request_queue.emplace_back(block);
    }
    return request_queue;
}

inline void piece_download::verify_block(const block_info& block) const
{
    if(block.index != m_index
       || block.offset % 0x4000 != 0
       || block.offset >= m_piece_length
       || block.length > m_piece_length - block.offset)
    {
        throw std::invalid_argument("block is invalid");
    }
}

inline int piece_download::block_index(const block_info& block) const noexcept
{
    return block.offset / 0x4000;
}

inline int piece_download::num_blocks(const int piece_length) const noexcept
{
    return (piece_length + (0x4000 - 1)) / 0x4000;
}

inline int piece_download::block_length(const int offset) const noexcept
{
    return std::min(m_piece_length - offset, 0x4000);
}

} // namespace tide
