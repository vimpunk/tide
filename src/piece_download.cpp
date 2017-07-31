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
    if(index >= m_blocks.size()) { return false; }
    return m_blocks[index].status == block::status::received;
}

void piece_download::got_block(const peer_id_t& peer, const block_info& block,
    completion_handler completion_handler)
{
    verify_block(block);

    const int index = block_index(block);
    if(m_blocks[index].status == block::status::received) { return; }

    const milliseconds elapsed = duration_cast<milliseconds>(
        cached_clock::now() - m_blocks[index].request_time);
    if(m_avg_request_rtt == milliseconds(0))
        m_avg_request_rtt = elapsed;
    else
        m_avg_request_rtt = (m_avg_request_rtt / 10) * 7 + (elapsed / 10) * 3;

    m_blocks[index].status = block::status::received;
    --m_num_blocks_left;

    // register this peer as a participant if it's the first block from it
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
    if((num_blocks_left() > 0) && (m_num_pickable_blocks == 0))
    {
        // if we've requested all blocks but haven't received all of them, we might be
        // able to time out some of them
        for(const auto& block : m_blocks)
        {
            if((block.status == block::status::requested) && has_timed_out(block))
            {
                return true;
            }
        }
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

    if(num_blocks_left() == 0) { return invalid_block; }

    // see comment in can_request
    if((num_blocks_left() == 1) && (m_num_pickable_blocks == 0))
    {
        auto it = std::find_if(m_blocks.begin(), m_blocks.end(),
            [](const auto& b) { return b.status == block::status::requested; });
        assert(it != m_blocks.end());
        const int offset = (it - m_blocks.begin()) * 0x4000;
        it->request_time = cached_clock::now();
        return {piece_index(), offset, block_length(offset)};
    }

    if((offset_hint >= m_piece_length) || (offset_hint < 0))
    {
        offset_hint = 0;
    }

    for(auto i = offset_hint / 0x4000; i < m_blocks.size(); ++i)
    {
        block& block = m_blocks[i];
        if(block.status == block::status::requested)
        {
            if(has_timed_out(block))
                block.status == block::status::free;
            else
                continue;
        }
        else if(block.status == block::status::free)
        {
            block.status = block::status::requested;
            --m_num_pickable_blocks;
            const int offset = i * 0x4000;
            return {piece_index(), offset, block_length(offset)};
        }
    }
    return invalid_block;
}

std::vector<block_info> piece_download::make_request_queue(const int n)
{
    std::vector<block_info> request_queue;
    for(auto i = 0, hint = 0;
        (i  < m_blocks.size()) && (int(request_queue.size()) < n);
        ++i)
    {
        auto block = pick_block(hint);
        if(block == invalid_block) { break; }
        request_queue.emplace_back(block);
        hint = block.offset + 0x4000;
    }
    return request_queue;
}

inline bool piece_download::has_timed_out(const block& block) const noexcept
{
    return cached_clock::now() - block.request_time >= 2 * m_avg_request_rtt;
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
