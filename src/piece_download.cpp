#include "piece_download.hpp"

#include <iostream>
#include <cassert>
#include <cmath>

namespace tide {

piece_download::piece_download(const piece_index_t index, const int piece_length)
    : m_completion(num_blocks(piece_length), false)
    , m_index(index)
    , m_piece_length(piece_length)
    , m_num_blocks_left(num_blocks(piece_length))
{}

piece_download::piece_download(const piece_download& other)
    : m_participants(other.m_participants)
    , m_timed_out_blocks(other.m_timed_out_blocks)
    , m_completion(other.m_completion)
    , m_index(other.m_index)
    , m_piece_length(other.m_piece_length)
    , m_num_blocks_left(other.m_num_blocks_left)
    , m_num_blocks_picked(other.m_num_blocks_picked)
{}

piece_download::piece_download(piece_download&& other)
    : m_participants(std::move(other.m_participants))
    , m_timed_out_blocks(std::move(other.m_timed_out_blocks))
    , m_completion(std::move(other.m_completion))
    , m_index(other.m_index)
    , m_piece_length(other.m_piece_length)
    , m_num_blocks_left(std::move(other.m_num_blocks_left))
    , m_num_blocks_picked(std::move(other.m_num_blocks_picked))
{}

piece_download& piece_download::operator=(const piece_download& other)
{
    assert((m_index == other.m_index) && (m_piece_length == other.m_piece_length));
    if(this != &other)
    {
        m_participants = other.m_participants;
        m_timed_out_blocks = other.m_timed_out_blocks;
        m_completion = other.m_completion;
        m_num_blocks_left = other.m_num_blocks_left;
        m_num_blocks_picked = other.m_num_blocks_picked;
    }
    return *this;
}

piece_download& piece_download::operator=(piece_download&& other)
{
    assert((m_index == other.m_index) && (m_piece_length == other.m_piece_length));
    if(this != &other)
    {
        m_participants = std::move(other.m_participants);
        m_timed_out_blocks = std::move(other.m_timed_out_blocks);
        m_completion = std::move(other.m_completion);
        m_num_blocks_left = std::move(other.m_num_blocks_left);
        m_num_blocks_picked = std::move(other.m_num_blocks_picked);
    }
    return *this;
}

bool piece_download::has_block(const block_info& block) const noexcept
{
    const int index = block_index(block);
    if(index >= int(m_completion.size()))
    {
        return false;
    }
    return m_completion[index];
}

// TODO don't use a vector here
std::vector<peer_id_t> piece_download::peers() const
{
    std::vector<peer_id_t> peers;
    peers.reserve(m_participants.size());
    for(const auto& p : m_participants)
    {
        peers.emplace_back(p.first);
    }
    return peers;
}

void piece_download::got_block(
    const peer_id_t& peer,
    const block_info& block,
    completion_handler completion_handler)
{
    verify_block(block);

    const int index = block_index(block);
    if(m_completion[index])
    {
        return;
    }

    const int old_num_participants = num_participants();
    m_completion[index] = true;
    m_participants.emplace(peer, std::move(completion_handler));
    --m_num_blocks_left;
    if(old_num_participants < num_participants())
    {
        ++m_all_time_num_participants;
    }

    auto it = m_timed_out_blocks.find(block);
    if(it != m_timed_out_blocks.end())
    {
        // this block has been timed out before, check if the original timed out peer
        // is the same as this one who dowloaded it; if not, notify it to cancel it
        auto& cancel_candidate = it->second;
        if(cancel_candidate.peer != peer)
        {
            cancel_candidate.handler(block);
        }
    }
}

void piece_download::post_hash_result(const bool is_piece_good)
{
    std::cerr << "notifying all participants of piece hash test result...\n";
    assert(m_num_blocks_left == 0);
    for(auto& p : m_participants)
    {
        p.second(is_piece_good);
    }
}

void piece_download::time_out(
    const peer_id_t& peer, const block_info& block, cancel_handler handler)
{
    verify_block(block);
    if(m_num_blocks_left == 1)
    {
        --m_num_blocks_picked;
        m_completion[block_index(block)] = false;
        m_timed_out_blocks.emplace(block, cancel_candidate(std::move(handler), peer));
    }
}

void piece_download::abort_request(const block_info& block)
{
    verify_block(block);
    m_completion[block_index(block)] = false;
}

void piece_download::remove_peer(const peer_id_t& peer)
{
    m_participants.erase(peer);
    auto it = m_timed_out_blocks.begin();
    const auto end = m_timed_out_blocks.end();
    while(it != end)
    {
        auto tmp = it++;
        if(tmp->second.peer == peer)
        {
            m_timed_out_blocks.erase(tmp);
        }
    }
}

std::vector<block_info> piece_download::make_request_queue(const int n)
{
    std::vector<block_info> request_queue;
    for(auto i = 0;
        (i  < int(m_completion.size())) && (int(request_queue.size()) < n);
        ++i)
    {
        if(!m_completion[i])
        {
            m_completion[i] = true;
            const int offset = i * 0x4000;
            request_queue.emplace_back(m_index, offset, block_length(offset));
            ++m_num_blocks_picked;
        }
    }
    return request_queue;
}

inline void piece_download::verify_block(const block_info& block) const
{
    if(block.index != m_index
       || block.offset >= m_piece_length
       || block.offset % 0x4000 != 0
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
    return std::ceil(double(piece_length) / 0x4000);
}

inline int piece_download::block_length(const int offset) const noexcept
{
    return std::min(m_piece_length - offset, 0x4000);
}

} // namespace tide
