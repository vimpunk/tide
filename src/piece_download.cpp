#include "piece_download.hpp"

#include <cassert>
#include <cmath>

piece_download::piece_download(const piece_index_t index, const int piece_length)
    : m_completion(num_blocks(piece_length), false)
    , m_index(index)
    , m_piece_length(piece_length)
    , m_num_blocks_left(num_blocks(piece_length))
{}

bool piece_download::got_block(const block_info& block) const noexcept
{
    const int index = block_index(block);
    if(index >= int(m_completion.size()))
    {
        return false;
    }
    return m_completion[index];
}

void piece_download::got_block(
    const peer_id& peer,
    const block_info& block,
    completion_handler completion_handler)
{
    verify_block(block);

    const int index = block_index(block);
    if(m_completion[index])
    {
        return;
    }
    m_completion[index] = true;
    m_participants.emplace(peer, std::move(completion_handler));
    --m_num_blocks_left;

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

#include <iostream>
void piece_download::notify_all_of_hash_result(const bool is_piece_good)
{
    std::cerr << "notifying all participants of piece hash test result...\n";
    assert(m_num_blocks_left == 0);
    for(auto& entry : m_participants)
    {
        entry.second(is_piece_good);
    }
    m_completion_handler(is_piece_good);
}

void piece_download::time_out(
    const peer_id& peer,
    const block_info& block,
    cancel_handler handler)
{
    verify_block(block);
    if(m_num_blocks_left == 1)
    {
        --m_num_blocks_picked;
        m_completion[block_index(block)] = false;
        m_timed_out_blocks.emplace(block, cancel_candidate(std::move(handler), peer));
    }
}

void piece_download::abort_download(const block_info& block)
{
    verify_block(block);
    m_completion[block_index(block)] = false;
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
