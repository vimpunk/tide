#include "send_buffer.hpp"

void send_buffer::append(std::vector<uint8_t> bytes)
{
    assert(!bytes.empty() && "tried to add empty payload to send_buffer");
    m_size += bytes.size();
    m_buffers.emplace_back(std::make_unique<raw_buffer_holder>(std::move(bytes)));
}

void send_buffer::append(const block_source& block)
{
    assert(block.length > 0 && "tried to add empty block to send_buffer");
    for(const mmap_source& chunk : block.chunks)
    {
        m_size += chunk.length();
        m_buffers.emplace_back(std::make_unique<disk_buffer_holder>(chunk));
    }
}

std::vector<asio::const_buffer> send_buffer::get_send_buffers(int min_num_bytes) const
{
    assert(min_num_bytes <= m_size && "requested more from send_buffer than available");
    std::vector<asio::const_buffer> buffers;
    if(!m_buffers.empty())
    {
        // first buffer may be partially sent
        buffers.emplace_back(
            m_buffers[0]->data() + m_first_unsent_byte,
            m_buffers[0]->size() - m_first_unsent_byte
        );
        for(auto i = 1; i < m_buffers.size(); ++i)
        {
            const auto& buffer = m_buffers[i];
            buffers.emplace_back(buffer->data(), buffer->size());
            min_num_bytes -= buffer->size();
            if(min_num_bytes <= 0)
            {
                break;
            }
        }
    }
    return buffers;
}

void send_buffer::consume(int num_sent_bytes)
{
    assert(num_sent_bytes <= m_size && "sent more than what buffer has");

    if(m_buffers.empty())
    {
        return;
    }

    while(!m_buffers.empty() && (num_sent_bytes > 0))
    {
        // buffer size is the number of UNSENT bytes (first buffer may contain sent bytes)
        const auto buffer_size = m_buffers.front()->size() - m_first_unsent_byte;
        if(buffer_size <= num_sent_bytes)
        {
            m_first_unsent_byte = 0;
            m_size -= buffer_size;
            m_buffers.pop_front();
        }
        else
        {
            m_first_unsent_byte += num_sent_bytes;
            m_size -= num_sent_bytes;
            break;
        }
        num_sent_bytes -= buffer_size;
    }
}
