#include "send_buffer.hpp"

#include <bitset>
#include <cmath>

namespace tide {

void send_buffer::append(std::vector<uint8_t> bytes)
{
    assert(!bytes.empty() && "tried to add empty payload to send_buffer");
    size_ += bytes.size();
    buffers_.emplace_back(std::make_unique<raw_buffer_holder>(std::move(bytes)));
}

void send_buffer::append(const block_source& block)
{
    assert(block.length > 0 && "tried to add empty block to send_buffer");
    for(const auto& buffer : block.buffers) {
        size_ += buffer.size();
        buffers_.emplace_back(
                std::make_unique<disk_buffer_holder<source_buffer>>(buffer));
    }
}

std::vector<asio::const_buffer> send_buffer::get_buffers(int num_bytes) const
{
    assert(num_bytes <= size_ && "requested more from send_buffer than available");

    std::vector<asio::const_buffer> buffers;
    if(!buffers_.empty()) {
        // first buffer may be partially sent, so treat separately
        const int first_size
                = std::min(buffers_[0]->size() - first_unsent_byte_, num_bytes);
        buffers.emplace_back(buffers_[0]->data() + first_unsent_byte_, first_size);
        num_bytes -= first_size;

        for(auto i = 1; (i < buffers_.size()) && (num_bytes > 0); ++i) {
            const auto& buffer = buffers_[i];
            const int buffer_size = buffer->size();
            if(buffer_size > num_bytes) {
                buffers.emplace_back(buffer->data(), num_bytes);
                num_bytes = 0;
            } else {
                buffers.emplace_back(buffer->data(), buffer_size);
                num_bytes -= buffer_size;
            }
        }
    }
    return buffers;
}

void send_buffer::consume(int num_sent_bytes)
{
    assert(num_sent_bytes <= size_ && "sent more than what buffer has");

    while(!buffers_.empty() && (num_sent_bytes > 0)) {
        // buffer size is the number of UNSENT bytes (first buffer may contain sent bytes)
        const auto buffer_size = buffers_.front()->size() - first_unsent_byte_;
        if(buffer_size <= num_sent_bytes) {
            first_unsent_byte_ = 0;
            size_ -= buffer_size;
            buffers_.pop_front();
        } else {
            first_unsent_byte_ += num_sent_bytes;
            size_ -= num_sent_bytes;
            break;
        }
        num_sent_bytes -= buffer_size;
    }
}

} // namespace tide
