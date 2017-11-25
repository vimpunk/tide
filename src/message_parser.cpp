#include "message_parser.hpp"
#include "endian.hpp"

#include <algorithm>
#include <stdexcept>
#include <cassert>
#include <cmath>

// TODO consider just asserting instead of throwing as this is a low-level class, so it's
// reasonable to assume that user of this class (currently only peer_session) doesn't
// exhibit erratic behaviour
namespace tide {

void message_parser::reserve(const int n)
{
    if(n <= buffer_size()) { return; }
    buffer_.resize(n);
}

void message_parser::reserve_free_space(const int n)
{
    reserve(buffer_size() + n - free_space_size());
}

void message_parser::shrink_to_fit(const int n)
{
    if(n >= buffer_size()) { return; }
    // Make sure not to delete unparsed messages.
    buffer_.resize(std::max(n, size()));
}

view<uint8_t> message_parser::get_receive_buffer(const int n)
{
    // TODO decide whether we want to always receive or let user know they requested more
    // (which may be useful when higher control over memory usage is needed)
    if(n > free_space_size())
    {
        buffer_.resize(buffer_size() + n - free_space_size());
    }
    return view<uint8_t>(&buffer_[unused_begin_], n);
}

void message_parser::record_received_bytes(const int n) noexcept
{
    assert(n > 0);
    assert(size() + n <= buffer_size());
    unused_begin_ += n;
}

bool message_parser::has_message() const noexcept
{
    if(has(4))
    {
        return has(4 + view_message_length());
    }
    return false;
}

bool message_parser::has_handshake() const noexcept
{
    if(has(1))
    {
        const uint8_t protocol_length = buffer_[message_begin_];
        return has(49 + protocol_length);
    }
    return false;
}

handshake message_parser::extract_handshake()
{
    if(!has(1))
    {
        throw std::logic_error("message_parser has no handshake message");
    }
    const uint8_t protocol_length = buffer_[message_begin_];
    if(!has(49 + protocol_length))
    {
        throw std::logic_error("message_parser has no handshake message");
    }

    const uint8_t* pos = &buffer_[message_begin_ + 1];
    handshake handshake;
    handshake.protocol = const_view<uint8_t>(pos, protocol_length);
    handshake.reserved = const_view<uint8_t>(pos += protocol_length, 8);
    handshake.info_hash = const_view<uint8_t>(pos += 8, 20);
    handshake.peer_id = const_view<uint8_t>(pos += 20, 20);

    message_begin_ += 49 + protocol_length;
    return handshake;
}

message message_parser::extract_message()
{
    auto msg = view_message();
    message_begin_ += 4 + msg.data.size();
    // keep_alive messages don't have a type field
    if(msg.type != message::keep_alive)
    {
        ++message_begin_;
    }
    return msg;
}

message message_parser::view_message() const
{
    if(!has(4)) { throw std::logic_error("message_parser has no messages"); }

    // Don't use `has_message` because the message length would be calculated twice then.
    const int msg_length = view_message_length();
    if(!has(4 + msg_length)) { throw std::logic_error("message_parser has no messages"); }

    message msg;
    if(msg_length == 0)
    {
        msg.type = message::keep_alive;
    }
    else
    {
        const int msg_id_pos = message_begin_ + 4;
        msg.type = buffer_[msg_id_pos];
        msg.data = const_view<uint8_t>(&buffer_[msg_id_pos + 1], msg_length - 1);
        // Subtract message type.
    }
    return msg;
}

int message_parser::type() const
{
    if(!has(4)) { throw std::logic_error("message_parser has no messages"); }
    if(view_message_length() == 0)
    {
        // It's a keep alive message.
        return message::keep_alive;
    }
    if(!has(5)) { throw std::logic_error("message_parser has no messages"); }
    return buffer_[message_begin_ + 4];
}

const_view<uint8_t> message_parser::view_raw_bytes() const noexcept
{
    assert(unused_begin_ >= message_begin_);
    return {buffer_.data() + message_begin_, size_t(unused_begin_ - message_begin_)};
}

int message_parser::num_bytes_left_till_completion() const noexcept
{
    if(!has(4)) { return -1; }
    const int num_available = unused_begin_ - message_begin_;
    const int total_msg_length = 4 + view_message_length();
    const int left = total_msg_length - num_available;
    return std::max(left, 0);
}

void message_parser::skip_message()
{
    if(!has(4)) { throw std::logic_error("no message to skip"); }
    const int msg_length = view_message_length();
    if(!has(4 + msg_length)) { throw std::logic_error("no message to skip"); }
    message_begin_ += 4 + msg_length;
}

inline bool message_parser::has(const int n) const noexcept
{
    return unused_begin_ - message_begin_ >= n;
}

inline int message_parser::view_message_length() const noexcept
{
    assert(has(4));
    return endian::parse<int>(&buffer_[message_begin_]);
}

void message_parser::optimize_receive_space()
{
    if(message_begin_ >= unused_begin_)
    {
        // Message pointer wrapped around, reset it to the beginning of the buffer.
        message_begin_ = 0;
        unused_begin_ = 0;
        return;
    }

    if(has(4))
    {
        // Check if this is the last message.
        const int total_length = 4 + view_message_length();
        if(has(total_length) && (total_length < unused_begin_ - message_begin_))
        {
            // We only want to shift the message to the front if it's the last one
            // (message is not the last if all its bytes are available and there's a
            // gap between its end and the first unused byte).
            return;
        }
        if(total_length > buffer_size())
        {
            // It could very well be that the current (incomplete) message may not even
            // fit in the buffer, so in anticipation of completing this message, ensure
            // that it completely fits in the buffer.
            // TODO decide if we want to do this here or whether this should be done
            // by user manually
            buffer_.resize(total_length);
        }
    }
    shift_last_message_to_front();
}

inline void message_parser::shift_last_message_to_front()
{
    // The number of bytes we have of the message (not necessarily the length of the
    // complete message).
    const auto begin = buffer_.begin();
    assert(begin + message_begin_ != begin + unused_begin_);
    std::copy(begin + message_begin_, begin + unused_begin_, begin);

    unused_begin_ -= message_begin_;
    message_begin_ = 0;
}

} // namespace tide
