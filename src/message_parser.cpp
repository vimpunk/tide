#include "message_parser.hpp"
#include "endian.hpp"

#include <algorithm>
#include <stdexcept>
#include <cassert>
#include <cmath>

void message_parser::reserve(const int n)
{
    if(n <= buffer_size())
    {
        return;
    }
    m_buffer.resize(n);
}

void message_parser::shrink_to_fit(const int n)
{
    if(n >= buffer_size())
    {
        return;
    }
    // make sure not to delete unparsed messages
    m_buffer.resize(std::max(n, size()));
}

view<uint8_t> message_parser::get_receive_buffer(const int n)
{
    if(n > free_space_size())
    {
        reserve(buffer_size() + n - free_space_size());
    }
    return view<uint8_t>(&m_buffer[m_unused_begin], m_unused_begin + n);
}

void message_parser::record_received_bytes(const int n) noexcept
{
    if(m_unused_begin + n > buffer_size())
    {
        throw std::logic_error(
            "recorded the receipt of more bytes in message parser than possible"
        );
    }
    m_unused_begin += n;
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
        const uint8_t protocol_id_length = m_buffer[m_message_begin];
        return has(49 + protocol_id_length);
    }
    return false;
}

message message_parser::extract()
{
    auto msg = peek();
    m_message_begin += 4 + msg.data.size();
    if(msg.type != keep_alive)
    {
        // keep_alive messages don't have an id field
        ++m_message_begin;
    }
    optimize_receive_space();
    return msg;
}

handshake message_parser::extract_handshake()
{
    if(!has(1))
    {
        throw std::runtime_error("message_parser has no handshake message");
    }
    const uint8_t protocol_id_length = m_buffer[m_message_begin];
    if(!has(49 + protocol_id_length))
    {
        throw std::runtime_error("message_parser has no handshake message");
    }

    const uint8_t* pos = &m_buffer[m_message_begin + 1];
    handshake handshake;
    handshake.protocol_id = const_view<uint8_t>(pos, protocol_id_length);
    handshake.reserved = const_view<uint8_t>(pos += protocol_id_length, 8);
    handshake.info_hash = const_view<uint8_t>(pos += 8, 20);
    handshake.peer_id = const_view<uint8_t>(pos += 20, 20);

    // advance message cursor
    m_message_begin += 49 + protocol_id_length;

    optimize_receive_space();

    return handshake;
}

message message_parser::peek() const
{
    if(!has(4))
    {
        throw std::runtime_error("peek (4): message_parser has no messages");
    }
    // don't use has_message() because the message length would be calculated twice then
    const int msg_length = view_message_length();
    if(!has(4 + msg_length))
    {
        throw std::runtime_error("peek (4 + msg_len): message_parser has no messages");
    }

    message msg;
    if(msg_length == 4)
    {
        msg.type = message_t::keep_alive;
    }
    else
    {
        const int msg_id_pos = m_message_begin + 4;
        msg.type = message_t(m_buffer[msg_id_pos]);
        msg.data = const_view<uint8_t>(&m_buffer[msg_id_pos + 1], msg_length - 1);
        // subtract message type
    }
    return msg;
}

message_t message_parser::type() const
{
    if(!has(4))
    {
        throw std::runtime_error("type (4): message_parser has no messages");
    }
    if(view_message_length() == 0)
    {
        return message_t::keep_alive;
    }
    if(!has(5))
    {
        throw std::runtime_error("type (5): message_parser has no messages");
    }
    return message_t(m_buffer[m_message_begin + 4]);
}

int message_parser::num_bytes_left_till_completion() const noexcept
{
    if(!has(4))
    {
        return -1;
    }
    const int num_available = m_unused_begin - m_message_begin;
    const int total_msg_length = 4 + view_message_length();
    const int left = total_msg_length - num_available;
    return std::max(left, 0);
}

void message_parser::skip()
{
    if(!has(4))
    {
        throw std::runtime_error("skip (4): message_parser has no messages");
    }
    const int msg_length = view_message_length();
    if(!has(4 + msg_length))
    {
        throw std::runtime_error("skip (4 + msg_length): message_parser has no messages");
    }
    m_message_begin += 4 + msg_length;
    optimize_receive_space();
}

inline bool message_parser::has(const int n) const noexcept
{
    return m_unused_begin - m_message_begin >= n;
}

inline int message_parser::view_message_length() const noexcept
{
    assert(has(4));
    return endian::parse<int>(&m_buffer[m_message_begin]);
}

inline void message_parser::optimize_receive_space()
{
    if(m_message_begin >= m_unused_begin)
    {
        // message pointer wrapped around, reset it to the beginning of the buffer
        m_message_begin = 0;
        m_unused_begin = 0;
        return;
    }

    if(has(4))
    {
        // check if this is the last message
        const int total_length = 4 + view_message_length();
        if(has(total_length) && (total_length < m_unused_begin - m_message_begin))
        {
            // we only want to shift the message to the front if it's the last one
            // (message is not the last if all its bytes are available and there's a
            // gap between its end and the first unused byte)
            return;
        }
        if(total_length > buffer_size())
        {
            // it could very well be that the current (incomplete) message may not even
            // fit in the buffer, so in anticipation of completing this message, ensure
            // that it completely fits in the buffer
            // TODO decide if we want to do this here or whether this should be done
            // by user
            m_buffer.resize(total_length);
        }
    }
    shift_last_message_to_front();
}

inline void message_parser::shift_last_message_to_front()
{
    // the number of bytes we have of the message (not necessarily the length of the
    // complete message)
    const int num_have = m_unused_begin - m_message_begin;
    const auto msg_begin = m_buffer.begin() + m_message_begin;
    const auto msg_end = msg_begin + num_have;
    assert(msg_begin != msg_end);

    std::copy(msg_begin, msg_end, m_buffer.begin());

    m_message_begin = 0;
    m_unused_begin = num_have;
}
