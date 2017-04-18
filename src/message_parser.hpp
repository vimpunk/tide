#ifndef TORRENT_MESSAGE_PARSER_HEADER
#define TORRENT_MESSAGE_PARSER_HEADER

#include "range.hpp"

#include <cstdint>
#include <vector>

/**
 * All currently supported BitTorrent message types. This is denoted by the 5th byte in
 * a torrent message (the byte values are shown next to each type).
 *
 * NOTE: whereas in the protocol the term 'piece' is used to describe both the pieces
 * into which a file is split and the payload sent over the network, for clarity, here
 * and throughout the application, the unofficial term 'block' is used to denote the
 * piece chunks sent over the network.
 */
enum message_t : uint8_t
{
    // -- standard BitTorrent messages --
    choke          = 0,
    unchoke        = 1,
    interested     = 2,
    not_interested = 3,
    have           = 4,
    bitfield       = 5,
    request        = 6,
    block          = 7,
    cancel         = 8,
    port           = 9,
    // keep alive has no identifier (it's just 4 zero bytes), only for convenience
    keep_alive     = 255
};

struct message
{
    message_t type;
    // The message content, excluding the four bytes of message length and one byte of
    // message identifier/type.
    const_range<uint8_t> data;
};

struct handshake
{
    char protocol_id_length;
    const_range<uint8_t> protocol_id;
    const_range<uint8_t> reserved;
    const_range<uint8_t> info_hash;
    const_range<uint8_t> peer_id;
};

/**
 * Raw bytes sent by peer are read into message_parser's internal buffer. These are
 * lazily parsed into BitTorrent messages, however, no extra copies are made. The user
 * receives merely a view into the internal buffer.
 *
 * The buffer grows dynamically and transparently, so user need not explicitly request
 * it, though it is possible and advised when more messages are expected.
 */
class message_parser
{
    std::vector<uint8_t> m_buffer;

    // The index of the beginning of the current message, i.e. the beginning of the
    // message length field.
    int m_message_begin = 0;

    // Since we're filling m_buffer when ensuring capacity, we need to know where
    // received bytes end and where the "empty" space start.
    int m_unused_begin = 0;

    // This is the upper bound on the receive buffer's capacity.
    int m_max_capacity;

public:

    message_parser() = default; // TODO delete this
    explicit message_parser(int max_capacity);

    bool is_full() const noexcept;
    bool is_empty() const noexcept;
    int size() const noexcept;
    int capacity() const noexcept;
    int num_free_bytes() const noexcept;

    void change_max_capacity(const int n);

    /**
     * Ensures that we have space to receive n bytes. Does nothing if we do, resizes
     * the receive buffer if we don't.
     */
    void ensure_capacity(const int n);

    /**
     * If n is below m_unused_begin, it will only shrink to m_unused_begin, to preserve
     * unhandled messages.
     */
    void shrink_to_fit(const int n);

    /**
     * This returns the range of memory [unused_begin, unused_begin + n) in which we can
     * receive bytes. Buffer is resized if there isn't enough space for n more bytes.
     */
    range<uint8_t> get_receive_buffer(const int n);

    /**
     * Records the number of bytes we managed to read (as it may not be the same amount
     * as was requested), so we need to tell parser where the actual data ends.
     */
    void record_received_bytes(const int n) noexcept;

    /** This method should be called before extracting the next message. */
    bool has_message() const noexcept;

    /**
     * Handshake strucure differs from regular message structure so this should be
     * called to check whether a handshake has been received.
     */
    bool has_handshake() const noexcept;

    /**
     * Returns the next message and advances the "message pointer", i.e. subsequent
     * calls to this function convey iterator semantics.
     *
     * An exception is thrown if has_message() returns false.
     */
    message extract();

    /**
     * Handshake message structure differ from the other BT messages, so this method must
     * be used to extract them.
     *
     * An exception is thrown if the handshake could not be parsed.
     *
     * NOTE: no guarantees can be made that the current message is not a handshake,
     * (since the message header is different), so caller must ensure that they only call
     * this when it is known that the message is a handshake.
     */
    handshake extract_handshake();

    /**
     * Same as above, except it doesn't advance the message pointer, so subsequent calls
     * always return the same message.
     *
     * An exception is thrown if has_message() returns false.
     */
    message peek() const;

    /**
     * Returns the message id/type of the current message.
     * Semantically the same as calling peek().type, but more efficient (doesn't parse
     * the whole message). The message need not be complete to determine the type, it
     * only requires that the first 5 bytes, or 4 bytes for the keep alive message, be
     * present.
     *
     * An excpetion is thrown if the available bytes is less than 5, or 4, in the case of
     * a keep alive message.
     */
    message_t type() const;

    /**
     * Returns the number of bytes left till the completion of the current message if
     * the message is incomplete (we only received a chunk of it), or 0 if it is. -1 is
     * returned if we don't even have the 4 four bytes to determine the message length.
     */
    int num_bytes_left_till_completion() const noexcept;

    /** Skips to the next message. Exception is thrown if there is no message to skip. */
    void skip();

private:

    /**
     * Determines if we have n more message bytes in buffer in the range
     * [m_message_begin, m_message_begin + n).
     */
    bool has(const int n) const noexcept;

    /**
     * Returns the current message's length but does not advance m_message_begin.
     * The return value is the same as the message length field in the BitTorrent
     * message. That is, it only counts the content length, excluding the message length
     * field itself (which is 4 bytes).
     */
    int view_message_length() const noexcept;

    /**
     * This is called after operations that move the "message pointer" to the next
     * message. If this resulted in reaching the end of the buffer, the message pointer
     * is simply reset to 0. If, on the other hand, we have an incomplete message, we
     * verify that the buffer is large enough to receive the rest (after the message has
     * been shifted), reserve space if it's not, and then shift the incomplete bytes to
     * the front to increase the receive space.
     */
    void optimize_receive_space();

    /**
     * Shift incomplete message to the front of the buffer so that we can maximize the
     * free receive space (because after the last valid message the message parser will
     * most likely be filled with new messages).
     *
     * from:
     *
     *  wasted space     receive space
     *  vvvvvvvvvvv      vvvvv
     *  -----------======-----
     *             ^- incomplete message
     *
     * to:
     *        receive space
     *        vvvvvvvvvvvvvvvv
     *  ======----------------
     */
    void shift_incomplete_message_to_front();
};

inline bool message_parser::is_empty() const noexcept
{
    return size() == 0;
}

inline bool message_parser::is_full() const noexcept
{
    return size() == capacity();
}

inline int message_parser::size() const noexcept
{
    return m_unused_begin;
}

inline int message_parser::num_free_bytes() const noexcept
{
    return capacity() - size();
}

inline int message_parser::capacity() const noexcept
{
    return m_buffer.size();
}

#endif /* end of include guard: TORRENT_SEND_BUFFER_HEADER */
