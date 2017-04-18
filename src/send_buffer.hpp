#ifndef TORRENT_SEND_BUFFER_HEADER
#define TORRENT_SEND_BUFFER_HEADER

#include "payload.hpp"
#include "block_disk_buffer.hpp"

#include <cstdint>
#include <vector>
#include <deque>

#include <asio/buffer.hpp>

/**
 * This class is used for accruing messages until it is drained and sent off to socket.
 *
 * It can take two types of data: raw and disk buffers. The former is some contiguous
 * byte sequence. This should be used for simple, short messages. The latter is what's
 * used for sending large piece blocks; these are views into memory mapped file buffers.
 * 
 * It takes ownership of the raw messages, and holds onto the disk buffers as well until
 * the consume() function is invoked, after which all resources that are confirmed to be
 * sent, are released.
 *
 * The output is a sequence of asio buffers that satisfies the ConstBufferSequence
 * concept.
 *
 * Memory allocation for the resources is dynamic, and currently no upper bound is
 * enforced on the buffer size (TODO).
 */
class send_buffer
{
    struct buffer_holder
    {
        virtual ~buffer_holder() {}
        virtual const uint8_t* data() const noexcept = 0;
        virtual int size() const noexcept = 0;
    };

    struct raw_buffer_holder : public buffer_holder
    {
        std::vector<uint8_t> bytes;
        raw_buffer_holder(std::vector<uint8_t>&& b) : bytes(std::move(b)) {}
        const uint8_t* data() const noexcept override { return bytes.data(); }
        int size() const noexcept override { return bytes.size(); }
    };

    struct disk_buffer_holder : public buffer_holder
    {
        mmap_source bytes;
        disk_buffer_holder(mmap_source b) : bytes(b) {}
        const uint8_t* data() const noexcept override { return bytes.data(); }
        int size() const noexcept override { return bytes.size(); }
    };

    // These are the bytes we want to send off to socket. It ensures their lifetime
    // until they are confirmed to be sent, after which the resources are released.
    std::deque<std::unique_ptr<buffer_holder>> m_buffers;
    // This is the offset into the first buffer in m_buffers that marks the beginning of
    // unsent bytes. This is employed because it may be that not all of the buffer is
    // drained during a send operation, and if so, it is very likely that the number of
    // sent bytes will not align with buffer boundaries, leaving the first buffer with
    // sent and unsent fractions. Thus, this buffer must be kept alive until all its
    // unsent bytes have been sent off.
    int m_first_unsent_byte = 0;
    // The total number of UNSENT bytes we have in buffer. That is, if the first buffer
    // was not fully drained (m_first_unsent_byte > 0), it will have excess bytes, which
    // are not counted (since it's a temporary state and is not relevant to the caller).
    int m_size = 0;
    //int m_capacity = 0;

public:

    bool is_empty() const noexcept;
    int size() const noexcept;
    //int capacity() const noexcept;

    void append(payload payload);
    void append(std::vector<uint8_t> bytes);
    void append(const block_source& block);
    template<size_t N> void append(const uint8_t (&bytes)[N]);

    /**
     * Returns an asio ConstBufferSequence compliant list of buffers whose total size is
     * at least min_num_bytes.
     */
    std::vector<asio::const_buffer> get_send_buffers(int min_num_bytes) const;

    /**
     * Must be called after send_buffer has been drained (sent to socket), so that
     * resources may be cleaned up and the unsent message cursor adjusted.
     */
    void consume(int num_sent_bytes);
};

inline bool send_buffer::is_empty() const noexcept
{
    return size() == 0;
}

inline int send_buffer::size() const noexcept
{
    return m_size;
}

inline void send_buffer::append(payload payload)
{
    append(std::move(payload.data));
}

template<size_t N>
void send_buffer::append(const uint8_t (&bytes)[N])
{
    append(std::vector<uint8_t>(std::begin(bytes), std::end(bytes)));
}

#endif // TORRENT_SEND_BUFFER_HEADER
