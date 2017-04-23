#ifndef TORRENT_BITFIELD_HEADER
#define TORRENT_BITFIELD_HEADER

#include <type_traits>
#include <stdexcept>
#include <iterator>
#include <string>
#include <vector>
#include <limits>
#include <cmath>

/**
 * This is a BitTorrent specific bitfield. The least significant bit is on the leftmost
 * side of the bitfield since it is used to represent piece availability, which is more
 * naturally represented as a left-to-right sequence.
 *
 * By calling data(), the underlying byte array is returned, which can be used to send
 * the bitfield over the wire (this means the excess bits are always kept zero, as
 * mandated by the protocol).
 */
class bt_bitfield
{
    class bit_reference;

    using block_type = uint8_t;

    std::vector<block_type> m_blocks;
    int m_num_bits;

public:

    class const_iterator;

    using value_type = bool;
    using difference_type = std::ptrdiff_t;
    using size_type = size_t;
    using reference = bit_reference;
    using const_reference = value_type;
    using pointer = value_type*;
    using const_pointer = const value_type*;
    using const_iterator = const_iterator;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    bt_bitfield() = default;

    explicit bt_bitfield(size_type num_bits, value_type initial_val = false)
        : m_blocks(num_blocks_for(num_bits), initial_val ? ~block_type(0) : 0)
        , m_num_bits(num_bits)
    {
        zero_unused_bits();
    }

    /**
     * Creates a bitfield from some contiguous array of bytes. The length of the byte
     * sequence must be equal to the blocks needed to store num_bits. If this condition
     * is not met, an invalid_argument exception is thrown. This way it is easy to verify
     * whether peer has sent us a valid bitfield.
     * NOTE: exceses bits are not tested, use is_bitfield_data_valid(). This is to
     * provide different levels of enforcement.
     */
    template<
        typename Bytes,
        typename = decltype(std::declval<Bytes>().begin())
    > explicit bt_bitfield(const Bytes& bytes, size_type num_bits)
        : m_blocks(bytes.begin(), bytes.end())
        , m_num_bits(num_bits)
    {
        if(num_blocks_for(num_bits) != int(m_blocks.size()))
        {
            throw std::invalid_argument(
                "byte sequence does not match the requested number of bits in bitfield"
            );
        }
        zero_unused_bits();
    }

    friend void swap(bt_bitfield& a , bt_bitfield& b);

    /**
     * Verifies whether the raw byte sequence is a valid bitfield. This should be used to
     * verify that the bitfield sent by peer (which is a sequence of bytes) is valid.
     * To pass the test, the length of the sequence must be equal to the blocks necessary
     * to store num_bits, and the excess bits, if any, must be zero.
     */
    template<
        typename Bytes,
        typename = decltype(std::declval<Bytes>().data())
    > static bool is_bitfield_data_valid(const Bytes& bytes, size_type num_bits) noexcept
    {
        if(num_blocks_for(num_bits) != int(bytes.size()))
        {
            return false;
        }
        // need to check the last block separately because of the zeroed out excess bits
        const block_type last_block_mask = ~block_type(0)
                                         << num_excess_bits(bytes, num_bits);
        return bytes.back() == last_block_mask;
    }

    /** Returns the underlying byte sequence. */
    const std::vector<block_type>& data() const noexcept
    {
        return m_blocks;
    }

    /**
     * Returns the same number of bits that was supplied in the ctor (and not the
     * number of bytes in the underlying storage).
     */
    size_type size() const noexcept
    {
        return m_num_bits;
    }

    bt_bitfield& set(const int pos) noexcept
    {
        get_block(pos) |= make_bit_mask(pos);
        return *this;
    }

    bt_bitfield& set() noexcept
    {
        std::fill(m_blocks.begin(), m_blocks.end(), ~block_type(0));
        zero_unused_bits();
        return *this;
    }

    bt_bitfield& reset(const int pos) noexcept
    {
        get_block(pos) &= ~make_bit_mask(pos);
        return *this;
    }

    bt_bitfield& reset() noexcept
    {
        std::fill(m_blocks.begin(), m_blocks.end(), block_type(0));
        return *this;
    }

    bt_bitfield& flip(const int pos) noexcept
    {
        get_block(pos) ^= make_bit_mask(pos);
        return *this;
    }

    bt_bitfield& flip() noexcept
    {
        for(auto& block : m_blocks)
        {
            block = ~block;
        }
        zero_unused_bits();
        return *this;
    }

    bool are_all_set() const noexcept
    {
        static constexpr auto all_set = std::numeric_limits<block_type>::max();
        const int last_block = m_blocks.size() - 1;
        for(auto i = 0; i < last_block; ++i)
        {
            if(m_blocks[i] != all_set)
            {
                return false;
            }
        }
        // need to check the last block separately because of the zerod out excess bits
        const block_type last_block_mask = ~block_type(0) << num_excess_bits();
        return m_blocks[last_block] == last_block_mask;
    }

    bool are_any_set() const noexcept
    {
        return !are_none_set();
    }

    bool are_none_set() const noexcept
    {
        for(const auto& block : m_blocks)
        {
            if(block != 0)
            {
                return false;
            }
        }
        return true;
    }

    reference operator[](const int pos) noexcept
    {
        return reference(get_block(pos), make_bit_mask(pos));
    }

    const_reference operator[](const int pos) const noexcept
    {
        return (get_block(pos) & make_bit_mask(pos)) != 0;
    }

    reference at(const int pos)
    {
        if((pos < 0) || (pos >= m_num_bits))
        {
            throw std::out_of_range("bitfield element ouf of range");
        }
        return operator[](pos);
    }

    const_reference at(const int pos) const
    {
        if((pos < 0) || (pos >= m_num_bits))
        {
            throw std::out_of_range("bitfield element ouf of range");
        }
        return operator[](pos);
    }

    const_iterator begin() const noexcept
    {
        return const_iterator(*this);
    }

    const_iterator cbegin() const noexcept
    {
        return const_iterator(*this);
    }

    const_iterator end() const noexcept
    {
        return const_iterator(*this, m_num_bits);
    }

    const_iterator cend() const noexcept
    {
        return const_iterator(*this, m_num_bits);
    }

    /** Returns the Hamming weight of this bitfield.
    int count() const
    {
    }
    */

    std::string to_string() const
    {
        std::string s(size(), '0');
        for(auto i = 0; i < size(); ++i)
        {
            if((*this)[i])
            {
                s[i] = '1';
            }
        }
        return s;
    }

    // Bitwise operations

    bt_bitfield operator-() const
    {
        bt_bitfield b(*this);
        b.flip();
        return b;
    }

    bt_bitfield& operator&=(const bt_bitfield& other)
    {
        const size_type end = std::min(m_blocks.size(), other.m_blocks.size());
        for(size_type i = 0; i < end; ++i)
        {
            m_blocks[i] &= other.m_blocks[i];
        }
        return *this;
    }

    bt_bitfield& operator|=(const bt_bitfield& other)
    {
        const size_type end = std::min(m_blocks.size(), other.m_blocks.size());
        for(size_type i = 0; i < end; ++i)
        {
            m_blocks[i] |= other.m_blocks[i];
        }
        return *this;
    }

    bt_bitfield& operator^=(const bt_bitfield& other)
    {
        const size_type end = std::min(m_blocks.size(), other.m_blocks.size());
        for(size_type i = 0; i < end; ++i)
        {
            m_blocks[i] ^= other.m_blocks[i];
        }
        return *this;
    }

    bt_bitfield& operator-=(const bt_bitfield& other)
    {
        const size_type end = std::min(m_blocks.size(), other.m_blocks.size());
        for(size_type i = 0; i < end; ++i)
        {
            m_blocks[i] = ~other.m_blocks[i];
        }
        return *this;
    }

    bt_bitfield operator<<(size_type n) const;
    bt_bitfield operator>>(size_type n) const;
    bt_bitfield& operator<<=(size_type n);
    bt_bitfield& operator>>=(size_type n);

    friend inline bt_bitfield operator&(const bt_bitfield& a, const bt_bitfield& b)
    {
        bt_bitfield tmp(a);
        return tmp &= b;
    }

    friend inline bt_bitfield operator|(const bt_bitfield& a, const bt_bitfield& b)
    {
        bt_bitfield tmp(a);
        return tmp |= b;
    }

    friend inline bt_bitfield operator^(const bt_bitfield& a, const bt_bitfield& b)
    {
        bt_bitfield tmp(a);
        return tmp ^= b;
    }

    friend inline bt_bitfield operator-(const bt_bitfield& a, const bt_bitfield& b)
    {
        bt_bitfield tmp(a);
        return tmp -= b;
    }

    // Relational operators

    friend bool operator==(const bt_bitfield& a, const bt_bitfield& b) noexcept
    {
        return (a.m_num_bits == b.m_num_bits) && (a.m_blocks == b.m_blocks);
    }

    friend bool operator!=(const bt_bitfield& a, const bt_bitfield& b) noexcept
    {
        return !(a == b);
    }

private:

    static constexpr int num_blocks_for(const size_type num_bits) noexcept
    {
        return std::ceil(double(num_bits) / bits_per_block());
    }

    block_type& get_block(const int pos) noexcept
    {
        return m_blocks[block_index(pos)];
    }

    const block_type& get_block(const int pos) const noexcept
    {
        return m_blocks[block_index(pos)];
    }

    static constexpr int block_index(const int pos) noexcept
    {
        return pos / bits_per_block();
    }

    static constexpr block_type make_bit_mask(const int pos) noexcept
    {
        // note that because of BitTorrent the least significant bit is on the left side
        // rather than on the right (as is the case with traditional bit layouts), so
        // shifting is a bit more involved
        const auto shift = bits_per_block() - bit_index(pos) - 1;
        return 1 << shift;
    }

    static constexpr size_type bit_index(const int pos) noexcept
    {
        return pos % bits_per_block();
    }

    void zero_unused_bits() noexcept
    {
        const auto num_excess = num_excess_bits();
        if(num_excess > 0)
        {
            m_blocks.back() &= ~block_type(0) << num_excess;
        }
    }

    block_type num_excess_bits() const noexcept
    {
        return num_excess_bits(m_blocks, m_num_bits);
    }

    template<
        typename Bytes,
        typename = decltype(std::declval<Bytes>().data())
    > static block_type num_excess_bits(const Bytes& bytes, const int num_bits) noexcept
    {
        return bits_per_block() * bytes.size() - num_bits;
    }

    static constexpr block_type bits_per_block() noexcept
    {
        // TODO check if this is sufficient (can't think of a popular architecture
        // that doesn't use 8-bit bytes), if not, use:
        //return std::numeric_limits<block_type>::digits;
        return sizeof(block_type) * 8;
    }

    class bit_reference
    {
        friend class bt_bitfield;

        block_type& m_block;
        const int m_mask;

        bit_reference(block_type& block, int mask)
            : m_block(block)
            , m_mask(mask)
        {}

    public:

        bit_reference& flip() noexcept
        {
            m_block ^= m_mask;
            return *this;
        }

        operator bool() const noexcept
        {
            return (m_block & m_mask) != 0;
        }

        bit_reference& operator=(bool x) noexcept
        {
            if(x)
            {
                m_block |= m_mask;
            }
            else
            {
                m_block &= ~m_mask;
            }
            return *this;
        }

        bit_reference& operator=(const bit_reference& other) noexcept
        {
            if(other)
            {
                m_block |= m_mask;
            }
            else
            {
                m_block &= ~m_mask;
            }
            return *this;
        }

        bit_reference& operator|=(bool x) noexcept
        {
            if(x)
            {
                m_block |= m_mask;
            }
            return *this;
        }

        bit_reference& operator&=(bool x) noexcept
        {
            if(x)
            {
                m_block &= m_mask;
            }
            return *this;
        }

        bit_reference& operator^=(bool x) noexcept
        {
            if(x)
            {
                m_block ^= m_mask;
            }
            return *this;
        }

        bit_reference& operator-=(bool x) noexcept
        {
            if(x)
            {
                m_block &= ~m_mask;
            }
            return *this;
        }

        friend bool operator==(const bit_reference& a, const bit_reference& b) noexcept
        {
            return &a.m_block == &b.m_block;
        }

        friend bool operator!=(const bit_reference& a, const bit_reference& b) noexcept
        {
            return !(a == b);
        }
    };

public:

    class const_iterator
    {
        const bt_bitfield* m_bitfield;
        size_type m_pos;

    public:

        using iterator_category = std::random_access_iterator_tag;

        const_iterator(const bt_bitfield& bitfield, size_type pos = 0)
            : m_bitfield(&bitfield)
            , m_pos(pos)
        {}

        const_reference operator*()
        {
            return (*m_bitfield)[m_pos];
        }

        const_iterator& operator++()
        {
            ++m_pos;
            return *this;
        }

        const_iterator operator++(int)
        {
            auto tmp(*this);
            ++m_pos;
            return tmp;
        }

        const_iterator& operator--()
        {
            --m_pos;
            return *this;
        }

        const_iterator operator--(int)
        {
            auto tmp(*this);
            --m_pos;
            return tmp;
        }

        const_iterator operator+(const size_type n)
        {
            auto tmp(*this);
            tmp += n;
            return tmp;
        }

        const_iterator operator-(const size_type n)
        {
            auto tmp(*this);
            tmp -= n;
            return tmp;
        }

        const_iterator& operator+=(const size_type n)
        {
            m_pos += n;
            return *this;
        }

        const_iterator& operator-=(const size_type n)
        {
            m_pos -= n;
            return *this;
        }

        difference_type operator-(const_iterator other) noexcept
        {
            return m_pos - other.m_pos;
        }

        friend bool operator==(const const_iterator& a, const const_iterator& b) noexcept
        {
            return (a.m_bitfield == b.m_bitfield) && (a.m_pos == b.m_pos);
        }

        friend bool operator!=(const const_iterator& a, const const_iterator& b) noexcept
        {
            return !(a == b);
        }
    };
};

inline void swap(bt_bitfield& a , bt_bitfield& b)
{
    using std::swap;
    swap(a.m_blocks, b.m_blocks);
    swap(a.m_num_bits, b.m_num_bits);
}

#endif // TORRENT_BITFIELD_HEADER
