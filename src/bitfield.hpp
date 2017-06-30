#ifndef TIDE_BITFIELD_HEADER
#define TIDE_BITFIELD_HEADER

#include <type_traits>
#include <stdexcept>
#include <iterator>
#include <cassert>
#include <string>
#include <vector>
#include <limits>
#include <cmath>

namespace tide {

/**
 * This is a BitTorrent specific bitfield. The least significant bit is on the leftmost
 * side of the bitfield since it is used to represent piece availability, which is more
 * naturally represented as a left-to-right sequence.
 *
 * By calling data(), the underlying byte array is returned, which can be used to send
 * the bitfield over the wire (this means the excess bits are always kept zero, as
 * mandated by the protocol).
 */
class bitfield
{
    using block_type = uint8_t;

    std::vector<block_type> m_blocks;
    int m_num_bits;

public:

    class reference;
    class const_iterator;

    using value_type = bool;
    using difference_type = std::ptrdiff_t;
    using size_type = size_t;
    using const_reference = value_type;
    using pointer = value_type*;
    using const_pointer = const value_type*;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    bitfield() = default;

    explicit bitfield(size_type num_bits, value_type initial_val = false)
        : m_blocks(num_blocks_for(num_bits), initial_val ? ~block_type(0) : 0)
        , m_num_bits(num_bits)
    {
        clear_unused_bits();
    }

    /**
     * Creates a bitfield from some contiguous array of bytes. The length of the byte
     * sequence must be equal to the blocks needed to store num_bits. If this condition
     * is not met, an invalid_argument exception is thrown. This way it is easy to verify
     * whether peer has sent us a valid bitfield.
     */
    template<
        typename Bytes,
        typename = decltype(std::declval<Bytes>().begin())
    > explicit bitfield(const Bytes& bytes, size_type num_bits)
        : m_blocks(bytes.begin(), bytes.end())
        , m_num_bits(num_bits)
    {
        if(!is_bitfield_data_valid(bytes, num_bits))
        {
            throw std::invalid_argument(
                "byte sequence does not match the requested number of bits in bitfield"
            );
        }
        clear_unused_bits();
    }

    friend void swap(bitfield& a , bitfield& b);

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
        const block_type last_block_mask = ~block_type(0) << num_excess_bits(bytes, num_bits);
        return (bytes.back() & last_block_mask) == bytes.back();
        // or, shift last block right (TODO test which is more optimal)
        // return (block_type(bytes.back()) << (bits_per_block - num_excess_bits(bytes, num_bits))) == 0;
    }

    /** Returns the underlying byte sequence. */
    const std::vector<block_type>& data() const noexcept
    {
        return m_blocks;
    }

    /**
     * Returns the same number of bits that was supplied in the ctor (and not
     * data().size(), which returns the number of bytes necessary to represent the
     * bitfield).
     */
    size_type size() const noexcept
    {
        return m_num_bits;
    }

    bitfield& set(const int bit) noexcept
    {
        get_block(bit) |= make_bit_mask(bit);
        return *this;
    }

    bitfield& set() noexcept
    {
        std::fill(m_blocks.begin(), m_blocks.end(), ~block_type(0));
        clear_unused_bits();
        return *this;
    }

    bitfield& reset(const int bit) noexcept
    {
        get_block(bit) &= ~make_bit_mask(bit);
        return *this;
    }

    bitfield& reset() noexcept
    {
        std::fill(m_blocks.begin(), m_blocks.end(), block_type(0));
        return *this;
    }

    bitfield& flip(const int bit) noexcept
    {
        get_block(bit) ^= make_bit_mask(bit);
        return *this;
    }

    bitfield& flip() noexcept
    {
        for(auto& block : m_blocks)
        {
            block = ~block;
        }
        clear_unused_bits();
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

    reference operator[](const int bit) noexcept
    {
        return reference(get_block(bit), make_bit_mask(bit));
    }

    const_reference operator[](const int bit) const noexcept
    {
        return (get_block(bit) & make_bit_mask(bit)) != 0;
    }

    reference at(const int bit)
    {
        if((bit < 0) || (bit >= m_num_bits))
        {
            throw std::out_of_range("bitfield element ouf of range");
        }
        return operator[](bit);
    }

    const_reference at(const int bit) const
    {
        if((bit < 0) || (bit >= m_num_bits))
        {
            throw std::out_of_range("bitfield element ouf of range");
        }
        return operator[](bit);
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

    bitfield operator-() const
    {
        bitfield b(*this);
        b.flip();
        return b;
    }

    bitfield& operator&=(const bitfield& other)
    {
        const size_type end = std::min(m_blocks.size(), other.m_blocks.size());
        for(size_type i = 0; i < end; ++i)
        {
            m_blocks[i] &= other.m_blocks[i];
        }
        return *this;
    }

    bitfield& operator|=(const bitfield& other)
    {
        const size_type end = std::min(m_blocks.size(), other.m_blocks.size());
        for(size_type i = 0; i < end; ++i)
        {
            m_blocks[i] |= other.m_blocks[i];
        }
        return *this;
    }

    bitfield& operator^=(const bitfield& other)
    {
        const size_type end = std::min(m_blocks.size(), other.m_blocks.size());
        for(size_type i = 0; i < end; ++i)
        {
            m_blocks[i] ^= other.m_blocks[i];
        }
        return *this;
    }

    bitfield& operator-=(const bitfield& other)
    {
        const size_type end = std::min(m_blocks.size(), other.m_blocks.size());
        for(size_type i = 0; i < end; ++i)
        {
            m_blocks[i] = ~other.m_blocks[i];
        }
        return *this;
    }

    // TODO
    bitfield operator<<(size_type n) const;
    bitfield operator>>(size_type n) const;
    bitfield& operator<<=(size_type n);
    bitfield& operator>>=(size_type n);

    friend inline bitfield operator&(const bitfield& a, const bitfield& b)
    {
        bitfield tmp(a);
        return tmp &= b;
    }

    friend inline bitfield operator|(const bitfield& a, const bitfield& b)
    {
        bitfield tmp(a);
        return tmp |= b;
    }

    friend inline bitfield operator^(const bitfield& a, const bitfield& b)
    {
        bitfield tmp(a);
        return tmp ^= b;
    }

    friend inline bitfield operator-(const bitfield& a, const bitfield& b)
    {
        bitfield tmp(a);
        return tmp -= b;
    }

    // Relational operators

    friend bool operator==(const bitfield& a, const bitfield& b) noexcept
    {
        return (a.m_num_bits == b.m_num_bits) && (a.m_blocks == b.m_blocks);
    }

    friend bool operator!=(const bitfield& a, const bitfield& b) noexcept
    {
        return !(a == b);
    }

private:

    static constexpr int num_blocks_for(const size_type num_bits) noexcept
    {
        return std::ceil(double(num_bits) / bits_per_block());
    }

    block_type& get_block(const int bit) noexcept
    {
        return m_blocks[block_index(bit)];
    }

    const block_type& get_block(const int bit) const noexcept
    {
        assert(bit < size());
        return m_blocks[block_index(bit)];
    }

    static constexpr int block_index(const int bit) noexcept
    {
        return bit / bits_per_block();
    }

    static constexpr block_type make_bit_mask(const int bit) noexcept
    {
        // note that because of BitTorrent the least significant bit is on the left side
        // rather than on the right (as is the case with traditional bit layouts), so
        // shifting is a bit more involved
        const auto shift = bits_per_block() - bit_index(bit) - 1;
        return 1 << shift;
    }

    static constexpr size_type bit_index(const int bit) noexcept
    {
        return bit % bits_per_block();
    }

    void clear_unused_bits() noexcept
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

public:

    class reference
    {
        friend class bitfield;

        block_type& m_block;
        const int m_mask;

        reference(block_type& block, int mask)
            : m_block(block)
            , m_mask(mask)
        {}

    public:

        reference& flip() noexcept
        {
            m_block ^= m_mask;
            return *this;
        }

        operator bool() const noexcept
        {
            return (m_block & m_mask) != 0;
        }

        reference& operator=(bool x) noexcept
        {
            if(x)
                m_block |= m_mask;
            else
                m_block &= ~m_mask;
            return *this;
        }

        reference& operator=(const reference& other) noexcept
        {
            return operator=(static_cast<bool>(other));
        }

        reference& operator|=(bool x) noexcept
        {
            if(x)
            {
                m_block |= m_mask;
            }
            return *this;
        }

        reference& operator&=(bool x) noexcept
        {
            if(x)
            {
                m_block &= m_mask;
            }
            return *this;
        }

        reference& operator^=(bool x) noexcept
        {
            if(x)
            {
                m_block ^= m_mask;
            }
            return *this;
        }

        reference& operator-=(bool x) noexcept
        {
            if(x)
            {
                m_block &= ~m_mask;
            }
            return *this;
        }

        friend bool operator==(const reference& a, const reference& b) noexcept
        {
            return &a.m_block == &b.m_block;
        }

        friend bool operator!=(const reference& a, const reference& b) noexcept
        {
            return !(a == b);
        }
    };

    class const_iterator
    {
        const bitfield* m_bitfield;
        size_type m_bit;

    public:

        using iterator_category = std::random_access_iterator_tag;

        const_iterator(const bitfield& bitfield, size_type bit = 0)
            : m_bitfield(&bitfield)
            , m_bit(bit)
        {}

        const_reference operator*()
        {
            return (*m_bitfield)[m_bit];
        }

        const_iterator& operator++()
        {
            ++m_bit;
            return *this;
        }

        const_iterator operator++(int)
        {
            auto tmp(*this);
            ++m_bit;
            return tmp;
        }

        const_iterator& operator--()
        {
            --m_bit;
            return *this;
        }

        const_iterator operator--(int)
        {
            auto tmp(*this);
            --m_bit;
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
            m_bit += n;
            return *this;
        }

        const_iterator& operator-=(const size_type n)
        {
            m_bit -= n;
            return *this;
        }

        difference_type operator-(const_iterator other) noexcept
        {
            return m_bit - other.m_bit;
        }

        friend bool operator==(const const_iterator& a, const const_iterator& b) noexcept
        {
            return (a.m_bitfield == b.m_bitfield) && (a.m_bit == b.m_bit);
        }

        friend bool operator!=(const const_iterator& a, const const_iterator& b) noexcept
        {
            return !(a == b);
        }
    };
};

inline void swap(bitfield& a , bitfield& b)
{
    using std::swap;
    swap(a.m_blocks, b.m_blocks);
    swap(a.m_num_bits, b.m_num_bits);
}

} // namespace tide

#endif // TIDE_BITFIELD_HEADER