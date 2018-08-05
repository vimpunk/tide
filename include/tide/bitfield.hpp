#ifndef TIDE_BITFIELD_HEADER
#define TIDE_BITFIELD_HEADER

#include <cassert>
#include <cmath>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

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
struct bitfield
{
    class reference;
    class const_iterator;

    using value_type = bool;
    using difference_type = std::ptrdiff_t;
    using size_type = size_t;
    using const_reference = value_type;
    using pointer = value_type*;
    using const_pointer = const value_type*;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;
    using block_type = uint8_t;

private:
    std::vector<block_type> blocks_;
    size_type num_bits_;

public:
    bitfield() = default;

    explicit bitfield(size_type num_bits, value_type initial_val = false)
        : blocks_(num_blocks_for(num_bits), initial_val ? ~block_type(0) : 0)
        , num_bits_(num_bits)
    {
        clear_unused_bits();
    }

    /**
     * Creates a bitfield from some contiguous array of bytes. The length of the byte
     * sequence must be equal to the blocks needed to store num_bits. If this condition
     * is not met, an invalid_argument exception is thrown. This way it is easy to verify
     * whether peer has sent us a valid bitfield.
     */
    template <typename Bytes, typename = decltype(std::declval<Bytes>().begin())>
    explicit bitfield(const Bytes& bytes, size_type num_bits)
        : blocks_(bytes.begin(), bytes.end()), num_bits_(num_bits)
    {
        if(!is_raw_bitfield_valid(bytes, num_bits)) {
            throw std::invalid_argument("byte sequence does not match the requested "
                                        "number of bits in bitfield");
        }
        clear_unused_bits();
    }

    friend void swap(bitfield& a, bitfield& b);

    /**
     * Verifies whether the raw byte sequence is a valid bitfield. This should be used to
     * verify that the bitfield sent by peer (which is a sequence of bytes) is valid.
     * To pass the test, the length of the sequence must be equal to the blocks necessary
     * to store num_bits, and the excess bits, if any, must be zero.
     */
    template <typename Bytes, typename = decltype(std::declval<Bytes>().data())>
    static bool is_raw_bitfield_valid(const Bytes& bytes, size_type num_bits) noexcept
    {
        if(num_blocks_for(num_bits) != size_type(bytes.size())) {
            return false;
        }
        // need to check the last block separately because of the zeroed out excess bits
        const block_type last_block_mask = ~block_type(0)
                << num_excess_bits(bytes, num_bits);
        return (bytes.back() & last_block_mask) == bytes.back();
        // or, shift last block right (TODO test which is more optimal)
        // return (block_type(bytes.back()) << (bits_per_block - num_excess_bits(bytes,
        // num_bits))) == 0;
    }

    /** Returns the underlying byte sequence. */
    const std::vector<block_type>& data() const noexcept { return blocks_; }

    /**
     * Returns the same number of bits that was supplied in the ctor (and not
     * data().size(), which returns the number of bytes necessary to represent the
     * bitfield).
     */
    size_type size() const noexcept { return num_bits_; }

    bitfield& set(const size_type bit) noexcept
    {
        get_block(bit) |= make_bit_mask(bit);
        return *this;
    }

    bitfield& set(const std::initializer_list<size_type> bits) noexcept
    {
        for(const auto b : bits) {
            set(b);
        }
        return *this;
    }

    bitfield& fill() noexcept
    {
        std::fill(blocks_.begin(), blocks_.end(), ~block_type(0));
        clear_unused_bits();
        return *this;
    }

    bitfield& reset(const size_type bit) noexcept
    {
        get_block(bit) &= ~make_bit_mask(bit);
        return *this;
    }

    bitfield& reset(const std::initializer_list<size_type> bits) noexcept
    {
        for(const auto b : bits) {
            reset(b);
        }
        return *this;
    }

    bitfield& clear() noexcept
    {
        std::fill(blocks_.begin(), blocks_.end(), block_type(0));
        return *this;
    }

    bitfield& flip(const size_type bit) noexcept
    {
        get_block(bit) ^= make_bit_mask(bit);
        return *this;
    }

    bitfield& flip_all() noexcept
    {
        for(auto& block : blocks_) {
            block = ~block;
        }
        clear_unused_bits();
        return *this;
    }

    bool are_all_set() const noexcept
    {
        static constexpr auto all_set = std::numeric_limits<block_type>::max();
        const size_type last_block = blocks_.size() - 1;
        for(size_type i = 0; i < last_block; ++i) {
            if(blocks_[i] != all_set) {
                return false;
            }
        }
        // need to check the last block separately because of the zerod out excess bits
        const block_type last_block_mask = ~block_type(0) << num_excess_bits();
        return blocks_[last_block] == last_block_mask;
    }

    bool are_any_set() const noexcept { return !are_none_set(); }

    bool are_none_set() const noexcept
    {
        for(const auto& block : blocks_) {
            if(block != 0) {
                return false;
            }
        }
        return true;
    }

    reference operator[](const size_type bit) noexcept
    {
        return reference(get_block(bit), make_bit_mask(bit));
    }

    const_reference operator[](const size_type bit) const noexcept
    {
        return (get_block(bit) & make_bit_mask(bit)) != 0;
    }

    reference at(const size_type bit)
    {
        if((bit < 0) || (bit >= num_bits_)) {
            throw std::out_of_range("bitfield element ouf of range");
        }
        return operator[](bit);
    }

    const_reference at(const size_type bit) const
    {
        if((bit < 0) || (bit >= num_bits_)) {
            throw std::out_of_range("bitfield element ouf of range");
        }
        return operator[](bit);
    }

    const_iterator begin() const noexcept { return const_iterator(*this); }
    const_iterator cbegin() const noexcept { return const_iterator(*this); }
    const_iterator end() const noexcept { return const_iterator(*this, num_bits_); }
    const_iterator cend() const noexcept { return const_iterator(*this, num_bits_); }

    /** Returns the Hamming weight of this bitfield. */
    size_type count() const
    {
        size_type n = 0;
        for(size_type i = 0; i < size(); ++i) {
            if((*this)[i]) {
                ++n;
            }
        }
        return n;
    }

    std::string to_string() const
    {
        std::string s(size(), '0');
        for(size_type i = 0; i < size(); ++i) {
            if((*this)[i]) {
                s[i] = '1';
            }
        }
        return s;
    }

    bitfield operator-() const
    {
        bitfield b(*this);
        b.flip_all();
        return b;
    }

    bitfield& operator&=(const bitfield& other)
    {
        const size_type end = std::min(blocks_.size(), other.blocks_.size());
        for(size_type i = 0; i < end; ++i) {
            blocks_[i] &= other.blocks_[i];
        }
        return *this;
    }

    bitfield& operator|=(const bitfield& other)
    {
        const size_type end = std::min(blocks_.size(), other.blocks_.size());
        for(size_type i = 0; i < end; ++i) {
            blocks_[i] |= other.blocks_[i];
        }
        return *this;
    }

    bitfield& operator^=(const bitfield& other)
    {
        const size_type end = std::min(blocks_.size(), other.blocks_.size());
        for(size_type i = 0; i < end; ++i) {
            blocks_[i] ^= other.blocks_[i];
        }
        return *this;
    }

    bitfield& operator-=(const bitfield& other)
    {
        const size_type end = std::min(blocks_.size(), other.blocks_.size());
        for(size_type i = 0; i < end; ++i) {
            blocks_[i] = ~other.blocks_[i];
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
        return (a.num_bits_ == b.num_bits_) && (a.blocks_ == b.blocks_);
    }

    friend bool operator!=(const bitfield& a, const bitfield& b) noexcept
    {
        return !(a == b);
    }

private:
    static constexpr size_type num_blocks_for(const size_type num_bits) noexcept
    {
        return std::ceil(double(num_bits) / bits_per_block());
    }

    block_type& get_block(const size_type bit) noexcept
    {
        return blocks_[block_index(bit)];
    }

    const block_type& get_block(const size_type bit) const noexcept
    {
        assert(bit < size());
        return blocks_[block_index(bit)];
    }

    static constexpr size_type block_index(const size_type bit) noexcept
    {
        return bit / bits_per_block();
    }

    static constexpr block_type make_bit_mask(const size_type bit) noexcept
    {
        // note that because of BitTorrent the least significant bit is on the left side
        // rather than on the right (as is the case with traditional bit layouts), so
        // shifting is a bit more involved
        const auto shift = bits_per_block() - bit_index(bit) - 1;
        return 1 << shift;
    }

    static constexpr size_type bit_index(const size_type bit) noexcept
    {
        return bit % bits_per_block();
    }

    void clear_unused_bits() noexcept
    {
        const auto num_excess = num_excess_bits();
        if(num_excess > 0) {
            blocks_.back() &= ~block_type(0) << num_excess;
        }
    }

    block_type num_excess_bits() const noexcept
    {
        return num_excess_bits(blocks_, num_bits_);
    }

    template <typename Bytes, typename = decltype(std::declval<Bytes>().data())>
    static block_type num_excess_bits(
            const Bytes& bytes, const size_type num_bits) noexcept
    {
        return bits_per_block() * bytes.size() - num_bits;
    }

    static constexpr block_type bits_per_block() noexcept
    {
        // TODO check if this is sufficient (can't think of a popular architecture
        // that doesn't use 8-bit bytes), if not, use:
        // return std::numeric_limits<block_type>::digits;
        return sizeof(block_type) * 8;
    }

public:
    class reference
    {
        friend class bitfield;

        block_type& block_;
        const size_type mask_;

        reference(block_type& block, size_type mask) : block_(block), mask_(mask) {}

    public:
        reference& flip() noexcept
        {
            block_ ^= mask_;
            return *this;
        }

        operator bool() const noexcept { return (block_ & mask_) != 0; }

        reference& operator=(bool x) noexcept
        {
            if(x)
                block_ |= mask_;
            else
                block_ &= ~mask_;
            return *this;
        }

        reference& operator=(const reference& other) noexcept
        {
            return operator=(static_cast<bool>(other));
        }

        reference& operator|=(bool x) noexcept
        {
            if(x)
                block_ |= mask_;
            return *this;
        }

        reference& operator&=(bool x) noexcept
        {
            if(x)
                block_ &= mask_;
            return *this;
        }

        reference& operator^=(bool x) noexcept
        {
            if(x)
                block_ ^= mask_;
            return *this;
        }

        reference& operator-=(bool x) noexcept
        {
            if(x)
                block_ &= ~mask_;
            return *this;
        }

        friend bool operator==(const reference& a, const reference& b) noexcept
        {
            return &a.block_ == &b.block_;
        }

        friend bool operator!=(const reference& a, const reference& b) noexcept
        {
            return !(a == b);
        }
    };

    class const_iterator
    {
        const bitfield* bitfield_;
        size_type bit_;

    public:
        using iterator_category = std::random_access_iterator_tag;

        const_iterator(const bitfield& bitfield, size_type bit = 0)
            : bitfield_(&bitfield), bit_(bit)
        {}

        const_reference operator*() { return (*bitfield_)[bit_]; }

        const_iterator& operator++()
        {
            ++bit_;
            return *this;
        }

        const_iterator operator++(int)
        {
            auto tmp(*this);
            ++bit_;
            return tmp;
        }

        const_iterator& operator--()
        {
            --bit_;
            return *this;
        }

        const_iterator operator--(int)
        {
            auto tmp(*this);
            --bit_;
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
            bit_ += n;
            return *this;
        }

        const_iterator& operator-=(const size_type n)
        {
            bit_ -= n;
            return *this;
        }

        difference_type operator-(const_iterator other) noexcept
        {
            return bit_ - other.bit_;
        }

        friend bool operator==(const const_iterator& a, const const_iterator& b) noexcept
        {
            return (a.bitfield_ == b.bitfield_) && (a.bit_ == b.bit_);
        }

        friend bool operator!=(const const_iterator& a, const const_iterator& b) noexcept
        {
            return !(a == b);
        }
    };
};

inline void swap(bitfield& a, bitfield& b)
{
    using std::swap;
    swap(a.blocks_, b.blocks_);
    swap(a.num_bits_, b.num_bits_);
}

} // namespace tide

#endif // TIDE_BITFIELD_HEADER
