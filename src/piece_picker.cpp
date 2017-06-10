#include "piece_picker.hpp"
#include "random.hpp"

#include <sstream>
#include <cassert>
#include <cmath>
#include <list>
#include <set>

namespace tide {

/**
 * Wrapper for keeping track of the number of pieces in a torrent swarm.
 * O(1) access by piece index and iteration by piece priority and frequency order.
 * Keeps track of all pieces regardless of availability, that is, memory usage is O(2n)
 * where n is the number of pieces.
 *
 * NOTE: since this is not exposed to the public, validating the index should be done in
 * higher level modules.
 */
class piece_picker::piece_tracker
{
public:

    struct block_info
    {
        const piece_index_t index;
        const int frequency = 0;
        mutable bool is_reserved = false;

        block_info(const piece_index_t i, const int f) : index(i), frequency(f) {}

        friend bool operator==(const block_info& a, const block_info& b)
        {
            return a.frequency == b.frequency;
        }

        friend bool operator<(const block_info& a, const block_info& b)
        {
            return a.frequency < b.frequency;
        }
    };

private:

    /**
     * Holds a group of piece indices, sorted by their frequency. This is to group
     * top priority, priority and normal pieces together.
     * A group is complete when all of its pieces are available (i.e. frequency > 0),
     * which are favored over incomplete groups, except when the group is top priority,
     * in which case it is always favored.
     * A new complete priority group is placed after the last complete priority group,
     * a new incomplete group is placed after the last incomplete group.
     * The default group is always the last one, and pieces are inserted there by
     * default.
     * This is used to prioritize selected files.
     * Pieces in a group MUST form a continous interval, that is, they must not be
     * scattered.
     */
    struct group
    {
        using piece_iterator = std::multiset<block_info>::iterator;
        using const_piece_iterator = std::multiset<block_info>::const_iterator;
        using difference_type = std::multiset<block_info>::difference_type;

        enum class type_t
        {
            normal,
            priority,
            top_priority
        };

    private:

        const type_t m_type;
        std::multiset<block_info> m_pieces;

    public:

        group(type_t type) : m_type(type) {}

        bool is_empty() const noexcept
        {
            return m_pieces.empty();
        }

        bool is_complete() const noexcept
        {
            // since pieces are ordered by their frequency, the group can only be fully
            // available if the first piece's frequency is not zero.
            return !is_empty() && (m_pieces.cbegin()->frequency > 0);
        }

        type_t type() const noexcept
        {
            return m_type;
        }

        piece_iterator begin() noexcept
        {
            return m_pieces.begin();
        }

        const_piece_iterator begin() const noexcept
        {
            return m_pieces.cbegin();
        }

        const_piece_iterator cbegin() const noexcept
        {
            return m_pieces.cbegin();
        }

        piece_iterator end() noexcept
        {
            return m_pieces.end();
        }

        const_piece_iterator end() const noexcept
        {
            return m_pieces.cend();
        }

        const_piece_iterator cend() const noexcept
        {
            return m_pieces.cend();
        }

        template<typename... Args>
        piece_iterator emplace(Args&&... args)
        {
            return m_pieces.emplace(std::forward<Args>(args)...);
        }

        void erase(const_piece_iterator it)
        {
            m_pieces.erase(it);
        }

        piece_iterator transfer_from(group& other, const_piece_iterator it)
        {
            block_info tmp(it->index, it->frequency);
            other.erase(it);
            return emplace(std::move(tmp));
        }

        piece_iterator increase_frequency(const_piece_iterator it)
        {
            block_info tmp(it->index, it->frequency + 1);
            erase(it);
            return emplace(std::move(tmp));
        }

        piece_iterator decrease_frequency(const_piece_iterator it)
        {
            block_info tmp(it->index, it->frequency - 1);
            erase(it);
            return emplace(std::move(tmp));
        }
    };

    using groups = std::list<group>;

    /**
     * Holds the position of a piece index in the database.
     * A piece index's position is determined by the group and the position in that
     * group's frequency ordered collection the piece is in.
     */
    struct piece_entry
    {
        groups::iterator group;
        group::piece_iterator piece;

        piece_entry() = default;
        piece_entry(groups::iterator g, group::piece_iterator p)
            : group(g)
            , piece(p)
        {}
        piece_entry(groups::iterator g, const piece_index_t piece, const int frequency)
            : group(g)
            , piece(g->emplace(piece, frequency))
        {}

        bool is_owner_group_complete() const noexcept
        {
            return group->is_complete();
        }

        bool is_priority() const noexcept
        {
            return group->type() != group::type_t::normal;
        }

        int frequency() const noexcept
        {
            return piece->frequency;
        }

        void increase_frequency()
        {
            piece = group->increase_frequency(piece);
        }

        void decrease_frequency()
        {
            piece = group->decrease_frequency(piece);
        }
    };

    // For O(1) access by piece index.
    std::vector<piece_entry> m_piece_map;
    // For iteration by priority (high -> low) and frequency (low -> high) order.
    groups m_groups;
    // This is the group into which all pieces are placed be default, and will persist
    // throughout the lifetime of the tracker, while priority groups last only as long
    // as there are piece indices in them.
    groups::iterator m_default_group;

public:

    class iterator;
    class const_iterator;

    using value_type = block_info;
    using reference = value_type&;
    using const_reference = const value_type&;
    using pointer = value_type*;
    using const_pointer = const value_type*;
    using size_type = size_t;
    using iterator = iterator;
    using const_iterator = const_iterator;

public:

    explicit piece_tracker(const int num_pieces)
    {
        m_groups.emplace_back(group::type_t::normal);
        m_default_group = --m_groups.end();
        m_piece_map.reserve(num_pieces);

        for(piece_index_t piece = 0; piece < num_pieces; ++piece)
        {
            m_piece_map.emplace_back(m_default_group, piece, 0);
        }
    }

    std::vector<int> piece_availability() const
    {
        std::vector<int> frequency_map(m_piece_map.size());
        piece_availability(frequency_map);
        return frequency_map;
    }

    void piece_availability(std::vector<int>& frequency_map) const
    {
        const int end = std::min(m_piece_map.size(), frequency_map.size());
        for(piece_index_t piece = 0; piece < end; ++piece)
        {
            frequency_map[piece] = m_piece_map[piece].frequency();
        }
    }

    void increase_frequency(const piece_index_t piece)
    {
        auto& entry = m_piece_map[piece];
        const bool was_group_complete = entry.is_owner_group_complete();
        entry.increase_frequency();
        // if the frequency increase has completed the group in which the piece
        // resides, and if it's a priority group, try to shift it ahead of potential
        // incomplete groups
        if(!was_group_complete && entry.is_priority() && entry.is_owner_group_complete())
        {
            restore_group_order();
        }
    }

    void decrease_frequency(const piece_index_t piece)
    {
        auto& entry = m_piece_map[piece];
        entry.decrease_frequency();
        // if the frequency decrease has left the group in which the piece resides
        // incomplete, and if it's a priority group, shift it behind priority groups
        if(entry.frequency() <= 0 && entry.is_priority())
        {
            restore_group_order();
        }
    }

    void make_top_priority(interval interval)
    {
        auto priority_group = m_groups.emplace(
            m_groups.cbegin(), group::type_t::top_priority
        );
        adjust_interval(interval);
        make_priority(interval, priority_group);
        if(priority_group->is_empty())
        {
            m_groups.erase(priority_group);
        }
    }

    void make_priority(interval interval)
    {
        auto priority_group = m_groups.emplace(m_default_group, group::type_t::priority);
        adjust_interval(interval);
        make_priority(interval, priority_group);
        if(priority_group->is_empty())
        {
            m_groups.erase(priority_group);
        }
        else if(priority_group->is_complete())
        {
            restore_group_order();
        }
    }

    void clear_priority(interval interval)
    {
        adjust_interval(interval);
        for(auto piece = interval.begin; piece != interval.end; ++piece)
        {
            auto& entry = m_piece_map[piece];
            if(entry.is_priority())
            {
                transfer_to_group(entry, m_default_group);
            }
        }
    }

    void reserve(iterator it)
    {
        reserve(*it);
    }

    void reserve(const piece_index_t piece)
    {
        reserve(const_cast<reference>(*m_piece_map[piece].piece));
    }

    void reserve(block_info& piece) noexcept
    {
        piece.is_reserved = true;
    }

    void unreserve(iterator it)
    {
        unreserve(*it);
    }

    void unreserve(const piece_index_t piece)
    {
        unreserve(const_cast<reference>(*m_piece_map[piece].piece));
    }

    void unreserve(block_info& piece) noexcept
    {
        piece.is_reserved = false;
    }

    iterator begin() noexcept
    {
        return iterator(m_groups.begin(), m_groups.end());
    }

    const_iterator begin() const noexcept
    {
        return const_iterator(m_groups.begin(), m_groups.end());
    }

    const_iterator cbegin() const noexcept
    {
        return begin();
    }

    iterator end() noexcept
    {
        return iterator(m_groups.end());
    }

    const_iterator end() const noexcept
    {
        return const_iterator(m_groups.end());
    }

    const_iterator cend() const noexcept
    {
        return end();
    }

    const_reference operator[](const piece_index_t index) const noexcept
    {
        return *m_piece_map[index].piece;
    }

    std::string debug_str() const
    {
        std::ostringstream ss;
        int n = 0;
        for(const auto& group : m_groups)
        {
            ss << "group#" << ++n << " ("
              << (group.type() == group::type_t::normal
                    ? "default"
                    : (group.type() == group::type_t::priority
                        ? "priority"
                        : "top priority"))
              << "): [";
            for(const auto& piece : group)
            {
                ss << " {" << piece.index << ":" << piece.frequency << '}';
            }
            ss << " ]\n";
        }
    }

private:

    void make_priority(const interval& interval, groups::iterator priority_group)
    {
        for(auto piece = interval.begin; piece < interval.end; ++piece)
        {
            transfer_to_group(m_piece_map[piece], priority_group);
        }
    }

    void transfer_to_group(piece_entry& entry, groups::iterator dst_group)
    {
        auto src_group = entry.group;
        entry.piece = dst_group->transfer_from(*src_group, entry.piece);
        entry.group = dst_group;
        // if group became empty after this transfer, and if it's a priority group,
        // erase the group as well
        if(should_delete_group(src_group))
        {
            m_groups.erase(src_group);
        }
    }

    bool should_delete_group(groups::iterator group) const noexcept
    {
        return group->is_empty() && (group->type() != group::type_t::normal);
    }

    // groups represent the group of pieces that constitute a file. But since files are
    // most likely not aligned with the piece demarcations, a piece on each end of the
    // file will most likely also have portions of it belonging to another file.
    // Therefore, ef such is the case, we need t remove the overlapping pieces from the
    // [begin, end) interval so as not to clear the priority from a piece that belongs
    // to another group as well (as in, if there are two groups marked priority with
    // shared pieces, and when one is removed, the shared piece must remain a priority
    // so as to keep the other group fully a priority). */
    void adjust_interval(interval& interval) const
    {
        if(interval.length() < 2)
        {
            return;
        }

        auto& begin_entry = m_piece_map[interval.begin];
        auto& next_entry  = m_piece_map[interval.begin + 1];

        if(!are_in_same_group(begin_entry, next_entry))
        {
            ++interval.begin;
        }
        // due to the exclusive nature of the interval, 'end' denotes one past the last
        // valid piece, so we need the last valid piece, then, we need another index that
        // points to the piece before 'last'
        //
        // |x|x|x|x|x|x|x|o|
        //              | | ^- end
        //              | last
        //              prev
        //
        // we need to check whether 'last' and 'prev' are in different groups, because
        // if they are, the end of the interval is overlapping with another group
        auto& last_entry = m_piece_map[interval.end - 1];
        auto& prev_entry = m_piece_map[interval.end - 2];

        if(!are_in_same_group(last_entry, prev_entry))
        {
            --interval.end;
        }
    }

    static bool are_in_same_group(const piece_entry& a, const piece_entry& b) noexcept
    {
        return &*a.group == &*b.group;
    }

    // NOTE: always O(n).
    // TODO a version which only restores the invalidation of a single group
    void restore_group_order()
    {
        if(m_groups.size() <= 1)
        {
            return;
        }

        auto last_incomplete = m_default_group;
        auto it = last_incomplete;
        const auto first = m_groups.begin();

        --it;

        while(it != first)
        {
            auto tmp = it--;
            if(should_reorder(tmp))
            {
                last_incomplete = splice(last_incomplete, tmp);
            }
        }

        if(should_reorder(it))
        {
            splice(last_incomplete, it);
        }
    }

    static bool should_reorder(const groups::const_iterator it)
    {
        return !it->is_complete() && (it->type() == group::type_t::priority);
    }

    groups::iterator splice(groups::iterator dest, groups::iterator it)
    {
        m_groups.splice(dest, m_groups, it);
        return it;
    }

public:

    // Both iterators go through the pieces in order of priority (highest to lowest) and
    // frequency (lowest to highest).

    class iterator
    {
        groups::iterator m_group;
        groups::iterator m_groups_end;
        group::piece_iterator m_piece;

    public:

        using difference_type = std::ptrdiff_t;
        using iterator_category = std::bidirectional_iterator_tag;
        using value_type = piece_tracker::value_type;
        using reference = piece_tracker::reference;
        using pointer = piece_tracker::pointer;

        iterator(groups::iterator group, groups::iterator groups_end)
            : m_group(group)
            , m_groups_end(groups_end)
        {
            if(m_group != m_groups_end) { m_piece = m_group->begin(); }
        }

        iterator(groups::iterator groups_end)
            : m_group(groups_end)
            , m_groups_end(groups_end)
        {}

        reference operator*() noexcept
        {
            // Pieces are stored in a set whose elements are const by default. But since
            // we cannot modify data essential to the ordering of the set (frequency),
            // it is OK to remove the const qualifier, as is_reserved field in
            // block_info is mutable.
            return const_cast<reference>(*m_piece);
        }

        pointer operator->() noexcept
        {
            return const_cast<pointer>(&*m_piece);
        }

        iterator& operator++()
        {
            if((m_piece == m_group->end()) || (++m_piece == m_group->end()))
            {
                if(++m_group != m_groups_end)
                {
                    m_piece = m_group->begin();
                }
            }
            return *this;
        }

        iterator operator++(int)
        {
            auto tmp = *this;
            ++(*this);
            return tmp;
        }

        iterator& operator--()
        {
            if((m_group == m_groups_end) || (m_piece == m_group->begin()))
            {
                m_piece = (--m_group)->end();
            }
            --m_piece;
            return *this;
        }

        iterator operator--(int)
        {
            auto tmp = *this;
            --(*this);
            return tmp;
        }

        bool operator==(const iterator& b) const noexcept
        {
            if(is_at_end() && b.is_at_end()) { return true; }
            return (m_group == b.m_group) && (m_piece == b.m_piece);
        }

        bool operator!=(const iterator& b) const noexcept
        {
            return !(*this == b);
        }

    private:

        bool is_at_end() const noexcept
        {
            return m_group == m_groups_end;
        }
    };

    class const_iterator
    {
        groups::const_iterator m_group;
        groups::const_iterator m_groups_end;
        group::const_piece_iterator m_piece;

    public:

        using difference_type = std::ptrdiff_t;
        using iterator_category = std::bidirectional_iterator_tag;
        using value_type = piece_tracker::value_type;
        using reference = piece_tracker::const_reference;
        using pointer = piece_tracker::const_pointer;

        const_iterator(groups::const_iterator group, groups::const_iterator groups_end)
            : m_group(group)
            , m_groups_end(groups_end)
        {
            if(m_group != m_groups_end) { m_piece = m_group->cbegin(); }
        }

        const_iterator(groups::const_iterator groups_end)
            : m_group(groups_end)
            , m_groups_end(groups_end)
        {}

        reference operator*() const noexcept
        {
            return *m_piece;
        }

        pointer operator->() const noexcept
        {
            return &*m_piece;
        }

        const_iterator& operator++()
        {
            if((m_piece == m_group->cend()) || (++m_piece == m_group->cend()))
            {
                if(++m_group != m_groups_end)
                {
                    m_piece = m_group->cbegin();
                }
            }
            return *this;
        }

        const_iterator operator++(int)
        {
            auto tmp = *this;
            ++(*this);
            return tmp;
        }

        const_iterator& operator--()
        {
            if((m_group == m_groups_end) || (m_piece == m_group->cbegin()))
            {
                m_piece = (--m_group)->cend();
            }
            --m_piece;
            return *this;
        }

        const_iterator operator--(int)
        {
            auto tmp = *this;
            --(*this);
            return tmp;
        }

        bool operator==(const const_iterator& b) const noexcept
        {
            if(is_at_end() && b.is_at_end()) { return true; }
            return (m_group == b.m_group) && (m_piece == b.m_piece);
        }

        bool operator!=(const const_iterator& b) const noexcept
        {
            return !(*this == b);
        }

    private:

        bool is_at_end() const noexcept
        {
            return m_group == m_groups_end;
        }
    };
};

// ------------------
// -- piece picker --
// ------------------

piece_picker::piece_picker(int num_pieces)
    : m_my_bitfield(num_pieces)
    , m_num_pieces_left(num_pieces)
    , m_piece_tracker(new piece_tracker(num_pieces))
{}

piece_picker::piece_picker(bt_bitfield available_pieces)
    : m_my_bitfield(std::move(available_pieces))
    , m_num_pieces_left(m_my_bitfield.size())
    , m_piece_tracker(new piece_tracker(m_my_bitfield.size()))
{}

// DO NOT DELETE THIS.
// (unique_ptr's default deleter employs a static_assert
// to ensure the raw pointer does not point to an incomplete type before
// executing delete. Thus, the compiler generated dtor encounters a
// static_assert and fails, because the default dtor is inline where
// it can't see the implementation of piece_tracker.)
piece_picker::~piece_picker() = default;

std::vector<int> piece_picker::piece_availability() const
{
    return m_piece_tracker->piece_availability();
}

void piece_picker::piece_availability(std::vector<int>& frequency_map) const
{
    m_piece_tracker->piece_availability(frequency_map);
}

int piece_picker::frequency(const piece_index_t piece) const noexcept
{
    return (*m_piece_tracker)[piece].frequency;
}

void piece_picker::increase_frequency(const piece_index_t piece)
{
    m_piece_tracker->increase_frequency(piece);
}

void piece_picker::increase_frequency(const std::vector<piece_index_t>& pieces)
{
    for(const auto piece : pieces) { m_piece_tracker->increase_frequency(piece); }
}

void piece_picker::increase_frequency(const bt_bitfield& available_pieces)
{
    for(piece_index_t piece = 0; piece < num_pieces(); ++piece)
    {
        if(available_pieces[piece])
        {
            increase_frequency(piece);
        }
    }
}

void piece_picker::decrease_frequency(const piece_index_t piece)
{
    m_piece_tracker->decrease_frequency(piece);
}

void piece_picker::decrease_frequency(const bt_bitfield& available_pieces)
{
    assert(available_pieces.size() == num_pieces());
    for(piece_index_t piece = 0; piece < num_pieces(); ++piece)
    {
        if(available_pieces[piece])
        {
            decrease_frequency(piece);
        }
    }
}

// -------------------
// -- piece picking --
// -------------------

piece_index_t piece_picker::pick(const bt_bitfield& available_pieces) const
{
    auto piece_it = m_piece_tracker->cbegin();
    const auto pieces_end = m_piece_tracker->cend();

    while(piece_it != pieces_end)
    {
        if(should_pick(available_pieces, *piece_it))
        {
            break;
        }
        ++piece_it;
    }

    if(piece_it == pieces_end)
    {
        return invalid_piece;
    }

    const int lowest_frequency = piece_it->frequency;
    std::vector<piece_index_t> candidates = { (piece_it++)->index };
    // check if peer has more pieces with the same frequency
    while((piece_it != pieces_end) && (piece_it->frequency == lowest_frequency))
    {
        if(should_pick(available_pieces, *piece_it))
        {
            candidates.emplace_back(piece_it->index);
        }
        ++piece_it;
    }
    return candidates[util::random_int(candidates.size() - 1)];
}

std::vector<piece_index_t> piece_picker::pick(
    const bt_bitfield& available_pieces, const int n) const
{
    std::vector<piece_index_t> indices;
    for(const auto& piece : *m_piece_tracker)
    {
        if(int(indices.size()) == n)
        {
            break;
        }
        if(should_pick(available_pieces, piece))
        {
            indices.emplace_back(piece.index);
        }
    }
    return indices;
}

piece_index_t piece_picker::pick_and_reserve(const bt_bitfield& available_pieces)
{
    const auto selected = pick(available_pieces);
    if(selected != invalid_piece) { m_piece_tracker->reserve(selected); }
    return selected;
}

std::vector<piece_index_t>
piece_picker::pick_and_reserve(const bt_bitfield& available_pieces, const int n)
{
    std::vector<piece_index_t> indices;
    for(auto& piece : *m_piece_tracker)
    {
        if(int(indices.size()) == n)
        {
            break;
        }
        if(should_pick(available_pieces, piece))
        {
            indices.emplace_back(piece.index);
            m_piece_tracker->reserve(piece);
        }
    }
    return indices;
}

piece_index_t piece_picker::pick_ignore_reserved(
    const bt_bitfield& available_pieces) const
{
    auto piece_it = m_piece_tracker->cbegin();
    const auto pieces_end = m_piece_tracker->cend();

    while(piece_it != pieces_end)
    {
        if(should_download_piece(available_pieces, piece_it->index))
        {
            break;
        }
        ++piece_it;
    }

    if(piece_it == pieces_end)
    {
        return invalid_piece;
    }

    const int lowest_frequency = piece_it->frequency;
    std::vector<piece_index_t> candidates = { (piece_it++)->index };
    // check whether peer has more pieces with the same frequency
    while((piece_it != pieces_end) && (piece_it->frequency == lowest_frequency))
    {
        if(should_download_piece(available_pieces, piece_it->index))
        {
            candidates.emplace_back(piece_it->index);
        }
        ++piece_it;
    }
    return candidates[util::random_int(candidates.size() - 1)];
}

std::vector<piece_index_t> piece_picker::pick_ignore_reserved(
    const bt_bitfield& available_pieces, const int n) const
{
    std::vector<piece_index_t> indices;
    for(const auto& piece : *m_piece_tracker)
    {
        if(int(indices.size()) == n)
        {
            break;
        }
        if(should_download_piece(available_pieces, piece.index))
        {
            indices.emplace_back(piece.index);
        }
    }
    return indices;
}

void piece_picker::unreserve(const piece_index_t piece)
{
    m_piece_tracker->unreserve(piece);
}

void piece_picker::got(const piece_index_t piece)
{
    m_my_bitfield.set(piece);
    unreserve(piece);
    --m_num_pieces_left;
    assert(m_num_pieces_left >= 0);
}

void piece_picker::lost(const piece_index_t piece)
{
    m_my_bitfield.reset(piece);
    ++m_num_pieces_left;
}

void piece_picker::lost(const std::vector<piece_index_t>& pieces)
{
    for(const auto piece : pieces)
    {
        m_my_bitfield.reset(piece);
    }
    m_num_pieces_left += pieces.size();
}

void piece_picker::make_top_priority(interval interval)
{
    m_piece_tracker->make_top_priority(interval);
}

void piece_picker::make_priority(interval interval)
{
    m_piece_tracker->make_priority(interval);
}

void piece_picker::clear_priority(interval interval)
{
    m_piece_tracker->clear_priority(interval);
}

bool piece_picker::am_interested_in(const bt_bitfield& available_pieces) const
{
    // cases to consider
    // -----------------
    // 1) we have all the pieces
    // 2) peer has no pieces or only a subset of our pieces
    // 3) peer has pieces that we don't
    //
    // we're interested if the union of peer's and my available_pieces are disparate from
    // my available_pieces, because then peer has pieces we don't
    // TODO optimize this
    return (available_pieces | m_my_bitfield) != m_my_bitfield;
}

std::string piece_picker::debug_str() const
{
    return m_piece_tracker->debug_str();
}

template<typename Piece>
bool piece_picker::should_pick(
    const bt_bitfield& available_pieces, const Piece& piece) const
{
    return !piece.is_reserved && should_download_piece(available_pieces, piece.index);
}

inline bool piece_picker::should_download_piece(
    const bt_bitfield& available_pieces, const piece_index_t piece) const
{
    return !m_my_bitfield[piece] && available_pieces[piece];
}

} // namespace tide
