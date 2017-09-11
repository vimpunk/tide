#include "piece_picker.hpp"
#include "random.hpp"

#include <algorithm>
#include <sstream>
#include <cassert>
#include <cmath>

namespace tide {

piece_picker::piece_picker(const int num_pieces)
    : m_my_pieces(num_pieces)
    , m_pieces(num_pieces)
    , m_piece_pos_map(num_pieces)
{
    for(auto i = 0; i < num_pieces; ++i)
    {
        m_pieces[i].index = i;
        m_piece_pos_map[i] = i;
    }
}

piece_picker::piece_picker(bitfield downloaded_pieces)
    : m_my_pieces(std::move(downloaded_pieces))
    , m_pieces([this] {
            int num_missing = 0;
            for(bool have : m_my_pieces)
            {
                if(!have) { ++num_missing; }
            }
            return num_missing;
        }())
    , m_piece_pos_map(m_my_pieces.size())
{
    for(auto piece = 0, pos = 0; piece < num_pieces(); ++piece)
    {
        if(m_my_pieces[piece])
        {
            // if we have the piece, we don't need it, so don't create an m_pieces entry
            m_piece_pos_map[piece] = invalid_pos;
        }
        else
        {
            m_pieces[pos].index = piece;
            m_piece_pos_map[piece] = pos;
            ++pos;
        }
    }
}

void piece_picker::set_strategy(const enum strategy s) noexcept
{
    switch(s) {
    case strategy::random: break; // don't need to do anything
    case strategy::sequential:
    {
        if(m_strategy != s)
        {
            // we need to rebuild the piece map to be ordered by piece indices
            std::sort(m_pieces.begin(), m_pieces.end(),
                [](const piece& a, const piece& b) { return a.index < b.index; });
            int pos = 0;
            for(const auto& piece : m_pieces)
            {
                m_piece_pos_map[piece.index] = pos;
                ++pos;
            }
        }
        break;
    }
    case strategy::rarest_first:
    {
        // if we're coming from another strategy we'll need to rebuild the frequency map
        if(m_strategy != s) { rebuild_frequency_map(); }
        break;
    }
    default: assert(0);
    }
    m_strategy = s;
}

bool piece_picker::am_interested_in(const bitfield& available_pieces) const noexcept
{
    // we're interested in peer if it has at least one piece that we don't have but want
    assert(available_pieces.size() == m_my_pieces.size());
    for(const auto& piece : m_pieces)
    {
        if(available_pieces[piece.index]) { return true; }
    }
    return false;
}

/*
std::vector<int> piece_picker::piece_availability() const
{
    std::vector<int> frequency_map;
    frequency_map.resize(num_pieces());
    piece_availability(frequency_map);
    return frequency_map;
}

void piece_picker::piece_availability(std::vector<int>& frequency_map) const
{
    if(frequency_map.size() != num_pieces()) { frequency_map.resize(num_pieces()); }
    for(auto i = 0; i < num_pieces(); ++i)
    {
        if(m_piece_pos_map[i] != invalid_pos)
            frequency_map[i] = m_pieces[frequency_map[i]].frequency;
        else
            frequency_map[i] = -1;
    }
}
*/

int piece_picker::frequency(const piece_index_t piece) const noexcept
{
    assert(piece < num_pieces());
    const auto pos = m_piece_pos_map[piece];
    if(pos != invalid_pos) { return m_pieces[pos].frequency; }
    return 0;
}

void piece_picker::increase_frequency(const piece_index_t piece)
{
    assert(piece < num_pieces());
    const auto pos = m_piece_pos_map[piece];
    if(pos != invalid_pos)
    {
        ++m_pieces[pos].frequency;
        m_is_dirty = true;
    }
}

void piece_picker::increase_frequency(const bitfield& available_pieces)
{
    for(piece_index_t piece = 0; piece < num_pieces(); ++piece)
    {
        if(available_pieces[piece]) { increase_frequency(piece); }
    }
}

void piece_picker::decrease_frequency(const piece_index_t piece)
{
    assert(piece < num_pieces());
    const auto pos = m_piece_pos_map[piece];
    if(pos != invalid_pos)
    {
        --m_pieces[pos].frequency;
        m_is_dirty = true;
    }
}

void piece_picker::decrease_frequency(const bitfield& available_pieces)
{
    assert(int(available_pieces.size()) == num_pieces());
    for(piece_index_t piece = 0; piece < num_pieces(); ++piece)
    {
        if(available_pieces[piece]) { decrease_frequency(piece); }
    }
}

piece_index_t piece_picker::pick(const bitfield& available_pieces)
{
    if(num_pieces_left() == 0) { return invalid_piece; }

    if((m_strategy == strategy::rarest_first) && m_is_dirty)
    {
        rebuild_frequency_map();
    }
    else if(m_strategy == strategy::random)
    {
        return m_pieces[util::random_int(0, m_pieces.size() - 1)].index;
    }

    const auto can_pick = [&available_pieces](const auto& piece)
    {
        return !piece.is_reserved && available_pieces[piece.index];
    };

    const auto piece = std::find_if(m_pieces.begin(), m_pieces.end(),
        [&can_pick](const auto& piece) { return can_pick(piece); });

    // TODO the protocol suggests that given several pieces with the same frequency, we
    // should randomize our choice; std::sort (in rebuild_frequency_map) does not guarantee
    // stable sorting, i.e. pieces in a group may get reordered--is this sufficient for
    // the purposes described in the protocol?
    if(piece == m_pieces.end())
    {
        return invalid_piece;
    }
    else
    {
        piece->is_reserved = true;
        return piece->index;
    }
}

inline void piece_picker::rebuild_frequency_map() noexcept
{
    if(m_priority_groups.empty())
    {
        rebuild_group(m_pieces.begin(), m_pieces.end());
    }
    else
    {
        for(const interval& group : m_priority_groups)
        {
            rebuild_group(m_pieces.begin() + group.begin, m_pieces.begin() + group.end);
        }
        const int last_group_end = m_priority_groups.back().end;
        rebuild_group(m_pieces.begin() + last_group_end, m_pieces.end());
    }
    m_is_dirty = false;
}

inline void piece_picker::rebuild_group(std::vector<piece>::iterator begin,
       std::vector<piece>::iterator end) noexcept 
{
    std::sort(begin, end, [](const piece& a, const piece& b)
        { return a.frequency < b.frequency; });
    while(begin != end)
    {
        const int pos = begin - m_pieces.begin();
        assert(pos >= 0);
        assert(pos < int(m_pieces.size()));
        m_piece_pos_map[begin->index] = pos;
        ++begin;
    }
}

void piece_picker::reserve(const piece_index_t piece)
{
    assert(piece < num_pieces());
    const auto pos = m_piece_pos_map[piece];
    if(pos != invalid_pos)
    {
        m_pieces[pos].is_reserved = true;
    }
}

void piece_picker::unreserve(const piece_index_t piece)
{
    assert(piece < num_pieces());
    const auto pos = m_piece_pos_map[piece];
    if(pos != invalid_pos)
    {
        m_pieces[pos].is_reserved = false;
    }
}

void piece_picker::got(const piece_index_t piece)
{
    assert(piece != invalid_piece);
    assert(piece < num_pieces());
    if(m_my_pieces[piece]) { return; }

    m_my_pieces[piece] = true;
    const int pos = m_piece_pos_map[piece];
    assert(pos != invalid_pos);
    assert(pos < int(m_pieces.size()));
    assert(!m_pieces.empty());

    // we no longer need to download this piece
    m_pieces.erase(m_pieces.begin() + pos);
    m_piece_pos_map[piece] = invalid_pos;

    // now we need to go through all piece entries that came after the now removed
    // piece, and decrement their position value in m_piece_pos_map by one to adjust
    // to the new size
    // (note that where piece used to be now the next piece resides, so don't add 1 to
    // begin() + pos to get the next piece!)
    // TODO OPT since we likely pick the rarest pieces most of the time, that is, those
    // that are at the front, it means that we have to iterate a lot here; whereas if
    // rarest pieces started at the back of m_pieces, we'd have to iterate very little
    for(auto it = m_pieces.begin() + pos; it != m_pieces.end(); ++it)
    {
        --m_piece_pos_map[it->index];
        assert(m_piece_pos_map[it->index] >= 0);
        assert(m_piece_pos_map[it->index] < int(m_pieces.size()));
    }

    if(m_priority_groups.empty()) { return; }

    // we need to adjust the group boundaries
    const auto group = std::find_if(m_priority_groups.begin(),
        m_priority_groups.end(), [pos](const auto& group) { return group.end > pos; });
    for(auto it = group; it != m_priority_groups.end(); ++it)
    {
        it->end -= 1;
    }

    // this piece may have completed a few groups (a single piece may be in multiple
    // priority groups if the piece overlaps files)
    const auto empty_group = std::find_if(group, m_priority_groups.end(),
        [pos](const auto& group) { return group.empty(); });
    if(empty_group != m_priority_groups.end())
    {
        m_priority_groups.erase(empty_group);
    }
}

void piece_picker::lost(const piece_index_t piece)
{
    assert(piece < num_pieces());
    if(!m_my_pieces[piece]) { return; }

    m_my_pieces[piece] = false;
    const int pos = m_piece_pos_map[piece];
    // we need to download this piece again
    if(pos != invalid_pos)
    {
        m_pieces.emplace_back(piece);
        m_piece_pos_map[piece] = m_pieces.size() - 1;
    }
}

void piece_picker::make_top_priority(interval pieces)
{
}

void piece_picker::make_priority(interval pieces)
{
}

void piece_picker::clear_priority(interval pieces)
{
}

std::string piece_picker::to_string() const
{
#define PRINT_PIECE(piece) do \
    ss << "p(" << piece.index \
       << "|" << piece.frequency \
       << "|" << (piece.is_reserved ? 'R' : '0') \
       << "|" << m_piece_pos_map[piece.index] \
       << ") "; while(0)
    std::ostringstream ss;
    if(m_priority_groups.empty())
    {
        for(const auto& piece : m_pieces) { PRINT_PIECE(piece); }
    }
    else
    {
        int pos = 0;
        for(const auto& group : m_priority_groups)
        {
            ss << "group#1[" << group.begin << ", " << group.end << "]: ";
            for(; pos != group.end; ++pos)
            {
                PRINT_PIECE(m_pieces[pos]);
            }
            ss << '\n';
        }
    }
    return ss.str();
#undef PRINT_PIECE
}

} // namespace tide
