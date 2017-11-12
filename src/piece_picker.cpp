#include "piece_picker.hpp"
#include "random.hpp"

#include <algorithm>
#include <sstream>
#include <cassert>
#include <cmath>

namespace tide {

piece_picker::piece_picker(const int num_pieces)
    : my_pieces_(num_pieces)
    , pieces_(num_pieces)
    , piece_pos_map_(num_pieces)
{
    for(auto i = 0; i < num_pieces; ++i)
    {
        pieces_[i].index = i;
        piece_pos_map_[i] = i;
    }
}

piece_picker::piece_picker(bitfield downloaded_pieces)
    : my_pieces_(std::move(downloaded_pieces))
    , pieces_([this] {
            int num_missing = 0;
            for(bool have : my_pieces_)
            {
                if(!have) { ++num_missing; }
            }
            return num_missing;
        }())
    , piece_pos_map_(my_pieces_.size())
{
    for(auto piece = 0, pos = 0; piece < num_pieces(); ++piece)
    {
        if(my_pieces_[piece])
        {
            // if we have the piece, we don't need it, so don't create an pieces_ entry
            piece_pos_map_[piece] = invalid_pos;
        }
        else
        {
            pieces_[pos].index = piece;
            piece_pos_map_[piece] = pos;
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
        if(strategy_ != s)
        {
            // we need to rebuild the piece map to be ordered by piece indices
            std::sort(pieces_.begin(), pieces_.end(),
                [](const piece& a, const piece& b) { return a.index < b.index; });
            int pos = 0;
            for(const auto& piece : pieces_)
            {
                piece_pos_map_[piece.index] = pos;
                ++pos;
            }
        }
        break;
    }
    case strategy::rarest_first:
    {
        // if we're coming from another strategy we'll need to rebuild the frequency map
        if(strategy_ != s) { rebuild_frequency_map(); }
        break;
    }
    default: assert(0);
    }
    strategy_ = s;
}

bool piece_picker::am_interested_in(const bitfield& available_pieces) const noexcept
{
    // we're interested in peer if it has at least one piece that we don't have but want
    assert(available_pieces.size() == my_pieces_.size());
    for(const auto& piece : pieces_)
    {
        if(available_pieces[piece.index]) { return true; }
    }
    return false;
}

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
        const auto pos = piece_pos_map_[i];
        if(pos != invalid_pos)
            frequency_map[i] = pieces_[pos].frequency;
        else
            frequency_map[i] = -1;
    }
}

int piece_picker::frequency(const piece_index_t piece) const noexcept
{
    assert(piece < num_pieces());
    const auto pos = piece_pos_map_[piece];
    if(pos != invalid_pos) { return pieces_[pos].frequency; }
    return 0;
}

void piece_picker::increase_frequency(const piece_index_t piece)
{
    assert(piece < num_pieces());
    const auto pos = piece_pos_map_[piece];
    if(pos != invalid_pos)
    {
        ++pieces_[pos].frequency;
        is_dirty_ = true;
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
    const auto pos = piece_pos_map_[piece];
    if(pos != invalid_pos)
    {
        --pieces_[pos].frequency;
        is_dirty_ = true;
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
    if(num_pieces_left() == 0) { return invalid_piece_index; }

    if((strategy_ == strategy::rarest_first) && is_dirty_)
    {
        rebuild_frequency_map();
    }
    else if(strategy_ == strategy::random)
    {
        return pieces_[util::random_int(0, pieces_.size() - 1)].index;
    }

    const auto can_pick = [&available_pieces](const auto& piece)
    {
        return !piece.is_reserved && available_pieces[piece.index];
    };

    const auto piece = std::find_if(pieces_.begin(), pieces_.end(),
        [&can_pick](const auto& piece) { return can_pick(piece); });

    // TODO the protocol suggests that given several pieces with the same frequency, we
    // should randomize our choice; std::sort (in rebuild_frequency_map) does not guarantee
    // stable sorting, i.e. pieces in a group may get reordered--is this sufficient for
    // the purposes described in the protocol?
    if(piece == pieces_.end())
    {
        return invalid_piece_index;
    }
    else
    {
        piece->is_reserved = true;
        return piece->index;
    }
}

inline void piece_picker::rebuild_frequency_map() noexcept
{
    if(priority_groups_.empty())
    {
        rebuild_group(pieces_.begin(), pieces_.end());
    }
    else
    {
        for(const interval& group : priority_groups_)
        {
            rebuild_group(pieces_.begin() + group.begin, pieces_.begin() + group.end);
        }
        const int last_group_end = priority_groups_.back().end;
        rebuild_group(pieces_.begin() + last_group_end, pieces_.end());
    }
    is_dirty_ = false;
}

inline void piece_picker::rebuild_group(std::vector<piece>::iterator begin,
       std::vector<piece>::iterator end) noexcept 
{
    std::sort(begin, end, [](const piece& a, const piece& b)
        { return a.frequency < b.frequency; });
    while(begin != end)
    {
        const int pos = begin - pieces_.begin();
        assert(pos >= 0);
        assert(pos < int(pieces_.size()));
        piece_pos_map_[begin->index] = pos;
        ++begin;
    }
}

void piece_picker::reserve(const piece_index_t piece)
{
    assert(piece < num_pieces());
    const auto pos = piece_pos_map_[piece];
    if(pos != invalid_pos)
    {
        pieces_[pos].is_reserved = true;
    }
}

void piece_picker::unreserve(const piece_index_t piece)
{
    assert(piece < num_pieces());
    const auto pos = piece_pos_map_[piece];
    if(pos != invalid_pos)
    {
        pieces_[pos].is_reserved = false;
    }
}

void piece_picker::got(const piece_index_t piece)
{
    assert(piece != invalid_piece_index);
    assert(piece < num_pieces());
    if(my_pieces_[piece]) { return; }

    my_pieces_[piece] = true;
    const int pos = piece_pos_map_[piece];
    assert(pos != invalid_pos);
    assert(pos < int(pieces_.size()));
    assert(!pieces_.empty());

    // we no longer need to download this piece
    pieces_.erase(pieces_.begin() + pos);
    piece_pos_map_[piece] = invalid_pos;

    // now we need to go through all piece entries that came after the now removed
    // piece, and decrement their position value in piece_pos_map_ by one to adjust
    // to the new size
    // (note that where piece used to be now the next piece resides, so don't add 1 to
    // begin() + pos to get the next piece!)
    // TODO OPT since we likely pick the rarest pieces most of the time, that is, those
    // that are at the front, it means that we have to iterate a lot here; whereas if
    // rarest pieces started at the back of pieces_, we'd have to iterate very little
    for(auto it = pieces_.begin() + pos; it != pieces_.end(); ++it)
    {
        --piece_pos_map_[it->index];
        assert(piece_pos_map_[it->index] >= 0);
        assert(piece_pos_map_[it->index] < int(pieces_.size()));
    }

    if(priority_groups_.empty()) { return; }

    // we need to adjust the group boundaries
    const auto group = std::find_if(priority_groups_.begin(),
        priority_groups_.end(), [pos](const auto& group) { return group.end > pos; });
    for(auto it = group; it != priority_groups_.end(); ++it)
    {
        it->end -= 1;
    }

    // this piece may have completed a few groups (a single piece may be in multiple
    // priority groups if the piece overlaps files)
    const auto empty_group = std::find_if(group, priority_groups_.end(),
        [pos](const auto& group) { return group.empty(); });
    if(empty_group != priority_groups_.end()) { priority_groups_.erase(empty_group); }
}

void piece_picker::lost(const piece_index_t piece)
{
    assert(piece < num_pieces());
    if(!my_pieces_[piece]) { return; }

    my_pieces_[piece] = false;
    const int pos = piece_pos_map_[piece];
    // we need to download this piece again
    if(pos != invalid_pos)
    {
        pieces_.emplace_back(piece);
        piece_pos_map_[piece] = pieces_.size() - 1;
    }
}

/*
void set_wanted_pieces(bitfield wanted_pieces);
void want_piece(const piece_index_t piece);
void want_pieces(const interval pieces);
void dont_want_piece(const piece_index_t piece);
void dont_want_pieces(const interval pieces);
*/

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
       << "|" << piece_pos_map_[piece.index] \
       << ") "; while(0)
    std::ostringstream ss;
    if(priority_groups_.empty())
    {
        for(const auto& piece : pieces_) { PRINT_PIECE(piece); }
    }
    else
    {
        int pos = 0;
        for(const auto& group : priority_groups_)
        {
            ss << "group#1[" << group.begin << ", " << group.end << "]: ";
            for(; pos != group.end; ++pos) { PRINT_PIECE(pieces_[pos]); }
            ss << '\n';
        }
    }
    return ss.str();
#undef PRINT_PIECE
}

} // namespace tide
