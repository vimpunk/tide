#ifndef TIDE_PIECE_PICKER_HEADER
#define TIDE_PIECE_PICKER_HEADER

#include "bitfield.hpp"
#include "interval.hpp"
#include "types.hpp"

#include <vector>

namespace tide {

class piece_picker
{
    // A full piece availability map of our pieces.
    bitfield m_my_pieces;

    struct piece
    {
        piece_index_t index;
        uint16_t frequency;
        bool is_reserved;

        piece() = default;
        piece(piece_index_t i, uint16_t f = 0, bool r = false)
            : index(i)
            , frequency(f)
            , is_reserved(r)
        {}
    };

    // These are the pieces that we still need (regardless of frequency) to download.
    // They are ordered according to priority (highest to lowest) and frequency (lowest
    // to highest). As soon as we get a piece, it is removed from here.
    std::vector<piece> m_pieces;

    // Since m_pieces is ordered by priority and frequency, we need a fast way to
    // retrieve individual pieces (by their indices). This vector is fully allocated to 
    // num_pieces and stores indices into m_pieces, and a piece's position can be
    // retrieved by m_piece_pos_map[piece_index].
    // While this vector always holds all pieces, pieces that we no longer need to 
    // download are removed from m_pieces. Those are mapped to invalid_pos.
    std::vector<int> m_piece_pos_map;
    static constexpr int invalid_pos = -1;

    // An entry in this vector represents a priority group with a [begin, end) interval
    // that denotes the boundaries of the group.
    // It is ordered by highest priority to lowest priority, with the default group
    // always positioned as the last group. However, the default group is not allocated
    // a slot in this list as it's always the last group. This allows us to avoid
    // allocating the vector if there are no priority pieces.
    std::vector<interval> m_priority_groups;

    // Keeping m_pieces sorted at all times is an expensive operation, so we only need
    // to reorder pieces when we actually pick a piece. That is, piece frequency
    // changes cause this flag to be set, and if this flag is set when picking, we
    // need to call rebuild_frequency_map() beforehand.
    bool m_is_dirty = false;

public:

    /** Describes the strategy used for picking pieces. */
    enum class strategy
    {
        // Random is usually enabled when a torrent is starting out. This is because by
        // choosing the rarest pieces at the beginning will most likely result in the
        // slowest ones to download, whereas choosing a popular piece is more likely to
        // be available from more peers, potentially speeding up the boostrapping
        // process. Enabled for the frist few pieces.
        random,
        // This is the mode in which a torrent operates after concluding the initial
        // phase with random.
        rarest_first,
        // If we donwload sequentially, we can drop a lot of the piece map logic by
        // always keeping m_pieces ordered by piece indices.
        // Pieces are requested in order [0, n). Useful for streaming. Also, piece picker
        // should operate much faster this way, since pieces are no longer ordered by
        // their frequency, we never have to reorder the internal piece registry.
        sequential
    };

private:

    strategy m_strategy = strategy::rarest_first;

public:

    static constexpr int invalid_piece = -1;

    explicit piece_picker(int num_pieces);
    explicit piece_picker(bitfield downloaded_pieces);

    /**
     * Called to determine whether client is interested in peer according to the
     * pieces it has, the ones we have and the availability in the swarm.
     */
    bool am_interested_in(const bitfield& available_pieces) const noexcept;
    bool has_no_pieces() const noexcept;
    bool has_all_pieces() const noexcept;

    /** Returns the total number of pieces in this torrent (my_bitfield().size()). */
    int num_pieces() const noexcept;
    int num_have_pieces() const noexcept;
    int num_pieces_left() const noexcept;
    const bitfield& my_bitfield() const noexcept;

    enum strategy strategy() const noexcept;
    void set_strategy(const enum strategy s) noexcept;

    /** Index corresponds to piece index, and the value at index is the frequency. */
    std::vector<int> piece_availability() const;

    /**
     * The piece availability is written into the input vector.
     * This method should be prefered over the above if piece availability is regularly
     * requested to avoid allocations when creating new vectors.
     */
    void piece_availability(std::vector<int>& frequency_map) const;

    /** Returns the piece's frequency. */
    int frequency(const piece_index_t piece) const noexcept;

    /**
     * Called when a 'have' or 'bitfield' message is received. Increases the global
     * availability of the piece in the swarm.
     */
    void increase_frequency(const piece_index_t piece);
    void increase_frequency(const bitfield& available_pieces);

    /**
     * This MUST be called when a connection with a peer is closed, to adjust the piece
     * availability now that peer no longer provides its pieces; or when peer turns out
     * not to have the piece it had previously advertised.
     */
    void decrease_frequency(const bitfield& available_pieces);
    void decrease_frequency(const piece_index_t piece);

    /** Picks and reserves the most suitable piece among available_pieces. */
    piece_index_t pick(const bitfield& available_pieces);

    void reserve(const piece_index_t piece);

    /**
     * Called when the client decides not to download the piece it has reserved using
     * pick_and_reserve(). It is also called by got(), which marks that we got a piece.
     */
    void unreserve(const piece_index_t piece);
    void got(const piece_index_t piece);

    /** Should be called when our saved pieces got erased. */
    void lost(const piece_index_t piece);

    /**
     * User may not wish to download all files in a torrent, in which case the file's
     * corresponding pieces will have to be marked as unwanted here.
     */
    void set_wanted_pieces(bitfield wanted_pieces);
    void want_piece(const piece_index_t piece);
    void want_pieces(const interval pieces);
    void dont_want_piece(const piece_index_t piece);
    void dont_want_pieces(const interval pieces);

    /**
     * Places pieces at the beginning of the to-download-next queue, regardless whether
     * they're fully available.
     */
    void make_top_priority(const piece_index_t begin, const piece_index_t end);
    void make_top_priority(interval pieces);

    /**
     * Places pieces at the beginning of the to-download-next queue if and only if all
     * the pieces in the interval [begin, end) are available to download. This is done
     * to favor those priority intervals that are fully available, as it is reasonable
     * to assume that the user would want a complete file rather than a half-complete
     * one.
     * If it is absolutely instrumental that these pieces be download first regardless
     * of availability, use make_top_priority() above.
     */
    void make_priority(const piece_index_t begin, const piece_index_t end);
    void make_priority(interval pieces);

    /**
     * Makes pieces in the interval [begin, end) normal priority. If however the first
     * and/or last pieces of the range overlap with another priority interval, the
     * priority on them is preserved.
     */
    void clear_priority(const piece_index_t begin, const piece_index_t end);
    void clear_priority(interval pieces);

    /**
     * Used only for debugging, returns a beautified string of the to-be-downloaded
     * pieces, ordered by priority groups and by frequency.
     */
    std::string to_string() const;

private:

   void rebuild_frequency_map() noexcept; 
   void rebuild_group(std::vector<piece>::iterator begin,
       std::vector<piece>::iterator end) noexcept; 
};

inline int piece_picker::num_pieces() const noexcept
{
    return m_my_pieces.size();
}

inline int piece_picker::num_have_pieces() const noexcept
{
    return num_pieces() - num_pieces_left();
}

inline int piece_picker::num_pieces_left() const noexcept
{
    return m_pieces.size();
}

inline
void piece_picker::make_top_priority(const piece_index_t begin, const piece_index_t end)
{
    make_top_priority(interval(begin, end));
}

inline
void piece_picker::make_priority(const piece_index_t begin, const piece_index_t end)
{
    make_priority(interval(begin, end));
}

inline
void piece_picker::clear_priority(const piece_index_t begin, const piece_index_t end)
{
    clear_priority(interval(begin, end));
}

inline const bitfield& piece_picker::my_bitfield() const noexcept
{
    return m_my_pieces;
}

inline bool piece_picker::has_no_pieces() const noexcept
{
    return num_pieces_left() == num_pieces();
}

inline bool piece_picker::has_all_pieces() const noexcept
{
    return num_pieces_left() == 0;
}

inline enum piece_picker::strategy piece_picker::strategy() const noexcept
{
    return m_strategy;
}

/*
inline void piece_picker::set_wanted_pieces(bitfield wanted_pieces)
{
    assert(wanted_pieces.size() == m_my_pieces.size());
    m_wanted_pieces = std::move(wanted_pieces);
}

inline void piece_picker::want_piece(const piece_index_t piece)
{
    assert(piece >= 0 && piece < num_pieces());
    m_wanted_pieces.set(piece);
}

inline void piece_picker::want_pieces(const interval pieces)
{
    for(auto i = pieces.begin; i < pieces.end; ++i) { want_piece(i); }
}

inline void piece_picker::dont_want_piece(const piece_index_t piece)
{
    m_wanted_pieces.reset(piece);
}

inline void piece_picker::dont_want_pieces(const interval pieces)
{
    for(auto i = pieces.begin; i < pieces.end; ++i) { dont_want_piece(i); }
}
*/

} // namespace tide

#endif // TIDE_PIECE_PICKER_HEADER
