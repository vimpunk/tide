#ifndef TIDE_PIECE_PICKER_HEADER
#define TIDE_PIECE_PICKER_HEADER

#include "bitfield.hpp"
#include "interval.hpp"
#include "units.hpp"

#include <vector>
#include <memory>

namespace tide {

class piece_picker
{
    // Records all the pieces that we have downloaded so far.
    bitfield m_downloaded_pieces;

    // And this keeps track of all the pieces that we want to download. By default this
    // is all set, but user may request to download only part of the torrent.
    bitfield m_wanted_pieces;

    // This is the number of pieces that we still need to download and want, i.e. pieces
    // corresponding to the bit positions in m_wanted_pieces.
    // TODO this has not been updated for the new wanted_pieces logic
    int m_num_pieces_left;

    // Tracks each piece in the peer swarm and orders them by priority and frequency.
    class piece_tracker;
    std::unique_ptr<piece_tracker> m_piece_tracker;

public:

    static constexpr int invalid_piece = -1;

    explicit piece_picker(int num_pieces);
    explicit piece_picker(bitfield available_pieces);
    ~piece_picker();

    /**
     * Called to determine whether client is interested in peer according to the
     * pieces it has, the ones we have and the availability in the swarm.
     */
    bool am_interested_in(const bitfield& available_pieces) const noexcept;
    bool has_no_pieces() const noexcept;
    bool has_all_pieces() const noexcept;

    /** Returns the total number of pieces in this torrent (== my_bitfield().size()). */
    int num_pieces() const noexcept;
    const bitfield& my_bitfield() const noexcept;
    // TODO rename above to:
    //const bitfield& my_available_pieces() const noexcept;

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
    void increase_frequency(const std::vector<piece_index_t>& pieces);
    void increase_frequency(const bitfield& available_pieces);

    /**
     * This MUST be called when a connection with a peer is closed, to adjust the piece
     * availability now that peer no longer provides its pieces; or when peer turns out
     * not to have the piece it had previously advertised.
     */
    void decrease_frequency(const bitfield& available_pieces);
    void decrease_frequency(const piece_index_t piece);

    // ---------------------
    // PIECE SELECTION LOGIC
    // ---------------------
    // Return value if no pieces could be picked:
    // - in single piece selection: invalid_piece(-1);
    // - in n piece selection     : an empty vector.
    // A peer's piece is desirable if we don't have it, and it is not reserved.
    //
    // pick_and_reserve should be used, the others are for testing.

    piece_index_t pick(const bitfield& available_pieces) const;
    std::vector<piece_index_t> pick(
        const bitfield& available_pieces, const int n) const;

    piece_index_t pick_and_reserve(const bitfield& available_pieces);
    std::vector<piece_index_t> pick_and_reserve(
        const bitfield& available_pieces, const int n);

    piece_index_t pick_ignore_reserved(const bitfield& available_pieces) const;
    std::vector<piece_index_t> pick_ignore_reserved(
        const bitfield& available_pieces, const int n) const;

    /**
     * Called when the client decides not to download the piece it has reserved using
     * pick_and_reserve(). It is also called by got(), which marks that we got a piece.
     */
    void unreserve(const piece_index_t piece);
    void got(const piece_index_t piece);

    /** Should be called when our saved pieces got erased. */
    void lost(const piece_index_t piece);
    void lost(const std::vector<piece_index_t>& pieces);

    /**
     * TODO
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
    void make_top_priority(interval interval);

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
    void make_priority(interval interval);

    /**
     * Makes pieces in the interval [begin, end) normal priority. If however the first
     * and/or last pieces of the range overlap with another priority interval, the
     * priority on them is preserved.
     */
    void clear_priority(const piece_index_t begin, const piece_index_t end);
    void clear_priority(interval interval);

    /**
     * Used only for debugging, returns a beautified string of the pieces, ordered by
     * priority groups and by frequency.
     */
    std::string to_string() const;

private:

    /** Returns true if we're interested in the piece and it is not reserved. */
    template<typename Piece>
    bool should_pick(const bitfield& available_pieces, const Piece& piece) const;

    /** Tests whether we're interested in the piece and whether peer has it. */
    bool should_download_piece(const bitfield& available_pieces,
        const piece_index_t piece) const;
};

inline int piece_picker::num_pieces() const noexcept
{
    return m_downloaded_pieces.size();
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
    return m_downloaded_pieces;
}

inline bool piece_picker::has_no_pieces() const noexcept
{
    m_num_pieces_left == num_pieces();
}

inline bool piece_picker::has_all_pieces() const noexcept
{
    return m_num_pieces_left == 0;
}

inline void piece_picker::set_wanted_pieces(bitfield wanted_pieces)
{
    assert(wanted_pieces.size() == m_downloaded_pieces.size());
    m_wanted_pieces = std::move(wanted_pieces);
}

inline void piece_picker::want_piece(const piece_index_t piece)
{
    assert(piece >= 0 && piece < num_pieces());
    m_wanted_pieces.set(piece);
}

inline void piece_picker::want_pieces(const interval pieces)
{
    for(auto i = pieces.begin; i < pieces.end; ++i)
    {
        want_piece(i);
    }
}

inline void piece_picker::dont_want_piece(const piece_index_t piece)
{
    m_wanted_pieces.reset(piece);
}

inline void piece_picker::dont_want_pieces(const interval pieces)
{
    for(auto i = pieces.begin; i < pieces.end; ++i)
    {
        dont_want_piece(i);
    }
}

} // namespace tide

#endif // TIDE_PIECE_PICKER_HEADER
