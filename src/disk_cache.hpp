#include "units.hpp"

#include <memory>

class piece
{
    // The torrent to which this piece belongs.
    const torrent_id_t torrent;
    const piece_index_t index;

    piece(torrent_id_t t, piece_index_t i) : torrent(t), index(i) {}

    virtual ~piece() = default;

    /** The number of valid 16KiB blocks that are loaded from disk. */
    virtual int num_blocks() = 0;

    //std::vector<block> blocks() = 0;
};


struct disk_cache_info
{
    int num_cache_hits = 0;
    int num_cache_misses = 0;
    int num_pinned_blocks = 0;
};

class disk_cache
{
    int m_size = 0;
    disk_cache_info m_info;

public:

    struct key
    {
        torrent_id_t torrent;
        piece_index_t piece;
    };

    /** Returns the number of 16KiB blocks in the cache. */
    int size() const noexcept;
    const disk_cache_info& stats() const noexcept;

    bool contains(const key& k) const noexcept;

    std::shared_ptr<piece> get(const key& k);
    template<typename Piece, typename... Args> emplace(Args&&... args);
    void insert(std::shared_ptr<piece> piece);
    void erase(const key& k);
    void shrink_to_fit(const int n);

    /** Marks entry as non-evictable. */
    void pin_down(const key& k);
};
