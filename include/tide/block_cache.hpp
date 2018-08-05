#ifndef TIDE_BLOCK_CACHE_HEADER
#define TIDE_BLOCK_CACHE_HEADER

#include "block_source.hpp"
#include "frequency_sketch.hpp"
#include "types.hpp"

#include <algorithm>
#include <list>
#include <map>
#include <memory>
#include <vector>

namespace tide {

/**
 * A Window-TinyLFU Cache (as per: https://arxiv.org/pdf/1512.00727.pdf) modified for
 * BitTorrent piece blocks.
 *
 *           Window Cache Victim .---------. Main Cache Victim
 *          .------------------->| TinyLFU |<-----------------.
 *          |                    `---------'                  |
 * .-------------------.              |    .------------------.
 * | Window Cache (1%) |              |    | Main Cache (99%) |
 * |      (LRU)        |              |    |      (SLRU)      |
 * `-------------------'              |    `------------------'
 *          ^                         |               ^
 *          |                         `---------------'
 *       new item                        Winner
 *
 * New entries are first placed in the window cache where they remain as long as they
 * have high temporal locality. An entry that's pushed out of the window cache gets a
 * chance to be admitted in the front of the main cache. If the main cache is full,
 * the TinyLFU admission policy determines whether this entry is to replace the main
 * cache's next victim based on TinyLFU's implementation defined historic frequency
 * filter. Currently a 4 bit frequency sketch is employed.
 *
 * TinyLFU's periodic reset operation ensures that lingering entries that are no longer
 * accessed are evicted.
 *
 * NOTE: it is advised that trivially copiable, small keys be used as there persist two
 * copies of each within the cache.
 * NOTE: it is NOT thread-safe!
 */
struct block_cache
{
    /** A block is mapped to this key. */
    struct key
    {
        torrent_id_t torrent;
        piece_index_t piece;
        int offset;
    };

private:
    enum class cache_t
    {
        window,
        probationary,
        eden
    };

    struct piece_key
    {
        torrent_id_t torrent;
        piece_index_t piece;

        friend bool operator==(const piece_key& a, const piece_key& b) noexcept
        {
            return (a.torrent == b.torrent) && (a.piece == b.piece);
        }

        friend bool operator<(const piece_key& a, const piece_key& b) noexcept
        {
            if(a.torrent == b.torrent) {
                return a.piece < b.piece;
            }
            return a.torrent < b.torrent;
        }
    };

    /** Holds a block. */
    struct page
    {
        // Store the key to the piece to which this block belongs so that when this
        // page is evicted, it can be removed from its piece's registry as well.
        piece_key key;
        cache_t cache_type;
        block_source block;

        page(piece_key key_, cache_t cache_type_, block_source block_)
            : key(key_), cache_type(cache_type_), block(std::move(block_))
        {}
    };

    class lru
    {
        std::list<page> lru_;
        int capacity_;

    public:
        using page_position = std::list<page>::iterator;
        using const_page_position = std::list<page>::const_iterator;

        explicit lru(int capacity) : capacity_(capacity) {}

        int size() const noexcept { return lru_.size(); }
        int capacity() const noexcept { return capacity_; }

        /**
         * NOTE: doesn't actually remove any pages, it only sets the capacity.
         *
         * This is because otherwise there'd be no way to delete the corresponding
         * entries from the page map outside of this LRU instance, so this is handled
         * externally.
         */
        void set_capacity(const int n) noexcept { capacity_ = n; }

        /** Returns the position of the hottest (most recently used) page. */
        page_position mru_pos() noexcept { return lru_.begin(); }
        const_page_position mru_pos() const noexcept { return lru_.begin(); }

        /** Returns the position of the coldest (least recently used) page. */
        page_position lru_pos() noexcept { return --lru_.end(); }
        const_page_position lru_pos() const noexcept { return --lru_.end(); }

        key victim_key() const noexcept
        {
            const auto page = lru_pos();
            return {page->key.torrent, page->key.piece, page->block.offset};
        }

        void evict() { erase(lru_pos()); }
        void erase(page_position page) { lru_.erase(page); }

        /** Inserts new page at the MRU position of the cache. */
        template <typename... Args>
        page_position insert(Args&&... args)
        {
            return lru_.emplace(mru_pos(), std::forward<Args>(args)...);
        }

        /** Moves page to the MRU position. */
        void handle_hit(page_position page) { transfer_page_from(page, *this); }

        /** Moves page from source to the MRU position of this cache. */
        void transfer_page_from(page_position page, lru& source)
        {
            lru_.splice(mru_pos(), source.lru_, page);
        }
    };

    /**
     * A cache which is divided into two segments, a probationary and a eden
     * segment. Both are LRU caches.
     *
     * Pages that are cache hits are promoted to the top (MRU position) of the eden
     * segment, regardless of the segment in which they currently reside. Thus, pages
     * within the eden segment have been accessed at least twice.
     *
     * Pages that are cache misses are added to the cache at the MRU position of the
     * probationary segment.
     *
     * Each segment is finite in size, so the migration of a page from the probationary
     * segment may force the LRU page of the eden segment into the MRU position of
     * the probationary segment, giving it another chance. Likewise, if both segments
     * reached their capacity, a new entry is replaced with the LRU victim of the
     * probationary segment.
     *
     * In this implementation 80% of the capacity is allocated to the eden (the
     * "hot" pages) and 20% for pages under probation (the "cold" pages).
     */
    class slru
    {
        lru eden_;
        lru probationary_;

    public:
        explicit slru(int capacity) : slru(0.8f * capacity, capacity - 0.8f * capacity)
        {
            // Correct truncation error.
            if(this->capacity() < capacity) {
                eden_.set_capacity(eden_.capacity() + 1);
            }
        }

        slru(int eden_capacity, int probationary_capacity)
            : eden_(eden_capacity), probationary_(probationary_capacity)
        {}

        const int size() const noexcept { return eden_.size() + probationary_.size(); }

        const int capacity() const noexcept
        {
            return eden_.capacity() + probationary_.capacity();
        }

        void set_capacity(const int n)
        {
            eden_.set_capacity(0.8f * n);
            probationary_.set_capacity(n - eden_.capacity());
        }

        key victim_key() const noexcept { return probationary_.victim_key(); }

        void evict() { probationary_.evict(); }

        void erase(lru::page_position page)
        {
            if(page->cache_type == cache_t::eden)
                eden_.erase(page);
            else
                probationary_.erase(page);
        }

        /** Moves page to the MRU position of the probationary segment. */
        void transfer_page_from(lru::page_position page, lru& source)
        {
            probationary_.transfer_page_from(page, source);
            page->cache_type = cache_t::probationary;
        }

        /**
         * If page is in the probationary segment:
         * promotes page to the MRU position of the eden segment, and if eden segment
         * capacity is reached, moves the LRU page of the eden segment to the MRU
         * position of the probationary segment.
         *
         * Otherwise, page is in eden:
         * promotes page to the MRU position of eden.
         */
        void handle_hit(lru::page_position page)
        {
            if(page->cache_type == cache_t::probationary) {
                promote_to_eden(page);
                if(eden_.size() > eden_.capacity()) {
                    demote_to_probationary(eden_.lru_pos());
                }
            } else {
                assert(page->cache_type == cache_t::eden); // this shouldn't happen
                eden_.handle_hit(page);
            }
        }

    private:
        // Both of the below functions promote to the MRU position.
        void promote_to_eden(lru::page_position page)
        {
            eden_.transfer_page_from(page, probationary_);
            page->cache_type = cache_t::eden;
        }

        void demote_to_probationary(lru::page_position page)
        {
            probationary_.transfer_page_from(page, eden_);
            page->cache_type = cache_t::probationary;
        }
    };

    struct piece
    {
        // Piece doesn't actually store any blocks, rather, it points into the LRU or
        // SLRU structures that hold the blocks.
        std::vector<lru::page_position> blocks;
    };

    // For faster lookups, we map torrent piece's, and not blocks. So to retrieve the
    // block, we first retrieve the piece to which it belongs, then find block within
    // piece.
    std::map<piece_key, piece> page_map_;

    frequency_sketch<key> filter_;

    // Allocated 1% of the total capacity. Window victims are granted the chance to
    // reenter the cache (into main_). This is to remediate the problem where sparse
    // bursts cause repeated misses in the regular TinyLfu architecture.
    lru window_;

    // Allocated 99% of the total capacity.
    slru main_;

    int num_cache_hits_ = 0;
    int num_cache_misses_ = 0;

public:
    explicit block_cache(int capacity)
        : filter_(capacity)
        , window_(window_capacity(capacity))
        , main_(capacity - window_.capacity())
    {}

    int size() const noexcept { return window_.size() + main_.size(); }

    int capacity() const noexcept { return window_.capacity() + main_.capacity(); }

    /**
     * NOTE: after this operation the accuracy of the cache will suffer until enough
     * historic data is gathered (because the frequency sketch is cleared).
     */
    void set_capacity(const int n)
    {
        if(n < 0)
            throw std::invalid_argument("cache capacity must be greater than zero");

        filter_.change_capacity(n);
        window_.set_capacity(window_capacity(n));
        main_.set_capacity(n - window_.capacity());

        while(window_.size() > window_.capacity()) {
            evict_from(window_);
        }
        while(main_.size() > main_.capacity()) {
            evict_from(main_);
        }
    }

    int num_cache_hits() const noexcept { return num_cache_hits_; }
    int num_cache_misses() const noexcept { return num_cache_misses_; }

    bool contains(const key& key) const noexcept
    {
        auto it = page_map_.find(to_piece_key(key));
        if(it != page_map_.end()) {
            for(const auto& page : it->second.blocks) {
                if(page->block.offset == key.offset) {
                    return true;
                }
            }
        }
        return false;
    }

    block_source get(const key& key)
    {
        filter_.record_access(key);
        auto it = page_map_.find(to_piece_key(key));
        if(it != page_map_.end()) {
            for(auto page : it->second.blocks) {
                if(page->block.offset == key.offset) {
                    handle_hit(page);
                    return page->block;
                }
            }
        }
        ++num_cache_misses_;
        return {};
    }

    block_source operator[](const key& key) { return get(key); }

    void insert(const key& key, block_source block)
    {
        if(window_.size() >= window_.capacity()) {
            evict();
        }

        const auto piece_key = to_piece_key(key);
        auto it = page_map_.find(piece_key);
        if(it != page_map_.end()) {
            piece& piece = it->second;
            auto pos = std::find_if(piece.blocks.begin(), piece.blocks.end(),
                    [offset = key.offset](
                            const auto& b) { return b->block.offset >= offset; });
            if((pos != piece.blocks.end()) && ((*pos)->block.offset == block.offset)) {
                // this won't happen, but we should still handle the case correctly
                (*pos)->block = std::move(block);
            } else {
                piece.blocks.emplace(pos,
                        window_.insert(piece_key, cache_t::window, std::move(block)));
            }
        } else {
            piece piece;
            piece.blocks.emplace_back(
                    window_.insert(piece_key, cache_t::window, std::move(block)));
            page_map_.emplace(piece_key, std::move(piece));
        }
    }

    void erase(const key& key)
    {
        auto it = page_map_.find(to_piece_key(key));
        if(it != page_map_.end()) {
            auto& piece = it->second;
            for(auto& block : piece.blocks) {
                if(block->cache_type == cache_t::window)
                    window_.erase(block);
                else
                    main_.erase(block);
            }
            page_map_.erase(it);
        }
    }

private:
    static int window_capacity(const int total_capacity) noexcept
    {
        return std::max(1, int(std::ceil(0.01f * total_capacity)));
    }

    void handle_hit(lru::page_position page)
    {
        if(page->cache_type == cache_t::window)
            window_.handle_hit(page);
        else
            main_.handle_hit(page);
        ++num_cache_hits_;
    }

    /**
     * Evicts from the window cache to the main cache's probationary space.
     * Called when the window cache is full.
     * If the cache's total size exceeds its capacity, the window cache's victim and
     * the main cache's eviction candidate are evaluated and the one with the worse
     * (estimated) access frequency is evicted. Otherwise, the window cache's victim is
     * just transferred to the main cache.
     */
    void evict()
    {
        if(size() >= capacity()) {
            const int window_victim_freq = filter_.frequency(window_.victim_key());
            const int main_victim_freq = filter_.frequency(main_.victim_key());
            if(window_victim_freq > main_victim_freq) {
                evict_from(main_);
                main_.transfer_page_from(window_.lru_pos(), window_);
            } else {
                evict_from(window_);
            }
        } else {
            main_.transfer_page_from(window_.lru_pos(), window_);
        }
    }

    template <typename Cache>
    void evict_from(Cache& cache)
    {
        page_map_.erase(to_piece_key(cache.victim_key()));
        cache.evict();
    }

    piece_key to_piece_key(const key& k) const noexcept { return {k.torrent, k.piece}; }
};

} // namespace tide

#endif // TIDE_BLOCK_CACHE_HEADER
