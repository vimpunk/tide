#ifndef TORRENT_BENCODE_HEADER
#define TORRENT_BENCODE_HEADER

#include <string>
#include <vector>
#include <memory>
#include <map>

namespace tide {

struct bencoder
{
    bencoder() = default;
    bencoder(const bencoder&) = default;
    bencoder(bencoder&&) = default;
    bencoder& operator=(const bencoder&) = default;
    bencoder& operator=(bencoder&&) = default;
    virtual ~bencoder() = default;

    /**
     * Encodes the underlying element by writing it in the range [begin, end) and
     * returns the number of bytes that were encoded. If the end - begin is smaller
     * than encoded_length(), an invalid_argument exception is thrown.
     */
    virtual int encode(std::string::iterator begin, std::string::iterator end) const = 0;
    virtual std::string encode() const = 0;
    virtual int encoded_length() const = 0;
};

struct bnumber_encoder final : public bencoder
{
    int64_t number;

    bnumber_encoder() = default;
    bnumber_encoder(int64_t n) : number(n) {}

    std::string encode() const override;
    int encode(std::string::iterator begin, std::string::iterator end) const override;
    int encoded_length() const override;
};

struct bstring_encoder final : public bencoder
{
    std::string string;

    bstring_encoder() = default;
    bstring_encoder(std::string s) : string(std::move(s)) {}

    std::string encode() const override;
    int encode(std::string::iterator begin, std::string::iterator end) const override;
    int encoded_length() const override;
};

class bmap_encoder final : public bencoder
{
    // Bencoded maps require that their elements be stored in lexicographical order of
    // their keys, so a std::map is used to ensure that the output is sorted.
    std::map<std::string, std::unique_ptr<bencoder>> m_map;
    // Every bmap starts with a map header token (d) and closes with an end token (e).
    // Thus empty maps have an encoded length of 2.
    int m_num_bytes = 2;

public:

    bmap_encoder() = default;
    bmap_encoder(const bmap_encoder& other);
    bmap_encoder(bmap_encoder&& other) = default;
    bmap_encoder& operator=(const bmap_encoder& other);
    bmap_encoder& operator=(bmap_encoder&& other) = default;

    template<typename BType, typename... Args>
    void emplace(std::string key, Args&&... args);
    void insert(std::string key, std::unique_ptr<bencoder> bencoder);

    std::string encode() const override;
    int encode(std::string::iterator begin, std::string::iterator end) const override;
    int encoded_length() const override { return m_num_bytes; }
};

class blist_encoder final : public bencoder
{
    std::vector<std::unique_ptr<bencoder>> m_list;
    // Every blist starts with a list header token (l) and closes with an end token (e).
    // Thus empty lists have an encoded length of 2.
    int m_num_bytes = 2;

public:

    blist_encoder() = default;
    blist_encoder(const blist_encoder& other);
    blist_encoder(blist_encoder&& other) = default;
    blist_encoder& operator=(const blist_encoder& other);
    blist_encoder& operator=(blist_encoder&& other) = default;

    void push_front(std::unique_ptr<bencoder> bencoder);
    void push_back(std::unique_ptr<bencoder> bencoder);
    template<typename BType, typename... Args>
    void emplace_back(Args&&... args);
    template<typename BType, typename... Args>
    void emplace_front(Args&&... args);

    std::string encode() const override;
    int encode(std::string::iterator begin, std::string::iterator end) const override;
    int encoded_length() const override { return m_num_bytes; }
};

template<typename BType, typename... Args>
void bmap_encoder::emplace(std::string key, Args&&... args)
{
    insert(std::move(key), std::make_unique<BType>(std::forward<Args>(args)...));
}

template<typename BType, typename... Args>
void blist_encoder::emplace_front(Args&&... args)
{
    push_front(std::make_unique<BType>(std::forward<Args>(args)...));
}

template<typename BType, typename... Args>
void blist_encoder::emplace_back(Args&&... args)
{
    push_back(std::make_unique<BType>(std::forward<Args>(args)...));
}

/**
 * An optimized bencoder that should be preferred over the above if the output string
 * size is known in advance. This will only allocate a single std::string and encode
 * the supplied elements in place by writing them directly to this output string
 * without intermediate allocations.
class flat_bencoder
{
};
 */

} // namespace tide

#endif // TORRENT_BENCODE_HEADER
