#ifndef TORRENT_BENCODE_HEADER
#define TORRENT_BENCODE_HEADER

#include "string_view.hpp"

#include <string>
#include <vector>
#include <memory>
#include <map>

namespace tide {

std::string bencode_string(string_view s);
std::string bencode_number(const int64_t);

class blist_encoder;

class bmap_encoder
{
    class proxy
    {
        friend class bmap_encoder;
        std::string m_value;
    public:
        proxy() = default;
        // overloads so that map["key"] = value becomes valid
        proxy(const int64_t i);
        proxy(const char* s);
        proxy(const std::string& s);
        proxy(const bmap_encoder& b);
        proxy(const blist_encoder& b);
        proxy& operator=(const int64_t i);
        proxy& operator=(const char* s);
        proxy& operator=(const std::string& s);
        proxy& operator=(const bmap_encoder& b);
        proxy& operator=(const blist_encoder& b);
        operator const std::string&() const { return m_value; }
    };

    // Bencoded maps require that their elements be stored in lexicographical order of
    // their keys, so a std::map is used to ensure that the output is sorted.
    std::map<std::string, proxy> m_map;

public:

    proxy& operator[](const std::string& key) { return m_map[key]; }

    std::string encode() const;
    int encoded_length() const;
};

class blist_encoder
{
    std::vector<std::string> m_list;
    // Every blist starts with a list header token (l) and closes with an end token (e).
    // Thus empty lists have an encoded length of 2.
    int m_num_bytes = 2;

public:

    void push_back(int64_t n);
    void push_back(string_view s);
    void push_back(const blist_encoder& l);
    void push_back(const bmap_encoder& m);

    std::string encode() const;
    int encoded_length() const { return m_num_bytes; }
};

} // namespace tide

#endif // TORRENT_BENCODE_HEADER
