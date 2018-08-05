#ifndef TIDE_BENCODE_HEADER
#define TIDE_BENCODE_HEADER

#include "string_view.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace tide {

std::string bencode_string(string_view s);
std::string bencode_number(const int64_t);

class blist_encoder;

class bmap_encoder
{
    class proxy
    {
        friend class bmap_encoder;
        std::string value_;

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
        operator const std::string&() const { return value_; }
    };

    // Bencoded maps require that their elements be stored in lexicographical order of
    // their keys, so a std::map is used to ensure that the output is sorted.
    std::map<std::string, proxy> map_;

public:
    proxy& operator[](const std::string& key) { return map_[key]; }

    std::string encode() const;
    int encoded_length() const;
};

class blist_encoder
{
    std::vector<std::string> list_;
    // Every blist starts with a list header token (l) and closes with an end token (e).
    // Thus empty lists have an encoded length of 2.
    int num_bytes_ = 2;

public:
    void push_back(int64_t n);
    void push_back(string_view s);
    void push_back(const blist_encoder& l);
    void push_back(const bmap_encoder& m);

    std::string encode() const;
    int encoded_length() const { return num_bytes_; }
};

} // namespace tide

#endif // TIDE_BENCODE_HEADER
