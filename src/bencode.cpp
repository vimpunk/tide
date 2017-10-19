#include "bencode.hpp"

#include <stdexcept>
#include <iostream>
#include <cassert>

namespace tide {
namespace util {

    inline int bencoded_string_length(string_view s)
    {
        return s.length() + std::to_string(s.length()).length() + 1; /* + 1 for : */
    }

    inline int bencoded_number_length(const int64_t n)
    {
        return 2 + std::to_string(n).length();
    }

    template<typename OutputIt>
    int bencode_string(string_view s, OutputIt begin)
    {
        std::string len_str = std::to_string(s.length());
        const int encoded_len = s.length() + len_str.length() + 1; /* + 1 for : */
        std::copy(len_str.begin(), len_str.end(), begin);
        begin += len_str.length();
        *begin++ = ':';
        std::copy(s.begin(), s.end(), begin);
        return encoded_len;
    }

} // namespace util

std::string bencode_number(const int64_t n)
{
    return 'i' + std::to_string(n) + 'e';
}

std::string bencode_string(string_view s)
{
    std::string result(util::bencoded_string_length(s), 0);
    util::bencode_string(s, result.begin());
    return result;
}

// ----------
// -- bmap -- 
// ----------

bmap_encoder::proxy::proxy(const int64_t i) : value_(bencode_number(i)) {}
bmap_encoder::proxy::proxy(const char* s) : value_(bencode_string(s)) {}
bmap_encoder::proxy::proxy(const std::string& s) : value_(bencode_string(s)) {}
bmap_encoder::proxy::proxy(const bmap_encoder& b) : value_(b.encode()) {}
bmap_encoder::proxy::proxy(const blist_encoder& b) : value_(b.encode()) {}
bmap_encoder::proxy& bmap_encoder::proxy::operator=(const int64_t i)
{ value_ = bencode_number(i); }
bmap_encoder::proxy& bmap_encoder::proxy::operator=(const char* s)
{ value_ = bencode_string(s); }
bmap_encoder::proxy& bmap_encoder::proxy::operator=(const std::string& s)
{ value_ = bencode_string(s); }
bmap_encoder::proxy& bmap_encoder::proxy::operator=(const bmap_encoder& b)
{ value_ = b.encode(); }
bmap_encoder::proxy& bmap_encoder::proxy::operator=(const blist_encoder& b)
{ value_ = b.encode(); }

std::string bmap_encoder::encode() const
{
    std::string result(encoded_length(), 0);
    assert(result.length() >= 2);
    auto it = result.begin();
    *it++ = 'd';
    for(const auto& entry : map_)
    {
        it += util::bencode_string(entry.first, it);
        const std::string& value = entry.second.value_;
        std::copy(value.begin(), value.end(), it);
        it += value.length();
    }
    *it = 'e';
    return result;
}

int bmap_encoder::encoded_length() const
{
    // start at 2, for even empty maps have the 'd' ... 'e' identifiers at both ends
    int length = 2;
    for(const auto& entry : map_)
    {
        length += util::bencoded_string_length(entry.first);
        length += entry.second.value_.length();
    }
    return length;
}

// -----------
// -- blist -- 
// -----------

void blist_encoder::push_back(const int64_t i)
{
    std::string encoded = bencode_number(i);
    num_bytes_ += encoded.length();
    list_.emplace_back(std::move(encoded));
}

void blist_encoder::push_back(string_view s)
{
    std::string encoded = bencode_string(s);
    num_bytes_ += encoded.length();
    list_.emplace_back(std::move(encoded));
}

void blist_encoder::push_back(const blist_encoder& l)
{
    std::string encoded = l.encode();
    num_bytes_ += encoded.length();
    list_.emplace_back(std::move(encoded));
}

void blist_encoder::push_back(const bmap_encoder& m)
{
    std::string encoded = m.encode();
    num_bytes_ += encoded.length();
    list_.emplace_back(std::move(encoded));
}

std::string blist_encoder::encode() const
{
    std::string result(encoded_length(), 0);
    result.front() = 'l';
    int i = 1;
    for(auto& s : list_)
    {
        std::copy(s.begin(), s.end(), &result[i]);
        i += s.length();
    }
    result.back() = 'e';
    return result;
}

} // namespace tide
