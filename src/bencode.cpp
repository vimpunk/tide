#include "bencode.hpp"

#include <stdexcept>
#include <iostream>

namespace tide {

inline int bencoded_string_length(const std::string& s)
{
    return s.length() + std::to_string(s.length()).length() + 1; /* + 1 for : */
}

template<typename OutputIt>
int bencode_string(const std::string& s, OutputIt begin)
{
    std::string len_str = std::to_string(s.length());
    const int encoded_len = s.length() + len_str.length() + 1; /* + 1 for : */
    std::copy(len_str.begin(), len_str.end(), begin);
    begin += len_str.length();
    *begin++ = ':';
    std::copy(s.begin(), s.end(), begin);
    return encoded_len;
}

// -------------
// -- bnumber -- 
// -------------

std::string bnumber_encoder::encode() const
{
    return 'i' + std::to_string(number) + 'e';
}

int bnumber_encoder::encode(std::string::iterator begin, std::string::iterator end) const
{
    if(end - begin < encoded_length())
    {
        throw std::invalid_argument("not enough space to bencode bnumber");
    }
    auto it = begin;
    *it++ = 'i';
    // TODO avoid creating a string here and manually write number to output it
    std::string num_str = std::to_string(number);
    std::copy(num_str.begin(), num_str.end(), it);
    it += num_str.length();
    *it++ = 'e';
    return it - begin;
}

int bnumber_encoder::encoded_length() const
{
    return 2 + std::to_string(number).length();
}

// -------------
// -- bstring -- 
// -------------

std::string bstring_encoder::encode() const
{
    std::string s(encoded_length(), 0);
    encode(s.begin(), s.end());
    return s;
}

int bstring_encoder::encode(std::string::iterator begin, std::string::iterator end) const
{
    if(end - begin < encoded_length())
    {
        throw std::invalid_argument("not enough space to bencode bstring");
    }
    return bencode_string(string, begin);
}

int bstring_encoder::encoded_length() const
{
    return bencoded_string_length(string);
}

// ----------
// -- bmap -- 
// ----------

bmap_encoder::bmap_encoder(const bmap_encoder& other) : m_num_bytes(other.m_num_bytes)
{
    for(const auto& entry : other.m_map)
    {
        if(dynamic_cast<const bnumber_encoder*>(entry.second.get()))
        {
            m_map.emplace(entry.first, std::make_unique<bnumber_encoder>(
                *static_cast<const bnumber_encoder*>(entry.second.get())));
        }
        else if(dynamic_cast<const bstring_encoder*>(entry.second.get()))
        {
            m_map.emplace(entry.first, std::make_unique<bstring_encoder>(
                *static_cast<const bstring_encoder*>(entry.second.get())));
        }
        else if(dynamic_cast<const bmap_encoder*>(entry.second.get()))
        {
            m_map.emplace(entry.first, std::make_unique<bmap_encoder>(
                *static_cast<const bmap_encoder*>(entry.second.get())));
        }
        else if(dynamic_cast<const blist_encoder*>(entry.second.get()))
        {
            m_map.emplace(entry.first, std::make_unique<blist_encoder>(
                *static_cast<const blist_encoder*>(entry.second.get())));
        }
    }
}

bmap_encoder& bmap_encoder::operator=(const bmap_encoder& other)
{
    if(this != &other)
    {
        *this = bmap_encoder(other);
    }
    return *this;
}

void bmap_encoder::insert(std::string key, std::unique_ptr<bencoder> bencoder)
{
    m_num_bytes += bencoded_string_length(key);
    m_num_bytes += bencoder->encoded_length();
    m_map.emplace(std::move(key), std::move(bencoder));
}

std::string bmap_encoder::encode() const
{
    std::string result(encoded_length(), 0);
    encode(result.begin(), result.end());
    return result;
}

int bmap_encoder::encode(std::string::iterator begin, std::string::iterator end) const
{
    if(end - begin < encoded_length())
    {
        throw std::invalid_argument("not enough space to bencode bmap");
    }
    auto it = begin;
    *it++ = 'd';
    for(const auto& entry : m_map)
    {
        it += bencode_string(entry.first, it);
        it += entry.second->encode(it, end);
    }
    *it++ = 'e';
    return it - begin;
}

// -----------
// -- blist -- 
// -----------

blist_encoder::blist_encoder(const blist_encoder& other) : m_num_bytes(other.m_num_bytes)
{
    for(const auto& entry : other.m_list)
    {
        if(dynamic_cast<const bnumber_encoder*>(entry.get()))
        {
            m_list.emplace_back(std::make_unique<bnumber_encoder>(
                *static_cast<const bnumber_encoder*>(entry.get())));
        }
        else if(dynamic_cast<const bstring_encoder*>(entry.get()))
        {
            m_list.emplace_back(std::make_unique<bstring_encoder>(
                *static_cast<const bstring_encoder*>(entry.get())));
        }
        else if(dynamic_cast<const blist_encoder*>(entry.get()))
        {
            m_list.emplace_back(std::make_unique<blist_encoder>(
                *static_cast<const blist_encoder*>(entry.get())));
        }
        else if(dynamic_cast<const blist_encoder*>(entry.get()))
        {
            m_list.emplace_back(std::make_unique<blist_encoder>(
                *static_cast<const blist_encoder*>(entry.get())));
        }
    }
}

blist_encoder& blist_encoder::operator=(const blist_encoder& other)
{
    if(this != &other)
    {
        *this = blist_encoder(other);
    }
    return *this;
}

void blist_encoder::push_front(std::unique_ptr<bencoder> bencoder)
{
    m_num_bytes += bencoder->encoded_length();
    m_list.emplace(m_list.begin(), std::move(bencoder));
}

void blist_encoder::push_back(std::unique_ptr<bencoder> bencoder)
{
    m_num_bytes += bencoder->encoded_length();
    m_list.emplace_back(std::move(bencoder));
}

std::string blist_encoder::encode() const
{
    std::string result(encoded_length(), 0);
    encode(result.begin(), result.end());
    return result;
}

int blist_encoder::encode(std::string::iterator begin, std::string::iterator end) const
{
    if(end - begin < encoded_length())
    {
        throw std::invalid_argument("not enough space to bencode blist");
    }
    auto it = begin;
    *it++ = 'l';
    for(auto& belement : m_list)
    {
        it += belement->encode(it, end);
    }
    *it++ = 'e';
    return it - begin;
}

} // namespace tide
