#ifndef TORRENT_STRING_UTILS_HEADER
#define TORRENT_STRING_UTILS_HEADER

#include <algorithm>
#include <iterator> // begin, end
#include <string>
#include <cctype> // isspace

namespace detail
{
    inline void ltrim(std::string& s)
    {
        s.erase(
            s.begin(),
            std::find_if(
                s.begin(),
                s.end(),
                [](const auto& c)
                {
                    return !std::isspace(c);
                }
            )
        );
    }

    inline void rtrim(std::string& s)
    {
        s.erase(
            std::find_if(
                s.rbegin(),
                s.rend(),
                [](const auto& c)
                {
                    return !std::isspace(c);
                }
            ).base(),
            s.end()
        );
    }

    inline void trim(std::string& s)
    {
        ltrim(s);
        rtrim(s);
    }

    inline void to_lower(std::string& s)
    {
        std::transform(
            s.begin(),
            s.end(),
            s.begin(),
            [](const auto& c)
            {
                return std::tolower(c);
            }
        );
    }

    inline void to_upper(std::string& s)
    {
        std::transform(
            s.begin(),
            s.end(),
            s.begin(),
            [](const auto& c)
            {
                return std::toupper(c);
            }
        );
    }

    template<typename Bytes>
    std::string to_hex(const Bytes& data)
    {
        static constexpr char hex_chars[] = "0123456789abcdef";
        std::string hex_str;
        const size_t size = std::end(data) - std::begin(data);
        hex_str.reserve(size * 2);
        for(size_t i = 0; i < size; ++i)
        {
            const uint8_t byte = data[i];
            hex_str += hex_chars[byte >> 4];
            hex_str += hex_chars[byte & 0xf];
        }
        return hex_str;
    }

} // namespace detail

#endif // TORRENT_STRING_UTILS_HEADER
