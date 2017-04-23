#ifndef TORRENT_STRING_UTILS_HEADER
#define TORRENT_STRING_UTILS_HEADER

#include <algorithm>
#include <string>
#include <cctype> // isspace

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

#endif // TORRENT_STRING_UTILS_HEADER
