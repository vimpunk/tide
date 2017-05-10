#ifndef TORRENT_STRING_VIEW_HEADER
#define TORRENT_STRING_VIEW_HEADER

#include "view.hpp"

#include <algorithm>
#include <string>

// TODO
struct string_view : public const_view<std::string::value_type>
{
    string_view() = default;
    string_view(pointer str, size_type length) : view(str, length) {}
    string_view(const std::string& s) : string_view(s.c_str(), s.length()) {}

    operator std::string() const
    {
        return std::string(begin(), end());
    }
};

inline bool operator==(const string_view& v, const std::string& s) noexcept
{
    // TODO check if std::equal checks for iterator lengths as well
    return v.length() == s.length()
        && std::equal(v.cbegin(), v.cend(), s.cbegin(), s.cend());
}

inline bool operator==(const std::string& s, const string_view& v) noexcept
{
    return v == s;
}

inline bool operator!=(const string_view& v, const std::string& s) noexcept
{
    return !(v == s);
}

inline bool operator!=(const std::string& s, const string_view& v) noexcept
{
    return !(v == s);
}

#endif // TORRENT_STRING_VIEW_HEADER
