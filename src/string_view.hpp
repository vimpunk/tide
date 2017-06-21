#ifndef TORRENT_STRING_VIEW_HEADER
#define TORRENT_STRING_VIEW_HEADER

#include "view.hpp"

#include <algorithm>
#include <ostream>
#include <string>

namespace tide {

// TODO
struct string_view : public const_view<std::string::value_type>
{
    string_view() = default;
    string_view(pointer str, size_type length) : view(str, length) {}
    string_view(pointer begin, pointer end) : view(begin, end) {}
    string_view(const char* s) : string_view(std::string(s)) {}
    string_view(const std::string& s) : string_view(s.c_str(), s.length()) {}

    operator std::string() const
    {
        return std::string(begin(), end());
    }
};

inline bool operator==(const string_view& v, const std::string& s) noexcept
{
    return std::equal(v.cbegin(), v.cend(), s.cbegin(), s.cend());
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

inline std::ostream& operator<<(std::ostream& out, const string_view& v)
{
    out << static_cast<std::string>(v);
    return out;
}

} // namespace tide

#endif // TORRENT_STRING_VIEW_HEADER
