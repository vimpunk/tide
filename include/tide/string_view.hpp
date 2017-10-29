#ifndef TIDE_STRING_VIEW_HEADER
#define TIDE_STRING_VIEW_HEADER

#include "view.hpp"

#include <algorithm>
#include <ostream>
#include <string>

namespace tide {

// TODO consider using std::string_view from std::experimental
struct string_view : public const_view<std::string::value_type>
{
    string_view() = default;
    template<typename T> string_view(view<T> v) : view(v) {}
    string_view(pointer str, size_type length) : view(str, length) {}
    string_view(pointer begin, pointer end) : view(begin, end) {}
    string_view(const char* s) : string_view(std::string(s)) {}
    string_view(const std::string& s) : string_view(s.c_str(), s.length()) {}

    operator std::string() const
    {
        return std::string(begin(), end());
    }
};

constexpr bool operator==(const string_view& a, const string_view& b) noexcept
{
    return (a.data() == b.data()) && (a.size() == b.size());
}

constexpr bool operator!=(const string_view& a, const string_view& b) noexcept
{
    return !(a == b);
}

constexpr bool operator<(const string_view& a, const string_view& b) noexcept
{
    if(a.data() == b.data()) { return a.size() < b.size(); }
    return a.data() < b.data();
}

constexpr bool operator>(const string_view& a, const string_view& b) noexcept
{
    if(a.data() == b.data()) { return a.size() > b.size(); }
    return a.data() > b.data();
}

constexpr bool operator<=(const string_view& a, const string_view& b) noexcept
{
    return !(a > b);
}

constexpr bool operator>=(const string_view& a, const string_view& b) noexcept
{
    return !(a < b);
}

// std::string operators

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

// const char[] operators

template<size_t N>
bool operator==(const string_view& v, const char (&s)[N]) noexcept
{
    return std::equal(v.cbegin(), v.cend(), s, s + N);
}

template<size_t N>
bool operator==(const char (&s)[N], const string_view& v) noexcept
{
    return v == s;
}

template<size_t N>
bool operator!=(const string_view& v, const char (&s)[N]) noexcept
{
    return !(v == s);
}

template<size_t N>
bool operator!=(const char (&s)[N], const string_view& v) noexcept
{
    return !(v == s);
}

inline std::ostream& operator<<(std::ostream& out, const string_view& v)
{
    out << static_cast<std::string>(v);
    return out;
}

} // namespace tide

#endif // TIDE_STRING_VIEW_HEADER
