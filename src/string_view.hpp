#ifndef TORRENT_STRING_VIEW_HEADER
#define TORRENT_STRING_VIEW_HEADER

#include "view.hpp"

#include <string>

// TODO
struct string_view : public const_view<std::string::value_type>
{
    string_view(pointer str, size_type length) : view(str, length) {}
    string_view(const std::string& s) : string_view(s.c_str(), s.length()) {}

    operator std::string() const
    {
        return std::string(begin(), end());
    }
};

#endif // TORRENT_STRING_VIEW_HEADER
