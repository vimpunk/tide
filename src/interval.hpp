#ifndef TORRENT_INTERVAL_HEADER
#define TORRENT_INTERVAL_HEADER

/** Represents a left inclusive interval. */
struct interval
{
    int begin;
    int end;

    interval(int begin_, int end_) : begin(begin_), end(end_) {}

    int length() const noexcept
    {
        return end - begin;
    }

    bool contains(const interval& other) const noexcept
    {
        return (other.begin >= begin) && (other.end <= end);
    }
};

inline bool operator<(const interval& a, const interval& b) noexcept
{
    return a.begin == b.begin ? a.end   < b.end
                              : a.begin < b.begin;
}

inline bool operator==(const interval& a, const interval& b) noexcept
{
    return (a.begin == b.begin) && (a.end == b.end);
}

inline bool operator!=(const interval& a, const interval& b) noexcept
{
    return !(a == b);
}

#include <functional>

namespace std
{
    template<> struct hash<interval>
    {
        size_t operator()(const interval& i) const noexcept
        {
            return std::hash<int>()(i.begin) * (101 ^ std::hash<int>()(i.end)) * 31 + 51;
        }
    };
} // namespace std

#endif // TORRENT_INTERVAL_HEADER
