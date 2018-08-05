#ifndef TIDE_INTERVAL_HEADER
#define TIDE_INTERVAL_HEADER

namespace tide {

struct interval
{
    int begin = 0;
    int end = 0;

    interval() = default;
    interval(int begin_, int end_) : begin(begin_), end(end_) {}

    bool empty() const noexcept { return length() == 0; }

    int length() const noexcept { return end - begin; }

    bool contains(const interval& other) const noexcept
    {
        return (other.begin >= begin) && (other.end <= end);
    }
};

inline bool operator<(const interval& a, const interval& b) noexcept
{
    return a.begin == b.begin ? a.end < b.end : a.begin < b.begin;
}

inline bool operator==(const interval& a, const interval& b) noexcept
{
    return (a.begin == b.begin) && (a.end == b.end);
}

inline bool operator!=(const interval& a, const interval& b) noexcept
{
    return !(a == b);
}

} // namespace tide

#include <functional>

namespace std {

template <>
struct hash<tide::interval>
{
    size_t operator()(const tide::interval& i) const noexcept
    {
        return std::hash<int>()(i.begin) * (101 ^ std::hash<int>()(i.end)) * 31 + 51;
    }
};

} // namespace std

#endif // TIDE_INTERVAL_HEADER
