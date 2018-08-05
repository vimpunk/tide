#ifndef TIDE_VIEW_HEADER
#define TIDE_VIEW_HEADER

#include <array>
#include <functional>
#include <iterator>
#include <type_traits>

namespace tide {

/**
 * A memory view that takes a pointer and a length and provides basic container like
 * operations, but does not take ownership of the resource.
 * Credit for the idea goes to libtorrent.
 */
template <typename T>
struct view
{
    using value_type = T;
    using difference_type = std::ptrdiff_t;
    using size_type = size_t;
    using reference = value_type&;
    using const_reference = const value_type&;
    using pointer = value_type*;
    using const_pointer = const value_type*;
    using iterator = pointer;
    using const_iterator = const_pointer;
    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

private:
    pointer data_ = nullptr;
    size_type length_ = 0;

public:
    view() = default;

    constexpr view(pointer data, size_type length) : data_(data), length_(length) {}

    constexpr view(pointer begin, pointer end) : data_(begin), length_(end - begin) {}

    template <typename U>
    constexpr view(view<U>& other) : data_(other.data()), length_(other.length())
    {}

    template <typename U, size_type N>
    constexpr view(std::array<U, N>& arr) : data_(arr.data()), length_(arr.size())
    {}

    template <typename U, size_type N>
    constexpr view(U (&arr)[N]) : data_(&arr[0]), length_(N)
    {}

    template <typename Container, typename = decltype(std::declval<Container>().data())>
    view(Container& c) : data_(c.data()), length_(c.size())
    {}

    constexpr size_type size() const noexcept { return length(); }
    constexpr size_type length() const noexcept { return length_; }
    constexpr bool empty() const noexcept { return length() == 0; }

    constexpr pointer data() noexcept { return data_; }
    constexpr const_pointer data() const noexcept { return data_; }

    constexpr reference front() noexcept { return *data(); }
    constexpr const_reference front() const noexcept { return *data(); }

    constexpr reference back() noexcept { return data_[length_ - 1]; }
    constexpr const_reference back() const noexcept { return data_[length_ - 1]; }

    constexpr iterator begin() noexcept { return data(); }
    constexpr const_iterator begin() const noexcept { return data(); }
    constexpr const_iterator cbegin() const noexcept { return begin(); }

    constexpr iterator end() noexcept { return begin() + size(); }
    constexpr const_iterator end() const noexcept { return begin() + size(); }
    constexpr const_iterator cend() const noexcept { return end(); }

    constexpr reverse_iterator rbegin() noexcept { return reverse_iterator(end()); }
    constexpr const_reverse_iterator rbegin() const noexcept
    {
        return const_reverse_iterator(end());
    }
    constexpr const_reverse_iterator crbegin() const noexcept { return rbegin(); }

    constexpr reverse_iterator rend() noexcept { return reverse_iterator(begin()); }
    constexpr const_reverse_iterator rend() const noexcept
    {
        return const_reverse_iterator(begin());
    }
    constexpr const_reverse_iterator crend() const noexcept { return rend(); }

    constexpr reference operator[](const size_type i) noexcept { return data_[i]; }
    constexpr const_reference operator[](const size_type i) const noexcept
    {
        return data_[i];
    }

    constexpr view subview(const size_type offset)
    {
        if(offset > size()) {
            throw std::out_of_range("tried to create a subview that is larger than view");
        }
        return {data() + offset, size() - offset};
    }

    constexpr view subview(const size_type offset, const size_type count)
    {
        if((offset > size()) || (offset + count > size())) {
            throw std::out_of_range("tried to create a subview that is larger than view");
        }
        return {data() + offset, count};
    }

    constexpr void trim_front(const size_type n)
    {
        if(n > size()) {
            throw std::out_of_range(
                    "tried to trim more from front of view than its size");
        }
        data_ += n;
        length_ -= n;
    }

    constexpr void trim_back(const size_type n)
    {
        if(n > size()) {
            throw std::out_of_range("tried to trim more from back of view than its size");
        }
        length_ -= n;
    }
};

template <typename T>
using const_view = view<const T>;

namespace util {

/** Used to test if two views are the same, even if one is const. */
template <typename T, typename U>
struct is_same
{
    static constexpr bool value = std::is_same<typename std::decay<T>::type,
            typename std::decay<U>::type>::value;
};

} // namespace util

template <typename T, typename U,
        typename = typename std::enable_if<util::is_same<T, U>::value>::type>
constexpr bool operator==(const view<T>& a, const view<U>& b) noexcept
{
    return (a.data() == b.data()) && (a.size() == b.size());
}

template <typename T, typename U>
constexpr bool operator!=(const view<T>& a, const view<U>& b) noexcept
{
    return !(a == b);
}

template <typename T, typename U,
        typename = typename std::enable_if<util::is_same<T, U>::value>::type>
constexpr bool operator<(const view<T>& a, const view<U>& b) noexcept
{
    if(a.data() == b.data()) {
        return a.size() < b.size();
    }
    return a.data() < b.data();
}

template <typename T, typename U,
        typename = typename std::enable_if<util::is_same<T, U>::value>::type>
constexpr bool operator>(const view<T>& a, const view<U>& b) noexcept
{
    if(a.data() == b.data()) {
        return a.size() > b.size();
    }
    return a.data() > b.data();
}

template <typename T, typename U>
constexpr bool operator<=(const view<T>& a, const view<U>& b) noexcept
{
    return !(a > b);
}

template <typename T, typename U>
constexpr bool operator>=(const view<T>& a, const view<U>& b) noexcept
{
    return !(a < b);
}

} // namespace tide

namespace std {

template <typename T>
struct hash<tide::view<T>>
{
    size_t operator()(const tide::view<T>& v) const noexcept
    {
        return std::hash<typename tide::view<T>::const_pointer>()(v.data()) * 31
                + std::hash<typename tide::view<T>::size_type>()(v.size())
                ^ 51 + 101;
    }
};

} // namespace std

#endif // TIDE_VIEW_HEADER
