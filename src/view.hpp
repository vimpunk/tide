#ifndef TORRENT_VIEW_HEADER
#define TORRENT_VIEW_HEADER

#include <type_traits>
#include <functional>
#include <iterator>
#include <array>

namespace tide {

/**
 * A memory view that takes a pointer and a length and provides basic container like
 * operations, but does not take ownership of the resource.
 * Credit for the idea goes to libtorrent.
 */
template<
    typename T
> struct view
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

    pointer m_data = nullptr;
    size_type m_length = 0;

public:

    view() = default;

    view(pointer data, size_type length)
        : m_data(data)
        , m_length(length)
    {}

    view(pointer begin, pointer end)
        : m_data(begin)
        , m_length(end - begin)
    {}

    template<typename U>
    view(const view<U>& other)
        : m_data(other.m_data)
        , m_length(other.m_length)
    {}

    template<typename U, size_type N>
    view(const std::array<U, N>& arr)
        : m_data(arr.data())
        , m_length(arr.size())
    {}

    template<typename U, size_type N>
    view(U (&arr)[N])
        : m_data(&arr[0])
        , m_length(N)
    {}

    template<
        typename Container,
        typename = decltype(std::declval<Container>().data())
    > view(Container& c)
        : m_data(c.data())
        , m_length(c.size())
    {}

    size_type size() const noexcept { return length(); }
    size_type length() const noexcept { return m_length; }
    bool is_empty() const noexcept { return length() == 0; }

    pointer data() noexcept { return m_data; }
    const_pointer data() const noexcept { return m_data; }

    reference front() noexcept { return *data(); }
    const_reference front() const noexcept { return *data(); }

    reference back() noexcept { return m_data[m_length - 1]; }
    const_reference back() const noexcept { return m_data[m_length - 1]; }

    iterator begin() noexcept { return data(); }
    const_iterator begin() const noexcept { return data(); }
    const_iterator cbegin() const noexcept { return begin(); }

    iterator end() noexcept { return begin() + size(); }
    const_iterator end() const noexcept { return begin() + size(); }
    const_iterator cend() const noexcept { return end(); }

    reverse_iterator rbegin() noexcept { return reverse_iterator(end()); }
    const_reverse_iterator rbegin() const noexcept
    { return const_reverse_iterator(end()); }
    const_reverse_iterator crbegin() const noexcept { return rbegin(); }

    reverse_iterator rend() noexcept { return reverse_iterator(begin()); }
    const_reverse_iterator rend() const noexcept
    { return const_reverse_iterator(begin()); }
    const_reverse_iterator crend() const noexcept { return rend(); }

    reference operator[](const size_type i) noexcept { return m_data[i]; }
    const_reference operator[](const size_type i) const noexcept { return m_data[i]; }

    view<T> subview(const size_type offset) const
    {
        if(offset > size())
        {
            throw std::out_of_range("tried to create a subview that is larger than view");
        }
        return { data() + offset, size() - offset };
    }

    view<T> subview(const size_type offset, const size_type count) const
    {
        if((offset > size()) || (offset + count > size()))
        {
            throw std::out_of_range("tried to create a subview that is larger than view");
        }
        return { data() + offset, count };
    }

    void trim_front(const size_type n)
    {
        if(n > size())
        {
            throw std::out_of_range("tried to trim more from front of view than its size");
        }
        m_data += n;
        m_length -= n;
    }

    void trim_back(const size_type n)
    {
        if(n > size())
        {
            throw std::out_of_range("tried to trim more from back of view than its size");
        }
        m_length -= n;
    }
};

/** A specialization of the above class which holds an immutable view to its resource. */
template<typename T> using const_view = view<const T>;

namespace util
{
    /** Used to test if two views are the same, even if one is const. */
    template<typename T, typename U> struct is_same
    {
        static constexpr bool value = std::is_same<
            typename std::decay<T>::type,
            typename std::decay<U>::type
        >::value;
    };
} // namespace util

template<
    typename T,
    typename U,
    typename = typename std::enable_if<util::is_same<T, U>::value, T>::type
> constexpr bool operator==(const view<T>& a, const view<U>& b) noexcept
{
    return (a.data() == b.data()) && (a.size() == b.size());
}

template<typename T, typename U>
constexpr bool operator!=(const view<T>& a, const view<U>& b) noexcept
{
    return !(a == b);
}

template<
    typename T,
    typename U,
    typename = typename std::enable_if<util::is_same<T, U>::value, T>::type
> constexpr bool operator<(const view<T>& a, const view<U>& b) noexcept
{
    if(a.data() == b.data())
    {
        return a.size() < b.size();
    }
    return a.data() < b.data();
}

template<
    typename T,
    typename U,
    typename = typename std::enable_if<util::is_same<T, U>::value, T>::type
> constexpr bool operator>(const view<T>& a, const view<U>& b) noexcept
{
    if(a.data() == b.data())
    {
        return a.size() > b.size();
    }
    return a.data() > b.data();
}

template<typename T, typename U>
constexpr bool operator<=(const view<T>& a, const view<U>& b) noexcept
{
    return !(a > b);
}

template<typename T, typename U>
constexpr bool operator>=(const view<T>& a, const view<U>& b) noexcept
{
    return !(a < b);
}

} // namespace tide

namespace std
{
    template<typename T> struct hash<tide::view<T>>
    {
        size_t operator()(const tide::view<T>& v) const noexcept
        {
            return std::hash<typename tide::view<T>::const_pointer>()(v.data()) * 31
                 + std::hash<typename tide::view<T>::size_type>()(v.size()) ^ 51
                 + 101;
        }
    };
} // namespace std

#endif // TORRENT_VIEW_HEADER
