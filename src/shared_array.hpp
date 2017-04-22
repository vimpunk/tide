#include <memory>
#include <iterator>

template<
    typename T,
    typename Allocator = std::allocator<T>
> class shared_array
{
    std::shared_ptr<T> m_data;

    using deleter = std::default_delete<T[]>;

public:

    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type*;
    using const_pointer = const pointer;
    using reference = value_type&;
    using const_reference = const reference;
    using iterator = pointer;
    using const_iterator = const_pointer;
    using reverse_iterator = std::reverse_iterator<iterator>;
    using reverse_const_iterator = std::reverse_iterator<const_iterator>;

    template<typename U>
    explicit shared_array(U* p) : m_data(p, deleter(), Allocator()) {}

    pointer get() const noexcept
    {
        return m_data.get()
    }

    value_type operator*()
    {
        return *m_data;
    }

    pointer operator->()
    {
        return &*m_data;
    }

    int use_count() const noexcept
    {
        return m_data.use_count();
    }

    operator bool() const noexcept
    {
        return m_data;
    }

    reference operator[](const size_type i) const noexcept
    {
        return get()[i];
    }

    const_reference operator[](const size_type i) const noexcept
    {
        return get()[i];
    }
};
