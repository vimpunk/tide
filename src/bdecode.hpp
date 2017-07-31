#ifndef TIDE_BDECODE_HEADER
#define TIDE_BDECODE_HEADER

#include "string_view.hpp"

#include <stdexcept>
#include <iterator>
#include <sstream>
#include <cstdlib> // atoi
#include <cstdint>
#include <cassert>
#include <string>
#include <memory>
#include <vector>

// TODO move as much as possible to source

namespace tide {

/** All the possible bencoded types. */
enum class btype
{
    // Encoded format: i<number>e, e.g.: i3244e
    number,
    // Encoded format: <len(str)>:<str>, e.g.: 6:string
    string,
    // Encoded format: l<elements>e, e.g.: l4:abcdi53452eli234ei234eee
    list,
    // Encoded format: d<<(str)key><value> pairs>e, and keys must be in lexicographical
    // order, e.g.: d4:eggsi324e4:spami432ee
    map
};

/**
 * Since parsing a bencoded string is not done by building a heterogenous tree of
 * bencode elements but rather by maintaining a shared_ptr to the encoded string and
 * only extracting elements on demand, some identifier is necessary with which we can
 * parse and construct the requested element from the source string. For this purpose
 * the btoken struct is used, which is aggregated in a flat sequence (array) of all the
 * other btokens describing the entire object tree, also kept in a shared_ptr for a
 * single decoded object tree.
 * This object describes where in the string the would-be element resides, where its
 * logical neighbour is (since the sequence is flat, just incrementing the pointer would
 * not correctly traverse the logical tree), and other info, see the comments below.
 */
struct btoken
{
    // Specifies the position in the bencoded string where this element resides.
    int offset = 0;

    // holds the distance till the next element's token in the tokens list
    // number | string: 0 if last or only element, otherwise always 1
    // map | list: the number of btokens till the first element that's not in list/map
    int next_item_array_offset = 0;

    // number: the total length of encoded string representing the number (i\d+e)
    // string: the length of the string header, i.e. the length value plus colon, so
    // must be at least 2
    // map: the number of key-value pairs (excluding the 'map' header token)
    // list: the number of elements in the list (excluding the 'list' header token), and
    // nested containers count as one element
    int length = 0;

    btype type;

    btoken() = default;

    explicit btoken(btype t, int o)
        : type(t)
        , offset(o)
    {
        if((type == btype::list) || (type == btype::map))
        {
            // container type belements' next element is the first element not contained
            // by them, so this must always be at least one
            next_item_array_offset = 1;
        }
    }
};

namespace detail {

class bcontainer;
void format_map(std::stringstream& ss, const bcontainer& map,
    const btoken* head = nullptr, int nesting_level = 0);
void format_list(std::stringstream& ss, const bcontainer& list,
    const btoken* head = nullptr, int nesting_level = 0);

/**
 * Defines common operations for container type bencode classes (list, map).
 * It holds a contiguous sequence of btokens and the raw bencoded string and provides
 * shared_ptr semantics, so for any given copy there exists only a single token list
 * and encoded string. Since all belements are read only, this avoids memory churn
 * and space overhead and is cache friendly.
 */
class bcontainer
{
    // This is the entire list of tokens, no matter if the container is nested and
    // only needs a subset of it. This is to always keep the reference count of
    // m_tokens (and m_encoded) at at least one. To refer to the actual start of the
    // container, use m_head.
    std::shared_ptr<std::vector<btoken>> m_tokens;
    std::shared_ptr<const std::string> m_encoded;

    // Both container types (list, map) have a head token that defines the start and
    // size of the container. m_head points into m_tokens, to the btoken that's the
    // conceptual head of this container.
    const btoken* m_head = nullptr;

protected:

    bcontainer() = default;

    /**
     * This ctor is called the first time a container is decoded from a bencoded
     * string, it stores the tokens buffer, the encoded string and initializes the
     * head of the container to the first element in the tokens buffer.
     */
    bcontainer(std::vector<btoken>&& tokens, std::string&& encoded)
        : m_tokens(std::make_shared<std::vector<btoken>>(std::move(tokens)))
        , m_encoded(std::make_shared<const std::string>(std::move(encoded)))
        , m_head(m_tokens->data())
    {
        assert(!m_tokens->empty());
    }

    /**
     * This ctor is called every time a nested container is extracted from its
     * enclosing container (regardless of actual type (list, map), because both use
     * only the fields in bcontainer, so slicing the derived containers is OK).
     */
    bcontainer(const bcontainer& b, const btoken* head)
        : m_tokens(b.m_tokens)
        , m_encoded(b.m_encoded)
        , m_head(head)
    {}

    /** Returns the head of this container. */
    const btoken* head() const noexcept
    {
        return m_head;
    }

    /**
     * Returns one past the last element of this container. If this is a nested
     * container, the pointer is likely valid, but if it's not, the pointer is
     * invalid. Therefore, NEVER DEREFERENCE.
     */
    const btoken* tail() const noexcept
    {
        return head() ? head() + head()->next_item_array_offset : nullptr;
    }

public:

    bcontainer(const bcontainer& other)
        : m_tokens(other.m_tokens)
        , m_encoded(other.m_encoded)
        , m_head(other.m_head)
    {}

    bcontainer(bcontainer&& other)
        : m_tokens(std::move(other.m_tokens))
        , m_encoded(std::move(other.m_encoded))
        , m_head(other.m_head)
    {
        other.m_head = nullptr;
    }

    bcontainer& operator=(const bcontainer& other)
    {
        if(this != &other)
        {
            m_tokens = other.m_tokens;
            m_encoded = other.m_encoded;
            m_head = other.m_head;
        }
        return *this;
    }

    bcontainer& operator=(bcontainer&& other)
    {
        if(this != &other)
        {
            m_tokens = std::move(other.m_tokens);
            m_encoded = std::move(other.m_encoded);
            m_head = std::move(other.m_head);
            other.m_head = nullptr;
        }
        return *this;
    }

    int size() const noexcept
    {
        return m_head ? m_head->length : 0;
    }

    bool empty() const noexcept
    {
        return size() == 0;
    }

    /** Returns a refernce to the raw bencoded string of the entire container. */
    const std::string& source() const noexcept
    {
        return *m_encoded;
    }

    /**
     * Returns a substring (view) of the portion of the source string that is the
     * current container. If this is the root container, the returned string is
     * identical to the source string. Note that no actual copies are made, so
     * calling this function is cheap.
     */
    string_view encode() const;

    friend void format_map(std::stringstream& ss, const bcontainer& map,
        const btoken* head, int nesting_level);
    friend void format_list(std::stringstream& ss, const bcontainer& list,
        const btoken* head, int nesting_level);
};

inline string_view make_string_view_from_token(
    const std::string& encoded, const btoken& token)
{
    assert(token.offset < encoded.length());
    const int str_length = std::atoi(&encoded[token.offset]);
    const int str_start = token.offset + token.length;
    assert(str_start + str_length <= encoded.length());
    return string_view(encoded.c_str() + str_start, str_length);
}

inline
std::string make_string_from_token(const std::string& encoded, const btoken& token)
{
    return make_string_view_from_token(encoded, token);
}

inline int64_t make_number_from_token(const std::string& encoded, const btoken& token)
{
    assert(token.offset < encoded.length());
    return atol(encoded.c_str() + token.offset + 1);
}

} // namespace detail

/**
 * This is the base class which all bencode types must extend. Its sole purpose is to
 * identify the type (number, string, list, map) to which it can then be cast.
 */
struct belement
{
    belement() = default;
    virtual ~belement() = default;
    belement(const belement&) = default;
    belement(belement&&) = default;
    belement& operator=(const belement&) = default;
    belement& operator=(belement&&) = default;

    virtual btype type() const noexcept = 0;
};

/**
 * The following two classes (bnumber and bstring) are used solely when the input
 * encoded string contains a single bencoded number ("i123e") or string ("3:abc").
 * Containers do not use them, for values in containers are only parsed from the source
 * string and constructed when explicitly requested. This is only used so that decode()
 * can return a bencode object even if the input string contains a single string or
 * number.
 */

namespace detail
{
    template<typename T, btype Type> class bprimitive : public belement
    {
        T m_data;
    public:
        bprimitive() = default;
        bprimitive(T t) : m_data(t) {}
        btype type() const noexcept override { return Type; }
        operator T() const noexcept { return m_data; }
    };
}

struct bnumber final : public detail::bprimitive<int64_t, btype::number>
{
    bnumber() = default;
    bnumber(int64_t n) : bprimitive(n) {}
};

struct bstring final : public detail::bprimitive<std::string, btype::string>
{
    bstring() = default;
    bstring(std::string s) : bprimitive(std::move(s)) {}
};

/**
 * The following two classes (blist, bmap) are containers, which means that they take
 * ownership of the original (bencoded) source string and btokens list, and only a
 * single instance of those are used by all subsequent nested container instances that
 * are extracted from the root container.
 * Therefore copying is relatively cheap with shared_ptr semantics, meaning that the
 * encoded source and btoken list are kept alive until the root or the last nested
 * container in root is destroyed.
 *
 * Values (strings and numbers) are only parsed when explicitly requested, in which case
 * the requested type is constructed from the value extracted from the source bencode
 * string and token list (this is why they are kept alive). This avoids needless memory
 * churn which would occur if every element were to be preparsed and allocated.
 *
 * Both structures are cache friendly, as both sources (token list and bencoded string)
 * are a single contiguous memory sequence. The drawback of this is that bmap cannot
 * provide O(logn) element lookup like a regular tree based map would, since it has
 * to traverse the token list to determine the elements in the source string.
 */

class bmap;

class blist final : public detail::bcontainer, public belement
{
    template<typename BType, btype TokenType> class list_proxy;

public:

    using numbers = list_proxy<int64_t, btype::number>;
    using strings = list_proxy<std::string, btype::string>;
    using string_views = list_proxy<string_view, btype::string>;
    using blists = list_proxy<blist, btype::list>;
    using bmaps = list_proxy<bmap, btype::map>;

    blist() = default;

    blist(std::vector<btoken>&& tokens, std::string&& encoded)
        : bcontainer(std::move(tokens), std::move(encoded))
    {}

    blist(const bcontainer& b, const btoken* list_head)
        : bcontainer(b, list_head)
    {}

    btype type() const noexcept override
    {
        return btype::list;
    }

    /** Returns a lazy iterable range of all numbers in this list. */
    numbers all_numbers() const
    {
        return numbers(*this);
    }

    /** Returns a lazy iterable range of all strings in this list. */
    strings all_strings() const
    {
        return strings(*this);
    }

    /**
     * Returns a lazy iterable range of views of all strings in this list, i.e. no
     * std::string is ever actually constructed. In almost all cases this should be
     * used over all_strings(), unless it is known that the extracted strings will
     * outlive its enclosing container. Even so, in most cases it is merely a quick
     * lookup that is done, so a string_view should be much faster. Moreover,
     * string_views will implicitly convert to a std::string, which makes interop
     * seamless.
     */
    string_views all_string_views() const
    {
        return string_views(*this);
    }

    /** Returns a lazy iterable range of all blist instances in this list. */
    blists all_blists() const
    {
        return blists(*this);
    }

    /** Returns a lazy iterable range of all bmap instances in this list. */
    bmaps all_bmaps() const
    {
        return bmaps(*this);
    }

    /** Returns a JSON-like, human readable string of this list. */
    std::string to_string() const
    {
        std::stringstream ss;
        detail::format_list(ss, *this);
        return ss.str();
    }

private:

    template<typename BType, btype TokenType> friend class list_proxy;

    /**
     * This is the iterable object that is returned by the getter functions. Its
     * iterator lazily filters the enclosing list for BType objects while iterating.
     *
     * NOTE: it must not outlive its enclosing blist.
     */
    template<
        typename BType,
        btype TokenType
    > class list_proxy
    {
        const blist& m_list;

    public:

        class const_iterator;

        using value_type = BType;
        using reference = const value_type&;
        using pointer = const value_type*;
        using iterator_category = std::forward_iterator_tag;

        list_proxy(const blist& list) : m_list(list) {}

        const_iterator begin() const noexcept
        {
            return cbegin();
        }

        const_iterator cbegin() const noexcept
        {
            if(!m_list.head())
            {
                return const_iterator(*this, nullptr);
            }

            const btoken* token = m_list.head();
            const btoken* const list_end = m_list.tail();

            assert(token->type == btype::list);

            // advance past the first element as that's the opening tag of the blist
            // (the result is either the first list element or list_end)
            ++token;
            // find the first element that matches TokenType or list_end
            while((token != list_end) && (token->type != TokenType))
            {
                token += token->next_item_array_offset;
            }
            return const_iterator(*this, token);
        }

        const_iterator end() const noexcept
        {
            return cend();
        }

        const_iterator cend() const noexcept
        {
            if(!m_list.head())
            {
                return const_iterator(*this, nullptr);
            }
            return const_iterator(*this, m_list.tail());
        }

        friend class const_iterator;

        /**
         * At any given time this iterator either points to an element of BType or to
         * the end of the list.
         */
        class const_iterator
        {
            const list_proxy* m_list_proxy;
            const btoken* m_pos;

        public:

            const_iterator() = default;

            /** pos must point to the first token in the list that matches TokenType. */
            const_iterator(const list_proxy& list_proxy, const btoken* pos)
                : m_list_proxy(&list_proxy)
                , m_pos(pos)
            {}

            template<typename T = BType>
            typename std::enable_if<
                std::is_same<T, int64_t>::value,
                int64_t
            >::type operator*()
            {
                return detail::make_number_from_token(
                    m_list_proxy->m_list.source(), *m_pos);
            }

            template<typename T = BType>
            typename std::enable_if<
                std::is_same<T, std::string>::value,
                std::string
            >::type operator*()
            {
                return detail::make_string_from_token(
                    m_list_proxy->m_list.source(), *m_pos);
            }

            template<typename T = BType>
            typename std::enable_if<
                std::is_same<T, string_view>::value,
                string_view
            >::type operator*()
            {
                return detail::make_string_view_from_token(
                    m_list_proxy->m_list.source(), *m_pos);
            }

            template<typename T = BType>
            typename std::enable_if<
                std::is_same<T, blist>::value,
                blist
            >::type operator*()
            {
                return blist(static_cast<detail::bcontainer>(
                    m_list_proxy->m_list), m_pos);
            }

            template<typename T = BType>
            typename std::enable_if<
                std::is_same<T, bmap>::value,
                bmap
            >::type operator*()
            {
                return bmap(static_cast<detail::bcontainer>(
                    m_list_proxy->m_list), m_pos);
            }

            pointer operator->() noexcept
            {
                return &operator*();
            }

            const_iterator& operator++() noexcept
            {
                if(m_pos)
                {
                    const btoken* list_end = m_list_proxy->m_list.tail();
                    do
                    {
                        m_pos += m_pos->next_item_array_offset;
                    }
                    while((m_pos != list_end) && (m_pos->type != TokenType));
                }
                return *this;
            }

            const_iterator operator++(int) noexcept
            {
                auto tmp(*this);
                operator++();
                return tmp;
            }

            friend
            bool operator==(const const_iterator& a, const const_iterator& b) noexcept
            {
                return a.m_pos == b.m_pos;
            }

            friend
            bool operator!=(const const_iterator& a, const const_iterator& b) noexcept
            {
                return a.m_pos != b.m_pos;
            }
        };
    };
};

class bmap final : public detail::bcontainer, public belement
{
public:

    bmap() = default;

    bmap(std::vector<btoken>&& tokens, std::string&& encoded)
        : bcontainer(std::move(tokens), std::move(encoded))
    {}

    bmap(const detail::bcontainer& b, const btoken* map_head)
        : bcontainer(b, map_head)
    {}

    btype type() const noexcept override
    {
        return btype::map;
    }

    int64_t find_number(const std::string& key) const
    {
        int64_t result;
        if(try_find_number(key, result))
        {
            return result;
        }
        throw std::invalid_argument(key + " not in bmap");
    }

    bool try_find_number(const std::string& key, int64_t& result) const
    {
        const auto token = find_token(key);
        if(!token || (token->type != btype::number))
        {
            return false;
        }
        result = detail::make_number_from_token(source(), *token);
        return true;
    }

    std::string find_string(const std::string& key) const
    {
        std::string result;
        if(try_find_string(key, result))
        {
            return result;
        }
        throw std::invalid_argument(key + " not in bmap");
    }

    bool try_find_string(const std::string& key, std::string& result) const
    {
        const auto token = find_token(key);
        if(!token || (token->type != btype::string))
        {
            return false;
        }
        result = detail::make_string_from_token(source(), *token);
        return true;
    }

    /**
     * Prefer the lookups of string_views over {try_,}find_string for better
     * performance. See comment in blist all_string_views.
     */
    string_view find_string_view(const std::string& key) const
    {
        string_view result;
        if(try_find_string_view(key, result))
        {
            return result;
        }
        throw std::invalid_argument(key + " not in bmap");
    }

    bool try_find_string_view(const std::string& key, string_view& result) const
    {
        const auto token = find_token(key);
        if(!token || (token->type != btype::string))
        {
            return false;
        }
        result = detail::make_string_view_from_token(source(), *token);
        return true;
    }


    blist find_blist(const std::string& key) const
    {
        blist result;
        if(try_find_blist(key, result))
        {
            return result;
        }
        throw std::invalid_argument(key + " not in bmap");
    }

    bool try_find_blist(const std::string& key, blist& result) const
    {
        const auto token = find_token(key);
        if(!token || (token->type != btype::list))
        {
            return false;
        }
        result = blist(*this, token);
        return true;
    }

    bmap find_bmap(const std::string& key) const
    {
        bmap result;
        if(try_find_bmap(key, result))
        {
            return result;
        }
        throw std::invalid_argument(key + " not in bmap");
    }

    bool try_find_bmap(const std::string& key, bmap& result) const
    {
        const auto token = find_token(key);
        if(!token || (token->type != btype::map))
        {
            return false;
        }
        result = bmap(*this, token);
        return true;
    }

    /**
     * Prefer the lookup methods specialized for each type if the type is known
     * beforehand, as those avoid a dynamic memory allocation.
     */
    std::unique_ptr<belement> operator[](const std::string& key) const
    {
        const auto token = find_token(key);
        if(!token)
        {
            return nullptr;
        }
        switch(token->type)
        {
        case btype::number:
            return std::make_unique<bnumber>(
                detail::make_number_from_token(source(), *token));
        case btype::string:
            return std::make_unique<bstring>(
                detail::make_string_from_token(source(), *token));
        case btype::list:
            return std::make_unique<blist>(
                static_cast<const detail::bcontainer&>(*this), token);
        case btype::map:
            return std::make_unique<bmap>(
                static_cast<const detail::bcontainer&>(*this), token);
        }
    }

    /** Returns a JSON-like, human readable string of this map. */
    std::string to_string() const
    {
        std::stringstream ss;
        detail::format_map(ss, *this);
        return ss.str();
    }

private:

    /**
     * Returns the first value in map (no matter at which level of nesting) whose key
     * matches the search key, or a nullptr if no match is found.
     *
     * Searching is linear in the number of tokens in m_tokens.
     *
     * start_pos must be a map token (i.e. a token with type == btype::map).
     */
    const btoken* find_token(const std::string& key,
        const btoken* start_pos = nullptr) const noexcept;

    /**
     * If list nested in this map (starting at token) has any nested maps, the search
     * for key is continued in them, otherwise nullptr is returned.
     */
    const btoken* find_token_in_list(
        const std::string& key, const btoken* token) const noexcept;
};

inline std::ostream& operator<<(std::ostream& out, const blist& b)
{
    return out << b.to_string();
}

inline std::ostream& operator<<(std::ostream& out, const bmap& b)
{
    return out << b.to_string();
}

/**
 * Decodes a bencoded dictionary into a bmap instance. This can be used for parsing
 * .torrent files.
 * The resulting bmap instance takes ownership of the intput string.
 */
bmap decode_bmap(std::string s);

/**
 * Decodes a bencoded list into a blist instance.
 * The resulting blist instance takes ownership of the intput string.
 */
blist decode_blist(std::string s);

/**
 * Returns one of the four bencode types. If the parsed type is a single bnumber or
 * bstring, the source string is discarded, whereas if the parsed type is a container,
 * the container takes ownership of the input string.
 */
std::unique_ptr<belement> decode(std::string s);

} // namespace tide

#endif // TIDE_BDECODE_HEADER
