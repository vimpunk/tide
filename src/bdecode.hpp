#ifndef TORRENT_BDECODE_HEADER
#define TORRENT_BDECODE_HEADER

#include <stdexcept>
#include <iterator>
#include <cstdlib> // atoi
#include <cstdint>
#include <cassert>
#include <string>
#include <memory>
#include <vector>

enum class btype
{
    number,
    string,
    list,
    map
};

struct btoken
{
    // Specifies the position in the bencoded string where this element resides.
    int offset = 0;

    // holds the distance till the next element's token in the tokens list
    // number | string: 0 if last or only element, otherwise always 1
    // map | list: the number of btokens till the first element that's not in list/map
    int next_item_array_offset = 0;
    // number: the total length of the match of this regex: i-?\d+e
    // string: the length of the string header, i.e. the length value plus colon, so
    // must be at least 2
    // map: the number of key-value pairs (excluding the 'map' header token)
    // list: the number of elements in the list (excluding the 'list' header token)
    int length = 0;

    btype type;

    btoken() = default;

    explicit btoken(btype t, int o) : type(t), offset(o)
    {
        if((type == btype::list) || (type == btype::map))
        {
            // container type belements' next element is the first element not contained
            // by them, so this must always be at least one
            next_item_array_offset = 1;
        }
    }
};

namespace detail
{
    /**
     * Defines common operations for container type bencode classes (list, map).
     * It holds a contiguous sequence of btokens and the raw bencoded string and provides
     * shared_ptr semantics, so for any given copy there exists only a single token list
     * and encoded string. Since all belements are read only, this avoids memory churn
     * and space overhead.
     */
    class bcontainer
    {
        // This is the entire list of tokens, no matter if the container is nested and
        // only needs to a subset of it. This is to always keep the reference count of
        // m_tokens (and m_encoded) at at least one. To refer to the actual start of the
        // container, use m_head.
        std::shared_ptr<const btoken> m_tokens;
        std::shared_ptr<const std::string> m_encoded;

        // Both container types (list, map) have a head token that defines the start and
        // size of the container. m_head points into m_tokens, to the btoken that's the
        // head of this container.
        const btoken* m_head = nullptr;

    protected:

        /**
         * This ctor is called the first time a container is decoded from a bencoded
         * string, it stores the tokens buffer, the encoded string and initializes the
         * head of the container to the first element in the tokens buffer.
         */
        bcontainer(const btoken* tokens, std::string&& encoded)
            : m_tokens(tokens, std::default_delete<const btoken[]>())
            , m_encoded(std::make_shared<const std::string>(std::move(encoded)))
            , m_head(tokens)
        {}

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
            assert(m_head);
            return m_head + m_head->next_item_array_offset;
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
            return m_head ? m_head->length
                          : 0;
        }

        bool is_empty() const noexcept
        {
            return size() == 0;
        }

        /** Returns a refernce to the raw bencoded string of the entire container. */
        const std::string& encoded() const noexcept
        {
            return *m_encoded;
        }

        /**
         * If this is a nested container, it creates and returns a substring from the
         * encoded string that belongs to this container. Otherwise (container is the
         * root container), it just returns a copy of the encoded string (although in
         * this case it is recommended to just use encoded() to avoid the copy).
         */
        std::string encode() const
        {
            // TODO verify this
            if(!head())
            {
                return "";
            }
            if(head() == m_tokens.get())
            {
                // this is the root container, just return the whole encoded string
                return encoded();
            }
            const btoken* last_element = tail() - 1;
            int last_element_offset = last_element->offset;
            if(last_element->type == btype::string)
            {
                const auto str_header = encoded().c_str() + last_element_offset;
                const auto str_length = std::atoi(str_header);
                last_element_offset += last_element->length + str_length;
            }
            else if(last_element->type == btype::number)
            {
                last_element_offset += last_element->length;
            }
            else if(last_element->type == btype::list
                    && last_element->type == btype::map)
            {
                // if last element is a blist or bmap header token, it means they are
                // empty, so they only have 2 characters: the header tag ('l') and the end
                // tag ('e')
                last_element_offset += 2;
            }
            return std::string(
                encoded().c_str() + head()->offset,
                encoded().c_str() + last_element_offset + 1
            );
        }
    };

    inline
    std::string make_string_from_token(const std::string& encoded, const btoken& token)
    {
        assert(token.offset < encoded.length());
        const int str_length = std::atoi(&encoded[token.offset]);
        const int str_start = token.offset + token.length;
        assert(str_start + str_length <= encoded.length());
        return std::string(encoded, str_start, str_length);
    }

    inline
    int64_t make_number_from_token(const std::string& encoded, const btoken& token)
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

class bnumber : public belement
{
    int64_t m_data = 0;

public:

    bnumber(int64_t i) : m_data(i) {}

    btype type() const noexcept override
    {
        return btype::number;
    }

    operator int64_t() const noexcept
    {
        return m_data;
    }
};

class bstring : public belement
{
    std::string m_data;

public:

    bstring(std::string s) : m_data(std::move(s)) {}

    btype type() const noexcept override
    {
        return btype::string;
    }

    operator std::string() const noexcept
    {
        return m_data;
    }
};

/**
 * The following two classes (blist, bmap) are containers, which means that they take
 * ownership of the original (bencoded) source string and btokens list, and only these
 * instances are used by all subsequent nested container instances that are extracted
 * from the root container.
 * Therefore copying is relatively cheap with shared_ptr semantics, meaning that the
 * encoded source and btoken list are kept valid until this or the last nested container
 * extracted from this container is destroyed.
 *
 * Values (strings and numbers) are only parsed when explicitly requested, in which case
 * the requested type is constructed from the value extracted from the source bencode
 * string and token list (this is why they are kept alive). This avoids needless memory
 * churn which would occur if every element were to be preparsed and allocated.
 *
 * Both structures are cache friendly, as the two sources (token list and bencoded
 * string) are both a single contiguous memory sequence. The drawback of this is that
 * bmap cannot provide O(logn) like a regular tree based map would.
 */

struct bmap;

class blist
    : public detail::bcontainer
    , public belement
{
    template<typename BType, btype TokenType> class list_proxy;

public:

    using numbers = list_proxy<int64_t, btype::number>;
    using strings = list_proxy<std::string, btype::string>;
    using blists = list_proxy<blist, btype::list>;
    using bmaps = list_proxy<bmap, btype::map>;

    blist(const btoken* tokens, std::string&& encoded)
        : bcontainer(tokens, std::move(encoded))
    {}

    blist(const bcontainer& b, const btoken* list_head)
        : bcontainer(b, list_head)
    {}

    btype type() const noexcept override
    {
        return btype::list;
    }

    /** Returns a lazy iterable range of all numbers in this list. */
    numbers get_numbers()
    {
        return numbers(*this);
    }

    /** Returns a lazy iterable range of all strings in this list. */
    strings get_strings()
    {
        return strings(*this);
    }

    /** Returns a lazy iterable range of all blist instances in this list. */
    blists get_blists()
    {
        return blists(*this);
    }

    /** Returns a lazy iterable range of all bmap instances in this list. */
    bmaps get_bmaps()
    {
        return bmaps(*this);
    }

    /** Returns a JSON-like, human readable string of this list. */
    std::string to_string() const
    {
        std::string s;
        s += '[';
        if(head())
        {
            const btoken* token = head() + 1;
            const btoken* const list_end = tail();
            while(token != list_end)
            {
                switch(token->type)
                {
                case btype::number:
                    break;
                case btype::string:
                    break;
                case btype::list:
                    break;
                case btype::map:
                    break;
                }
                token += token->next_item_array_offset;
            }
        }
        return s += ']';
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
            const btoken* token = m_list.head();
            const btoken* const list_end = m_list.tail();

            assert(token && token->type == btype::list);

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
            assert(m_list.head());
            return const_iterator(*this, m_list.tail());
        }

    public:

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
                    m_list_proxy->m_list.encoded(), *m_pos
                );
            }

            template<typename T = BType>
            typename std::enable_if<
                std::is_same<T, std::string>::value,
                std::string
            >::type operator*()
            {
                return detail::make_string_from_token(
                    m_list_proxy->m_list.encoded(), *m_pos
                );
            }

            template<typename T = BType>
            typename std::enable_if<
                std::is_same<T, blist>::value,
                blist
            >::type operator*()
            {
                return blist(
                    static_cast<detail::bcontainer>(m_list_proxy->m_list), m_pos
                );
            }

            template<typename T = BType>
            typename std::enable_if<
                std::is_same<T, bmap>::value,
                bmap
            >::type operator*()
            {
                return bmap(
                    static_cast<detail::bcontainer>(m_list_proxy->m_list), m_pos
                );
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

struct bmap
    : public detail::bcontainer
    , public belement
{
    bmap(const btoken* tokens, std::string&& encoded)
        : bcontainer(tokens, std::move(encoded))
    {}

    bmap(const detail::bcontainer& b, const btoken* map_head)
        : bcontainer(b, map_head)
    {}

    btype type() const noexcept override
    {
        return btype::map;
    }

    // TODO not finding an element shouldn't result in an exception, think of a good
    // way to return back an invalid element. iterators?

    std::string find_string(const std::string& key)
    {
        const auto token = find_token(key);
        if(!token)
        {
            return "";
        }
        return detail::make_string_from_token(encoded(), *token);
    }

    int64_t find_number(const std::string& key)
    {
        const auto token = find_token(key);
        if(!token)
        {
            return -1;
        }
        return detail::make_number_from_token(encoded(), *token);
    }

    blist find_blist(const std::string& key)
    {
        return blist(*this, find_token(key));
    }

    bmap find_bmap(const std::string& key)
    {
        return bmap(*this, find_token(key));
    }

    std::unique_ptr<belement> operator[](const std::string& key)
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
                detail::make_number_from_token(encoded(), *token)
            );
        case btype::string:
            return std::make_unique<bstring>(
                detail::make_string_from_token(encoded(), *token)
            );
        case btype::list:
            return std::make_unique<blist>(
                static_cast<const detail::bcontainer&>(*this), token
            );
        case btype::map:
            return std::make_unique<bmap>(
                static_cast<const detail::bcontainer&>(*this), token
            );
        }
    }

    std::unique_ptr<const belement> operator[](const std::string& key) const
    {
        return operator[](key);
    }

    /** Returns a JSON-like, human readable string of this map. */
    std::string to_string() const
    {
        std::string s;
        s += '{';
        if(head())
        {
            const btoken* token = head() + 1;
            const btoken* const map_end = tail();
        }
        return s += '}';
    }


private:

    /**
     * Returns the first token that matches $key and is a map key, no matter how
     * how deeply nested, or a nullptr if no match is found.
     *
     * Searching is linear in the number of tokens in m_tokens.
     *
     * start_pos must be a map token (i.e. a token with type == btype::map).
     */
    const btoken* find_token(
        const std::string& key,
        const btoken* start_pos = nullptr
    ) const noexcept
    {
        const btoken* token = start_pos == nullptr ? head()
                                                   : start_pos;
        const btoken* const map_end = token + token->next_item_array_offset;

        assert(token);
        assert(token->type == btype::map);

        // advance past the first element as that's the opening tag of the bmap
        // (note to self: don't offset ptr by next_item_array_offset becauce that would
        // transport it to the first element not in map; instead, go one to the right,
        // it's either the first key or map_end, if map is empty)
        ++token;

        while(token != map_end
              // stop looping if the distance till the end of the encoded string from
              // the current token is less than key's length (to avoid SIGSEGV in
              // std::equal())
              && encoded().length() - token->offset - token->length >= key.length())
        {
            const auto encoded_key_header = encoded().c_str() + token->offset;
            assert(token->type == btype::string);
            const auto encoded_key_length = std::atoi(encoded_key_header);
            const auto encoded_key_start = encoded_key_header + token->length;
            // advance to value
            token += token->next_item_array_offset;
            // compare search key to key token
            if(std::equal(
                key.c_str(),
                key.c_str() + key.length(),
                encoded_key_start,
                encoded_key_start + encoded_key_length))
            {
                return token;
            }
            else if(token->type == btype::map)
            {
                // recursively search nested map
                // TODO decide if we want DFS or BFS
                auto res = find_token(key, token);
                if(res != nullptr)
                {
                    return res;
                }
            }
            // advance to next key, which may be map_end
            token += token->next_item_array_offset;
        }
        return nullptr;
    }
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

#endif // TORRENT_BDECODE_HEADER
