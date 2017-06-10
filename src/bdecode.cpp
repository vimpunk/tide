#include "bdecode.hpp"

#include <cctype> // isdigit

namespace tide {

class bdecoder
{
    // Temporary holds the list of tokens, ownership of which will be passed to the
    // decoded bcontainer. (Unused when the decoded element is a bstring or bnumber.)
    std::vector<btoken> m_tokens;

    // This is the raw bencoded string. Ownership of this string will be handed over to
    // the belement instance produced after decoding.
    std::string m_encoded;

    // The index of the current character in m_encoded.
    int m_pos = 0;

public:

    explicit bdecoder(std::string s) : m_encoded(std::move(s)) {}

    bmap decode_map()
    {
        if(m_encoded.empty())
        {
            throw std::runtime_error("empty source string, cannot decode");
        }
        else if(m_encoded.front() != 'd')
        {
            throw std::runtime_error("invalid bmap encoding (invalid header)");
        }
        m_tokens.reserve(count_tokens());
        decode_bmap();
        return bmap(std::move(m_tokens), std::move(m_encoded));
    }

    blist decode_list()
    {
        if(m_encoded.empty())
        {
            throw std::runtime_error("empty source string, cannot decode");
        }
        else if(m_encoded.front() != 'l')
        {
            throw std::runtime_error("invalid blist encoding (invalid header)");
        }
        m_tokens.reserve(count_tokens());
        decode_blist();
        return blist(std::move(m_tokens), std::move(m_encoded));
    }

    std::unique_ptr<belement> decode()
    {
        if(m_encoded.empty())
        {
            throw std::runtime_error("empty source string, cannot decode");
        }

        const char c = m_encoded.front();
        if(c == 'd')
        {
            return std::make_unique<bmap>(decode_map());
        }
        else if(c == 'l')
        {
            return std::make_unique<blist>(decode_list());
        }
        else if(c == 'i')
        {
            return std::make_unique<bnumber>(
                detail::make_number_from_token(m_encoded, decode_bnumber())
            );
        }
        else if(std::isdigit(c))
        {
            return std::make_unique<bstring>(
                detail::make_string_from_token(m_encoded, decode_bstring())
            );
        }
        return nullptr;
    }

private:

    /**
     * Goes over m_encoded and counts the number of btokens that would be constructed by
     * parsing the entire input string. This is to allocate the tokens buffer in one
     * instead of incrementally.
     */
    int count_tokens()
    {
        int count = 0;
        for(auto i = 0; i < m_encoded.length() - 1; ++i)
        {
            const char c = m_encoded[i];
            if(std::isdigit(c))
            {
                const int str_length = std::atoi(&m_encoded[i]);
                while((i < m_encoded.length()) && (m_encoded[i] != ':'))
                {
                    ++i;
                }
                if(i == m_encoded.length())
                {
                    throw std::runtime_error("invalid bencoding (out of range)");
                }
                i += str_length;
            }
            else if(c == 'i')
            {
                while((i < m_encoded.length()) && (m_encoded[i] != 'e'))
                {
                    ++i;
                }
            }
            else if(c == 'e')
            {
                // don't count the blist's and bmap's 'e' end token as a token
                continue;
            }
            ++count;
        }
        return count;
    }

    /**
     * Dispatches decoding to specialized functions and returns the number of btokens
     * that were created decoding the current element.
     */
    int decode_dispatch()
    {
        assert(m_pos < m_encoded.length());
        const int prev_num_tokens = m_tokens.size();
        //std::cout << "type: " << m_encoded[m_pos] << '\n';
        switch(m_encoded[m_pos])
        {
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            m_tokens.emplace_back(decode_bstring());
            return 1;
        case 'i':
            m_tokens.emplace_back(decode_bnumber());
            return 1;
        case 'l':
            decode_blist();
            return m_tokens.size() - prev_num_tokens;
        case 'd':
            decode_bmap();
            return m_tokens.size() - prev_num_tokens;
        default:
            throw std::runtime_error("cannot bdecode, unknown type: " + m_encoded[m_pos]);
        }
    }

    btoken decode_bstring()
    {
        // check for correct string length
        if((m_encoded[m_pos] == '0') && (m_encoded[m_pos + 1] != ':'))
        {
            throw std::runtime_error("invalid bstring encoding (invalid length)");
        }

        int colon_index = m_pos + 1;
        while(std::isdigit(m_encoded[colon_index]))
        {
            ++colon_index;
        }
        // the first character after the digits in a string must be a colon
        if(m_encoded[colon_index] != ':')
        {
            throw std::runtime_error("invalid bstring encoding (missing colon)");
        }

        btoken bstring(btype::string, m_pos);
        bstring.length = colon_index - m_pos + 1;

        // go to the next element
        const int str_length = std::atoi(&m_encoded[m_pos]);
        m_pos = colon_index + 1 + str_length;

        // if there is still an element after this, the offset is 1 (default is 0)
        if(m_pos < m_encoded.length())
        {
            bstring.next_item_array_offset = 1;
        }

        return bstring;
    }

    btoken decode_bnumber()
    {
        // don't allow leading zeros
        if((m_encoded[m_pos + 1] == '0') && (m_encoded[m_pos + 2] != 'e'))
        {
            throw std::runtime_error("invalid bnumber encoding (trailing zeros)");
        }

        int end = m_pos + 1;
        while(std::isdigit(m_encoded[end]))
        {
            ++end;
        }
        // the first character after the digits in number must be the 'e' end token
        if(m_encoded[end] != 'e')
        {
            throw std::runtime_error("invalid bnumber encoding (missing 'e' end token)");
        }

        btoken bnumber(btype::number, m_pos);
        bnumber.length = end - m_pos + 1;

        // got to the next element
        m_pos = end + 1;
        // if there is still an element after this, the offset is 1 (default is 0)
        if(m_pos < m_encoded.length())
        {
            bnumber.next_item_array_offset = 1;
        }

        return bnumber;
    }

    void decode_blist()
    {
        m_tokens.emplace_back(btype::list, m_pos);
        // save the position of list header so we can refer to it later (cannot use
        // reference as m_tokens may reallocate)
        const int list_pos = m_tokens.size() - 1;
        // go to first element in list
        ++m_pos;
        while((m_pos < m_encoded.length()) && (m_encoded[m_pos] != 'e'))
        {
            // add the number of tokens that were parsed while decoding value; this is
            // necessary to determine where the list ends
            m_tokens[list_pos].next_item_array_offset += decode_dispatch();
            ++m_tokens[list_pos].length;
        }

        if(m_encoded[m_pos] != 'e')
        {
            throw std::runtime_error("invalid blist encoding (missing 'e' end token)");
        }
        // got past the 'e' end token to the next element
        ++m_pos;
    }

    void decode_bmap()
    {
        m_tokens.emplace_back(btype::map, m_pos);
        // save the position of map header so we can refer to it later (cannot use
        // reference as m_tokens may reallocate)
        const int map_pos = m_tokens.size() - 1;
        // go to first element in map
        ++m_pos;
        while((m_pos < m_encoded.length()) && (m_encoded[m_pos] != 'e'))
        {
            if(!std::isdigit(m_encoded[m_pos]))
            {
                // keys must be strings
                throw std::runtime_error("invalid bmap encoding (key not a string)");
            }
            // decode key
            m_tokens.emplace_back(decode_bstring());
            ++m_tokens[map_pos].next_item_array_offset;
            // TODO validate key

            if(m_pos >= m_encoded.length())
            {
                throw std::runtime_error("invalid bmap encoding (no value assigned to key)");
            }

            // decode value and add the number of tokens that were parsed while decoding
            // value to array offset accumulator
            // this is necessary to determine where the map ends
            m_tokens[map_pos].next_item_array_offset += decode_dispatch();
            // a map's length is its number of key-value pairs
            ++m_tokens[map_pos].length;
        }

        if(m_encoded[m_pos] != 'e')
        {
            throw std::runtime_error("invalid bmap encoding (missing 'e' end token)");
        }
        // got past the 'e' end token to the next element
        ++m_pos;
    }
};

bmap decode_bmap(std::string s)
{
    return bdecoder(std::move(s)).decode_map();
}

blist decode_blist(std::string s)
{
    return bdecoder(std::move(s)).decode_list();
}

std::unique_ptr<belement> decode(std::string s)
{
    return bdecoder(std::move(s)).decode();
}

namespace detail
{
    string_view bcontainer::encode() const
    {
        // TODO verify this
        if(!head())
        {
            return string_view();
        }
        if(head() == m_tokens->data())
        {
            // this is the root container, just return the whole encoded string
            return source();
        }
        const btoken* last_element = tail() - 1;
        int last_element_offset = last_element->offset;
        if(last_element->type == btype::string)
        {
            const auto str_header = source().c_str() + last_element_offset;
            const auto str_length = std::atoi(str_header);
            last_element_offset += last_element->length + str_length;
        }
        else if(last_element->type == btype::number)
        {
            last_element_offset += last_element->length;
        }
        else if((last_element->type == btype::list) && (last_element->type == btype::map))
        {
            // if last element is a blist or bmap header token, it means they are
            // empty, so they only have 2 characters: the header tag ('l') and the end
            // tag ('e')
            last_element_offset += 2;
        }
        return string_view(
            source().c_str() + head()->offset,
            source().c_str() + last_element_offset + 1
        );
    }

    void format_map(
        std::stringstream& ss,
        const bcontainer& map,
        const btoken* head,
        int nesting_level)
    {
        ss << '{';
        if(!map.head())
        {
            ss << '}';
            return;
        }

        const btoken* token = head ? head
                                   : map.head();
        const btoken* const map_end = token + token->next_item_array_offset;
        ++token;

        if(token == map_end)
        {
            ss << '}';
            return;
        }

        while(token != map_end)
        {
            ss << '\n';
            for(auto i = 0; i < nesting_level + 1; ++i)
            {
                ss << "  ";
            }
            ss << '"' << make_string_from_token(map.source(), *token) << "\": ";
            token += token->next_item_array_offset;
            switch(token->type)
            {
            case btype::number:
                ss << make_number_from_token(map.source(), *token);
                break;
            case btype::string:
                ss << '"' << make_string_from_token(map.source(), *token) << '"';
                break;
            case btype::list:
                format_list(ss, map, token, nesting_level + 1);
                break;
            case btype::map:
                format_map(ss, map, token, nesting_level + 1);
                break;
            }
            token += token->next_item_array_offset;
            if(token != map_end)
            {
                ss << ',';
            }
        }

        ss << '\n';
        for(auto i = 0; i < nesting_level; ++i)
        {
            ss << "  ";
        }
        ss << '}';
    }

    void format_list(
        std::stringstream& ss,
        const bcontainer& list,
        const btoken* head,
        int nesting_level)
    {
        ss << '[';
        if(!list.head())
        {
            ss << ']';
            return;
        }

        const btoken* token = head ? head
                                   : list.head();
        const btoken* const list_end = token + token->next_item_array_offset;
        ++token;

        if(token == list_end)
        {
            ss << ']';
            return;
        }

        while(token != list_end)
        {
            ss << '\n';
            for(auto i = 0; i < nesting_level + 1; ++i)
            {
                ss << "  ";
            }
            switch(token->type)
            {
            case btype::number:
                ss << make_number_from_token(list.source(), *token);
                break;
            case btype::string:
                ss << '"' << make_string_from_token(list.source(), *token) << '"';
                break;
            case btype::list:
                format_list(ss, list, token, nesting_level + 1);
                break;
            case btype::map:
                format_map(ss, list, token, nesting_level + 1);
                break;
            }
            token += token->next_item_array_offset;
            if(token != list_end)
            {
                ss << ", ";
            }
        }

        ss << '\n';
        for(auto i = 0; i < nesting_level; ++i)
        {
            ss << "  ";
        }
        ss << ']';
    }
} // namespace detail

const btoken* bmap::find_token(
    const std::string& key, const btoken* start_pos) const noexcept
{
    if(!head())
    {
        return nullptr;
    }

    const btoken* token = start_pos == nullptr ? head() : start_pos;
    const btoken* const map_end = token + token->next_item_array_offset;

    assert(token);
    assert(token->type == btype::map);

    // advance past the first element as that's the opening tag of the bmap
    // (note to self: don't offset ptr by next_item_array_offset becauce that would
    // transport it to the first element not in map; instead, go one to the right,
    // it's either the first key or map_end, if map is empty)
    ++token;

    while(token != map_end)
          // stop looping if the distance till the end of the encoded string from
          // the current token is less than key's length (to avoid SIGSEGV in
          // std::equal())
          // TODO 
          //&& source().length() - token->offset - token->length >= key.length())
    {
        assert(token->type == btype::string);
        const auto encoded_key_header = source().c_str() + token->offset;
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
            auto result = find_token(key, token);
            if(result)
            {
                return result;
            }
        }
        else if(token->type == btype::list)
        {
            auto result = find_token_in_list(key, token);
            if(result)
            {
                return result;
            }
        }
        // advance to next key, which may be map_end
        token += token->next_item_array_offset;
    }
    return nullptr;
}

const btoken* bmap::find_token_in_list(
    const std::string& key, const btoken* token) const noexcept
{
    const btoken* const list_end = token + token->next_item_array_offset;
    // advance past the opening tag of list
    ++token;
    while(token != list_end)
    {
        if(token->type == btype::map)
        {
            auto result = find_token(key, token);
            if(result)
            {
                return result;
            }
        }
        if(token->type == btype::list)
        {
            auto result = find_token_in_list(key, token);
            if(result)
            {
                return result;
            }
        }
        token += token->next_item_array_offset;
    }
    return nullptr;
}

} // namespace tide
