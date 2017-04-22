#include "bdecode.hpp"

#include <algorithm>
#include <cctype> // isdigit

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
        else if((m_encoded.front() != 'd') || (m_encoded.back() != 'e'))
        {
            throw std::runtime_error("invalid bmap encoding (invalid header or end token)");
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
        else if((m_encoded.front() != 'l') || (m_encoded.back() != 'e'))
        {
            throw std::runtime_error("invalid blist encoding (invalid header or end token)");
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
        while((m_pos < m_encoded.length() - 1) && (m_encoded[m_pos] != 'e'))
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
        while((m_pos < m_encoded.length() - 1) && (m_encoded[m_pos] != 'e'))
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
