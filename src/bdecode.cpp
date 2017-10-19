#include "bdecode.hpp"

#include <cctype> // isdigit

namespace tide {

std::string bencode_error_category::message(int env) const
{
    switch(static_cast<bencode_errc>(env))
    {
    case bencode_errc::blist_missing_header: return "No 'l' header in blist";
    case bencode_errc::blist_missing_end_token: return "No 'e' end token in blist";
    case bencode_errc::bmap_missing_header: return "No 'd' header in bmap";
    case bencode_errc::bmap_missing_end_token: return "No 'e' end token in bmap";
    case bencode_errc::bmap_key_not_string: return "Key not a String in bmap";
    case bencode_errc::bmap_keys_unordered: return "Keys in bmap not alphabetically ordered";
    case bencode_errc::bmap_missing_value: return "No value assigned to key in bmap";
    case bencode_errc::bstring_invalid_length: return "Invalid length in bstring header";
    case bencode_errc::bstring_missing_colon: return "Missing colon after bstring header";
    case bencode_errc::bnumber_trailing_zeros: return "Trailing zeros in bnumber";
    case bencode_errc::bnumber_missing_end_token: return "No 'e' end token in bnumber";
    case bencode_errc::out_of_range: return "Out of range: could not find bencode end";
    case bencode_errc::unknown_type: return "Unknown bencode type";
    default: return "Unknown";
    }
}

std::error_condition
bencode_error_category::default_error_condition(int ev) const noexcept
{
    switch(static_cast<bencode_errc>(ev))
    {
    default:
        return std::error_condition(ev, *this);
    }
}

const bencode_error_category& bencode_category()
{
    static bencode_error_category instance;
    return instance;
}

std::error_code make_error_code(bencode_errc e)
{
    return std::error_code(static_cast<int>(e), bencode_category());
}

std::error_condition make_error_condition(bencode_errc e)
{
    return std::error_condition(static_cast<int>(e), bencode_category());
}

class bdecoder
{
    // Temporary holds the list of tokens, ownership of which will be passed to the
    // decoded bcontainer. (Unused when the decoded element is a bstring or bnumber.)
    std::vector<btoken> tokens_;

    // This is the raw bencoded string. Ownership of this string will be handed over to
    // the belement instance produced after decoding.
    std::string encoded_;

    // The index of the current character in encoded_.
    int pos_ = 0;

public:

    explicit bdecoder(std::string s) : encoded_(std::move(s)) {}

    bmap decode_map(std::error_code& error)
    {
        error.clear();
        if(encoded_.empty())
        {
            return {};
        }
        else if(encoded_[0] != 'd')
        {
            error = make_error_code(bencode_errc::bmap_missing_header);
            return {};
        }
        const int num_tokens = count_tokens(error);
        if(error) { return {}; }
        tokens_.reserve(num_tokens);
        decode_bmap(error);
        return bmap(std::move(tokens_), std::move(encoded_));
    }

    blist decode_list(std::error_code& error)
    {
        error.clear();
        if(encoded_.empty())
        {
            return {};
        }
        else if(encoded_[0] != 'l')
        {
            error = make_error_code(bencode_errc::blist_missing_header);
            return {};
        }
        const int num_tokens = count_tokens(error);
        if(error) { return {}; }
        tokens_.reserve(num_tokens);
        decode_blist(error);
        return blist(std::move(tokens_), std::move(encoded_));
    }

    std::unique_ptr<belement> decode(std::error_code& error)
    {
        error.clear();
        if(encoded_.empty()) { return {}; }

        const char c = encoded_[0];
        if(c == 'd')
        {
            bmap map = decode_map(error);
            if(!error) { return std::make_unique<bmap>(std::move(map)); }
        }
        else if(c == 'l')
        {
            blist list = decode_list(error);
            if(!error) { return std::make_unique<blist>(std::move(list)); }
        }
        else if(c == 'i')
        {
            const auto token = decode_bnumber(error);
            if(!error) return std::make_unique<bnumber>(
                detail::make_number_from_token(encoded_, token));
        }
        else if(std::isdigit(c))
        {
            const auto token = decode_bstring(error);
            if(!error) return std::make_unique<bstring>(
                detail::make_string_from_token(encoded_, token));
        }
        return nullptr;
    }

private:

    /**
     * Goes over encoded_ and counts the number of btokens that would be constructed by
     * parsing the entire input string. This is to allocate the tokens buffer in one
     * instead of incrementally.
     */
    int count_tokens(std::error_code& error)
    {
        int count = 0;
        for(auto i = 0; i < encoded_.length() - 1; ++i)
        {
            const char c = encoded_[i];
            if(std::isdigit(c))
            {
                const int str_length = std::atoi(&encoded_[i]);
                while((i < encoded_.length()) && (encoded_[i] != ':'))
                {
                    ++i;
                }
                if(i == encoded_.length())
                {
                    error = make_error_code(bencode_errc::out_of_range);
                    return count;
                }
                i += str_length;
            }
            else if(c == 'i')
            {
                while((i < encoded_.length()) && (encoded_[i] != 'e'))
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
    int decode_dispatch(std::error_code& error)
    {
        assert(pos_ < encoded_.length());
        const int prev_num_tokens = tokens_.size();
        //std::cout << "type: " << encoded_[pos_] << '\n';
        switch(encoded_[pos_])
        {
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
        {
            auto token = decode_bstring(error);
            if(error) { return 0; }
            tokens_.emplace_back(std::move(token));
            return 1;
        }
        case 'i':
        {
            auto token = decode_bnumber(error);
            if(error) { return 0; }
            tokens_.emplace_back(std::move(token));
            return 1;
        }
        case 'l':
        {
            decode_blist(error);
            if(error) { return 0; }
            return tokens_.size() - prev_num_tokens;
        }
        case 'd':
        {
            decode_bmap(error);
            if(error) { return 0; }
            return tokens_.size() - prev_num_tokens;
        }
        default:
        {
            error = make_error_code(bencode_errc::unknown_type);
            return 0;
        }
        }
    }

    btoken decode_bstring(std::error_code& error)
    {
        // check for correct string length
        if((encoded_[pos_] == '0') && (encoded_[pos_ + 1] != ':'))
        {
            error = make_error_code(bencode_errc::bstring_invalid_length);
            return {};
        }

        int colon_index = pos_ + 1;
        while(std::isdigit(encoded_[colon_index]))
        {
            ++colon_index;
        }
        // the first character after the digits in a string must be a colon
        if(encoded_[colon_index] != ':')
        {
            error = make_error_code(bencode_errc::bstring_missing_colon);
            return {};
        }

        btoken bstring(btype::string, pos_);
        bstring.length = colon_index - pos_ + 1;

        // go to the next element
        const int str_length = std::atoi(&encoded_[pos_]);
        pos_ = colon_index + 1 + str_length;

        // if there is still an element after this, the offset is 1 (default is 0)
        if(pos_ < encoded_.length())
        {
            bstring.next_item_array_offset = 1;
        }

        return bstring;
    }

    btoken decode_bnumber(std::error_code& error)
    {
        // don't allow leading zeros
        if((encoded_[pos_ + 1] == '0') && (encoded_[pos_ + 2] != 'e'))
        {
            error = make_error_code(bencode_errc::bnumber_trailing_zeros);
            return {};
        }

        int end = pos_ + 1;
        while(std::isdigit(encoded_[end]))
        {
            ++end;
        }
        // the first character after the digits in number must be the 'e' end token
        if(encoded_[end] != 'e')
        {
            error = make_error_code(bencode_errc::bnumber_missing_end_token);
            return {};
        }

        btoken bnumber(btype::number, pos_);
        bnumber.length = end - pos_ + 1;

        // got to the next element
        pos_ = end + 1;
        // if there is still an element after this, the offset is 1 (default is 0)
        if(pos_ < encoded_.length())
        {
            bnumber.next_item_array_offset = 1;
        }

        return bnumber;
    }

    void decode_blist(std::error_code& error)
    {
        tokens_.emplace_back(btype::list, pos_);
        // save the position of list header so we can refer to it later (cannot use
        // reference as tokens_ may reallocate)
        const int list_pos = tokens_.size() - 1;
        // go to first element in list
        ++pos_;
        while((pos_ < encoded_.length()) && (encoded_[pos_] != 'e'))
        {
            // add the number of tokens that were parsed while decoding value; this is
            // necessary to determine where the list ends
            tokens_[list_pos].next_item_array_offset += decode_dispatch(error);
            ++tokens_[list_pos].length;
            if(error) { return; }
        }

        if(encoded_[pos_] != 'e')
        {
            error = make_error_code(bencode_errc::blist_missing_end_token);
            return;
        }
        // got past the 'e' end token to the next element
        ++pos_;
    }

    void decode_bmap(std::error_code& error)
    {
        tokens_.emplace_back(btype::map, pos_);
        // save the position of map header so we can refer to it later (cannot use
        // reference as tokens_ may reallocate)
        const int map_pos = tokens_.size() - 1;
        // go to first element in map
        ++pos_;
        while((pos_ < encoded_.length()) && (encoded_[pos_] != 'e'))
        {
            if(!std::isdigit(encoded_[pos_]))
            {
                // keys must be strings
                error = make_error_code(bencode_errc::bmap_key_not_string);
                return;
            }
            // decode key
            tokens_.emplace_back(decode_bstring(error));
            ++tokens_[map_pos].next_item_array_offset;
            if(error) { return; }
            // TODO validate key

            if(pos_ >= encoded_.length())
            {
                error = make_error_code(bencode_errc::bmap_missing_value);
                return;
            }

            // decode value and add the number of tokens that were parsed while decoding
            // value to array offset accumulator
            // this is necessary to determine where the map ends
            tokens_[map_pos].next_item_array_offset += decode_dispatch(error);
            // a map's length is its number of key-value pairs
            ++tokens_[map_pos].length;
            if(error) { return; }
        }

        if(encoded_[pos_] != 'e')
        {
            error = make_error_code(bencode_errc::bmap_missing_end_token);
            return;
        }
        // got past the 'e' end token to the next element
        ++pos_;
    }
};

bmap decode_bmap(std::string s, std::error_code& error)
{
    return bdecoder(std::move(s)).decode_map(error);
}

bmap decode_bmap(std::string s)
{
    std::error_code error;
    auto bmap = bdecoder(std::move(s)).decode_map(error);
    if(error) { throw error; }
    return bmap;
}

blist decode_blist(std::string s, std::error_code& error)
{
    return bdecoder(std::move(s)).decode_list(error);
}

blist decode_blist(std::string s)
{
    std::error_code error;
    auto blist = bdecoder(std::move(s)).decode_list(error);
    if(error) { throw error; }
    return blist;
}

std::unique_ptr<belement> decode(std::string s, std::error_code& error)
{
    return bdecoder(std::move(s)).decode(error);
}

std::unique_ptr<belement> decode(std::string s)
{
    std::error_code error;
    auto b = bdecoder(std::move(s)).decode(error);
    if(error) { throw error; }
    return b;
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
        if(head() == tokens_->data())
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

    void format_map(std::stringstream& ss, const bcontainer& map,
        const btoken* head, int nesting_level)
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

    void format_list(std::stringstream& ss, const bcontainer& list,
        const btoken* head, int nesting_level)
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

const btoken* bmap::find_token(const std::string& key,
    const btoken* start_pos) const noexcept
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
            if(result) { return result; }
        }
        else if(token->type == btype::list)
        {
            auto result = find_token_in_list(key, token);
            if(result) { return result; }
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
            if(result) { return result; }
        }
        if(token->type == btype::list)
        {
            auto result = find_token_in_list(key, token);
            if(result) { return result; }
        }
        token += token->next_item_array_offset;
    }
    return nullptr;
}

} // namespace tide
