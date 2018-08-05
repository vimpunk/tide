#ifndef TIDE_STRING_UTILS_HEADER
#define TIDE_STRING_UTILS_HEADER

#include <algorithm>
#include <cctype> // std::isspace, std::isdigit, std::isalnum
#include <cmath> // std::pow
#include <cstdio> // std::snprintf
#include <iomanip> // std::setw
#include <iterator> // std::begin, std::end
#include <memory> // std::unique_ptr
#include <sstream>
#include <stdexcept>
#include <string>

#include "string_view.hpp"

namespace tide {
namespace util {
namespace c_str {

template <typename C>
constexpr auto size(const C& c) noexcept(noexcept(c.size())) -> decltype(c.size())
{
    return c.size();
}

/**
 * Since C-strings are 0 terminated, the actual returned length is one less than the
 * array's size.
 */
template <typename C, size_t N>
constexpr size_t size(const C (&array)[N]) noexcept
{
    return N - 1;
}

} // namespace c_str

template <typename String>
inline void ltrim(String& s)
{
    s.erase(std::begin(s), std::find_if(std::begin(s), std::end(s), [](const auto& c) {
        return !std::isspace(c);
    }));
}

template <typename String>
inline void rtrim(String& s)
{
    s.erase(std::find_if(std::rbegin(s), std::rend(s),
                    [](const auto& c) { return !std::isspace(c); })
                    .base(),
            std::end(s));
}

template <typename String>
inline void trim(String& s)
{
    ltrim(s);
    rtrim(s);
}

template <typename String>
inline void to_lower(String& s)
{
    std::transform(std::begin(s), std::end(s), std::begin(s),
            [](const auto& c) { return std::tolower(c); });
}

template <typename String>
inline void to_upper(String& s)
{
    std::transform(std::begin(s), std::end(s), std::begin(s),
            [](const auto& c) { return std::toupper(c); });
}

template <typename String1, typename String2>
bool starts_with(const String1& s, const String2& prefix) noexcept
{
    using std::begin;
    return c_str::size(s) >= c_str::size(prefix)
            && std::equal(begin(s), begin(s) + c_str::size(prefix), begin(prefix));
}

template <typename String1, typename String2>
bool ends_with(const String1& s, const String2& suffix) noexcept
{
    using std::rbegin;
    return c_str::size(s) >= c_str::size(suffix)
            // TODO verify this
            && std::equal(rbegin(s), rbegin(s) + c_str::size(suffix), rbegin(suffix));
}

template <typename Bytes>
std::string to_hex(const Bytes& data)
{
    static constexpr char hex_chars[] = "0123456789abcdef";
    std::string hex_str;
    const size_t size = std::end(data) - std::begin(data);
    hex_str.reserve(size * 2);
    for(size_t i = 0; i < size; ++i) {
        const uint8_t byte = data[i];
        hex_str += hex_chars[byte >> 4];
        hex_str += hex_chars[byte & 0xf];
    }
    return hex_str;
}

/**
 * The announce urls in metainfo are usually specified as follows:
 * "udp://subdomain.host.domain:port/announce" -- this extracts "subdomain.host.domain".
 *
 * If url is invalid, an invalid_argument exception is thrown.
 */
// TODO find more accurate name
// TODO error handling -> exception
inline std::string extract_host(const std::string& url)
{
    int begin = 0;
    constexpr static char udp_protocol[] = "udp://";
    constexpr static int udp_protocol_len = sizeof(udp_protocol) - 1;
    constexpr static char http_protocol[] = "http://";
    constexpr static int http_protocol_len = sizeof(http_protocol) - 1;
    if(url.length() >= udp_protocol_len
            && std::equal(url.begin(), url.begin() + udp_protocol_len, udp_protocol)) {
        begin = udp_protocol_len;
    } else if(url.length() >= http_protocol_len
            && std::equal(url.begin(), url.begin() + http_protocol_len, http_protocol)) {
        begin = http_protocol_len;
    }
    int end = url.find(':', begin);
    if(end == std::string::npos) {
        end = url.length();
    }
    return url.substr(begin, end - begin);
}

/** Strips the "protocol://" identifier from the front of the URL. */
inline std::string strip_protocol_identifier(const std::string& url)
{
    const int prot_id_pos = url.find("//");
    if((prot_id_pos != std::string::npos) && (url.length() >= prot_id_pos + 2)) {
        return url.substr(prot_id_pos + 2);
    } else {
        return url;
    }
}

/**
 * This extracts the port from an url. If absent, an invalid_argument exception is
 * thrown.
 */
inline uint16_t extract_port(const std::string& url)
{
    const int prot_id_pos = url.find("//");
    int colon_pos = 0;
    if(prot_id_pos == std::string::npos) {
        colon_pos = url.find(':');
    } else {
        colon_pos = url.find(':', prot_id_pos);
    }
    // a port number has to be after a colon
    if((colon_pos == std::string::npos) || !std::isdigit(url[colon_pos + 1])) {
        if(starts_with(url, "https"))
            return 440;
        else if(starts_with(url, "http"))
            return 80;
        else
            throw std::invalid_argument("no port in url (" + url + ")");
    }
    return std::atoi(url.c_str() + colon_pos + 1);
}

template <typename... Args>
std::string format(const char* format_str, Args&&... args)
{
    // TODO optimize this as it's used a lot
    const size_t length = std::snprintf(nullptr, 0, format_str, args...) + 1;
    std::unique_ptr<char[]> buffer(new char[length]);
    std::snprintf(buffer.get(), length, format_str, args...);
    // -1 to exclude the '\0' at the end
    return std::string(buffer.get(), buffer.get() + length - 1);
}

/** Determines whether `s` is a hexadecimal number. */
template <typename InputIt>
bool is_hex(InputIt begin, InputIt end)
{
    static const char hex_digits[] = "0123456789abcdefABCDEF";
    while(begin != end) {
        const auto c = *begin++;
        if(std::end(hex_digits)
                == std::find(std::begin(hex_digits), std::end(hex_digits), c)) {
            return false;
        }
    }
    return true;
}

template <typename Iterable>
bool is_hex(const Iterable& s)
{
    return is_hex(std::begin(s), std::end(s));
}

inline std::string dec_to_hex(uint64_t x)
{
    std::string hex;
    uint8_t remainder;
    uint64_t quotient = x;
    while(quotient != 0) {
        remainder = quotient % 16;
        if(remainder < 10)
            hex += remainder + 48;
        else
            hex += remainder + 87;
        quotient /= 16;
    }
    std::reverse(hex.begin(), hex.end());
    return hex;
}

template <typename InputIt>
uint64_t hex_to_dec(InputIt begin, InputIt end)
{
    if(!is_hex(begin, end)) {
        throw std::invalid_argument(
                std::string(begin, end) + " is not a hexadecimal number.");
    }

    uint64_t result = 0;
    size_t power = std::distance(begin, end) - 1;
    while(begin != end) {
        const auto c = *begin++;
        if(std::isdigit(c)) {
            c -= 48;
        } else {
            if(std::islower(c))
                c -= 87;
            else
                c -= 31;
        }
        result += c * std::pow(16, power);
        --power;
    }
    return result;
}

template <typename Iterable>
uint64_t hex_to_dec(const Iterable& s)
{
    return hex_to_dec(std::begin(s), std::end(s));
}

/**
 * Encodes a given string using the standard URL encoding protocol, also known as
 * percent-encoding protocol as per RFC 1738.
 */
template <typename InputIt>
std::string url_encode(InputIt begin, InputIt end, const bool space_plus_coded = false)
{
    std::string encoded = "";
    while(begin != end) {
        const auto c = *begin++;
        if(std::isalnum(c) || c == '.' || c == ',' || c == '-' || c == '_' || c == '~') {
            encoded += c;
        } else if(space_plus_coded && c == ' ') {
            encoded += '+';
        } else {
            char buf[3];
            std::snprintf(buf, sizeof buf, "%.2X", static_cast<int>(c));
            buf[2] = 0; // sprintf appends a zero terminator, but just in case.
            encoded += '%';
            encoded += buf;
        }
    }
    return encoded;
}

template <typename Iterable>
std::string url_encode(const Iterable& iterable, const bool space_plus_coded = false)
{
    return url_encode(std::begin(iterable), std::end(iterable), space_plus_coded);
}

/** Decodes a given URL encoded string as per RFC 1738. */
template <typename InputIt>
std::string url_decode(InputIt begin, InputIt end, bool space_plus_coded = false)
{
    std::ostringstream decoded;
    while(begin != end) {
        std::string::value_type c = *begin;
        if(isalnum(c) || c == '.' || c == ',' || c == '-' || c == '_' || c == '~') {
            decoded << c;
        } else if(space_plus_coded && c == '+') {
            decoded << ' ';
        } else if(c == '%') {
            // Grab the next two chars representing a hexadecimal number.
            decoded << static_cast<char>(hex_to_dec(begin + 1, begin + 3));
            begin += 2;
        }
    }
    return decoded.str();
}

template <typename Iterable>
std::string url_decode(const Iterable& iterable, const bool space_plus_coded = false)
{
    return url_decode(std::begin(iterable), std::end(iterable), space_plus_coded);
}

} // namespace util
} // namespace tide

#endif // TIDE_STRING_UTILS_HEADER
