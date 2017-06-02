#ifndef TORRENT_STRING_UTILS_HEADER
#define TORRENT_STRING_UTILS_HEADER

#include <algorithm>
#include <iterator> // begin, end
#include <string>
#include <stdexcept>
#include <cctype> // isspace, isdigit

namespace util
{
    inline void ltrim(std::string& s)
    {
        s.erase(
            s.begin(),
            std::find_if(
                s.begin(), s.end(), [](const auto& c) { return !std::isspace(c); }
            )
        );
    }

    inline void rtrim(std::string& s)
    {
        s.erase(
            std::find_if(
                s.rbegin(), s.rend(), [](const auto& c) { return !std::isspace(c); }
            ).base(),
            s.end()
        );
    }

    inline void trim(std::string& s)
    {
        ltrim(s);
        rtrim(s);
    }

    inline void to_lower(std::string& s)
    {
        std::transform(
            s.begin(), s.end(), s.begin(), [](const auto& c) { return std::tolower(c); }
        );
    }

    inline void to_upper(std::string& s)
    {
        std::transform(
            s.begin(), s.end(), s.begin(), [](const auto& c) { return std::toupper(c); }
        );
    }

    template<typename Bytes>
    std::string to_hex(const Bytes& data)
    {
        static constexpr char hex_chars[] = "0123456789abcdef";
        std::string hex_str;
        const size_t size = std::end(data) - std::begin(data);
        hex_str.reserve(size * 2);
        for(size_t i = 0; i < size; ++i)
        {
            const uint8_t byte = data[i];
            hex_str += hex_chars[byte >> 4];
            hex_str += hex_chars[byte & 0xf];
        }
        return hex_str;
    }

    /**
     * The announce urls in metainfo are usually specified as follows:
     * "udp://host.domain:port/announce" -- this extracts "host.domain".
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
        if(url.length() >= udp_protocol_len
           && std::equal(url.begin(), url.begin() + udp_protocol_len, udp_protocol))
        {
            begin = udp_protocol_len;
        }
        int end = url.find(':', begin);
        if(end == std::string::npos)
        {
            end = url.length();
        }
        return url.substr(begin, end - begin);
    }

    /** Strips the "protocol://" identifier from the front of the URL. */
    inline std::string strip_protocol_identifier(const std::string& url)
    {
        const int prot_id_pos = url.find("//");
        if((prot_id_pos != std::string::npos) && (url.length() >= prot_id_pos + 2))
        {
            return url.substr(prot_id_pos + 2);
        }
        else
        {
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
        if(prot_id_pos == std::string::npos)
        {
            colon_pos = url.find(':');
        }
        else
        {
            colon_pos = url.find(':', prot_id_pos);
        }
        // a port number has to be after a colon
        if((colon_pos == std::string::npos) || !std::isdigit(url[colon_pos + 1]))
        {
            throw std::invalid_argument("no port in url (" + url + ")");
        }
        return std::atoi(url.c_str() + colon_pos + 1);
    }
} // namespace util

#endif // TORRENT_STRING_UTILS_HEADER
