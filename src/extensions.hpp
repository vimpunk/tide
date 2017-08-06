#ifndef TIDE_EXTENSIONS_HEADER
#define TIDE_EXTENSIONS_HEADER

#include "flag_set.hpp"

#include <string>

namespace tide {
namespace extensions {

/**
 * Each extension maps to a value corresponding to the 0-based index which indicates
 * which bit in the handshake's 'reserved' field (counting from the least significant
 * bit) denotes the extension.
 */
enum {
    // Currently NOT supported.
    dht = 0,
    // Experimental support.
    fast = 2,
    // Currently NOT supported, but may be supported in the future.
    nat_traversal = 3,
    // Not going to be supported, only used to identify a peer's extensions.
    libtorrent = 20,
    // Not going to be supported.
    location_aware_protocol = 43,
    // Not going to be supported, only used to identify a peer's extensions.
    azureus = 63,
};

using flags = flag_set<uint64_t, 64>;

inline std::string to_string(const flags& flags)
{
    if(flags.empty()) { return "none"; }
    std::string s;
    int num_ext = 0;
    for(auto i = 0; i < flags.size(); ++i)
    {
        if(flags[i]) { ++num_ext; }
    }
    for(auto i = 0; i < flags.size(); ++i)
    {
        if(flags[i])
        {
            // some extensions occupy two bits
            if((i == 64 - 47) && (flags[64 - 48]))
            {
                s += "extension negotiation protocol";
                --num_ext;
            }
            else if((i == 64 - 1) && (flags[64 - 14]))
            {
                s += "BitComet extension protocol";
                --num_ext;
            }
            else
            {
                s += [](const int ext)
                {
                    switch(ext)
                    {
                    case dht: return "DHT";
                    case fast: return "Fast";
                    case nat_traversal: return "NAT traversal";
                    case libtorrent: return "libtorrent";
                    case location_aware_protocol: return "location aware protocol 1.0";
                    case azureus: return "Azureus";
                    default: return "unknown";
                    }
                }(i);
            }
            --num_ext;
            if(num_ext > 0) { s += ", "; }
        }
    }
    return s;
}

} // namespace extensions
} // namespace tide

#endif // TIDE_EXTENSIONS_HEADER
