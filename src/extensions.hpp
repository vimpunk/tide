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
    // Currently NOT supported.
    fast = 2,
    // Currently NOT supported, but may be supported in the future.
    nat_traversal = 3,
    // Not going to be supported, only used to identify a peer's extensions.
    libtorrent = 20,
    // Not going to be supported, only used to identify a peer's extensions.
    azureus = 63,
};

using flags = flag_set<uint64_t, 64>;

inline std::string to_string(const flags& flags)
{
    if(flags.empty()) { return "none"; }
    const auto to_string = [](const int ext)
    {
        switch(ext)
        {
        case dht: return "dht";
        case fast: return "fast";
        case nat_traversal: return "nat traversal";
        case libtorrent: return "libtorrent";
        case azureus: return "azureus";
        default: return "unknown";
        }
    };
    std::string s;
    int num_ext = 0;
    for(auto i = 0; i < flags.size(); ++i)
    {
        if(flags[i]) { ++num_ext; }
    }
    // afaik, there are currently no (official) extensions occupying two or more bits,
    // but as soon as this changes, this algorithm will no longer suffice
    for(auto i = 0; i < flags.size(); ++i)
    {
        if(flags[i])
        {
            --num_ext;
            s += to_string(i);
            if(num_ext > 0) { s += ", "; }
        }
    }
    return s;
}

} // namespace extensions
} // namespace tide

#endif // TIDE_EXTENSIONS_HEADER
