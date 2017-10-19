#ifndef TIDE_ENDPOINT_FILTER_HEADER
#define TIDE_ENDPOINT_FILTER_HEADER

#include "address.hpp"
#include "socket.hpp"

namespace tide {

class endpoint_filter
{
public:

    bool is_allowed(const tcp::endpoint& ep)
    {
        // TODO
        return true;
    }

    void block_ip(const address& ip);
    void block_ip_range(const address& ip);
    void block_port(const uint16_t port);
    void block_endpoint(const tcp::endpoint& ep);

    void unblock_ip(const address& ip);
    void unblock_ip_range(const address& ip);
    void unblock_port(const uint16_t port);
    void unblock_endpoint(const tcp::endpoint& ep);
};

} // namespace tide

#endif // TIDE_ENDPOINT_FILTER_HEADER
