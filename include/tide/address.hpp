#ifndef TIDE_ADDRESS_HEADER
#define TIDE_ADDRESS_HEADER

#include <asio/ip/address.hpp>

namespace tide {

using address = asio::ip::address;
using address_v4 = asio::ip::address_v4;
using address_v6 = asio::ip::address_v6;

} // namespace tide

#endif // TIDE_ADDRESS_HEADER
