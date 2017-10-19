#ifndef TIDE_SOCKET_HEADER
#define TIDE_SOCKET_HEADER

#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/write.hpp>
#include <asio/read.hpp>

namespace tide {

using asio::ip::tcp;
using asio::ip::udp;
using asio::async_write;
using asio::async_read;

} // namespace tide

#endif // TIDE_SOCKET_HEADER
