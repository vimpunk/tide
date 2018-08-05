#ifndef TIDE_SOCKET_HEADER
#define TIDE_SOCKET_HEADER

#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>

namespace tide {

using asio::async_read;
using asio::async_write;
using asio::ip::tcp;
using asio::ip::udp;

} // namespace tide

#endif // TIDE_SOCKET_HEADER
