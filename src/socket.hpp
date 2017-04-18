#ifndef TORRENT_SOCKET_HEADER
#define TORRENT_SOCKET_HEADER

#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/write.hpp>
#include <asio/read.hpp>

using asio::ip::tcp;
using asio::ip::udp;
using asio::async_write;
using asio::async_read;

#endif // TORRENT_SOCKET_HEADER
