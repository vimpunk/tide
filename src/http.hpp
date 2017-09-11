#ifndef TIDE_HTTP_HEADER
#define TIDE_HTTP_HEADER

/*
#include "socket.hpp"
#include "time.hpp"

#include <string>
#include <memory>
#include <system_error>

#include <asio/io_service.hpp>
*/
#include <boost/beast/http.hpp>
#include <boost/beast/core/flat_buffer.hpp>

namespace tide {
namespace http {

using namespace boost::beast::http;
using boost::beast::flat_buffer;

/*
class connection
{
    tcp::socket m_socket;
    tcp::resolver m_resolver;
    boost::beast::flat_buffer m_buffer;

public:

    explicit connection(asio::io_service& ios)
        : m_socket(ios)
        , m_resolver(ios)
    {}

    void connect(const std::string& host, std::error_code& error)
    {
        m_socket.connect(*m_resolver.resolve({host, "http"}));
    }

    template<typename Handler>
    void async_connect(const std::string& host, Handler handler)
    {
        // TODO make assertions on the handler
        m_resolver.async_resolve({host, "http"},
            [this, handler = std::move(handler)](const auto& error, auto iterator)
            {
                if(error)
                    handler(error);
                else
                    // if there was no error there is guaranteed to be at least one endpoint
                    m_socket.async_connect(*iterator, std::move(handler));
            });
    }

    template<typename Body>
    void send(request<Body>& r, std::error_code& error)
    {
        write(m_socket, r, error);
    }

    template<typename Body, typename Handler>
    void async_send(request<Body>& r, Handler&& h)
    {
        async_write(m_socket, r, std::forward<Handler>(h));
    }

    template<typename Body = dynamic_body>
    response<Body> receive(std::error_code& error)
    {
        response<Body> r;
        read(m_socket, m_buffer, r, error);
        return r;
    }

    template<typename Handler, typename Body = dynamic_body>
    void async_receive(Handler&& h)
    {
        auto r = std::make_unique<response<Body>>();
        async_read(m_socket, m_buffer, *r,
            [r = std::move(r), handler = std::forward<Handler>(h)]
            (const auto& error) { handler(error, *r); });
    }

    template<typename ResponseBody, typename RequestBody>
    response<ResponseBody> make_request(request<RequestBody>& r, std::error_code& error)
    {
        send(r, error);
        if(error) { return {}; }
        return receive(error);
    }

    template<typename ResponseBody, typename RequestBody, typename Handler>
    void async_make_request(request<RequestBody>& r, Handler&& h)
    {
    }
};
*/

} // namespace http
} // namespace tide

#endif // TIDE_HTTP_HEADER
