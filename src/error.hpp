#ifndef TORRENT_ERROR_HEADER
#define TORRENT_ERROR_HEADER

enum errors
{

};

namespace std
{
    template<> struct is_error_code_enum<errors>
    {
        static constexpr bool value = true;
    };
}

#endif // TORRENT_ERROR_HEADER
