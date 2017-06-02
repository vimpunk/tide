#ifndef TORRENT_RANDOM_HEADER
#define TORRENT_RANDOM_HEADER

#include <random>

namespace util
{
    std::mt19937& random_engine();

    /** Returns a random integer in the range [0, max] or [min, max]. */
    int random_int(const int max);
    int random_int(const int min, const int max);
}

#endif // TORRENT_RANDOM_HEADER
