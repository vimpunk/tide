#ifndef TIDE_RANDOM_HEADER
#define TIDE_RANDOM_HEADER

#include <random>

namespace tide {
namespace util {

std::mt19937& random_engine();

/** Returns a random integer in the range [0, max] or [min, max]. */
int random_int(const int max);
int random_int(const int min, const int max);

/** Returns a random double in the range [0, 1], [0, max] or [min, max]. */
double random_real();
double random_real(const double max);
double random_real(const double min, const double max);

} // namespace util
} // namespace tide

#endif // TIDE_RANDOM_HEADER
