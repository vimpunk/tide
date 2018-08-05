#include "random.hpp"

namespace tide {
namespace util {

std::mt19937& random_engine()
{
    static std::random_device dev;
    static std::mt19937 rng(dev());
    return rng;
}

int random_int(const int max)
{
    return random_int(0, max);
}

int random_int(const int min, const int max)
{
    return std::uniform_int_distribution<int>(min, max)(random_engine());
}

double random_real()
{
    return random_real(0, 1);
}

double random_real(const double max)
{
    return random_real(0, max);
}

double random_real(const double min, const double max)
{
    return std::uniform_real_distribution<double>(min, max)(random_engine());
}

} // namespace util
} // namespace tide
