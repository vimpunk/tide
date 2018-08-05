#ifndef TIDE_MMAP_HEADER
#define TIDE_MMAP_HEADER

#include <mio/mmap.hpp>

namespace tide {

using mmap_source = mio::basic_mmap_source<uint8_t>;
using mmap_sink = mio::basic_mmap_sink<uint8_t>;

} // namespace tide

#endif // TIDE_MMAP_HEADER
