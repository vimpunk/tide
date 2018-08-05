#ifndef TIDE_ERROR_CODE_HEADER
#define TIDE_ERROR_CODE_HEADER

#include <system_error>

namespace tide {

// Use aliases so that should we need to migrate to Boost.Asio, the transition
// will be easier.
using std::errc;
using std::error_category;
using std::error_code;
using std::error_condition;
using std::generic_category;
using std::is_error_code_enum;
using std::is_error_condition_enum;
using std::make_error_code;
using std::make_error_condition;
using std::system_category;
using std::system_error;

#define TIDE_ERROR_CODE_NS std

} // tide

#endif // TIDE_ERROR_CODE_HEADER
