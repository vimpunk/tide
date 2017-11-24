#ifndef TIDE_PATH_HEADER
#define TIDE_PATH_HEADER

#if defined(TIDE_USE_BOOST_FILESYSTEM)
# include <boost/filesystem/path.hpp>
namespace tide { using boost::filesystem::path; }
#elif __cplusplus >= 201406L
# include <filesystem>
namespace tide { using std::filesystem::path; }
#elif defined(TIDE_USE_EXPERIMENTAL_FILESYSTEM)
# include <experimental/filesystem>
namespace tide { using std::experimental::filesystem::path; }
#else
# error "Need boost or std filesystem support."
#endif

#endif // TIDE_PATH_HEADER
