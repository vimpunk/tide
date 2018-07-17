#include "path_sanitizer.hpp"
#include "string_view.hpp"

namespace tide {

std::filesystem::path sanitize_path(std::string_view path)
{
    return path;
}

std::filesystem::path create_and_sanitize_path(const blist& path_elements)
{
    // TODO
    std::filesystem::path p;
    for(const string_view s : path_elements.all_string_views())
    {
        p /= std::filesystem::path(s);
    }
    return p;
}

} // namespace tide
