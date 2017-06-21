#include "path_sanitizer.hpp"

namespace tide {

path create_and_sanitize_path(const blist& path_elements)
{
    // TODO
    path p;
    for(const string_view s : path_elements.all_string_views())
    {
        p /= path(s);
    }
    return p;
}

} // namespace tide
