#include "path_sanitizer.hpp"
#include "metainfo.hpp"

namespace tide {

metainfo parse_and_sanitize_metainfo(bmap source)
{
    metainfo m;
    m.announce = source.find_string_view("announce");

    blist announce_list;
    if(source.try_find_blist("announce-list", announce_list))
    {
        for(string_view s : announce_list.all_string_views())
        {
            m.announce_list.emplace_back(std::move(s));
        }
    }

    const bmap info_map = source.find_bmap("info");

    // TODO perhaps we should create the info sha1 hash here as well?
    m.piece_length = info_map.find_number("piece length");

    // if torrent is multi-file, there is a 'files' blist in info_map, otherwise info
    // map has a single 'length' parameter
    blist files;
    if(info_map.try_find_blist("files", files))
    {
        m.total_length = 0;
        m.files.reserve(files.size());
        for(const bmap& file_info : files.all_bmaps())
        {
            const int64_t length = file_info.find_number("length");
            m.files.emplace_back(
                create_and_sanitize_path(file_info.find_blist("path")),
                length
            );
            m.total_length += length;
        }
    }
    else
    {
        m.total_length = info_map.find_number("length");
    }
    
    m.num_pieces = (m.total_length + (m.piece_length - 1)) / m.piece_length;
    m.piece_hashes = info_map.find_string_view("pieces");
    m.source = std::move(source);

    return m;
}

} // namespace tide
