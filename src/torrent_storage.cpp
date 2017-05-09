#include "torrent_storage.hpp"

torrent_storage::torrent_storage(
    const torrent_info& info,
    bmap metainfo,
    path save_path,
    std::string name,
)
    : m_info(info)
    , m_files(create_file_entries(files))
    , m_hashes(std::move(hashes))
    , m_path(std::move(path))
    , m_name(std::move(name))
{}

void torrent_storage::create_file_entries(const std::vector<file_info>& files)
{
    m_files.reserve(files.size());
    //const int piece_length = m_info.piece_length;
    for(const auto& info : files)
    {
        // TODO 
        uint8_t mode = 0;
        piece_index_t first_overlapped_piece = 0;
        piece_index_t last_overlapped_piece = 0;
        piece_index_t first_full_piece = 0;
        piece_index_t last_full_piec = 0;

        if(m_size % m_info.piece_length == 0)
        {
            first_full_piece = first_overlapping_piece = m_size;
        }
        m_files.emplace_back(
            info.path,
            info.length,
            mode,
            first_overlapped_piece,
            last_overlapped_piece,
            first_full_piece,
            last_full_piece
        );
        m_size += info.length;
    }
}

view<file> torrent_storage::files_containing_piece(const piece_index_t piece)
{
    int first_file_index = 0;
    int last_file_index = 0;
    int index = 0;
    for(file& file : m_files)
    {
        if(file.first_overlapping_piece() == piece)
        {
            first_file_index = index;
        }
        if(file.last_overlapping_piece() == piece)
        {
            last_file_index = index;
            break;
        }
        ++index;
    }
    return { m_files.data() + first_file_index, last_file_index - first_file_index };
}

