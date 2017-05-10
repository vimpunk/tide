#include "torrent_storage.hpp"

#include <cassert>
#include <cmath>

torrent_storage::torrent_storage(
    const torrent_info& info,
    std::vector<string_view> piece_hashes,
    path save_path,
    std::string name
)
    : m_info(info)
    , m_piece_hashes(std::move(piece_hashes))
    , m_save_path(std::move(save_path))
    , m_name(std::move(name))
{
    initialize_file_entries();
}

std::vector<mmap_source> torrent_storage::create_ro_mmap(
    const block_info& info, std::error_code& error)
{
}

std::vector<mmap_sink> torrent_storage::create_rw_mmap(
    const block_info& info, std::error_code& error)
{
}

void torrent_storage::write(
    view<view<uint8_t>> buffers,
    const block_info& info,
    std::error_code& error)
{
    do_file_io(
        [this](file& file,
         view<view<uint8_t>> buffers,
         const int64_t offset,
         const int64_t length,
         const std::error& error)
        {
            file.write(buffers, offset, length, error);
        },
        buffers,
        info,
        error
    );
}

void torrent_storage::read(
    view<view<uint8_t>> buffers,
    const block_info& info,
    std::error_code& error)
{
    do_file_io(
        [this](file& file,
         view<view<uint8_t>> buffers,
         const int64_t offset,
         const int64_t length,
         const std::error& error)
        {
            file.read(buffers, offset, length, error);
        },
        buffers,
        info,
        error
    );
}

template<typename FileIOFunction>
void torrent_storage::do_file_io(
    FileIOFunction file_io_fn,
    view<view<uint8_t>> buffers,
    const block_info& info,
    std::error_code& error)
{
    error.clear();
    view<file_entry> files = find_files_containing_block(info);
    assert(!files.empty()); // TODO perhaps set error here as well

    int block_offset = info.index * m_info.piece_length;
    int block_bytes_left = info.length;
    int file_index = 0;
    for(file_entry& file : files)
    {
        const int file_end = file.offset + file.storage.length();
        const int file_bytes_left = file_end - block_offset;
        const int block_offset_in_file = block_offset - file.offset;
        const int block_bytes_in_file = std::max(block_bytes_left, file_bytes_left);
        int num_transferred = 0;

        if(m_info.files[file_index].is_wanted)
        {
            set_up_file(file, error);
            if(error)
            {
                return;
            }
            num_transferred = file_io_fn(
                file.storage, buffers, block_offset_in_file, block_bytes_in_file, error
            );
            if(error)
            {
                return;
            }
            assert(num_transferred == block_bytes_in_file);
        }
        else
        {
            num_transferred = block_bytes_in_file;
        }

        // we need to trim buffers by num_transferred bytes by removing the buffers that
        // were fully used and trimming the last buffer used by the number of bytes that
        // were extracted or written to it, like so:
        //
        // remove these two buffers
        // |      |      .num_transferred
        // v      v      V
        // ====|=====|===-----|---
        //             ^ and trim this buffer's front
        //
        while(num_transferred > 0)
        {
            const int buff_len = buffers.front().length();
            if(buff_len > num_transferred)
            {
                break;
            }
            num_transferred -= buff_len;
            buffers.trim_front(1);
        }
        if(num_transferred > 0)
        {
            buffers.front().trim_front(num_transferred);
        }

        block_offset = file_end;
        block_bytes_left -= block_bytes_in_file;
        ++file_index;
    }
}

void torrent_storage::set_up_file(file_entry& file, std::error_code& error)
{
    if(!file.storage.is_open())
    {
        file.storage.open(error);
        if(error)
        {
            return;
        }
    }
    if(!file.storage.is_allocated())
    {
        file.storage.allocate_storage(error);
        if(error)
        {
            return;
        }
    }
}

void torrent_storage::initialize_file_entries()
{
    m_files.reserve(files.size());
    file_index_t index = 0;
    int64_t file_offset = 0;
    for(const file_info& file_info : m_info.files)
    {
        // TODO mode
        uint8_t mode = 0;
        file_entry entry(file_info.path, file_info.length, mode);
        entry.offset = file_offset;
        entry.first_piece = file_offset / m_info.piece_length;

        // move file_offset to the next file's beginning / this file's end
        file_offset += file_info.length;

        entry.last_overlapped_piece = file_offset / m_info.piece_length;

        // only count the size of the files that we want to download
        // (we don't store is_wanted in file, because it may be changed during the
        // download, so every time we would write to file we check with the updated
        // value in m_info)
        if(file_info.is_wanted)
        {
            m_size += file_info.length;
        }
        m_files.emplace_back(std::move(entry));
    }
    m_total_size += file_offset;
}

view<file_entry> torrent_storage::find_files_containing_block(const block_info& block)
{
    // get the first byte of block in the conceptual file stream by finding the first
    // byte of the piece and adding the block offset; and one past its last byte
    const int block_offset = block.index * m_info.piece_length + block.offset;
    const int block_end = block_offset + block.length;
    auto it = m_files.begin();
    const auto end = m_files.end();

    // find the first file containing block_offset
    // TODO check if we can do logarithmic search here
    while((it != end) && (it->offset + it->storage.length() <= block_offset))
    {
        ++it;
    }
    assert(it != end);
    file_entry* first_file = &*it;

    // find the last file containing block_end
    while((it != end) && (it->offset + it->storage.length() < block_end))
    {
        ++it;
    }
    assert(it != end);
    file_entry* last_file = &*it;

    return { first_file, last_file };
}

view<file_entry> torrent_storage::find_files_containing_piece(const piece_index_t piece)
{
    int first_file_index = 0;
    int last_file_index = 0;
    int index = 0;
    for(const auto& file : m_files)
    {
        if(file.first_overlapping_piece == piece)
        {
            first_file_index = index;
        }
        if(file.last_overlapping_piece == piece)
        {
            last_file_index = index;
            break;
        }
        ++index;
    }
    return { m_files.data() + first_file_index, last_file_index - first_file_index };
}
