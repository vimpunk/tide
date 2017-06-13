#include "torrent_storage.hpp"
#include "disk_io_error.hpp"

#include <cassert>
#include <cmath>

#include <boost/filesystem/operations.hpp>

namespace tide {

torrent_storage::torrent_storage(
    std::shared_ptr<torrent_info> info, string_view piece_hashes
)
    : m_info(info)
    , m_piece_hashes(piece_hashes)
    , m_save_path(info->save_path)
    , m_name(info->name)
    , m_piece_length(info->piece_length)
    , m_num_pieces(info->num_pieces)
{
    initialize_file_entries(info->files);
    create_directory_tree();
}

inline bool torrent_storage::is_valid_file_index(const file_index_t index) const noexcept
{
    return (index > 0) && (index < m_files.size()); 
}

interval torrent_storage::pieces_in_file(const file_index_t file) const noexcept
{
    if(!is_valid_file_index(file))
    {
        return {};
    }
    return interval(m_files[file].first_piece, m_files[file].last_piece + 1);
}

interval torrent_storage::files_containing_piece(const piece_index_t piece) const noexcept
{
    interval result;
    for(auto i = 0; i < m_files.size(); ++i)
    {
        if(m_files[i].first_piece == piece)
        {
            result.begin = i;
        }
        if(m_files[i].last_piece == piece)
        {
            // TODO should we return a left inclusive or a left right inclusive ival?
            result.end = i + 1;
            break;
        }
    }
    return result;
}

file_slice torrent_storage::get_file_slice(
    const file_index_t file, const block_info& block) const noexcept
{
    if(!is_valid_file_index(file))
    {
        return {};
    }
    // first check if block is actually in this file
    const int64_t piece_offset = block.index * m_piece_length;
    const file_entry& entry = m_files[file];
    if((piece_offset < entry.offset) || (piece_offset >= entry.offset + block.length))
    {
        // block is not in file
        return {};
    }
    return get_file_slice(entry, piece_offset, block.length);
}

string_view torrent_storage::expected_hash(const piece_index_t piece) const noexcept
{
    if((piece > 0) && (piece < m_num_pieces))
    {
        return { m_piece_hashes.data() + piece * m_piece_length, 20 };
    }
    return {};
}

void torrent_storage::want_file(const file_index_t file) noexcept
{
    if(!is_valid_file_index(file) || m_files[file].is_wanted) return;
    m_size_to_download += m_files[file].storage.length();
    m_files[file].is_wanted = true;
}

void torrent_storage::dont_want_file(const file_index_t file) noexcept
{
    if(!is_valid_file_index(file) || !m_files[file].is_wanted) return;
    m_size_to_download -= m_files[file].storage.length();
    m_files[file].is_wanted = false;
}

void torrent_storage::erase_file(const file_index_t file_index, std::error_code& error)
{
    error.clear();
    file& file = m_files[file_index].storage;
    if(file.is_open())
    {
        file.close();
    }
    file.erase(error);
}

void torrent_storage::move(path path, std::error_code& error)
{
    if(path == m_save_path) return;
    // TODO must close all files, I think
    // TODO things we must watch out for:
    // path may exist -> should probably be an error
    // what if renaming does not succeed?
    // what about symlinks?
#ifdef _WIN32
    if(MoveFile(m_save_path, path) == 0)
    {
        util::assign_errno(error);
        return;
    }
#else // _WIN32
    if(rename(m_save_path.c_str(), path.c_str()) != 0)
    {
        util::assign_errno(error);
        return;
    }
#endif // _WIN32
    m_save_path = std::move(path);
}

/*
std::vector<mmap_source> torrent_storage::create_mmap_source(
    const block_info& info, std::error_code& error)
{
    std::vector<mmap_source> mmaps;
    do_file_io(
        [this, &mmaps]
        (file_entry& file,
         const file_slice& slice,
         std::error_code& error) mutable -> int
        {
            before_reading(file, error);
            if(error)
            {
                return 0;
            }
            mmaps.emplace_back(file.storage.create_mmap_source(
                slice.offset, slice.length, error
            ));
            if(error)
            {
                return 0;
            }
            //assert(slice.length == mmaps.back().length());
            return slice.length;
        },
        info,
        error);
    return mmaps;
}

std::vector<mmap_sink> torrent_storage::create_mmap_sink(
    const block_info& info, std::error_code& error)
{
    std::vector<mmap_sink> mmaps;
    do_file_io(
        [this, &mmaps]
        (file_entry& file,
         const file_slice& slice,
         std::error_code& error) mutable -> int
        {
            // TODO there is the contingency in which we want to write a block to
            // several files, but one of them is not wanted, to which we obviously
            // don't want to write. the problem here is that we return a vector of
            // mmap sinks which user expects to represent the contiguous blocks of
            // memory where the block will be written. so if a file is omitted, the
            // block will all of a sudden not be there. I don't think the whole op
            // should fail because of this, but somehow user must know that either
            // not all mappings have returned so don't count the mapped regions'
            // lengths to keep track of how much of the block has been written, or
            // that some of the mappings are false but *would* represent this much
            // memory so user can skip that
            return 0;
            /*
            num_written = file.storage.write(
                buffers, slice.offset, slice.length, error
            );
            if(error)
            {
                return 0;
            }
            //assert(slice.length == mmaps.back().length());
            return slice.length;
            * /
        },
        info,
        error);
    return mmaps;
}
*/

void torrent_storage::read(
    view<iovec>& buffers, const block_info& info, std::error_code& error)
{
    do_file_io(
        [this, &buffers]
        (file_entry& file,
         const file_slice& slice,
         std::error_code& error) mutable -> int
        {
            before_reading(file, error);
            if(error)
            {
                return 0;
            }
            // note that file::read trims buffers' front by num_read, so we must not do
            // it here again
            const int num_read = file.storage.read(buffers, slice.offset, error);
            if(!error)
            {
                assert(num_read == slice.length);
            }
            return num_read;
        },
        info,
        error);
}

void torrent_storage::read(
    std::vector<iovec> buffers, const block_info& info, std::error_code& error)
{
    read(buffers, info, error);
}

void torrent_storage::write(
    view<iovec>& buffers, const block_info& info, std::error_code& error)
{
    do_file_io(
        [this, &buffers]
        (file_entry& file,
         const file_slice& slice,
         std::error_code& error) mutable -> int
        {
            int num_written = 0;
            if(file.is_wanted)
            {
                before_writing(file, error);
                if(error)
                {
                    return 0;
                }
                // note that file::write trims buffers' front by num_written, so we must
                // not do it here again
                num_written = file.storage.write(buffers, slice.offset, error);
                if(error)
                {
                    return 0;
                }
            }
            else
            {
                // we don't want this file, so just ignore it (must not write to it),
                // but we must also trim the buffer as if it had been consumed by
                // file::write
                util::trim_buffers_front(buffers, slice.length);
                num_written = slice.length;
            }
            assert(num_written == slice.length);
            return num_written;
        },
        info,
        error);
}

void torrent_storage::write(
    std::vector<iovec> buffers, const block_info& info, std::error_code& error)
{
    write(buffers, info, error);
}

template<typename IOFunction>
void torrent_storage::do_file_io(
    IOFunction io_fn, const block_info& info, std::error_code& error)
{
    error.clear();
    view<file_entry> files = files_containing_block(info);
    if(files.is_empty())
    {
        // TODO perhaps create tailed error codes
        error = std::make_error_code(std::errc::no_such_file_or_directory);
        return;
    }

    int64_t offset = info.index * m_piece_length + info.offset;
    int num_left = info.length;
    for(file_entry& file : files)
    {
        num_left -= io_fn(file, get_file_slice(file, offset, num_left), error);
        if(error)
        {
            return;
        }
        offset = file.offset + file.storage.length();
    }
}

inline file_slice torrent_storage::get_file_slice(
    const file_entry& file, int64_t offset, int64_t length) const noexcept
{
    file_slice slice;
    slice.offset = offset - file.offset;
    const int64_t file_end = file.offset + file.storage.length();
    slice.length = std::max(length, file_end - offset);
    return slice;
}

void torrent_storage::before_writing(file_entry& file, std::error_code& error)
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
        file.storage.allocate(error);
    }
}

void torrent_storage::before_reading(file_entry& file, std::error_code& error)
{
    if(!file.is_wanted)
    {
        error = make_error_code(disk_io_errc::tried_unwanted_file_read);
        return;
    }
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
        error = make_error_code(disk_io_errc::tried_unallocated_file_read);
    }
}

void torrent_storage::initialize_file_entries(const_view<file_info> files)
{
    m_files.reserve(files.size());
    file_index_t index = 0;
    int64_t file_offset = 0;
    for(const auto& f : files)
    {
        // TODO mode
        uint8_t mode = 0;
        file_entry entry;
        entry.storage = file(m_save_path / f.path, f.length, mode);
        entry.offset = file_offset;
        entry.is_wanted = f.is_wanted;
        // move file_offset to the next file's beginning / this file's end
        entry.first_piece = file_offset / m_piece_length;
        file_offset += f.length;
        entry.last_piece = file_offset / m_piece_length;
        m_files.emplace_back(std::move(entry));
        if(entry.is_wanted)
        {
            m_size_to_download += f.length;
        }
    }
}

void torrent_storage::create_directory_tree()
{
    using boost::filesystem::create_directory;
    using boost::filesystem::create_directories;
    // we only need directories if this is a multi file torrent
    if(m_files.size() != 1)
    {
        // first initialize the root directory (these will throw exceptions so uhm)
        std::error_code ec;
        // TODO correct error handling
        if(!exists(m_save_path / m_name, ec))
        {
            create_directory(m_save_path);
        }
        for(const file_entry& file : m_files)
        {
            path dir_path = file.storage.absolute_path().parent_path();
            if(!dir_path.empty())
            {
                create_directories(dir_path);
            }
        }
    }
}

/*
void torrent_storage::create_directory(const path& path, std::error_code& error)
{
    assert(!path.empty());
#ifdef _WIN32
    if(CreateDirectory(path.c_str(), 0) == 0)
    {
        util::assign_errno(error);
    }
#else
    int mode = S_IRWXU | S_IRWXG | S_IRWXO;
    if(mkdir(path.c_str(), mode) != 0)
    {
        util::assign_errno(error);
    }
#endif
}

void torrent_storage::create_directories(const path& path, std::error_code& error)
{
    // this is mostly a port of the function of the same name in boost::filesystem
    // because boost::system::error_code does not interop with its std:: equivalent
    assert(!path.empty());
    if(path.filename_is_dot() || p.filename_is_dot_dot())
    {
        create_directories(path.parent_path(), error);
        return;
    }

    path parent = path.parent_path();
    if(!parent.empty())
    {
        create_directories(error, error);
    }

    if(!boost::filesystem::exists(path))
    {
        create_directory(path, error);
    }
}
*/

view<torrent_storage::file_entry>
torrent_storage::files_containing_block(const block_info& block)
{
    // get the first byte of block in the conceptual file stream by finding the first
    // byte of the piece and adding the block offset; and one past its last byte
    const int block_offset = block.index * m_piece_length + block.offset;
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

} // namespace tide

/*
view<torrent_storage::file_entry>
torrent_storage::files_containing_piece(const piece_index_t piece)
{
    const interval files = files_covering_piece(piece);
    return view<file_entry>(
        m_files.data() + files.begin,
        files.end - files.begin,
    );
}
*/
