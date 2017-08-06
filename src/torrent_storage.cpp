#include "torrent_storage.hpp"
#include "disk_buffer.hpp"
#include "bitfield.hpp"
#include "system.hpp"

#include "string_utils.hpp"
#include "log.hpp"

#include <cassert>
#include <cmath>

#include <boost/filesystem/operations.hpp>

namespace tide {

// a shared_ptr to info is passed in case torrent is removed while this is running
torrent_storage::torrent_storage(const torrent_info& info,
    string_view piece_hashes, path resume_data_path
)
    : m_resume_data(resume_data_path, 0,
        file::open_mode_flags{ file::read_write, file::sequential, file::no_os_cache })
    , m_piece_hashes(piece_hashes)
    , m_root_path(info.files.size() == 1
        ? info.save_path
        : info.save_path / info.name)
    , m_name(info.name)
    , m_piece_length(info.piece_length)
    , m_num_pieces(info.num_pieces)
{
    assert(!resume_data_path.empty());
    assert(!m_piece_hashes.empty());
    assert(!m_root_path.empty());
    assert(m_piece_length > 0);
    assert(m_num_pieces > 0);
    initialize_file_entries(info.files);
    create_directory_tree();
}

inline bool torrent_storage::is_file_index_valid(const file_index_t index) const noexcept
{
    return (index > 0) && (index < m_files.size()); 
}

interval torrent_storage::pieces_in_file(const file_index_t file) const noexcept
{
    if(!is_file_index_valid(file))
    {
        return {};
    }
    return interval(m_files[file].first_piece, m_files[file].last_piece + 1);
}

interval torrent_storage::files_containing_piece(const piece_index_t piece) const noexcept
{
    auto file = std::find_if(m_files.cbegin(), m_files.cend(),
        [piece](const auto& f) { return f.last_piece >= piece; });
    interval result;
    if(file != m_files.end())
    {
        result.begin = file - m_files.begin();
        result.end = result.begin + 1;
        ++file;
        while(file != m_files.end())
        {
            if(file->first_piece != piece) { break; }
            result.end = file - m_files.begin();
            ++file;
        }
    }
    return result;
}

interval torrent_storage::files_containing_pieces(const interval& pieces) const noexcept
{
    assert(false && "not impl");
    // TODO
}

file_slice torrent_storage::get_file_slice(
    const file_index_t file, const block_info& block) const noexcept
{
    if(!is_file_index_valid(file)) { return {}; }
    // first check if block is actually in this file
    const int64_t piece_offset = block.index * m_piece_length;
    const file_entry& entry = m_files[file];
    if(piece_offset < entry.torrent_offset
       || piece_offset >= entry.torrent_offset + block.length)
    {
        // block is not in file
        return {};
    }
    return get_file_slice(entry, piece_offset, block.length);
}

sha1_hash torrent_storage::expected_piece_hash(const piece_index_t piece) const noexcept
{
    if((piece >= 0) && (piece < m_num_pieces))
    {
        assert(!m_piece_hashes.empty());
        sha1_hash hash;
        const auto src = m_piece_hashes.data() + piece * 20;
        std::copy(src, src + 20, hash.begin());
        return hash;
    }
    assert(false);
    return {};
}

void torrent_storage::want_file(const file_index_t file) noexcept
{
    if(is_file_index_valid(file) && !m_files[file].is_wanted)
    {
        m_size_to_download += m_files[file].storage.length();
        m_files[file].is_wanted = true;
    }
}

void torrent_storage::dont_want_file(const file_index_t file) noexcept
{
    if(is_file_index_valid(file) && m_files[file].is_wanted)
    {
        m_size_to_download -= m_files[file].storage.length();
        m_files[file].is_wanted = false;
    }
}

bmap torrent_storage::read_resume_data(std::error_code& error)
{
    error.clear();
    before_reading(m_resume_data, error);
    if(error) { return {}; }

    std::string encoded(m_resume_data.length(), 0);
    iovec buffer;
    buffer.iov_base = &encoded[0];
    buffer.iov_len = encoded.length();
    m_resume_data.read(buffer, 0, error);
    if(error) { return {}; }

    return decode_bmap(std::move(encoded));
}

void torrent_storage::write_resume_data(
    const bmap_encoder& resume_data, std::error_code& error)
{
    error.clear();
    if(!m_resume_data.is_open())
    {
        m_resume_data.open(error);
        if(error) { return; }
    }
    std::string encoded = resume_data.encode();
    if(!m_resume_data.is_allocated() || (m_resume_data.length() < encoded.length()))
    {
        m_resume_data.allocate(encoded.length(), error);
        if(error) { return; }
    }
    iovec buffer;
    buffer.iov_base = &encoded[0];
    buffer.iov_len = encoded.length();
    m_resume_data.write(buffer, 0, error);
}

void torrent_storage::erase_file(const file_index_t file_index, std::error_code& error)
{
    error.clear();
    if(!is_file_index_valid(file_index))
    {
        error = std::make_error_code(std::errc::no_such_file_or_directory);
        return;
    }
    file& file = m_files[file_index].storage;
    if(file.is_open()) { file.close(); }
    file.erase(error);
}

void torrent_storage::move(path path, std::error_code& error)
{
    if(m_files.size() == 1)
    {
        file_entry& file = m_files.front();
        // TODO check if we have to close file before moving on Windows
        /*
        path new_file_path = path / file.relative_path();
        sys::move(file.absolute_path(), new_file_path, error);
        if(!error)
        {
            file.on_parent_moved(new_file_path);
            m_root_path = path;
        }
        */
    }
    else
    {
        /** TODO
        path name = m_root_path.
        sys::move(m_root_path, path, error);
        */
    }
}

void torrent_storage::check_storage_integrity(bitfield& pieces, std::error_code& error)
{
    check_storage_integrity(pieces, 0, m_num_pieces, error);
}

void torrent_storage::check_storage_integrity(bitfield& pieces, int first_piece,
    int num_pieces_to_check, std::error_code& error)
{
    if(pieces.size() != m_num_pieces
       || first_piece >= m_num_pieces
       || num_pieces_to_check > m_num_pieces)
    {
        error = std::make_error_code(std::errc::value_too_large);
        return;
    }
    error.clear();
    const interval files = files_containing_pieces(
        interval(first_piece, first_piece + num_pieces_to_check));
    for(auto i = files.begin; i < files.end; ++i)
    {
    }
    // TODO
}

std::vector<mmap_source> torrent_storage::create_mmap_sources(
    const block_info& info, std::error_code& error)
{
    std::vector<mmap_source> mmaps;
    for_each_file(
        [this, &mmaps]
        (file_entry& file,
         const file_slice& slice,
         std::error_code& error) mutable -> int
        {
            before_reading(file, error);
            if(error) { return 0; }
            mmaps.emplace_back(file.storage.create_mmap_source(
                slice.offset, slice.length, error));
            if(error) { return 0; }
            //assert(slice.length == mmaps.back().length());
            return slice.length;
        },
        info,
        error);
    return mmaps;
}

/*
std::vector<mmap_sink> torrent_storage::create_mmap_sink(
    const block_info& info, std::error_code& error)
{
    std::vector<mmap_sink> mmaps;
    for_each_file(
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
            num_written = file.storage.write(buffers, slice.offset, slice.length, error);
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

void torrent_storage::read(iovec buffer, const block_info& info, std::error_code& error)
{
    read(view<iovec>(&buffer, 1), info, error);
}

void torrent_storage::read(view<disk_buffer> buffers,
    const block_info& info, std::error_code& error)
{
    if(buffers.size() == 1)
    {
        // if we only have a single buffer, we don't need a vector (and thus can cut
        // dynalloc overhead), can call just read(iovec, info, error) directly
        iovec iov;
        iov.iov_base = buffers[0].data();
        iov.iov_len = buffers[0].size();
        read(iov, info, error);
    }
    else
    {
        std::vector<iovec> iovecs;
        iovecs.reserve(buffers.size());
        for(auto& buffer : buffers)
        {
            iovec iov;
            iov.iov_base = buffer.data();
            iov.iov_len = buffer.size();
            iovecs.emplace_back(iov);
        }
        read(std::move(iovecs), info, error);
    }
}

void torrent_storage::read(std::vector<iovec> buffers,
    const block_info& info, std::error_code& error)
{
    read(view<iovec>(buffers), info, error);
}

void torrent_storage::read(view<iovec> buffers,
    const block_info& info, std::error_code& error)
{
    for_each_file(
        [this, &buffers]
        (file_entry& file,
         const file_slice& slice,
         std::error_code& error) mutable -> int
        {
            before_reading(file, error);
            if(error) { return 0; }
            // note that file::read trims buffers' front by num_read, so we must not do
            // it here again
            const int num_read = file.storage.read(buffers, slice.offset, error);
            if(!error) { assert(num_read == slice.length); }
            return num_read;
        },
        info,
        error);
}

void torrent_storage::write(iovec buffer, const block_info& info, std::error_code& error)
{
    write(view<iovec>(&buffer, 1), info, error);
}

void torrent_storage::write(view<disk_buffer> buffers,
    const block_info& info, std::error_code& error)
{
    if(buffers.size() == 1)
    {
        iovec iov;
        iov.iov_base = buffers[0].data();
        iov.iov_len = buffers[0].size();
        write(iov, info, error);
    }
    else
    {
        std::vector<iovec> iovecs;
        iovecs.reserve(buffers.size());
        for(auto& buffer : buffers)
        {
            iovec iov;
            iov.iov_base = buffer.data();
            iov.iov_len = buffer.size();
            iovecs.emplace_back(iov);
        }
        write(std::move(iovecs), info, error);
    }
}

void torrent_storage::write(std::vector<iovec> buffers,
    const block_info& info, std::error_code& error)
{
    write(view<iovec>(buffers), info, error);
}

void torrent_storage::write(view<iovec> buffers,
    const block_info& info, std::error_code& error)
{
    for_each_file(
        [this, &buffers]
        (file_entry& file,
         const file_slice& slice,
         std::error_code& error) mutable -> int
        {
            int num_written = 0;
            if(file.is_wanted)
            {
                before_writing(file.storage, error);
                if(error) { return 0; }
                // note that file::write trims buffers' front by num_written, so we must
                // not do it here again
                num_written = file.storage.write(buffers, slice.offset, error);
                if(error) { return 0; }
            }
            else
            {
                // we don't want this file, so just ignore it (must not write to it),
                // but we must also trim the buffer as if it had been consumed by
                // file::write
                util::trim_buffers_front(buffers, slice.length);
                num_written = slice.length;
            }
            // we should have written to the entire file slice since file::write
            // guarantees this (and file slice describes the largest possible portion
            // of buffers that can be written to file without enlarging it)
            if(num_written != slice.length)
                log::log_disk_io("{TORRENT_STORAGE}",
                    util::format("FATAL! num_written(%i) <> slice.length(%i)",
                    num_written, slice.length), false, log::priority::high);
            assert(num_written == slice.length);
            return num_written;
        },
        info,
        error);
}

template<typename Function>
void torrent_storage::for_each_file(Function fn,
    const block_info& block, std::error_code& error)
{
    error.clear();
    view<file_entry> files = files_containing_block(block);
    if(files.empty())
    {
        error = std::make_error_code(std::errc::no_such_file_or_directory);
        return;
    }
        log::log_disk_io("{TORRENT_STORAGE}",
            util::format("writing %i bytes in piece(%i) to %i files",
                block.length, block.index, files.size()),
            false, log::priority::high);

    int64_t offset = int64_t(block.index) * m_piece_length + block.offset;
    int num_left = block.length;
    for(file_entry& file : files)
    {
        const auto slice = get_file_slice(file, offset, num_left);
            log::log_disk_io("{TORRENT_STORAGE}",
                util::format("writing %i bytes to %s at offset(%lli)", 
                    slice.length, file.storage.absolute_path().c_str(), slice.offset),
                false, log::priority::high);
        const int num_transferred = fn(file, slice, error);
        if(error) { return; }
        assert(num_transferred > 0);
        offset += num_transferred;
        num_left -= num_transferred;
    }
}

inline file_slice torrent_storage::get_file_slice(const file_entry& file,
    int64_t torrent_offset, int64_t length) const noexcept
{
    file_slice slice;
    slice.offset = torrent_offset - file.torrent_offset;
    const int64_t file_end = file.torrent_offset + file.storage.length();
    slice.length = std::min(length, file_end - torrent_offset);
    assert(slice.length > 0);
    assert(slice.offset >= 0);
    assert(slice.offset < file.torrent_offset + file.storage.length());
    return slice;
}

void torrent_storage::before_writing(file& file, std::error_code& error)
{
    if(!file.is_open())
    {
        file.open(error);
        if(error) { return; }
    }
    if(!file.is_allocated()) { file.allocate(error); }
}

void torrent_storage::before_reading(file_entry& file, std::error_code& error)
{
    if(!file.is_wanted)
    {
        error = make_error_code(file_errc::tried_unwanted_file_read);
        return;
    }
    before_reading(file.storage, error);
}

void torrent_storage::before_reading(file& file, std::error_code& error)
{
    if(!file.is_open())
    {
        file.open(error);
        if(error) { return; }
    }
    if(!file.is_allocated())
    {
        error = make_error_code(file_errc::tried_unallocated_file_read);
    }
}

void torrent_storage::initialize_file_entries(const_view<file_info> files)
{
    assert(!files.empty());
    m_files.reserve(files.size());
    // the path of a file depends whether torrent is multi file or single file/
    file_index_t index = 0;
    int64_t torrent_offset = 0;
    for(const auto& f : files)
    {
        // TODO mode
        file::open_mode_flags mode = { file::read_write, file::random, file::no_atime };
        file_entry entry;
        entry.storage = file(m_root_path / f.path, f.length, mode);
        entry.torrent_offset = torrent_offset;
        entry.is_wanted = f.is_wanted;
        entry.first_piece = torrent_offset / m_piece_length;
        // move torrent_offset to the next file's beginning / this file's end
        torrent_offset += f.length;
        entry.last_piece = torrent_offset / m_piece_length;
        m_files.emplace_back(std::move(entry));
        if(f.is_wanted)
        {
            m_size_to_download += f.length;
        }
        m_size += f.length;
    }
    assert(m_size >= 0);
    assert(m_size_to_download >= 0);
}

void torrent_storage::create_directory_tree()
{
    // we only need directories if this is a multi file torrent
    if(m_files.size() == 1) { return; }
    // first, establish the root directory
    std::error_code error;
    // create directory will not fail if root directory already exists
    sys::create_directory(m_root_path, error);
    // this is called from the constructor, so we must throw here
    if(error) { throw error; }
    // then the subdirectories
    for(const file_entry& file : m_files)
    {
        path dir_path = file.storage.absolute_path().parent_path();
        if(!dir_path.empty())
        {
            sys::create_directories(dir_path, error);
            if(error) { throw error; }
        }
    }
}

view<torrent_storage::file_entry>
torrent_storage::files_containing_block(const block_info& block)
{
    // get the first byte of block in the conceptual file stream
    const int64_t block_offset = int64_t(block.index) * m_piece_length + block.offset;
    // find the first file containing block_offset
    // TODO check if we can do logarithmic search here
    auto it = std::find_if(m_files.begin(), m_files.end(), [block_offset](const auto& f)
        { return f.torrent_offset + f.storage.length() > block_offset; });
    assert(it != m_files.end());
    file_entry* first_file = &*it;

    const int64_t block_end = block_offset + block.length;
    // find the last file containing block_end
    it = std::find_if(it, m_files.end(), [block_end](const auto& f)
        { return f.torrent_offset + f.storage.length() >= block_end; });
    assert(it != m_files.end());
    file_entry* last_file = &*it;

    // + 1 because it's a left inclusive interval and last_file points to a valid file
    return {first_file, last_file + 1};
}

} // namespace tide
