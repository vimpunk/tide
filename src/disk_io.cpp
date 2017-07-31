#include "string_utils.hpp"
#include "torrent_info.hpp"
#include "file_info.hpp"
#include "settings.hpp"
#include "bencode.hpp"
#include "disk_io.hpp"

#include <cmath>
#include <tuple>
#include <iterator>

namespace tide {

// -- partial_piece --

disk_io::partial_piece::partial_piece(piece_index_t index_, int length_,
    int max_write_buffer_size, std::function<void(bool)> completion_handler_,
    asio::io_service& ios)
    : save_progress((length_ + (0x4000 - 1)) / 0x4000)
    , index(index_)
    , length(length_)
    , completion_handler(std::move(completion_handler_))
    , buffer_expiry_timer(ios)
{
    const int to_reserve = std::min(num_blocks(), max_write_buffer_size);
    buffer.reserve(to_reserve);
    work_buffer.reserve(to_reserve);
}

disk_io::partial_piece::block::block(disk_buffer buffer_, int offset_, 
    std::function<void(const std::error_code&)> save_handler_)
    : buffer(std::move(buffer_))
    , offset(offset_)
    , save_handler(std::move(save_handler_))
{}

inline bool disk_io::partial_piece::is_complete() const noexcept
{
    return buffer.size() + num_saved_blocks == num_blocks();
}

inline int disk_io::partial_piece::num_blocks() const noexcept
{
    return save_progress.size();
}

inline int disk_io::partial_piece::num_hashable_blocks() const noexcept
{
    if(buffer.empty()) { return 0; }
#ifdef TIDE_ENABLE_EXPENSIVE_ASSERTS
    // buffer most be ordered at all times
    for(auto i = 1; i < buffer.size(); ++i)
    {
        assert(buffer[i-1].offset < buffer[i].offset);
    }
#endif // TIDE_ENABLE_EXPENSIVE_ASSERTS
    int num_hashable_blocks = 0;
    if(unhashed_offset >= buffer[0].offset)
    {
        const auto first_unhashed = std::find_if(buffer.begin(), buffer.end(),
            [this](const auto& b) { return b.offset == unhashed_offset; });
        // even though there is no gap between last unhashed block and the first block
        // in buffer, we may not have the block that is aligned with the unhashed offset
        if(first_unhashed == buffer.end()) { return 0; }
        num_hashable_blocks = 1;
        for(auto it = first_unhashed + 1; it != buffer.end(); ++it)
        {
            const auto prev = it - 1;
            if(prev->offset + prev->buffer.size() != it->offset) { break; }
            ++num_hashable_blocks;
        }
    }
    return num_hashable_blocks;
}

inline interval disk_io::partial_piece::largest_contiguous_range() const noexcept
{
    assert(!buffer.empty());
    int max = 1;
    int n = 1;
    interval contiguous_range(0, 1);
    for(auto i = 1; i < buffer.size(); ++i)
    {
        if(buffer[i-1].offset + 0x4000 == buffer[i].offset)
        {
            ++n;
        }
        else
        {
            if(n > max)
            {
                max = n;
                contiguous_range.begin = i - max;
                contiguous_range.end = i;
            }
            n = 1;
        }
    }
    return contiguous_range;
}

inline void disk_io::partial_piece::restore_buffer()
{
    if(buffer.empty())
    {
        buffer.swap(work_buffer);
    }
    else
    {
        // this is not optimal but we don't expect to need this often so don't bother
        // for now
        for(auto& block : work_buffer)
        {
            buffer.emplace(std::find_if(buffer.begin(), buffer.end(),
                [&block](const auto& b) { return b.offset > block.offset; }),
                std::move(block));
        }
        work_buffer.clear();
    }
}

// -- torrent_entry --

disk_io::torrent_entry::torrent_entry(std::shared_ptr<torrent_info> info,
    string_view piece_hashes, path resume_data_path)
    : id(info->id)
    , storage(info, piece_hashes, std::move(resume_data_path))
{}

// -- disk_io --

disk_io::disk_io(asio::io_service& network_ios, const disk_io_settings& settings)
    : m_network_ios(network_ios)
    , m_settings(settings)
    , m_read_cache(settings.read_cache_capacity)
    , m_disk_buffer_pool(0x4000)
    , m_retry_timer(network_ios)
{}

disk_io::~disk_io()
{
    // TODO make sure we don't destruct while there are jobs etc
}

void disk_io::change_cache_size(const int64_t n)
{
}

void disk_io::read_metainfo(const path& path,
    std::function<void(const std::error_code&, metainfo)> handler)
{
}

torrent_storage_handle disk_io::allocate_torrent(std::shared_ptr<torrent_info> info,
    std::string piece_hashes, std::error_code& error)
{
    // TODO investigate whether this can potentially be so expensive an operation as to
    // justify sending it to thread pool
    log(log_event::torrent, "creating disk_io entry for torrent#%i"
        " and setting up directory tree", info->id);
    try
    {
        // insert new torrent before the first torrent that has a larger id than this
        // one
        torrent_storage_handle handle;
        if(m_torrents.empty() || (m_torrents.back()->id < info->id))
        {
            m_torrents.emplace_back(std::make_unique<torrent_entry>(
                info, std::move(piece_hashes), m_settings.resume_data_path));
            handle = m_torrents.back()->storage;
        }
        else
        {
            auto it = m_torrents.emplace(std::upper_bound(
                m_torrents.begin(), m_torrents.end(), info->id,
                [](const auto& id, const auto& torrent) { return id < torrent->id; }),
                std::make_unique<torrent_entry>(info, std::move(piece_hashes),
                    m_settings.resume_data_path));
            handle = (*it)->storage;
        }
        assert(handle);
        log(log_event::torrent, "torrent#%i allocated at %s",
            info->id, handle.root_path().c_str());
        return handle;
    }
    catch(const std::error_code& ec)
    {
        const auto reason = ec.message();
        log(log_event::torrent, "error allocating torrent#%i: %s",
            info->id, reason.c_str());
        error = ec;
        return {};
    }
}

// the following are a bit tricky, I think, because we need to ensure that no concurrent
// ops are run on file, but the kernel may provide some guarantees. TODO check
void disk_io::move_torrent(const torrent_id_t id, std::string new_path,
    std::function<void(const std::error_code&)> handler)
{
}

void disk_io::rename_torrent(const torrent_id_t id, std::string name,
    std::function<void(const std::error_code&)> handler)
{
}

void disk_io::erase_torrent_files(const torrent_id_t id,
    std::function<void(const std::error_code&)> handler)
{
}

void disk_io::erase_torrent_resume_data(const torrent_id_t id,
    std::function<void(const std::error_code&)> handler)
{
}

void disk_io::save_torrent_resume_data(const torrent_id_t id,
    const bmap_encoder& resume_data, std::function<void(const std::error_code&)> handler)
{
}

void disk_io::load_torrent_resume_data(const torrent_id_t id,
    std::function<void(const std::error_code&, bmap)> handler)
{
}

void disk_io::load_all_torrent_resume_data(
    std::function<void(const std::error_code&, std::vector<bmap>)> handler)
{
}

void disk_io::check_storage_integrity(const torrent_id_t id, bitfield pieces,
    std::function<void(const std::error_code&, bitfield)> handler)
{
}

void disk_io::create_sha1_digest(const_view<uint8_t> data,
    std::function<void(sha1_hash)> handler)
{
}

disk_buffer disk_io::get_disk_buffer(const int length)
{
    return disk_buffer(reinterpret_cast<uint8_t*>(m_disk_buffer_pool.malloc()),
        length, m_disk_buffer_pool);
}

// -------------
// -- writing --
// -------------

void disk_io::save_block(const torrent_id_t id,
    const block_info& block_info, disk_buffer block_data,
    std::function<void(const std::error_code&)> save_handler,
    std::function<void(bool)> piece_completion_handler)
{
    // TODO check for block_info correctness
    torrent_entry& torrent = find_torrent_entry(id);
    // find the partial_piece to which this block belongs
    auto it = std::find_if(torrent.write_buffer.begin(), torrent.write_buffer.end(),
        [index = block_info.index](const auto& p) { return p->index == index; });
    // if none is found, this is the first block in piece, i.e. a new piece download
    if(it == torrent.write_buffer.end())
    {
        log(log_event::write, "new piece(%i) in torrent#%i", block_info.index, id);
        torrent.write_buffer.emplace_back(std::make_unique<partial_piece>(
            block_info.index, torrent.storage.piece_length(block_info.index),
            m_settings.write_cache_line_size, std::move(piece_completion_handler),
            m_network_ios));
        it = torrent.write_buffer.end() - 1;
        ++m_stats.num_partial_pieces;
    }
    partial_piece& piece = **it;

    // insert new block such that the resulting set of blocks remains sorted by
    // block::offset; find the first block whose offset is larger than this block's
    const auto pos = std::find_if(piece.buffer.begin(), piece.buffer.end(),
        [offset = block_info.offset](const auto& b) { return b.offset >= offset; });
    // before insertion, check if we don't already have this block
    if(((pos != piece.buffer.end()) && (pos->offset == block_info.offset))
       || piece.save_progress[block_info.offset / 0x4000])
    {
#define FORMAT_BLOCK_STRING "block(torrent: %i; index: %i; offset: %i; length: %i)"
#define FORMAT_BLOCK_ARGS id, block_info.index, block_info.offset, block_info.length
        log(log_event::write, "duplicate " FORMAT_BLOCK_STRING, FORMAT_BLOCK_ARGS);
        return;
    }
    log(log_event::write, FORMAT_BLOCK_STRING " save issued", FORMAT_BLOCK_ARGS);
#undef FORMAT_BLOCK_STRING
#undef FORMAT_BLOCK_ARGS
    piece.buffer.emplace(pos, partial_piece::block(std::move(block_data),
        block_info.offset, std::move(save_handler)));
    if(m_settings.write_buffer_expiry_timeout > seconds(0))
    {
        start_timer(piece.buffer_expiry_timer, m_settings.write_buffer_expiry_timeout,
            [this, &torrent, &piece](const std::error_code& error)
            { on_write_buffer_expiry(error, torrent, piece); });
    }

    // only a single thread may work (hash/write) on a piece at a time
    if(!piece.is_busy) { dispatch_write(torrent, piece); }
}

inline void disk_io::on_write_buffer_expiry(const std::error_code& error,
    torrent_entry& torrent, partial_piece& piece)
{
    if(error) { return; }

    // if piece is busy, its buffer is being flushed so no further action is necessary
    if(!piece.is_busy && !piece.buffer.empty())
    {
        assert(!piece.is_complete());
        assert(!piece.buffer.empty());
        assert(piece.work_buffer.empty());
        piece.is_busy = true;
        piece.buffer.swap(piece.work_buffer);
        log(log_event::write, "piece(%i) buffer expiry reached, flushing %i blocks",
             piece.index, piece.work_buffer.size());
        m_thread_pool.post([this, &torrent, &piece] { flush_buffer(torrent, piece); });
    }
}

inline void disk_io::dispatch_write(torrent_entry& torrent, partial_piece& piece)
{
    assert(!piece.is_busy);
    assert(!piece.buffer.empty());
    assert(piece.work_buffer.empty());

    // even if a piece does not have write_cache_line_size blocks, if it's complete
    // it is written to disk in order to save it asap
    if(piece.is_complete())
    {
        piece.is_busy = true;
        piece.buffer.swap(piece.work_buffer);
        log(log_event::write, "piece(%i) complete, writing %i blocks",
            piece.index, piece.work_buffer.size());
        m_thread_pool.post([this, &torrent, &piece]
            { handle_complete_piece(torrent, piece); });
        return;
    }

    // otherwise we're only interested in writing blocks to disk if piece's buffer has
    // at least settings::write_cache_line_size blocks; if it doesn't, don't bother
    if(piece.buffer.size() < m_settings.write_cache_line_size) { return; }

    // if we have a full hash batch, flush those to disk, and if there are any other
    // blocks in the write buffer, leave them there in hopes that the blocks needed to 
    // make those hashable will arrive soon, likely helping us to avoid a readback
    const int num_hashable_blocks = piece.num_hashable_blocks();
    if(num_hashable_blocks >= m_settings.write_cache_line_size)
    {
        piece.is_busy = true;
        if(piece.buffer.size() == num_hashable_blocks)
        {
            piece.buffer.swap(piece.work_buffer);
        }
        else
        {
            const auto first_unhashed = std::find_if(
                piece.buffer.begin(), piece.buffer.end(),
                [&piece](const auto& b) { return b.offset == piece.unhashed_offset; });
            for(auto it = first_unhashed, end = it + num_hashable_blocks; it != end; ++it)
            {
                piece.work_buffer.emplace_back(*it);
            }
            piece.buffer.erase(first_unhashed, first_unhashed + num_hashable_blocks);
        }
        log(log_event::write, "hashing and saving %i blocks in piece(%i)",
            piece.work_buffer.size(), piece.index);
        m_thread_pool.post([this, &torrent, &piece]
            { hash_and_save_blocks(torrent, piece); });
        return;
    }

    // if we couldn't collect enough contiguous blocks to write them in one batch but
    // write buffer capacity has been reached, we must flush the whole thing and read
    // back the blocks for hashing later
    // (>= is used because if we couldn't save blocks, they are placed back into piece's
    // buffer, in which case buffer size will exceed its configured capacity)
    if(piece.buffer.size() >= m_settings.write_buffer_capacity)
    {
        piece.is_busy = true;
        piece.buffer.swap(piece.work_buffer);
        log(log_event::write, "piece(%i) buffer capacity reached, saving %i"
            " blocks (need readback)",  piece.index, piece.work_buffer.size());
        m_thread_pool.post([this, &torrent, &piece] { flush_buffer(torrent, piece); });
        return;
    }

    // if we have write cache line size contiguous blocks but we don't have enough
    // space for the blocks needed to fill the gap between last hashed block and
    // first block in the contiguous sequence, meaning we'll need to read back
    // anyway, flush the contiguos blocks and leave the rest in piece's buffer
    // TODO or should we flush the entire buffer?
    const interval contiguous_range = piece.largest_contiguous_range();
    const int num_contiguous_blocks = contiguous_range.length();
    if(num_contiguous_blocks >= m_settings.write_cache_line_size
       && !should_wait_for_hashing(piece, contiguous_range))
    {
        piece.is_busy = true;
        if(num_contiguous_blocks == piece.buffer.size())
        {
            piece.buffer.swap(piece.work_buffer);
        }
        else
        {
            const auto first_block = piece.buffer.begin() + contiguous_range.begin;
            for(auto it = first_block, end = it + num_contiguous_blocks; it != end; ++it)
            {
                piece.work_buffer.emplace_back(*it);
            }
            piece.buffer.erase(first_block, first_block + num_contiguous_blocks);
        }
        log(log_event::write, "saving %i contiguous blocks in piece(%i)"
            " (need readback)", piece.work_buffer.size(), piece.index);
        m_thread_pool.post([this, &torrent, &piece] { flush_buffer(torrent, piece); });
    }
}

inline bool disk_io::should_wait_for_hashing(const partial_piece& piece,
    const interval& contiguous_range) const noexcept
{
    if(piece.buffer.size() < m_settings.write_buffer_capacity)
    {
        // now check the size of the gap between the start of the contiguous sequence
        // and the last hashed block
        const int gap_size = contiguous_range.begin - (piece.unhashed_offset / 0x4000);
        // if we need more blocks than for what we have space to make a hash batch,
        // we'll just flush the entire write buffer, otherwise we'll wait
        return gap_size < m_settings.write_buffer_capacity - piece.buffer.size();
    }
    return false;
}

// TODO refactor
void disk_io::handle_complete_piece(torrent_entry& torrent, partial_piece& piece)
{
    // TODO ensure torrent_entry thread safety
    ++torrent.num_pending_ops;
    // we should have all blocks by now
    assert(!piece.work_buffer.empty());

    std::error_code error;
    // although rare, the event in which we could hash a piece but not save it may
    // occur, in which case unhashed_offset is at the end of the piece
    // (note that if such an event occured, the piece is valid, since invalid pieces
    // are discarded, hence the true default value)
    bool is_piece_good = true;
    if(piece.unhashed_offset < piece.length)
    {
        const sha1_hash hash = finish_hashing(torrent, piece, error);
        if(error)
        {
            const auto reason = error.message();
            log(invoked_on::thread_pool, log_event::write,
                "error during piece readback: %s", reason.c_str());
            // TODO let someone know of the readback error--but who? it's not a save
            // error, so we probably shouldn't call block's save handlers
            m_network_ios.post([&piece] { piece.restore_buffer(); });
            return;
        }
        const sha1_hash expected_hash = torrent.storage.expected_piece_hash(piece.index);
        is_piece_good = std::equal(hash.begin(), hash.end(), expected_hash.begin());
        // invoke piece completion handler before saving piece to disk as saving might
        // take a while
        if(is_piece_good)
        {
            // NOTE: must not capture reference to piece as it may be removed by
            // the save completion handler below and io_service does not guarantee in
            // order execution
            log(invoked_on::thread_pool, log_event::write,
                "piece(%i) passed hash test", piece.index);
            m_network_ios.post([handler = std::move(piece.completion_handler)]
                { handler(true); });
        }
        else
        {
            log(invoked_on::thread_pool, log_event::write,
                "piece(%i) failed hash test", piece.index);
            m_network_ios.post([&torrent, piece_index = piece.index,
                handler = std::move(piece.completion_handler)]
            { 
                handler(false);
                // since piece is corrupt, we won't be saving it, so it's safe to remove
                // it in this callback, as we'll no longer refer to it
                const auto it = std::find_if(torrent.write_buffer.begin(),
                    torrent.write_buffer.end(), [piece_index](const auto& p)
                    { return p->index == piece_index; });
                assert(it != torrent.write_buffer.end());
                torrent.write_buffer.erase(it);
            });
        }
    }

    // only save piece if it passed the hash test
    if(is_piece_good)
    {
        save_maybe_contiguous_blocks(torrent, piece, error);
        m_network_ios.post([this, &torrent, &piece, error]
        {
            std::error_code ec;
            piece.buffer_expiry_timer.cancel(ec);
            piece.is_busy = false;
            for(auto& block : piece.work_buffer) { block.save_handler(error); }
            // we usually download pieces that are rare, so it's reasonable to expect
            // other peers to request this piece as soon as we announce it, so even
            // though there have technically not been any requests for these blocks,
            // we put them in cache so they can be served as fast as possible
            // TODO consider this
            for(const auto& block : piece.work_buffer)
            {
                block_source block_source(
                    block_info(piece.index, block.offset, block.buffer.size()),
                    source_buffer(std::make_shared<disk_buffer>(block.buffer)));
                m_read_cache.insert({torrent.id, piece.index, block.offset},
                    std::move(block_source));
            }
            if(error)
            {
                // there was an error saving remaining blocks in piece, so we cannot 
                // remove it from write buffer yet, as data would be lost
                // we'll retry later
                piece.restore_buffer();
            }
            else
            {
                m_stats.num_buffered_blocks -= piece.work_buffer.size();
                m_stats.num_blocks_written += piece.work_buffer.size();
                // otherwise piece was saved so we can remove it from write buffer
                torrent.write_buffer.erase(std::find_if(
                    torrent.write_buffer.begin(), torrent.write_buffer.end(),
                    [index = piece.index](const auto& p) { return p->index == index; }));
                --m_stats.num_partial_pieces;
            }
        });
    }
    --torrent.num_pending_ops;
}

// TODO consider whether to update unhashed offset here or just return how many bytes
// were hashed
inline sha1_hash disk_io::finish_hashing(torrent_entry& torrent, partial_piece& piece,
    std::error_code& error)
{
    assert(piece.unhashed_offset < piece.length);
    assert(!piece.work_buffer.empty());

    // blocks need not be contiguous and as such they may be interleaved with
    // blocks already saved to disk
    error.clear();
    const_view<partial_piece::block> blocks = piece.work_buffer;
    // some of the blocks in piece's buffer may already be hashed but couldn't be saved,
    // so skip to the first unhashed block
    while(blocks[0].offset < piece.unhashed_offset) { blocks.trim_front(0); }
    while(piece.unhashed_offset < piece.length)
    {
        if(!blocks.empty() && (blocks[0].offset == piece.unhashed_offset))
        {
            piece.hasher.update(blocks[0].buffer);
            piece.unhashed_offset += blocks[0].buffer.size();
            blocks.trim_front(1);
        }
        else
        {
            // next block to be hashed is not in piece's buffer, so we need to read it
            // back from disk
            const int block_index = piece.unhashed_offset / 0x4000;
            assert(piece.save_progress[block_index]);
            // check how many blocks follow this one, so we can pull them back in one
            int length = 0x4000;
            int num_contiguous = 1;
            for(auto i = block_index + 1; i < piece.num_blocks(); ++i, ++num_contiguous)
            {
                if(!piece.save_progress[i]) { break; }
                if(i == piece.num_blocks() - 1)
                    length += piece.length - (piece.num_blocks() - 1) * 0x4000;
                else
                    length += 0x4000;
            }

            log(invoked_on::thread_pool, log_event::write,
                "reading back %i contiguous blocks for hashing", num_contiguous);
            const block_info info(piece.index, piece.unhashed_offset, length);
            const std::vector<mmap_source> mmaps =
                torrent.storage.create_mmap_source(info, error);
            if(error) { return {}; }

            for(const auto& buffer : mmaps)
            {
                piece.hasher.update(buffer);
                piece.unhashed_offset += buffer.size();
            }
        }
    }
    return piece.hasher.finish();
}

void disk_io::hash_and_save_blocks(torrent_entry& torrent, partial_piece& piece)
{
    ++torrent.num_pending_ops;
    assert(!piece.work_buffer.empty());

    auto block = std::find_if(piece.work_buffer.begin(), piece.work_buffer.end(),
        [&piece](const auto& b) { return b.offset == piece.unhashed_offset; });
    assert(block != piece.work_buffer.end());
    while(block != piece.work_buffer.end())
    {
        piece.hasher.update(block->buffer);
        piece.unhashed_offset += block->buffer.size();
        ++block;
    }

    std::error_code error;
    save_contiguous_blocks(torrent.storage, piece.index, piece.work_buffer, error);
    m_network_ios.post([this, &torrent, &piece, error]
        { on_blocks_saved(error, torrent, piece); });

    --torrent.num_pending_ops;
}

void disk_io::flush_buffer(torrent_entry& torrent, partial_piece& piece)
{
    ++torrent.num_pending_ops;
    assert(!piece.work_buffer.empty());

    // first check if one or more blocks in the beginning of work_buffer is hashable
    if(piece.unhashed_offset == piece.work_buffer[0].offset)
    {
        const int num_contiguous = count_contiguous_blocks(piece.work_buffer);
        auto block = piece.work_buffer.begin();
        const auto end = piece.work_buffer.begin() + num_contiguous;
        while(block != end)
        {
            piece.hasher.update(block->buffer);
            piece.unhashed_offset += block->buffer.size();
            ++block;
        }
        log(invoked_on::thread_pool, log_event::write,
            "hashed %i pieces in non-hash job", num_contiguous);
    }

    // now save buffers
    std::error_code error;
    save_maybe_contiguous_blocks(torrent, piece, error);

    // invoke completion handler
    m_network_ios.post([this, &torrent, &piece, error]
        { on_blocks_saved(error, torrent, piece); });

    --torrent.num_pending_ops;
}

void disk_io::on_blocks_saved(const std::error_code& error,
    torrent_entry& torrent, partial_piece& piece)
{
    std::error_code ec;
    piece.buffer_expiry_timer.cancel(ec);
    piece.is_busy = false;
    for(auto& block : piece.work_buffer) { block.save_handler(error); }
    if(error)
    {
        // if we couldn't save blocks, we have to put them back into piece::buffer for
        // future reattempt
        piece.restore_buffer();
    }
    else
    {
        // mark blocks as saved
        for(const auto& block : piece.work_buffer)
        {
            piece.save_progress[block.offset / 0x4000] = true;
        }
        piece.num_saved_blocks += piece.work_buffer.size();
        m_stats.num_buffered_blocks -= piece.work_buffer.size();
        m_stats.num_blocks_written += piece.work_buffer.size();
        // blocks were saved, safe to remove them
        piece.work_buffer.clear();
        // we may have received new blocks for this piece while this thread was
        // processing the current batch; if so, launch another op
        if(!piece.buffer.empty()) { dispatch_write(torrent, piece); }
    }
}

inline void disk_io::save_maybe_contiguous_blocks(torrent_entry& torrent,
    partial_piece& piece, std::error_code& error)
{
    // blocks may not be contiguous, but they are ordered by their offsets, so in order
    // to save them in as few operations as possible, we try to probe for contiguous 
    // subsequences within blocks (if blocks were saved optimally, there will be only
    // one such sequence, the entire blocks list), and save them in one go
    error.clear();
    view<partial_piece::block> blocks(piece.work_buffer);
    while(!blocks.empty())
    {
        const int num_contiguous = count_contiguous_blocks(blocks);
        save_contiguous_blocks(torrent.storage, piece.index,
            blocks.subview(0, num_contiguous), error);
        if(error) { return; }
        blocks.trim_front(num_contiguous);
    }
}

inline void disk_io::save_contiguous_blocks(torrent_storage& storage,
    const piece_index_t piece_index, view<partial_piece::block> blocks,
    std::error_code& error)
{
    assert(!blocks.empty());
    log(invoked_on::thread_pool, log_event::write, log::priority::low,
        "saving %i contiguous blocks", blocks.size());
    // don't allocate an iovec vector if there is only a single buffer
    if(blocks.size() == 1)
    {
        auto& block = blocks[0];
        const block_info info(piece_index, block.offset, block.buffer.size());
        iovec buffer;
        buffer.iov_base = block.buffer.data();
        buffer.iov_len = block.buffer.length();
        storage.write(buffer, info, error);
    }
    else
    {
        std::vector<iovec> buffers;
        int num_bytes;
        std::tie(buffers, num_bytes) = prepare_iovec_buffers(blocks);
        assert(num_bytes > 0);
        const block_info info(piece_index, blocks[0].offset, num_bytes);
        storage.write(std::move(buffers), info, error);
    }
}

// -------------
// -- reading --
// -------------
// TODO add more logging to fetch related functions

void disk_io::fetch_block(const torrent_id_t id, const block_info& block_info,
    std::function<void(const std::error_code&, block_source)> handler)
{
    block_source block = m_read_cache[{id, block_info.index, block_info.offset}];
    if(block)
    {
        ++m_stats.num_read_cache_hits;
        m_network_ios.post([block = std::move(block), handler = std::move(handler)]
            { handler({}, std::move(block)); });
        log(log_event::cache, "%ith cache HIT", m_stats.num_read_cache_hits);
        return;
    }

    ++m_stats.num_read_cache_misses;
    log(log_event::cache, "%ith cache MISS", m_stats.num_read_cache_misses);
    torrent_entry& torrent = find_torrent_entry(id);
    auto it = std::find_if(torrent.block_fetches.begin(), torrent.block_fetches.end(),
        [&block_info, num_read_ahead = m_settings.read_cache_line_size](const auto& entry)
        {
            // we only read ahead blocks within the same piece
            if(entry.first.index != block_info.index) { return false; }
            // if requested block is within settings::read_cache_line_size blocks after 
            // entry.first, we know the requested block will be pulled in with this entry
            const int begin = entry.first.offset;
            const int end = begin + num_read_ahead * 0x4000;
            return (block_info.offset >= begin) && (block_info.offset <= end);
        });
    // if a fetch for this block has already been initiated, don't issue this request
    // instead, subscribe to this block and the current fetcher will call this function
    // with the proper block upon reading it in
    if(it != torrent.block_fetches.end())
    {
        torrent_entry::fetch_subscriber sub;
        sub.handler = std::move(handler);
        sub.requested_offset = block_info.offset; 
        auto& subscribers = it->second;
        // subscribers must be ordered by their requested block offset in piece
        subscribers.emplace(std::find_if(subscribers.begin(), subscribers.end(),
            [offset = block_info.offset](const auto& sub)
            { return sub.requested_offset >= offset; }), std::move(sub));
    }
    else
    {
        // otherwise we need to pull in the block ourself
        torrent.block_fetches.emplace_back(block_info,
            std::vector<torrent_entry::fetch_subscriber>());
        m_thread_pool.post([this, block_info, &torrent, handler = std::move(handler)]
            { dispatch_read(torrent, block_info, std::move(handler)); });
    }
}

inline void disk_io::dispatch_read(torrent_entry& torrent, const block_info& info, 
    std::function<void(const std::error_code&, block_source)> handler)
{
    const int piece_length = torrent.storage.piece_length(info.index);
    assert(info.offset < piece_length);
    const int num_bytes_left = piece_length - info.offset;
    const int num_blocks_left = (num_bytes_left + (0x4000 - 1)) / 0x4000;

    // only read ahead if it's not disabled and there is more than 1 block left in piece
    if((m_settings.read_cache_line_size > 0) && (num_blocks_left > 1))
    {
        read_ahead(torrent, info, std::move(handler));
    }
    else
    {
        read_single_block(torrent, info, std::move(handler));
    }
}

inline void disk_io::read_single_block(torrent_entry& torrent, const block_info& info,
    std::function<void(const std::error_code&, block_source)> handler)
{
    std::error_code error;
    // for single blocks we use a simple disk_buffer rather than mmapping
    auto buffer = std::make_shared<disk_buffer>(get_disk_buffer());
    torrent.storage.read(iovec{buffer->data(), size_t(buffer->size())}, info, error);
    block_source block(info, source_buffer(std::move(buffer)));
    m_network_ios.post([this, error, block, handler = std::move(handler),
        torrent_id = torrent.id]
    {
        handler(error, block);
        if(!error)
        {
            ++m_stats.num_blocks_read;
            m_read_cache.insert({torrent_id, block.index, block.offset}, block);
        }
    });
}

inline void disk_io::read_ahead(torrent_entry& torrent, const block_info& first_block,
    std::function<void(const std::error_code&, block_source)> handler)
{
    // we may not have read_cache_line_size number of blocks left in piece (we only
    // read ahead within the boundaries of a single piece)
    const int piece_length = torrent.storage.piece_length(first_block.index);
    assert(first_block.offset < piece_length);
    const int num_bytes_left = piece_length - first_block.offset;
    const int num_blocks_left = (num_bytes_left + (0x4000 - 1)) / 0x4000;
    const int num_blocks = std::min(num_blocks_left, m_settings.read_cache_line_size);
    // allocate blocks and prepare iovec buffers
    std::vector<block_source> blocks;
    std::vector<iovec> iovecs;
    blocks.reserve(num_blocks);
    iovecs.reserve(num_blocks);
    auto info = first_block;
    for(auto i = 0, left = num_bytes_left; i < num_blocks; ++i)
    {
        // account for the last block which may not be 16KiB
        const int length = std::min(left, 0x4000);
        auto buffer = std::make_shared<disk_buffer>(get_disk_buffer(length));
        blocks.emplace_back(info, source_buffer(buffer));
        iovecs.emplace_back(iovec{buffer->data(), size_t(buffer->size())});
        info.offset += 0x4000;
        left -= length;
    }
    auto read_ahead_info = first_block;
    read_ahead_info.length = std::min(num_blocks * 0x4000, num_bytes_left);

    std::error_code error;
    torrent.storage.read(std::move(iovecs), read_ahead_info, error);

    if(error)
    {
        m_network_ios.post([this, error, handler = std::move(handler)]
            { handler(error, {}); });
    }
    else
    {
        m_network_ios.post([this, &torrent,
            handler = std::move(handler), blocks = std::move(blocks)]
            { on_blocks_read_ahead(torrent, std::move(blocks), std::move(handler)); });
    }
}

// currently unused since we're not memory mapping read aheads
inline block_info disk_io::make_mmap_read_ahead_info(torrent_entry &torrent,
    const block_info& first_block) const noexcept
{
    // we may not have read_cache_line_size number of blocks left in piece (we only
    // read ahead within the boundaries of a single piece)
    const int piece_length = torrent.storage.piece_length(first_block.index);
    assert(first_block.offset < piece_length);
    int num_bytes_left = std::min(piece_length - first_block.offset,
        m_settings.read_cache_line_size * 0x4000) - first_block.length;
    // allocate blocks and prepare iovec buffers
    block_info read_ahead_info = first_block;
    while(num_bytes_left > 0)
    {
        // account for the last block which may not be 16KiB
        const int length = std::min(num_bytes_left, 0x4000);
        read_ahead_info.length += length;
        num_bytes_left -= length;
    }
    return read_ahead_info;
}

inline void disk_io::on_blocks_read_ahead(torrent_entry& torrent,
    std::vector<block_source> blocks,
    std::function<void(const std::error_code&, block_source)> handler)
{
    // a read-ahead always starts with the initiator's block
    handler({}, blocks[0]);

    // invoke handlers subscribed to this read cache stripe
    auto it = std::find_if(
        torrent.block_fetches.begin(), torrent.block_fetches.end(), 
        [info = static_cast<const tide::block_info&>(blocks[0])](const auto& entry)
        { return entry.first == info; });
    assert(it != torrent.block_fetches.end());
    auto& subscribers = it->second;
    for(auto& sub : subscribers)
    {
        assert(sub.requested_offset <= blocks.back().offset);
        sub.handler({}, blocks[sub.requested_offset / 0x4000]);
    }

    for(auto& block : blocks)
    {
        m_read_cache.insert({torrent.id, block.index, block.offset}, block);
    }
    m_stats.num_blocks_read += blocks.size();
}

// -----------
// -- utils --
// -----------

inline std::pair<std::vector<iovec>, int> disk_io::prepare_iovec_buffers(
    view<partial_piece::block> blocks)
{
    std::vector<iovec> buffers;
    buffers.reserve(blocks.size());
    int num_bytes = 0;
    for(auto& block : blocks)
    {
        num_bytes += block.buffer.size();
        buffers.emplace_back(iovec{block.buffer.data(), size_t(block.buffer.size())});
    }
    return {std::move(buffers), num_bytes};
}

inline int disk_io::count_contiguous_blocks(
    const_view<partial_piece::block> blocks) noexcept
{
    if(blocks.empty()) { return 0; }
    int num_contiguous = 1;
    for(auto i = 1; i < blocks.size(); ++i, ++num_contiguous)
    {
        if(blocks[i-1].offset + blocks[i-1].buffer.size() != blocks[i].offset) { break; }
    }
    return num_contiguous;
}

inline disk_io::torrent_entry& disk_io::find_torrent_entry(const torrent_id_t id)
{
    auto it = std::lower_bound(m_torrents.begin(), m_torrents.end(), id,
        [](const auto& torrent, const auto& id) { return torrent->id < id; });
    // even though this is called by public functions, this really shouldn't happen as
    // we're only expecting valid torrent ids
    assert(it != m_torrents.end());
    // lower_bound may return an element that is larger than what we asked for
    assert((*it)->id == id);
    return **it;
}

template<typename... Args>
void disk_io::log(const log_event event, const char* format, Args&&... args) const
{
    log(event, log::priority::normal, format, std::forward<Args>(args)...);
}

template<typename... Args>
void disk_io::log(const log_event event, const log::priority priority,
    const char* format, Args&&... args) const
{
    log(invoked_on::network_thread, event, priority,
        format, std::forward<Args>(args)...);
}

template<typename... Args>
void disk_io::log(const invoked_on thread, const log_event event,
    const char* format, Args&&... args) const
{
    log(thread, event, log::priority::normal, format, std::forward<Args>(args)...);
}

template<typename... Args>
void disk_io::log(const invoked_on thread, const log_event event,
    const log::priority priority, const char* format, Args&&... args) const
{
#ifdef TIDE_ENABLE_LOGGING
    const auto header = [event]() -> std::string
    {
        switch(event) {
        case log_event::cache: return "CACHE";
        case log_event::metainfo: return "METAINFO";
        case log_event::torrent: return "TORRENT";
        case log_event::write: return "WRITE";
        case log_event::read: return "READ";
        case log_event::resume_data: return "RESUME_DATA";
        case log_event::integrity_check: return "INTEGRITY_CHECK";
        default: return "";
        }
    }();
    log::log_disk_io(header, util::format(format, std::forward<Args>(args)...),
         thread == invoked_on::thread_pool, priority);
#endif // TIDE_ENABLE_LOGGING
}

} // namespace tide
