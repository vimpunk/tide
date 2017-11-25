#include "string_utils.hpp"
#include "torrent_info.hpp"
#include "file_info.hpp"
#include "settings.hpp"
#include "bencode.hpp"
#include "disk_io.hpp"

#include <cmath>
#include <tuple>
#include <iterator>

// Functions that have this in their signature are executed on `disk_io`'s thread pool.
#define TIDE_WORKER_THREAD

namespace tide {

constexpr int block_index(const int offset) noexcept
{
    // FIXME this fired...
    assert(offset % 0x4000 == 0);
    return offset / 0x4000;
}

// -------------
// partial_piece
// -------------

disk_io::partial_piece::partial_piece(piece_index_t index_, int length_,
    int max_write_buffer_size, std::function<void(bool)> completion_handler_,
    asio::io_service& ios
)
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
    std::function<void(const std::error_code&)> save_handler_
)
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

inline interval disk_io::partial_piece::hashable_range() const noexcept
{
    if(buffer.empty()) { return {}; }
#ifdef TIDE_ENABLE_EXPENSIVE_ASSERTS
    // Buffer most be ordered at all times.
    for(auto i = 1; i < buffer.size(); ++i)
    {
        assert(buffer[i-1].offset < buffer[i].offset);
    }
#endif // TIDE_ENABLE_EXPENSIVE_ASSERTS
    if(unhashed_offset >= buffer[0].offset)
    {
        const auto first_unhashed = std::find_if(buffer.begin(), buffer.end(),
            [this](const auto& b) { return b.offset == unhashed_offset; });
        // Even though there is no gap between last unhashed block and the first block
        // in buffer, we may not have the block that is aligned with the unhashed offset.
        if(first_unhashed == buffer.end()) { return {}; }
        // Find one past the last hashable block.
        auto it = first_unhashed + 1;
        while(it != buffer.end())
        {
            const auto prev = it - 1;
            if(prev->offset + prev->buffer.size() != it->offset) { break; }
            ++it;
        }
        return interval(first_unhashed - buffer.begin(), it - buffer.begin());
    }
    else
    {
        return {};
    }
}

inline interval disk_io::partial_piece::largest_contiguous_range() const noexcept
{
    if(buffer.empty()) { return {}; }
    int max = 1;
    int n = 1;
    interval contiguous_range(0, 1);
    for(auto i = 1; i < buffer.size(); ++i)
    {
        if(buffer[i-1].offset + 0x4000 == buffer[i].offset)
            ++n;
        else
            n = 1;
        if(n > max)
        {
            max = n;
            contiguous_range.begin = i - max;
            contiguous_range.end = i;
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
        // This is not optimal but we don't expect to need this often so don't bother
        // for now.
        for(auto& block : work_buffer)
        {
            buffer.emplace(std::find_if(buffer.begin(), buffer.end(),
                [&block](const auto& b) { return b.offset > block.offset; }),
                std::move(block));
        }
        work_buffer.clear();
    }
}

// -------------
// torrent_entry
// -------------

disk_io::torrent_entry::torrent_entry(const torrent_info& info,
    string_view piece_hashes, path resume_data_path)
    : id(info.id)
    , storage(info, piece_hashes, std::move(resume_data_path))
{}

inline bool disk_io::torrent_entry::is_block_valid(const block_info& block)
{
    return block.index >= 0
        && block.index < storage.num_pieces()
        && block.offset % 0x4000 == 0;
}

// -------
// disk_io
// -------

disk_io::disk_io(asio::io_service& network_ios, const disk_io_settings& settings)
    : network_ios_(network_ios)
    , settings_(settings)
    , read_cache_(std::max(settings.read_cache_capacity, 0))
    , disk_buffer_pool_(0x4000)
    , retry_timer_(network_ios)
    , retry_delay_(5) // start with a 5 second wait between the first retry
{}

disk_io::~disk_io()
{
    // TODO make sure we don't destruct while there are jobs etc.
}

void disk_io::set_cache_size(const int n)
{
}

void disk_io::set_concurrency(const int n)
{
    const int old_concurrency = thread_pool_.concurrency();
    if(old_concurrency != n)
    {
        thread_pool_.set_concurrency(n);
        log(log_event::info, "changed concurrency from %i to %i", old_concurrency, n);
    }
}

void disk_io::read_metainfo(const path& path,
    std::function<void(const std::error_code&, metainfo)> handler)
{
    thread_pool_.post([this, path, handler = std::move(handler)]
    {
        //network_ios_.post([handler = std::move(handler),
            //metainfo = std::move(metainfo)] { handler(std::move(metainfo)); });
    });
}

torrent_storage_handle disk_io::allocate_torrent(const torrent_info& info,
    std::string piece_hashes, std::error_code& error)
{
    // TODO investigate whether this can potentially be so expensive an operation as to
    // justify sending it to thread pool.
    log(log_event::torrent, "creating disk_io entry for torrent#%i"
        " and setting up directory tree", info.id);
    try
    {
        // Insert new torrent before the first torrent that has a larger id than this
        // one.
        torrent_storage_handle handle;
        if(torrents_.empty() || (torrents_.back()->id < info.id))
        {
            torrents_.emplace_back(std::make_unique<torrent_entry>(
                info, std::move(piece_hashes), settings_.resume_data_path));
            handle = torrents_.back()->storage;
        }
        else
        {
            auto it = torrents_.emplace(std::upper_bound(
                torrents_.begin(), torrents_.end(), info.id,
                [](const auto& id, const auto& torrent) { return id < torrent->id; }),
                std::make_unique<torrent_entry>(info, std::move(piece_hashes),
                    settings_.resume_data_path));
            handle = (*it)->storage;
        }
        assert(handle);
        log(log_event::torrent, "torrent#%i allocated at %s",
            info.id, handle.root_path().c_str());
        return handle;
    }
    catch(const std::error_code& ec)
    {
        const auto reason = ec.message();
        log(log_event::torrent, "error allocating torrent#%i: %s",
            info.id, reason.c_str());
        error = ec;
        return {};
    }
}

// The following are a bit tricky, I think, because we need to ensure that no concurrent
// ops are run on file, but the kernel may provide some guarantees. TODO check..
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
    bmap_encoder resume_data, std::function<void(const std::error_code&)> handler)
{
    thread_pool_.post([resume_data = std::move(resume_data),
        handler = std::move(handler), &torrent = find_torrent_entry(id)]
    { 
        std::error_code error;
        torrent.storage.write_resume_data(resume_data, error);
        handler(error);
    });
}

void disk_io::load_torrent_resume_data(const torrent_id_t id,
    std::function<void(const std::error_code&, bmap)> handler)
{
    thread_pool_.post([handler = std::move(handler), &torrent = find_torrent_entry(id)]
    { 
        std::error_code error;
        auto resume_data = torrent.storage.read_resume_data(error);
        handler(error, std::move(resume_data));
    });
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
    return disk_buffer(reinterpret_cast<uint8_t*>(
        disk_buffer_pool_.malloc()), length, disk_buffer_pool_);
}

// -------
// writing
// -------

void disk_io::save_block(const torrent_id_t id,
    const block_info& block_info, disk_buffer block_data,
    std::function<void(const std::error_code&)> save_handler,
    std::function<void(bool)> piece_completion_handler)
{
#define BLOCK_FORMAT_STRING "block(torrent: %i; piece: %i; offset: %i; length: %i)"
#define BLOCK_FORMAT_ARGS id, block_info.index, block_info.offset, block_info.length
    if(settings_.max_buffered_blocks > 0
       && stats_.num_buffered_blocks >= settings_.max_buffered_blocks)
    {
        log(log_event::write, log::priority::high,
            "write buffer capacity reached, droppping " BLOCK_FORMAT_STRING,
            BLOCK_FORMAT_ARGS);
        network_ios_.post([handler = std::move(save_handler)]
            { handler(make_error_code(disk_io_errc::block_dropped)); });
        return;
    }

    torrent_entry& torrent = find_torrent_entry(id);

    if(!torrent.is_block_valid(block_info))
    {
        log(log_event::write, log::priority::high,
            "tried to save invalid " BLOCK_FORMAT_STRING, BLOCK_FORMAT_ARGS);
        network_ios_.post([handler = std::move(save_handler)]
            { handler(make_error_code(disk_io_errc::invalid_block)); });
        return;
    }

    // Find the partial_piece to which this block belongs.
    auto it = std::find_if(torrent.write_buffer.begin(), torrent.write_buffer.end(),
        [index = block_info.index](const auto& p) { return p->index == index; });
    // If none is found, this is the first block in piece, i.e. a new piece download.
    if(it == torrent.write_buffer.end())
    {
        torrent.write_buffer.emplace_back(std::make_unique<partial_piece>(
            block_info.index, torrent.storage.piece_length(block_info.index),
            settings_.write_cache_line_size, std::move(piece_completion_handler),
            network_ios_));
        it = torrent.write_buffer.end() - 1;
        ++stats_.num_partial_pieces;
        log(log_event::write,
            "new piece(%i) in torrent#%i (diskIO total: %i pieces; %i blocks)",
            block_info.index, id, stats_.num_partial_pieces,
            stats_.num_buffered_blocks);
#ifdef TIDE_ENABLE_DEBUGGING
        std::string s;
        for(const auto& piece : torrent.write_buffer)
            s += std::to_string(piece->index) + ' ';
        log(log_event::write, "pieces in torrent#%i write buffer: %s", id, s.c_str());
#endif //  TIDE_ENABLE_LOGGING
    }
    partial_piece& piece = **it;

    // Buffer must always be sorted by `block::offset`.
    const auto pos = std::find_if(piece.buffer.begin(), piece.buffer.end(),
        [offset = block_info.offset](const auto& b) { return b.offset >= offset; });
    // Before insertion, check if we don't already have this block.
    if(((pos != piece.buffer.end()) && (pos->offset == block_info.offset))
       || piece.save_progress[block_index(block_info.offset)])
    {
        log(log_event::write, "duplicate " BLOCK_FORMAT_STRING, BLOCK_FORMAT_ARGS);
        network_ios_.post([handler = std::move(save_handler)]
            { handler(make_error_code(disk_io_errc::duplicate_block)); });
        return;
    }
    log(log_event::write, BLOCK_FORMAT_STRING " save issued", BLOCK_FORMAT_ARGS);
    piece.buffer.emplace(pos, partial_piece::block(std::move(block_data),
        block_info.offset, std::move(save_handler)));
    ++stats_.num_buffered_blocks;
    if(settings_.write_buffer_expiry_timeout > seconds(0))
    {
        start_timer(piece.buffer_expiry_timer, settings_.write_buffer_expiry_timeout,
            [this, &torrent, &piece](const std::error_code& error)
            { on_write_buffer_expiry(error, torrent, piece); });
    }

    // Only a single thread may work (hash/write) on a piece at a time.
    if(!piece.is_busy) { dispatch_write(torrent, piece); }
#undef BLOCK_FORMAT_STRING
#undef BLOCK_FORMAT_ARGS
}

inline void disk_io::on_write_buffer_expiry(const std::error_code& error,
    torrent_entry& torrent, partial_piece& piece)
{
    if(error) { return; }

    // If piece is busy, its buffer is being flushed so no further action is necessary.
    if(!piece.is_busy && !piece.buffer.empty())
    {
        assert(!piece.is_complete());
        assert(!piece.buffer.empty());
        assert(piece.work_buffer.empty());
        piece.is_busy = true;
        piece.buffer.swap(piece.work_buffer);
        log(log_event::write, "piece(%i) buffer expiry reached, flushing %i blocks",
             piece.index, piece.work_buffer.size());
        thread_pool_.post([this, &torrent, &piece] { flush_buffer(torrent, piece); });
    }
}

// TODO refactor
inline void disk_io::dispatch_write(torrent_entry& torrent, partial_piece& piece)
{
    assert(!piece.is_busy);
    assert(!piece.buffer.empty());
    assert(piece.work_buffer.empty());

    // Even if a piece does not have write_cache_line_size blocks, if it's complete
    // it is written to disk in order to save it asap.
    if(piece.is_complete())
    {
#ifdef TIDE_ENABLE_EXPENSIVE_ASSERTS
        // Assert that we do indeed have all blocks.
        const_view<partial_piece::block> blocks(piece.buffer);
        for(auto offset = 0; offset < piece.length; offset += 0x4000)
        {
            if(!blocks.empty() && (blocks[0].offset == offset))
                blocks.trim_front(1);
            else
                // FIXME this fired!!!
                assert(piece.save_progress[block_index(offset)]);
        }
#endif // TIDE_ENABLE_EXPENSIVE_ASSERTS
        piece.is_busy = true;
        piece.buffer.swap(piece.work_buffer);
        log(log_event::write, "piece(%i) complete, writing %i blocks",
            piece.index, piece.work_buffer.size());
        thread_pool_.post([this, &torrent, &piece]
            { handle_complete_piece(torrent, piece); });
        return;
    }

    // Otherwise we're only interested in writing blocks to disk if piece's buffer has
    // at least settings::write_cache_line_size blocks; if it doesn't, don't bother.
    if(piece.buffer.size() < settings_.write_cache_line_size) { return; }

    // If we have a full hash batch, flush those to disk, and if there are any other
    // blocks in the write buffer, leave them there in hopes that the blocks needed to 
    // make those hashable will arrive soon, likely helping us to avoid a readback.
    const interval hashable_range = piece.hashable_range();
    const int num_hashable_blocks = hashable_range.length();
    if(num_hashable_blocks >= settings_.write_cache_line_size)
    {
        piece.is_busy = true;
        if(piece.buffer.size() == num_hashable_blocks)
        {
            piece.buffer.swap(piece.work_buffer);
        }
        else
        {
            const auto first_unhashed = piece.buffer.begin() + hashable_range.begin;
            for(auto it = first_unhashed, end = it + num_hashable_blocks; it != end; ++it)
            {
                piece.work_buffer.emplace_back(*it);
            }
            piece.buffer.erase(first_unhashed, first_unhashed + num_hashable_blocks);
        }
        log(log_event::write, "hashing and saving %i blocks in piece(%i)",
            piece.work_buffer.size(), piece.index);
        thread_pool_.post([this, &torrent, &piece]
            { hash_and_save_blocks(torrent, piece); });
        return;
    }

    // If we couldn't collect enough contiguous blocks to write them in one batch but
    // write buffer capacity has been reached, we must flush the whole thing and read
    // back the blocks for hashing later
    // (>= is used because if we couldn't save blocks, they are placed back into piece's
    // buffer, in which case buffer size will exceed its configured capacity).
    if(piece.buffer.size() >= settings_.write_buffer_capacity)
    {
        piece.is_busy = true;
        piece.buffer.swap(piece.work_buffer);
        log(log_event::write, "piece(%i) buffer capacity reached, saving %i"
            " blocks (need readback)",  piece.index, piece.work_buffer.size());
        thread_pool_.post([this, &torrent, &piece] { flush_buffer(torrent, piece); });
        return;
    }

    // If we have write cache line size contiguous blocks but we don't have enough
    // space for the blocks needed to fill the gap between last hashed block and
    // first block in the contiguous sequence, meaning we'll need to read back
    // anyway, flush the contiguos blocks and leave the rest in piece's buffer.
    const interval contiguous_range = piece.largest_contiguous_range();
    const int num_contiguous_blocks = contiguous_range.length();
    // Even though we have write_cache_line_size number of contiguous blocks in piece, 
    // they are not hashable, so as an optimization we try to wait for the blocks that 
    // fill the gap between the last hashed block and the beginning of the contiguous 
    // sequence, which would help us to avoid reading them back later.
    const int gap_size = contiguous_range.begin - block_index(piece.unhashed_offset);
    if(num_contiguous_blocks >= settings_.write_cache_line_size
       && gap_size < settings_.write_buffer_capacity - piece.buffer.size())
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
        log(log_event::write, "saving %i contiguous blocks in piece(%i) (need readback)",
            piece.work_buffer.size(), piece.index);
        thread_pool_.post([this, &torrent, &piece] { flush_buffer(torrent, piece); });
        return;
    }

    log(log_event::write, "piece(%i) has write cache line, but not flushing"
        " (buffer size: %i, num_hashable: %i, max contiguous: %i, unhashed offset: %i)",
        piece.index, piece.buffer.size(), num_hashable_blocks, num_contiguous_blocks,
        piece.unhashed_offset);
}

// TODO refactor
TIDE_WORKER_THREAD
void disk_io::handle_complete_piece(torrent_entry& torrent, partial_piece& piece)
{
    // TODO ensure torrent_entry thread safety
    ++torrent.num_pending_ops;
    // We should have all blocks by now.
    assert(!piece.work_buffer.empty());

    std::error_code error;
    // Although rare, the event in which we could hash a piece but not save it may
    // occur, in which case unhashed_offset is at the end of the piece
    // (note that if such an event occured, the piece is valid, since invalid pieces
    // are discarded, hence the true default value).
    bool is_piece_good = true;
    if(piece.unhashed_offset < piece.length)
    {
        const sha1_hash hash = finish_hashing(torrent, piece, error);
        if(error)
        {
            const auto reason = error.message();
            log(invoked_on::thread_pool, log_event::write,
                "error during piece(%i) readback: %s", piece.index, reason.c_str());
            network_ios_.post([&torrent, &piece, this]
            {
                piece.restore_buffer();
                // Try again later.
                if(settings_.write_buffer_expiry_timeout > seconds(0))
                {
                    start_timer(piece.buffer_expiry_timer,
                        settings_.write_buffer_expiry_timeout,
                        [this, &torrent, &piece](const std::error_code& error)
                        { on_write_buffer_expiry(error, torrent, piece); });
                }
            });
            return;
        }
        const sha1_hash expected_hash = torrent.storage.expected_piece_hash(piece.index);
        is_piece_good = std::equal(hash.begin(), hash.end(), expected_hash.begin());
        // Invoke piece completion handler before saving piece to disk as saving might
        // take a while.
        if(is_piece_good)
        {
            // NOTE: must not capture reference to piece as it may be removed by
            // the save completion handler below and io_service does not guarantee in
            // order execution.
            log(invoked_on::thread_pool, log_event::write,
                "piece(%i) passed hash test", piece.index);
            network_ios_.post([handler = std::move(piece.completion_handler)]
                { handler(true); });
        }
        else
        {
            log(invoked_on::thread_pool, log_event::write,
                "piece(%i) failed hash test", piece.index);
            network_ios_.post([&torrent, &piece]
            { 
                piece.completion_handler(false);
                const auto error = make_error_code(disk_io_errc::corrupt_data_dropped);
                for(auto& block : piece.work_buffer) { block.save_handler(error); }
                // Since piece is corrupt, we won't be saving it, so it's safe to remove
                // it in this callback, as we'll no longer refer to it.
                const auto it = std::find_if(torrent.write_buffer.begin(),
                    torrent.write_buffer.end(), [&piece](const auto& p)
                    { return p->index == piece.index; });
                assert(it != torrent.write_buffer.end());
                torrent.write_buffer.erase(it);
            });
        }
    }

    // Only save piece if it passed the hash test.
    if(is_piece_good)
    {
        save_maybe_contiguous_blocks(torrent, piece, error);
        network_ios_.post([this, &torrent, &piece, error]
        {
            std::error_code ec;
            piece.buffer_expiry_timer.cancel(ec);
            piece.is_busy = false;
            for(auto& block : piece.work_buffer) { block.save_handler(error); }
            // We usually download pieces that are rare, so it's reasonable to expect
            // other peers to request this piece as soon as we announce it, so even
            // though there have technically not been any requests for these blocks,
            // we put them in cache so they can be served as fast as possible
            // TODO consider this.
            for(const auto& block : piece.work_buffer)
            {
                block_source block_source(
                    block_info(piece.index, block.offset, block.buffer.size()),
                    source_buffer(std::make_shared<disk_buffer>(block.buffer)));
                read_cache_.insert({torrent.id, piece.index, block.offset},
                    std::move(block_source));
            }
            if(error)
            {
                // There was an error saving remaining blocks in piece, so we cannot 
                // remove it from write buffer yet, as data would be lost
                // we'll retry later.
                piece.restore_buffer();
                const auto reason = error.message();
                log(log_event::write, log::priority::high,
                    "error saving %i blocks while completing piece(%i), reason: %s",
                    piece.work_buffer.size(), reason.c_str());
            }
            else
            {
                log(log_event::write, "saved %i blocks, piece(%i) fully saved",
                    piece.work_buffer.size(), piece.index);
                stats_.num_buffered_blocks -= piece.work_buffer.size();
                stats_.num_blocks_written += piece.work_buffer.size();
                // Otherwise piece was saved so we can remove it from write buffer.
                torrent.write_buffer.erase(std::find_if(
                    torrent.write_buffer.begin(), torrent.write_buffer.end(),
                    [index = piece.index](const auto& p) { return p->index == index; }));
                --stats_.num_partial_pieces;
            }
        });
    }
    --torrent.num_pending_ops;
}

// TODO consider whether to update unhashed offset here or just return how many bytes
// were hashed.
TIDE_WORKER_THREAD
inline sha1_hash disk_io::finish_hashing(torrent_entry& torrent, partial_piece& piece,
    std::error_code& error)
{
    assert(piece.unhashed_offset < piece.length);
    assert(!piece.work_buffer.empty());

    error.clear();

    auto block = std::find_if(piece.work_buffer.begin(), piece.work_buffer.end(),
        [&piece](const auto& b) { return b.offset == piece.unhashed_offset; });
    const auto end = piece.work_buffer.end();
#ifdef TIDE_ENABLE_LOGGING
    if(block == end)
    {
        std::stringstream ss;
        ss << "FATAL: no hashable block. unhashed_offset: ";
        ss << piece.unhashed_offset;
        ss << ", blocks: ";
        for(const auto& b : piece.work_buffer) ss << ", " << b.offset;
        ss << '\n';
        std::string l = ss.str();
        log(invoked_on::thread_pool, log_event::write, log::priority::high, l.c_str());
    }
#endif // TIDE_ENABLE_LOGGING
    while(piece.unhashed_offset < piece.length)
    {
        if((block != end) && (block->offset == piece.unhashed_offset))
        {
            assert(!block->buffer.empty());
            piece.hasher.update(block->buffer);
            piece.unhashed_offset += block->buffer.size();
            ++block;
        }
        else
        {
            // Next block to be hashed is not in piece's buffer, so we need to read it
            // back from disk; check how many follow it, so we can pull them back in one.
            int length = 0x4000;
            int num_contiguous = 1;
            for(auto i = block_index(piece.unhashed_offset) + 1;
                i < piece.num_blocks(); ++i, ++num_contiguous)
            {
                // Note that we can't access save_progress from this thread so we loop
                // through all blocks saved to disk or until we hit block.
                if((block != end) && (i * 0x4000 == block->offset)) { break; }
                // Account for the last block's possible shorter length.
                if(i == piece.num_blocks() - 1)
                    length += piece.length - (piece.num_blocks() - 1) * 0x4000;
                else
                    length += 0x4000;
            }

            log(invoked_on::thread_pool, log_event::write,
                "reading back %i contiguous blocks for hashing in piece(%i)",
                num_contiguous, piece.index);

            const block_info info(piece.index, piece.unhashed_offset, length);
            const std::vector<mmap_source> mmaps =
                torrent.storage.create_mmap_sources(info, error);
            if(error) { return {}; }

            for(const auto& buffer : mmaps)
            {
                assert(!buffer.empty());
                piece.hasher.update(buffer);
                piece.unhashed_offset += buffer.size();
            }
        }
    }
    return piece.hasher.finish();
}

TIDE_WORKER_THREAD
void disk_io::hash_and_save_blocks(torrent_entry& torrent, partial_piece& piece)
{
    ++torrent.num_pending_ops;
    assert(!piece.work_buffer.empty());

    // The first unhashed block may not be the first block in piece.buffer.
    auto block = std::find_if(piece.work_buffer.begin(), piece.work_buffer.end(),
        [&piece](const auto& b) { return b.offset == piece.unhashed_offset; });
    assert(block != piece.work_buffer.end());
    while(block != piece.work_buffer.end())
    {
        assert(!block->buffer.empty());
        piece.hasher.update(block->buffer);
        piece.unhashed_offset += block->buffer.size();
        ++block;
    }

    std::error_code error;
    save_contiguous_blocks(torrent.storage, piece.index, piece.work_buffer, error);
    network_ios_.post([this, &torrent, &piece, error]
        { on_blocks_saved(error, torrent, piece); });

    --torrent.num_pending_ops;
}

TIDE_WORKER_THREAD
void disk_io::flush_buffer(torrent_entry& torrent, partial_piece& piece)
{
    ++torrent.num_pending_ops;
    assert(!piece.work_buffer.empty());

    // First check if one or more blocks in work_buffer is hashable the first unhashed 
    // block may not be the first block in piece.buffer.
    if(piece.unhashed_offset >= piece.work_buffer[0].offset)
    {
        // If so, the first hashable block may not be the first block in work_buffer if
        // blocks were hashed earlier but could not be saved.
        auto block = std::find_if(piece.work_buffer.begin(), piece.work_buffer.end(),
            [&piece](const auto& b) { return b.offset == piece.unhashed_offset; });
        if(block != piece.work_buffer.end())
        {
            const int num_contiguous = count_contiguous_blocks(piece.work_buffer);
            const auto end = piece.work_buffer.begin() + num_contiguous;
            while(block != end)
            {
                assert(!block->buffer.empty());
                piece.hasher.update(block->buffer);
                piece.unhashed_offset += block->buffer.size();
                ++block;
            }
            log(invoked_on::thread_pool, log_event::write,
                "hashed %i blocks in piece(%i) in non-hash job",
                num_contiguous, piece.index);
        }
    }

    // Now save buffers.
    std::error_code error;
    save_maybe_contiguous_blocks(torrent, piece, error);

    // Invoke completion handler.
    network_ios_.post([this, &torrent, &piece, error]
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
        // If we couldn't save blocks, we have to put them back into piece::buffer for
        // future reattempt.
        const auto reason = error.message();
        log(log_event::write, log::priority::high,
            "error saving %i blocks in piece(%i), reason: %s",
            piece.work_buffer.size(), piece.index, reason.c_str());
        piece.restore_buffer();
    }
    else
    {
        log(log_event::write, "saved %i blocks in piece(%i)",
            piece.work_buffer.size(), piece.index);
        // Mark blocks as saved.
        for(const auto& block : piece.work_buffer)
        {
            piece.save_progress[block.offset / 0x4000] = true;
        }
        piece.num_saved_blocks += piece.work_buffer.size();
        stats_.num_buffered_blocks -= piece.work_buffer.size();
        stats_.num_blocks_written += piece.work_buffer.size();
        // Blocks were saved, safe to remove them.
        piece.work_buffer.clear();
        // We may have received new blocks for this piece while this thread was
        // processing the current batch; if so, launch another op.
        if(!piece.buffer.empty()) { dispatch_write(torrent, piece); }
    }
}

TIDE_WORKER_THREAD
inline void disk_io::save_maybe_contiguous_blocks(torrent_entry& torrent,
    partial_piece& piece, std::error_code& error)
{
    // Blocks may not be contiguous, but they are ordered by their offsets, so in order
    // to save them in as few operations as possible, we try to probe for contiguous 
    // subsequences within blocks, and save them in one go.
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

TIDE_WORKER_THREAD
inline void disk_io::save_contiguous_blocks(torrent_storage& storage,
    const piece_index_t piece_index, view<partial_piece::block> blocks,
    std::error_code& error)
{
    assert(!blocks.empty());
    log(invoked_on::thread_pool, log_event::write, log::priority::low,
        "saving %i contiguous blocks", blocks.size());
    // Don't allocate an iovec vector if there is only a single buffer.
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

// -------
// reading
// -------
// TODO add more logging to fetch related functions.

void disk_io::fetch_block(const torrent_id_t id, const block_info& block_info,
    std::function<void(const std::error_code&, block_source)> handler)
{
    torrent_entry& torrent = find_torrent_entry(id);

    if(!torrent.is_block_valid(block_info))
    {
        network_ios_.post([handler = std::move(handler)]
            { handler(make_error_code(disk_io_errc::invalid_block), {}); });
        return;
    }

    block_source block = read_cache_[{id, block_info.index, block_info.offset}];
    if(block)
    {
        ++stats_.num_read_cache_hits;
        network_ios_.post([block = std::move(block), handler = std::move(handler)]
            { handler({}, std::move(block)); });
        log(log_event::cache, "%ith cache HIT", stats_.num_read_cache_hits);
        return;
    }

    ++stats_.num_read_cache_misses;
    log(log_event::cache, "%ith cache MISS", stats_.num_read_cache_misses);
    auto it = std::find_if(torrent.block_fetches.begin(), torrent.block_fetches.end(),
        [&block_info, num_read_ahead = settings_.read_cache_line_size](const auto& entry)
        {
            // We only read ahead blocks within the same piece.
            if(entry.first.index != block_info.index) { return false; }
            // If requested block is within settings::read_cache_line_size blocks after 
            // entry.first, we know the requested block will be pulled in with this entry.
            const int begin = entry.first.offset;
            const int end = begin + num_read_ahead * 0x4000;
            return (block_info.offset >= begin) && (block_info.offset <= end);
        });
    // If a fetch for this block has already been initiated, don't issue this request
    // instead, subscribe to this block and the current fetcher will call this function
    // with the proper block upon reading it in.
    if(it != torrent.block_fetches.end())
    {
        torrent_entry::fetch_subscriber sub;
        sub.handler = std::move(handler);
        sub.requested_offset = block_info.offset; 
        auto& subscribers = it->second;
        // Subscribers must be ordered by their requested block offset in piece.
        subscribers.emplace(std::find_if(subscribers.begin(), subscribers.end(),
            [offset = block_info.offset](const auto& sub)
            { return sub.requested_offset >= offset; }), std::move(sub));
    }
    else
    {
        // Otherwise we need to pull in the block ourself.
        torrent.block_fetches.emplace_back(block_info,
            std::vector<torrent_entry::fetch_subscriber>());
        thread_pool_.post([this, block_info, &torrent, handler = std::move(handler)]
            { dispatch_read(torrent, block_info, std::move(handler)); });
    }
}

TIDE_WORKER_THREAD
inline void disk_io::dispatch_read(torrent_entry& torrent, const block_info& info, 
    std::function<void(const std::error_code&, block_source)> handler)
{
    const int piece_length = torrent.storage.piece_length(info.index);
    assert(info.offset < piece_length);
    const int num_bytes_left = piece_length - info.offset;
    const int num_blocks_left = (num_bytes_left + (0x4000 - 1)) / 0x4000;

    // Only read ahead if it's not disabled and there is more than 1 block left in piece.
    if((settings_.read_cache_line_size > 0) && (num_blocks_left > 1))
        read_ahead(torrent, info, std::move(handler));
    else
        read_single_block(torrent, info, std::move(handler));
}

TIDE_WORKER_THREAD
inline void disk_io::read_single_block(torrent_entry& torrent, const block_info& info,
    std::function<void(const std::error_code&, block_source)> handler)
{
    std::error_code error;
    // For single blocks we use a simple disk_buffer rather than mmapping.
    auto buffer = std::make_shared<disk_buffer>(get_disk_buffer(info.length));
    torrent.storage.read(iovec{buffer->data(), size_t(buffer->size())}, info, error);
    block_source block(info, source_buffer(std::move(buffer)));
    network_ios_.post([this, error, block, handler = std::move(handler),
        torrent_id = torrent.id]
    {
        handler(error, block);
        if(!error)
        {
            ++stats_.num_blocks_read;
            read_cache_.insert({torrent_id, block.index, block.offset}, block);
        }
    });
}

TIDE_WORKER_THREAD
inline void disk_io::read_ahead(torrent_entry& torrent, const block_info& first_block,
    std::function<void(const std::error_code&, block_source)> handler)
{
    // We may not have read_cache_line_size number of blocks left in piece (we only
    // read ahead within the boundaries of a single piece).
    const int piece_length = torrent.storage.piece_length(first_block.index);
    assert(first_block.offset < piece_length);
    const int num_bytes_left = piece_length - first_block.offset;
    const int num_blocks_left = (num_bytes_left + (0x4000 - 1)) / 0x4000;
    const int num_blocks = std::min(num_blocks_left, settings_.read_cache_line_size);
    // Allocate blocks and prepare iovec buffers.
    std::vector<block_source> blocks;
    std::vector<iovec> iovecs;
    blocks.reserve(num_blocks);
    iovecs.reserve(num_blocks);
    auto info = first_block;
    for(auto i = 0, left = num_bytes_left; i < num_blocks; ++i)
    {
        // Account for the last block which may not be 16KiB.
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
        network_ios_.post([this, error, handler = std::move(handler)]
            { handler(error, {}); });
    }
    else
    {
        network_ios_.post([this, &torrent,
            handler = std::move(handler), blocks = std::move(blocks)]
            { on_blocks_read_ahead(torrent, std::move(blocks), std::move(handler)); });
    }
}

// Currently unused since we're not memory mapping read aheads.
TIDE_WORKER_THREAD
inline block_info disk_io::make_mmap_read_ahead_info(torrent_entry &torrent,
    const block_info& first_block) const noexcept
{
    // We may not have read_cache_line_size number of blocks left in piece (we only
    // read ahead within the boundaries of a single piece).
    const int piece_length = torrent.storage.piece_length(first_block.index);
    assert(first_block.offset < piece_length);
    int num_bytes_left = std::min(piece_length - first_block.offset,
        settings_.read_cache_line_size * 0x4000) - first_block.length;
    // Allocate blocks and prepare iovec buffers.
    block_info read_ahead_info = first_block;
    while(num_bytes_left > 0)
    {
        // Account for the last block which may not be 16KiB.
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
    // A read-ahead always starts with the initiator's block.
    handler({}, blocks[0]);

    // Invoke handlers subscribed to this read cache stripe.
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
        read_cache_.insert({torrent.id, block.index, block.offset}, block);
    }
    stats_.num_blocks_read += blocks.size();
}

// -----
// utils
// -----

TIDE_WORKER_THREAD
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

TIDE_WORKER_THREAD
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
    auto it = std::lower_bound(torrents_.begin(), torrents_.end(), id,
        [](const auto& torrent, const auto& id) { return torrent->id < id; });
    // Even though this is called by public functions, this really shouldn't happen as
    // we're only expecting valid torrent ids.
    assert(it != torrents_.end());
    // Lower_bound may return an element that is larger than what we asked for.
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
