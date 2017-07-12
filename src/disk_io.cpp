#include "string_utils.hpp"
#include "torrent_info.hpp"
#include "file_info.hpp"
#include "settings.hpp"
#include "bencode.hpp"
#include "disk_io.hpp"

#include <cmath>
#include <tuple>
#include <iterator>
#include <iostream>

namespace tide {

// -- partial_piece --

disk_io::partial_piece::partial_piece(piece_index_t index_, int length_,
    int max_write_buffer_size, std::function<void(bool)> completion_handler_,
    asio::io_service& ios)
    : index(index_)
    , length(length_)
    , num_blocks((length_ + (0x4000 - 1)) / 0x4000)
    , completion_handler(std::move(completion_handler_))
    , buffer_expiry_timer(ios)
{
    const int to_reserve = std::min(num_blocks, max_write_buffer_size);
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
    return buffer.size() + num_saved_blocks == num_blocks;
}

inline int disk_io::partial_piece::num_hashable_blocks() const noexcept
{
    assert(!buffer.empty());
    int num_hashable_blocks = 0;
    if(unhashed_offset >= buffer[0].offset)
    {
        // find the first unhashed block
        const auto first_unhashed = std::find_if(buffer.begin(), buffer.end(),
            [this](const auto& b) { return b.offset == unhashed_offset; });
        assert(first_unhashed != buffer.end());
        // since there is no gap between last unhashed block and blocks in buffer,
        // we have at least one hashable block
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
    auto begin = buffer.begin();
    auto it = begin + 1;
    while(it != buffer.end())
    {
        if((it - 1)->offset + 0x4000 != it->offset)
        {
            if(n > max) { max = n; }
            begin = it;
            n = 1;
        }
        else
        {
            ++n;
        }
        ++it;
    }
    return {int(begin - buffer.begin()), int(it - buffer.begin())};
}

inline void disk_io::partial_piece::move_blocks_to_work_buffer(const int n)
{
    move_blocks_to_work_buffer(0, n);
}

inline void disk_io::partial_piece::move_blocks_to_work_buffer(int begin, int end)
{
    const int num_blocks = end - begin;
    assert(num_blocks <= buffer.size());
    assert(num_blocks > 0);

    if(buffer.size() == num_blocks)
    {
        buffer.swap(work_buffer);
    }
    else
    {
        for(auto i = 0; i < num_blocks; ++i)
        {
            work_buffer.emplace_back(std::move(buffer[i]));
        }
        // TODO can we prevent buffer from shrinking its capacity? it should stay
        // allocated at its initial capacity at all times as its continually refilled
        buffer.erase(buffer.begin(), buffer.begin() + num_blocks);
    }
}

inline void disk_io::partial_piece::restore_buffer()
{
    // TODO
    assert(0);
}

// -- torrent_entry --

disk_io::torrent_entry::torrent_entry(std::shared_ptr<torrent_info> info,
    string_view piece_hashes, path resume_data_path)
    : storage(info, piece_hashes, std::move(resume_data_path))
{}

disk_io::torrent_entry::torrent_entry(torrent_entry&& other)
    : storage(std::move(other.storage))
    , write_buffer(std::move(other.write_buffer))
    , block_fetches(std::move(other.block_fetches))
    , num_pending_ops(other.num_pending_ops.load(std::memory_order_relaxed))
{}

disk_io::torrent_entry& disk_io::torrent_entry::operator=(torrent_entry&& other)
{
    if(this != &other)
    {
        storage = std::move(other.storage);
        write_buffer = std::move(other.write_buffer);
        block_fetches = std::move(other.block_fetches);
        num_pending_ops.store(other.num_pending_ops.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
    }
    return *this;
}

// -- disk_io --

disk_io::disk_io(asio::io_service& network_ios, const disk_io_settings& settings)
    : m_network_ios(network_ios)
    , m_settings(settings)
    , m_disk_buffer_pool(0x4000)
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
    log(log_event::torrent, "creating disk_io entry for torrent"
        " and setting up directory tree");
    try
    {
        torrent_entry torrent(info, std::move(piece_hashes), m_settings.resume_data_path);
        // pair<iterator, bool>
        auto r = m_torrents.emplace(info->id, std::move(torrent));
        auto handle = torrent_storage_handle(r.first->second.storage);
        if(handle)
        {
            log(log_event::torrent, "torrent allocated at %s", handle.root_path().c_str());
        }
        return handle;
    }
    catch(const std::error_code& ec)
    {
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
        torrent.write_buffer.emplace_back(std::make_unique<partial_piece>(
            block_info.index, torrent.storage.piece_length(block_info.index),
            m_settings.write_cache_line_size, std::move(piece_completion_handler),
            m_network_ios));
        it = torrent.write_buffer.end() - 1;
    }
    partial_piece& piece = **it;
    // insert new block such that the resulting set of blocks remains sorted by
    // block offset; find the first block whose offset is larger than this block's
    piece.buffer.emplace(std::find_if(piece.buffer.begin(), piece.buffer.end(),
        [offset = block_info.offset](const auto& b) { return b.offset > offset; }),
        partial_piece::block(std::move(block_data), block_info.offset,
        std::move(save_handler)));
    // only a single thread may work (hash/write) on a piece at a time
    if(!piece.is_busy) { dispatch_write(torrent, piece); }
}

inline void disk_io::dispatch_write(torrent_entry& torrent, partial_piece& piece)
{
    // note: we use if-fallthrough so we don't have to calculate num_hashable_blocks and
    // num_contiguous_blocks in the beginning of the function as they may not be used
    // and they aren't *that* cheap // TODO fix, it's ugly
    assert(piece.work_buffer.empty());

    if(piece.is_complete())
    {
        // even if a piece does not have write_cache_line_size blocks, if it's complete
        // it is written to disk in order to save it asap
        piece.is_busy = true;
        piece.buffer.swap(piece.work_buffer);
        log(log_event::piece, "piece(%i) complete, writing %i blocks",
            piece.index, piece.work_buffer.size());
        m_thread_pool.post([this, &torrent, &piece]
            { handle_complete_piece(torrent, piece); });
        return;
    }

    const int num_hashable_blocks = piece.num_hashable_blocks();
    if(num_hashable_blocks == m_settings.write_cache_line_size)
    {
        // we have a full hash batch, so flush those to disk, but if there are any other
        // blocks in the write buffer leave those in buffer in hopes that the blocks 
        // needed to make those hashable will arrive soon, likely helping us to avoid a 
        // readback
        piece.is_busy = true;
        piece.move_blocks_to_work_buffer(num_hashable_blocks);
        log(log_event::piece, "hashing and saving %i blocks in piece(%i)",
            piece.index, piece.work_buffer.size());
        //piece.num_hashable_blocks = 0;
        m_thread_pool.post([this, &torrent, &piece]
            { hash_and_save_blocks(torrent, piece); });
        return;
    }

    if(piece.buffer.size() == m_settings.write_buffer_capacity)
    {
        // we couldn't collect enough contiguous blocks to write them in one batch but
        // write buffer capacity has been reached so we must flush the whole thing and
        // read back the blocks for hashing later
        piece.is_busy = true;
        piece.buffer.swap(piece.work_buffer);
        log(log_event::piece, "piece(%i) buffer capacity reached, saving %i"
            "blocks (need readback)",  piece.index, piece.work_buffer.size());
        m_thread_pool.post([this, &torrent, &piece] { flush_buffer(torrent, piece); });
        return;
    }

    const interval contiguous_range = piece.largest_contiguous_range();
    const int num_contiguous_blocks = contiguous_range.length();
    if(num_contiguous_blocks == m_settings.write_cache_line_size
       && !should_wait_for_hashing(piece, num_contiguous_blocks))
    {
        // we have write cache line size contiguous blocks but we don't have enough
        // space for the blocks needed to fill the gap between last hashed block and
        // first block in the contiguous sequence, meaning we'll need to read back
        // anyway, so flush the contiguos blocks and leave the rest in piece's buffer
        // TODO or should we flush the entire buffer?
        piece.is_busy = true;
        piece.move_blocks_to_work_buffer(contiguous_range.begin, contiguous_range.end);
        log(log_event::piece, "saving %i contiguous blocks in piece(%i) (need readback)",
            piece.work_buffer.size(), piece.index);
        m_thread_pool.post([this, &torrent, &piece] { flush_buffer(torrent, piece); });
    }
}

inline bool disk_io::should_wait_for_hashing(const partial_piece& piece,
    const int num_contiguous_blocks) const noexcept
{
    if(piece.buffer.size() < m_settings.write_buffer_capacity)
    {
        // first find the blocks that constitute the contiguous block sequence
        auto begin = piece.buffer.begin();
        auto it = begin + 1;
        const auto end = piece.buffer.end();
        while((it != end) && (it - begin < num_contiguous_blocks))
        {
            if(it->offset - (it - 1)->offset != 0x4000)
                begin = it++;
            else
                ++it;
        }
        assert(begin != end);
        // now check the size of the gap between the start of the contiguous sequence
        // and the last hashed block
        const int gap_size = (begin->offset - piece.unhashed_offset) / 0x4000;
        // if we need more blocks than for what we have space to make a hash batch,
        // we'll just flush the entire write buffer, otherwise we'll wait
        return gap_size < m_settings.write_buffer_capacity - piece.buffer.size();
    }
    return false;
}

void disk_io::handle_complete_piece(torrent_entry& torrent, partial_piece& piece)
{
    // TODO ensure torrent_entry thread safety
    ++torrent.num_pending_ops;
    // we should have all blocks by now
    assert(!piece.work_buffer.empty());

    std::error_code error;
    // although rare, the event in which we could hash a piece but not save it may
    // occur, in which case first_unhashed_byte is at the end of the piece
    // (note that if such an event occured, the piece is valid, since invalid pieces
    // are discarded, hence the true default value)
    bool is_piece_good = true;
    if(piece.unhashed_offset < piece.length)
    {
        const sha1_hash hash = finish_hashing(torrent, piece, error);
        if(error)
        {
            // finish_block only fails if it has to read back blocks for hashing, and
            // that may fail, so we couldn't fully hash blocks
            // TODO it's quite unclear how to proceed from here: put back blocks into
            // piece's buffer and retry later? or perhaps a disk read error does not
            // equate to failing a disk write and we can at least save these blocks?
            m_network_ios.post([&piece]
            {
                piece.restore_buffer();
                // TODO let someone know of the readback error--but who?
            });
            return;
        }
        // retrieving the piece hash is thread-safe
        const sha1_hash expected_hash = torrent.storage.expected_piece_hash(piece.index);
        is_piece_good = std::equal(hash.begin(), hash.end(), expected_hash.begin());
        // invoke piece completion handler before saving piece to disk as saving might
        // take a while
        if(is_piece_good)
        {
            // NOTE: must not capture reference to piece as it may be removed by
            // the save completion handler below and io_service does not guarantee in
            // order execution
            m_network_ios.post([handler = std::move(piece.completion_handler)]
                { handler(true); });
        }
        else
        {
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
        m_network_ios.post([&torrent, &piece, error]
        {
            piece.is_busy = false;
            for(auto& block : piece.work_buffer) { block.save_handler(error); }
            if(error)
            {
                // there was an error saving remaining blocks in piece, so we cannot 
                // remove it from write buffer yet, as data would be lost
                // we'll retry later
                piece.restore_buffer();
            }
            else
            {
                // otherwise piece was saved so we can remove it from write buffer
                torrent.write_buffer.erase(std::find_if(
                    torrent.write_buffer.begin(), torrent.write_buffer.end(),
                    [index = piece.index](const auto& p) { return p->index == index; }));
                // TODO since we know that piece is good even though we couldn't save it,
                // we can still serve it once requested, so move it to the read cache
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
    // NOTE: blocks need not be contiguous and as such they may be interleaved with
    // blocks already saved to disk
    error.clear();
    const_view<partial_piece::block> blocks = piece.work_buffer;
    while(piece.unhashed_offset < piece.length)
    {
        if(!blocks.is_empty() && (blocks[0].offset == piece.unhashed_offset))
        {
            piece.hasher.update(blocks[0].buffer);
            piece.unhashed_offset += blocks[0].buffer.size();
            blocks.trim_front(1);
        }
        else
        {
            // next block to be hashed is not in blocks, so we need to read it back
            // from disk
            const int block_index = piece.unhashed_offset / 0x4000;
            // by now we must have this piece on disk, otherwise we're flawed human beings
            assert(piece.save_progress[block_index]);
            // for optimization, check how many blocks follow this one, so we can pull
            // them back in one
            int length = 0x4000;
            for(auto i = block_index + 1; i < piece.num_blocks; ++i)
            {
                if(!piece.save_progress[i]) { break; }
                if(i == piece.num_blocks - 1)
                    length += piece.length - (piece.num_blocks - 1) * 0x4000;
                else
                    length += 0x4000;
            }

            // memory mapping is used to avoid excessive copying
            /*
            const block_info info(piece.index, piece.unhashed_offset, length);
            const std::vector<mmap_source> mmaps =
                torrent.storage.create_mmap_source(info, error);
            if(error) { return {}; }

            // hash blocks
            for(const auto& buffer : mmaps)
            {
                piece.hasher.update(buffer);
                piece.unhashed_offset += buffer.size();
            }
            */
        }
    }
    return piece.hasher.finish();
}

void disk_io::hash_and_save_blocks(torrent_entry& torrent, partial_piece& piece)
{
    ++torrent.num_pending_ops;
    assert(!piece.work_buffer.empty());

    // hash blocks
    for(const auto& block : piece.work_buffer)
    {
        piece.hasher.update(block.buffer);
        piece.unhashed_offset += block.buffer.size();
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
        // count how many blocks are hashable
        const int num_contiguous = count_contiguous_blocks(piece.work_buffer);
        auto block = piece.work_buffer.begin();
        const auto end = piece.work_buffer.begin() + num_contiguous;
        while(block != end)
        {
            piece.hasher.update(block->buffer);
            piece.unhashed_offset += block->buffer.size();
            ++block;
        }
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
        // blocks were saved, safe to remove them
        piece.work_buffer.clear();
        // we may have received new blocks for this piece while this thread was
        // processing the current batch; if so, launch another op
        dispatch_write(torrent, piece);
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
    while(!blocks.is_empty())
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
    assert(!blocks.is_empty());
    std::vector<iovec> buffers;
    int num_bytes;
    std::tie(buffers, num_bytes) = prepare_iovec_buffers(blocks);
    assert(num_bytes > 0);
    const block_info info(piece_index, blocks[0].offset, num_bytes);
    storage.write(std::move(buffers), info, error);
}

// -------------
// -- reading --
// -------------

void disk_io::fetch_block(const torrent_id_t id, const block_info& block_info,
    std::function<void(const std::error_code&, block_source)> handler)
{
    // TODO first check if block is in disk cache, if so, no need to fetch it. but
    // cache is as yet unimplemented so we'll read from disk unconditionally for now
    torrent_entry& torrent = find_torrent_entry(id);
    // if a fetch for this block has already been initiated, don't issue this request
    // instead, subscribe to this block and the current fetcher will call this function
    // with the proper block upon reading it in
    auto it = std::find_if(torrent.block_fetches.begin(), torrent.block_fetches.end(),
        [&block_info, num_read_ahead = m_settings.read_cache_line_size](const auto& entry)
        {
            // for now we only read ahead blocks within the same piece (but this is
            // expected to change)
            if(entry.first.index != block_info.index) { return false; }
            // if requested block is within settings::read_cache_line_size blocks after 
            // entry.first, we know the requested block will be pulled in with this entry
            const int begin = entry.first.offset;
            const int end = begin + num_read_ahead * 0x4000;
            return (block_info.offset >= begin) && (block_info.offset <= end);
        });
    if(it != torrent.block_fetches.end())
    {
        // this block will be pulled in with an ongoing block fetch
        torrent_entry::piece_fetch_subscriber subscriber;
        subscriber.handler = std::move(handler);
        subscriber.requested_offset = block_info.offset; 
        auto& subscribers = it->second;
        subscribers.emplace_back(std::move(subscriber));
        // subs must be ordered by their requested block offset in piece
        std::sort(subscribers.begin(), subscribers.end(), [](const auto& a, const auto& b)
            { return a.requested_offset < b.requested_offset; });
    }
    else
    {
        // otherwise we need to pull in the block ourself
        torrent.block_fetches.emplace_back(block_info,
            std::vector<torrent_entry::piece_fetch_subscriber>());
        m_thread_pool.post([this, block_info, &torrent, handler = std::move(handler)]
            { fetch_block(torrent, block_info, std::move(handler)); });
    }
}

void disk_io::fetch_block(torrent_entry& torrent, const block_info& block_info, 
    std::function<void(const std::error_code&, block_source)> handler)
{
    // NOTE: this function is run in a different thread to where m_network_ios.run()
    // is invoked

    // TODO later we'll just memory map it, but for now for simplicity's sake use
    // regular disk_buffers
    if(m_settings.read_cache_line_size > 0)
    {
        read_ahead(torrent, block_info, std::move(handler));
    }
    else
    {
        // read-ahead is disabled, so just read a single block
        std::error_code error;
        auto buffer = std::make_shared<disk_buffer>(get_disk_buffer());
        torrent.storage.read(iovec{buffer->data(), size_t(buffer->size())},
            block_info, error);
        block_source block(block_info, source_buffer(std::move(buffer)));
        m_network_ios.post([this, error, block = std::move(block),
            handler = std::move(handler)]
        {
            handler(error, std::move(block));
            if(!error)
            {
                // TODO save block in disk cache
            }
        });
    }
}

inline void disk_io::read_ahead(torrent_entry& torrent, const block_info& block_info,
    std::function<void(const std::error_code&, block_source)> handler)
{
    // we may not have read_cache_line_size number of blocks left in piece (we only
    // read ahead within the boundaries of a single piece)
    const int piece_length = torrent.storage.piece_length(block_info.index);
    assert(block_info.offset < piece_length);
    const int num_bytes_left = piece_length - block_info.offset;
    const int num_blocks_left = num_bytes_left / 0x4000;
    const int num_blocks = std::min(num_blocks_left, m_settings.read_cache_line_size);
    // allocate blocks and prepare iovec buffers
    std::vector<block_source> blocks;
    std::vector<iovec> iovecs;
    blocks.reserve(num_blocks);
    iovecs.reserve(num_blocks);
    auto info = block_info;
    for(auto i = 0, left = num_bytes_left; i < num_blocks; ++i)
    {
        // if this is the last piece and we read till its end, the last block is likely
        // to be smaller than 0x4000, so this case must be handled
        const int length = std::min(left, 0x4000);
        auto buffer = std::make_shared<disk_buffer>(get_disk_buffer(length));
        blocks.emplace_back(info, source_buffer(buffer));
        iovecs.emplace_back(iovec{buffer->data(), size_t(buffer->size())});
        info.offset += 0x4000;
        left -= length;
    }
    auto read_ahead_info = block_info;
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
        m_network_ios.post([this, &torrent, handler = std::move(handler),
            blocks = std::move(blocks)]
        {
            auto& block = blocks.front();
            handler({}, block);
            auto it = std::find_if(
                torrent.block_fetches.begin(), torrent.block_fetches.end(), 
                [info = static_cast<const tide::block_info&>(block)](const auto& entry)
                { return entry.first == info; });
            assert(it != torrent.block_fetches.end());
            auto& subscribers = it->second;
            for(auto& sub : subscribers)
            {
                assert(sub.requested_offset <= blocks.back().offset);
                sub.handler({}, blocks[sub.requested_offset / 0x4000]);
            }
        });
    }
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
    if(blocks.is_empty()) { return 0; }
    int num_contiguous = 1;
    for(auto i = 1; i < blocks.size(); ++i, ++num_contiguous)
    {
        if(blocks[i - 1].offset + 0x4000 != blocks[i].offset) { break; }
    }
    return num_contiguous;
}

disk_io::torrent_entry& disk_io::find_torrent_entry(const torrent_id_t id)
{
    auto it = m_torrents.find(id);
    // even though this is called by public functions, this really shouldn't happen as
    // we're only expecting valid torrent ids
    assert(it != m_torrents.end());
    return it->second;
}

template<typename... Args>
void disk_io::log(const log_event event, const char* format, Args&&... args) const
{
    std::cerr << "[diskIO|";
    switch(event)
    {
    case log_event::cache: std::cerr << "CACHE"; break;
    case log_event::metainfo: std::cerr << "METAINFO"; break;
    case log_event::torrent: std::cerr << "TORRENT"; break;
    case log_event::piece: std::cerr << "PIECE"; break;
    case log_event::resume_data: std::cerr << "RESUME_DATA"; break;
    case log_event::integrity_check: std::cerr << "INTEGRITY_CHECK"; break;
    }
    std::cerr << "] - " << util::format(format, std::forward<Args>(args)...) << '\n';
}

} // namespace tide
