#include "torrent_info.hpp"
#include "file_info.hpp"
#include "settings.hpp"
#include "bencode.hpp"
#include "disk_io.hpp"

#include "string_utils.hpp"

#include <cmath>
#include <tuple>
#include <iterator>
#include <iostream>

namespace tide {

// -- partial_piece --

disk_io::partial_piece::partial_piece(piece_index_t index_, int length_,
    int max_write_buffer_size, std::function<void(bool)> completion_handler_
)
    : index(index_)
    , length(length_)
    , num_blocks((length_ + (0x4000 - 1)) / 0x4000)
    , completion_handler(std::move(completion_handler_))
{
    m_blocks.reserve(std::min(num_blocks, max_write_buffer_size));
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
    // to determine whether the piece is complete we add the number of blocks already
    // hashed and written to disk and the number of unhashed blocks in piece, as,
    // depending on the configured write buffer size, a piece may be written in several 
    // chunks to disk, so blocks may never hold all blocks in piece
    int num_blocks_hashed = m_unhashed_offset / 0x4000;
    return m_blocks.size() + num_blocks_hashed == num_blocks;
}

inline void disk_io::partial_piece::insert_block(disk_buffer block_data,
    const int offset, std::function<void(const std::error_code&)> save_handler)
{
    insert_block(block(std::move(block_data), offset, std::move(save_handler)));
}

inline void disk_io::partial_piece::insert_block(block b)
{
    // TODO we should verify that b isn't a duplicate
    // insert new block such that the resulting set of blocks remains sorted by
    // block offset; find the first block whose offset is larger than this block's
    const auto pos = std::find_if(m_blocks.begin(), m_blocks.end(),
        [offset = b.offset](const auto& b) { return b.offset > offset; });
    m_blocks.emplace(pos, std::move(b));
    // we need to recalculate the number of writeable blocks as this block may have
    // filled in a gap (like: |x|x|x|x| |x|x|x|)
    update_num_writeable_blocks();
}

inline void disk_io::partial_piece::insert_blocks(std::vector<block> contiguous_blocks)
{
    m_num_writeable_blocks += contiguous_blocks.size();
    if(m_blocks.empty())
    {
        m_blocks.swap(contiguous_blocks);
    }
    else
    {
        // TODO efficiently insert blocks in the beginning of blocks
        m_blocks.reserve(m_blocks.size() + contiguous_blocks.size());
        m_blocks.insert(m_blocks.begin(),
            std::make_move_iterator(contiguous_blocks.begin()),
            std::make_move_iterator(contiguous_blocks.end()));
    }
}

inline std::vector<disk_io::partial_piece::block>
disk_io::partial_piece::extract_writeable_blocks()
{
    std::vector<block> writeable;
    if(m_num_writeable_blocks == m_blocks.size())
    {
        writeable.swap(m_blocks);
    }
    else
    {
        assert(m_num_writeable_blocks < m_blocks.size());
        writeable.reserve(m_num_writeable_blocks);
        for(auto i = 0; i < m_num_writeable_blocks; ++i)
        {
            writeable.emplace_back(std::move(m_blocks[i]));
        }
        m_blocks.erase(m_blocks.begin(), m_blocks.begin() + m_num_writeable_blocks);
    }
    m_num_writeable_blocks = 0;
    return writeable;
}

inline void disk_io::partial_piece::record_hashed_bytes(const int n)
{
    m_unhashed_offset += n;
    update_num_writeable_blocks();
}

inline void disk_io::partial_piece::update_num_writeable_blocks()
{
    int n = 0;
    if(m_unhashed_offset >= m_blocks[0].offset)
    {
        // since there is no gap between first unhashed block's offset and the first
        // block, we have at least one writeable block (e.g. the one just inserted)
        // TODO can we somehow optimize the looping away? granted there shouldn't be
        // to many entries (i.e. trivial traversal costs), but still
        n = 1;
        for(auto it = m_blocks.begin() + 1, end = m_blocks.end(); it != end; ++it, ++n)
        {
            auto prev = it - 1;
            if(prev->offset + prev->buffer.size() != it->offset)
            {
                break;
            }
        }
    }
    m_num_writeable_blocks = n;
}

// -- torrent_entry --

disk_io::torrent_entry::torrent_entry(std::shared_ptr<torrent_info> info,
    string_view piece_hashes, path resume_data_path
)
    : storage(info, piece_hashes, std::move(resume_data_path))
    , num_pending_ops(0)
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
}

void disk_io::change_cache_size(const int64_t n)
{
}

void disk_io::read_metainfo(const path& path,
    std::function<void(const std::error_code&, metainfo)> handler)
{
}

torrent_storage_handle disk_io::allocate_torrent(std::shared_ptr<torrent_info> info,
    string_view piece_hashes, std::error_code& error)
{
    // TODO investigate whether this can potentially be so expensive an operation as to
    // justify sending it to thread pool
    log(log_event::torrent, "creating disk_io entry for torrent and"
        " setting up directory tree");
    try
    {
        torrent_entry entry(info, piece_hashes, m_settings.resume_data_path);
        // pair<iterator, bool>
        auto it_success_pair = m_torrents.emplace(info->id, std::move(entry));
        return torrent_storage_handle(it_success_pair.first->second.storage);
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

void disk_io::save_block(const torrent_id_t id,
    const block_info& block_info, disk_buffer block_data,
    std::function<void(const std::error_code&)> save_handler,
    std::function<void(bool)> piece_completion_handler)
{
    // TODO check for block_info correctness
    torrent_entry& torrent = find_torrent_entry(id);
    // find the partial_piece to which this block belongs
    auto pit = std::find_if(torrent.write_buffer.begin(), torrent.write_buffer.end(),
        [index = block_info.index](const auto& p) { return p->index == index; });
    // if none is found, this is the first block in piece, i.e. a new piece download
    if(pit == torrent.write_buffer.end())
    {
        torrent.write_buffer.emplace_back(std::make_unique<partial_piece>(
            block_info.index, torrent.storage.piece_length(block_info.index),
            m_settings.write_cache_line_size, std::move(piece_completion_handler)));
        pit = torrent.write_buffer.end() - 1;
    }
    partial_piece& piece = **pit;
    piece.insert_block(std::move(block_data), block_info.offset, std::move(save_handler));
    // only a single thread may work (hash/write) on a piece simultaneously
    if(!piece.is_busy)
    {
        dispatch_block_write(torrent, piece);
    }
}

inline void disk_io::dispatch_block_write(torrent_entry& torrent, partial_piece& piece)
{
    // even if a piece does not have write_cache_line_size blocks, if it's complete it is
    // written to disk in order to save it asap
    if(piece.is_complete())
    {
        log(log_event::piece, "piece(%i) completed, writing %i blocks",
            piece.index, piece.num_writeable_blocks());
        piece.is_busy = true;
        std::vector<partial_piece::block> blocks = piece.extract_writeable_blocks();
        m_thread_pool.post([this, &torrent, &piece, blocks = std::move(blocks)]
            { handle_complete_piece(torrent, piece, std::move(blocks)); });
    }
    else if(piece.num_writeable_blocks() >= m_settings.write_cache_line_size)
    {
        // piece is incomplete, but its write buffer is full so we must flush all
        // writeable blocks (i.e. all contiguous blocks following the last hashed block)
        // to disk
        log(log_event::piece, "piece(%i) write buffer fill, writing %i blocks",
            piece.index, piece.num_writeable_blocks());
        piece.is_busy = true;
        std::vector<partial_piece::block> blocks = piece.extract_writeable_blocks();
        m_thread_pool.post([this, &torrent, &piece, blocks = std::move(blocks)]
            { flush_write_buffer(torrent, piece, std::move(blocks)); });
    }
}

void disk_io::handle_complete_piece(torrent_entry& torrent,
    partial_piece& piece, std::vector<partial_piece::block> blocks)
{
    // TODO ensure torrent_entry thread safety
    ++torrent.num_pending_ops;
    // we should have all blocks by now
    assert(!blocks.empty());
    // although rare, the event in which we could hash a piece but not save it may
    // occur, in which case first_unhashed_byte is at the end of the piece
    // (note that if such an event occured, the piece is valid, since invalid pieces
    // are discarded, hence the true default value)
    bool is_piece_good = true;
    int num_bytes_hashed = 0;
    if(piece.first_unhashed_byte() < piece.length)
    {
        num_bytes_hashed = hash_blocks(piece.hasher, piece.first_unhashed_byte(), blocks);
        const sha1_hash hash = piece.hasher.finish();
        // retrieving the piece hash is thread-safe
        const sha1_hash expected_hash = torrent.storage.expected_piece_hash(piece.index);
        is_piece_good = std::equal(hash.begin(), hash.end(), expected_hash.begin());
        // invoke piece completion handler before saving piece to disk as saving might
        // take a while
        m_network_ios.post([is_piece_good, handler = std::move(piece.completion_handler),
            piece_index = piece.index, &torrent]
        { 
            handler(is_piece_good);
            if(!is_piece_good)
            {
                // since piece is corrupt, we won't be saving it, so it's safe to remove
                // it in this callback, as we'll no longer refer to it afterwards
                torrent.write_buffer.erase(std::find_if(
                    torrent.write_buffer.begin(), torrent.write_buffer.end(),
                    [piece_index](const auto& p) { return p->index == piece_index; }));
            }
        });
    }
    // only save piece if it passed the hash test
    // NOTE: if it didn't, we must not refer to piece as it has or is being deleted by
    // the network thread (in the piece completion callback above)
    if(is_piece_good)
    {
        std::vector<iovec> buffers;
        int num_bytes;
        std::tie(buffers, num_bytes) = prepare_iovec_buffers(blocks);
        assert(num_bytes > 0);
        std::error_code ec;
        // FIXME TODO ensure thread-safety here either on this level or within storage
        torrent.storage.write(std::move(buffers),
            block_info(piece.index, blocks[0].offset, num_bytes), ec);
        m_network_ios.post([this, &torrent, &piece, ec,
            blocks = std::move(blocks), num_bytes_hashed]
        {
            for(auto& block : blocks) { block.save_handler(ec); }
            if(ec)
            {
                // there was an error saving piece, so we cannot remove it from write
                // buffer yet, as data would be lost; we'll retry later
                piece.is_busy = false;
                piece.record_hashed_bytes(num_bytes_hashed);
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

void disk_io::flush_write_buffer(torrent_entry& torrent, partial_piece& piece,
    std::vector<partial_piece::block> blocks)
{
    ++torrent.num_pending_ops;
    const int num_bytes_hashed = hash_blocks(piece.hasher,
        piece.first_unhashed_byte(), blocks);
    // prepare iovecs buffers for file writing
    std::vector<iovec> buffers;
    int num_bytes = 0;
    std::tie(buffers, num_bytes) = prepare_iovec_buffers(blocks);
    assert(num_bytes > 0);
    std::error_code ec;
    // FIXME TODO ensure thread-safety here either on this level or within storage
    // now write iovec buffers to disk
    torrent.storage.write(std::move(buffers),
        block_info(piece.index, blocks[0].offset, num_bytes), ec);
    m_network_ios.post([this, &torrent, &piece, ec,
        num_bytes_hashed, blocks = std::move(blocks)]
    {
        piece.is_busy = false;
        piece.record_hashed_bytes(num_bytes_hashed);
        for(auto& block : blocks) { block.save_handler(ec); }
        if(ec)
        {
            // if we couldn't save blocks, we have to put them back in their piece for
            // future reattempt
            piece.insert_blocks(std::move(blocks));
        }
        // we may have received new blocks while this thread was processing
        // the current batch; if so, launch another hash & save op
        dispatch_block_write(torrent, piece);
    });
    --torrent.num_pending_ops;
}

inline std::pair<std::vector<iovec>, int> disk_io::prepare_iovec_buffers(
    std::vector<partial_piece::block>& blocks)
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

int disk_io::hash_blocks(sha1_hasher& hasher, const int first_unhashed_byte,
    std::vector<partial_piece::block>& blocks)
{
    // find first unhashed block, which may not be blocks[0], as saving blocks may
    // fail (see partial_piece comment), in which case hashed, but unsaved blocks are
    // put back into blocks
    // TODO alternatively we may want views to start at the correct block
    auto block = blocks.begin();
    const auto end = blocks.end();
    assert(block != end && block->offset <= first_unhashed_byte);
    while((block != end) && (block->offset != first_unhashed_byte))
    {
        ++block;
    }
    // then proceed to hash the unhashed contiguous blocks
    const int num_to_hash = blocks.size() - (block - blocks.begin());
    int num_bytes_hashed = 0;
    for(auto i = 0; i < num_to_hash; ++i, ++block)
    {
        hasher.update(block->buffer);
        num_bytes_hashed += block->buffer.size();
    }
    return num_bytes_hashed;
}

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
        std::error_code ec;
        auto buffer = std::make_shared<disk_buffer>(get_disk_buffer());
        torrent.storage.read(iovec{buffer->data(), size_t(buffer->size())},
            block_info, ec);
        block_source block(block_info, source_buffer(std::move(buffer)));
        m_network_ios.post([this, ec, block = std::move(block),
            handler = std::move(handler)]
        {
            handler(ec, std::move(block));
            if(!ec)
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

    std::error_code ec;
    torrent.storage.read(std::move(iovecs), read_ahead_info, ec);

    if(ec)
    {
        m_network_ios.post([this, ec, handler = std::move(handler)] { handler(ec, {}); });
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
    // TODO proper logging
    std::cerr << '[';
    switch(event)
    {
    case log_event::cache: std::cerr << "CACHE"; break;
    case log_event::metainfo: std::cerr << "METAINFO"; break;
    case log_event::torrent: std::cerr << "TORRENT"; break;
    case log_event::piece: std::cerr << "PIECE"; break;
    case log_event::resume_data: std::cerr << "RESUME_DATA"; break;
    case log_event::integrity_check: std::cerr << "INTEGRITY_CHECK"; break;
    }
    std::cerr << "] -- ";

    // TODO we can just use a string here directly, instead of buffer
    // + 1 for '\0'
    const size_t length = std::snprintf(nullptr, 0, format, args...) + 1;
    std::unique_ptr<char[]> buffer(new char[length]);
    std::snprintf(buffer.get(), length, format, args...);
    // -1 to exclude the '\0' at the end
    // TODO this is temporary
    std::string message(buffer.get(), buffer.get() + length - 1);
    std::cerr << message << '\n';
}

} // namespace tide
