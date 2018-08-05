#ifndef TIDE_TORRENT_STORAGE_HANDLE_HEADER
#define TIDE_TORRENT_STORAGE_HANDLE_HEADER

#include "torrent_storage.hpp"

#include <cassert>

namespace tide {

/**
 * A torrent doesn't directly interact with the logic of saving and reading blocks to
 * and from disk, this is done through an indirection that is disk_io so that these
 * operations may run in separate threads, but torrent does need to interact with its
 * storage for different purposes. This handle exposes only these functions.
 * For a description of the functions see torrent_storage.hpp.
 */
class torrent_storage_handle
{
    torrent_storage* storage_ = nullptr;

public:
    torrent_storage_handle() = default;
    torrent_storage_handle(torrent_storage& storage) : storage_(&storage) {}

    operator bool() const noexcept { return storage_ != nullptr; }

    torrent_storage* native_handle() noexcept { return storage_; }

    const path& root_path() const noexcept
    {
        assert(*this);
        return storage_->root_path();
    }

    int64_t size_to_download() const noexcept
    {
        assert(*this);
        return storage_->size_to_download();
    }

    interval pieces_in_file(const file_index_t file_index) const noexcept
    {
        assert(*this);
        return storage_->pieces_in_file(file_index);
    }

    interval files_containing_piece(const piece_index_t piece) const noexcept
    {
        assert(*this);
        return storage_->files_containing_piece(piece);
    }

    file_slice get_file_slice(const file_index_t file, const block_info& block) const
    {
        assert(*this);
        return storage_->get_file_slice(file, block);
    }

    sha1_hash expected_piece_hash(const piece_index_t piece) const noexcept
    {
        assert(*this);
        return storage_->expected_piece_hash(piece);
    }

    void want_file(const file_index_t file)
    {
        assert(*this);
        storage_->want_file(file);
    }

    void dont_want_file(const file_index_t file)
    {
        assert(*this);
        storage_->dont_want_file(file);
    }
};

} // namespace tide

#endif // TIDE_TORRENT_STORAGE_HANDLE_HEADER
