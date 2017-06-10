#ifndef TORRENT_TORRENT_STORAGE_HANDLE_HEADER
#define TORRENT_TORRENT_STORAGE_HANDLE_HEADER

#include "torrent_storage.hpp"

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
    torrent_storage* m_storage;
public:

    torrent_storage_handle() = default;
    torrent_storage_handle(torrent_storage& storage) : m_storage(&storage) {}

    operator bool() const noexcept
    {
        return m_storage != nullptr;
    }

    const std::string& name() const noexcept
    {
        return m_storage->name();
    }

    const path& save_path() const noexcept
    {
        return m_storage->save_path();
    }

    int64_t size_to_download() const noexcept
    {
        return m_storage->size_to_download();
    }

    interval pieces_in_file(const file_index_t file_index) const noexcept
    {
        return m_storage->pieces_in_file(file_index);
    }

    interval files_containing_piece(const piece_index_t piece) const noexcept
    {
        return m_storage->files_containing_piece(piece);
    }

    file_slice get_file_slice(const file_index_t file, const block_info& block) const
    {
        return m_storage->get_file_slice(file, block);
    }

    string_view expected_hash(const piece_index_t piece) const noexcept
    {
        return m_storage->expected_hash(piece);
    }

    void want_file(const file_index_t file)
    {
        m_storage->want_file(file);
    }

    void dont_want_file(const file_index_t file)
    {
        m_storage->dont_want_file(file);
    }
};

} // namespace tide

#endif // TORRENT_TORRENT_STORAGE_HANDLE_HEADER
