#include "torrent_info.hpp"
#include "sha1_hasher.hpp"
#include "file_info.hpp"
#include "settings.hpp"
#include "disk_io.hpp"

// TODO cross platform
#define PATH_SEPARATOR '/'

struct file_piece_context : public file_info
{
    // These two fields denote where in the file the requested piece (fragment) resides.
    int piece_start;
    int piece_end;

    file_piece_context(
        std::string path,
        int length,
        int piece_start_in_file,
        int piece_end_in_file
    )
        : file_info(std::move(path), length)
        , piece_start(piece_start_in_file)
        , piece_end(piece_end_in_file)
    {}
};

/**
 * Each torrent that's currently loaded in the application (regardless of its state) has
 * an entry in disk_io.
 */
class disk_io::torrent_entry
{
    const torrent_info& m_info;

    // These are all the expected SHA-1 piece hashes from the metainfo file. They are
    // used to compare downloaded piece's hash results for verification.
    // The hash's position in the vector corresponds to the index of the piece to which
    // the hash belongs.
    const std::vector<sha1_hash> m_piece_hashes;

    struct hash_context
    {
        // Each block that has been hashed is set to true. This is to avoid hashing the
        // same blocks twice.
        std::vector<bool> completion;

        // Incremental hashing is employed, so this hasher is updated with each block.
        sha1_hasher hasher;

        // This is called once the piece is complete and it has been hashed. The bool
        // parameter specifies whether the piece passed the hash test.
        std::function<void(bool)> completion_handler;

        bool is_piece_complete() const noexcept
        {
            for(const bool is_set : completion)
            {
                if(!is_set)
                {
                    return false;
                }
            }
            return true;
        }
    };

    // All as yet unfinished hash jobs are stored here. After a piece is fully hashed,
    // the completers of the piece are notified with their supplied callbacks.
    std::map<piece_index_t, hash_context> m_hash_jobs;

    // The nth entry has the summed up lengths of all n files leading up to that file
    // as key. This facilitates the lookup of a piece's position if we consider all
    // files as a flat sequence of bytes into which we can more easily index.
    const std::map<int64_t, file_info> m_files;

    // A torrent's save path may change during the course of the {up,down}load.
    std::string m_save_path;

public:

    torrent_entry(
        std::string save_path,
        const torrent_info& info,
        std::vector<sha1_hash> piece_hashes
    )
        : m_files(map_length_to_files(info.files))
        , m_info(info)
        , m_piece_hashes(std::move(piece_hashes))
        , m_save_path(std::move(save_path))
    {}

    std::vector<file_piece_context>
    find_files_containing_piece(const piece_index_t piece) const
    {
        int piece_bytes_left = piece_length(piece);
        // denotes the first byte of the piece in current file, that is, it is always
        // set to the first piece byte of each file that contains the piece (which after
        // the initial file is always 0)
        int64_t    piece_start = piece * m_info.piece_length;
        const auto piece_end   = piece_start + piece_bytes_left;
        auto       file_it     = find_first_file_containing(piece_start);
        const auto files_end   = m_files.cend();

        std::vector<file_piece_context> files;

        while(file_it != files_end)
        {
            const auto& file                = file_it->second;
            const auto  file_end            = file_it->first;
            const auto  file_start          = file_end - file.length;
            const auto  piece_start_in_file = piece_start - file_start;
            const auto  file_bytes_left     = file_end - piece_start;
            const auto  piece_bytes_in_file = file_bytes_left >= piece_bytes_left
                                            ? piece_bytes_left
                                            : file_bytes_left;
            const auto  piece_end_in_file   = piece_start_in_file + piece_bytes_in_file;

            files.emplace_back(
                m_save_path + PATH_SEPARATOR + file.path,
                file.length,
                piece_start_in_file,
                piece_end_in_file
            );

            if(file_end >= piece_end)
            {
                break;
            }

            piece_start = file_end;
            piece_bytes_left -= piece_bytes_in_file;
        }

        assert(!files.empty());

        return files;
    }

    sha1_hasher& hasher(const piece_index_t piece)
    {
        return find_hash_context(piece).hasher;
    }

    void hashed_block(const block_info& block)
    {
        hash_context& context = find_hash_context(block.index);
        context.completion[block.offset / 0x4000] = true;

        if(context.is_piece_complete())
        {
            const bool is_valid = context.hasher.finish() == m_piece_hashes[block.index];
            context.completion_handler(is_valid);
        }
    }

private:

    static
    std::map<int64_t, file_info> map_length_to_files(const std::vector<file_info>& files)
    {
        std::map<int64_t, file_info> file_mapping;
        int64_t length_rsum = 0; // running sum
        for(const auto& file : files)
        {
            length_rsum += file.length;
            file_mapping.emplace(length_rsum, file);
        }
        return file_mapping;
    }

    int piece_length(const piece_index_t piece) const noexcept
    {
        return piece == m_info.num_pieces - 1 ? m_info.last_piece_length
                                              : m_info.piece_length;
    }

    std::map<int64_t, file_info>::const_iterator
    find_first_file_containing(const int offset) const noexcept
    {
        auto it = m_files.cbegin();
        const auto end = m_files.cend();
        while((it != end) && (it->first <= offset))
        {
            ++it;
        }
        assert(it != end);
        return it;
    }

    hash_context& find_hash_context(const piece_index_t piece)
    {
        auto it = m_hash_jobs.find(piece);
        assert(it != m_hash_jobs.end());
        return it->second;
    }
};
