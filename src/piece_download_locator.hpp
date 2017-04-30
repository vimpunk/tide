#ifndef TORRENT_PIECE_DOWNLOAD_LOCATOR_HEADER
#define TORRENT_PIECE_DOWNLOAD_LOCATOR_HEADER

#include <memory>
#include <vector>

struct piece_download;
class bt_bitfield;

/**
 * A single instance exists per torrent. It serves as a mediator for piece_downloads
 * whose blocks may be downloaded from multiple peers, to speed up piece completion. This
 * is the default state, and a piece_download is only barred from sharing when the peer
 * is suspected of polluting our pieces, in which case it's the sole downloader of the
 * block to verify its suspicion. Thus, in this case the piece_download must not be
 * added to the locator.
 */
class piece_download_locator
{
    // These are all the active (unfinished) piece downloads. These only hold weak
    // references to the actual downloads, so pointer validity must be checked before
    // handling them, and deleted if the pointer is invalid. This is so as to avoid
    // unused piece_download pointers when all peers have erased their copies but one
    // remains in locator (and to avoid an explicit erase() function).
    std::vector<std::weak_ptr<piece_download>> m_active_downloads;

public:

    /**
     * This should be called when a new piece_download is started and it is shared, i.e.
     * its blocks can be downloaded by multiple peers.
     */
    void add(std::shared_ptr<piece_download> download);

    /**
     * Finds a suitable download for available_pieces. This means that the piece
     * download must be reachable by available_pieces and the download must have missing
     * blocks. If none is found, a nullptr is returned;
     */
    std::shared_ptr<piece_download> find(const bt_bitfield& available_pieces);
};

#endif // TORRENT_PIECE_DOWNLOAD_LOCATOR_HEADER
