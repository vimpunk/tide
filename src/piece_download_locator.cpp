#include "piece_download_locator.hpp"
#include "piece_download.hpp"
#include "bt_bitfield.hpp"

void piece_download_locator::add(std::shared_ptr<piece_download> download)
{
    m_active_downloads.emplace_back(download);
}

std::shared_ptr<piece_download>
piece_download_locator::find(const bt_bitfield& available_pieces)
{
    int size = m_active_downloads.size();
    for(auto i = 0; i < size; ++i)
    {
        // this is all on the network thread, so it's OK not to use (atomic) lock()
        std::shared_ptr<piece_download> download = m_active_downloads[i].lock();
        if(!download)
        {
            m_active_downloads.erase(m_active_downloads.begin() + i);
            --size;
            // normalize i (since an element has been removed) TODO is this UB?
            --i;
            continue;
        }

        if(available_pieces[download->piece_index()])
        {
            return download;
        }
    }
    return nullptr;
}
