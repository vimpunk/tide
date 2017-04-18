#ifndef TORRENT_BANDWIDTH_CONTROLLER_HEADER
#define TORRENT_BANDWIDTH_CONTROLLER_HEADER

class bandwidth_controller
{
public:

    void request_upload_bandwidth(const int num_desired_bytes);
    void request_download_bandwidth(const int num_desired_bytes);
};

#endif // TORRENT_BANDWIDTH_CONTROLLER_HEADER
