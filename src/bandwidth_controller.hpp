#ifndef TIDE_BANDWIDTH_CONTROLLER_HEADER
#define TIDE_BANDWIDTH_CONTROLLER_HEADER

namespace tide {

class bandwidth_controller
{
public:

    int request_upload_bandwidth(const int num_desired_bytes);
    int request_download_bandwidth(const int num_desired_bytes);
};

} // namespace tide

#endif // TIDE_BANDWIDTH_CONTROLLER_HEADER
