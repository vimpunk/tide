#include "filesystem.hpp"

namespace tide {
namespace fs {

size_t page_size()
{
    static const size_t page_size = []
    {
#ifdef _WIN32
        SYSTEM_INFO SystemInfo;
        GetSystemInfo(&SystemInfo);
        return SystemInfo.dwAllocationGranularity;
#else
        return sysconf(_SC_PAGE_SIZE);
#endif
    }();
    return page_size;
}

// these are mostly 1-1 mappings to their C++17 equivalents, so upgrade should be effortless

file_status status(const path& path, std::error_code& error)
{
    error.clear();
    file_status status;
#ifdef _WIN32
    // TODO
#else // _WIN32
    struct stat s;
    if(stat(path.c_str(), &s) != 0)
    {
        util::assign_errno(error);
        return {};
    }

    /*
    status.devide_id = s.st_dev;
    status.inode_number = s.st_ino;
    status.mode = s.st_mode;
    status.num_hardlinks = s.st_nlink;
    status.uid = s.st_uid;
    status.gid = s.st_gid;
    status.block_length = s.st_blksize;
    status.num_blocks = s.st_blocks;
    */
    status.length = s.st_size;
    status.last_access_time = time_point(duration(s.st_atime));
    status.last_modification_time = time_point(duration(s.st_mtime));
    status.last_status_change_time = time_point(duration(s.st_ctime));
    status.mode = (S_ISSOCK(s.st_mode) ? file_status::socket : 0)
                | (S_ISLNK(s.st_mode) ? file_status::symbolic_link : 0)
                | (S_ISREG(s.st_mode) ? file_status::regular_file : 0)
                | (S_ISBLK(s.st_mode) ? file_status::block_device : 0)
                | (S_ISDIR(s.st_mode) ? file_status::directory : 0)
                | (S_ISCHR(s.st_mode) ? file_status::character_device : 0)
                | (S_ISFIFO(s.st_mode) ? file_status::fifo : 0);
#endif // _WIN32
    return status;
}

bool exists(const path& path)
{
    std::error_code ec;
    return exists(path, ec);
}

bool exists(const path& path, std::error_code& error)
{
    error.clear();
    status(path, error);
    if(error)
    {
        // this is not an error as this is exactly what the function tests against
        if(error == std::errc::no_such_file_or_directory) { error.clear(); }
        return false;
    }
    return true;
}

int64_t file_size(const path& path, std::error_code& error)
{
    file_status s = status(path, error);
    if(error) { return 0; }
    return s.length;
}

bool is_directory(const path& path, std::error_code& error)
{
    error.clear();
    file_status s = status(path, error);
    return !error && (s.mode & file_status::directory);
}

void create_directory(const path& path, std::error_code& error)
{
    error.clear();
#ifdef _WIN32
    // TODO probably use CreateDirectoryA instead for unicode support
    if(CreateDirectory(path.c_str(), 0) == 0
       && GetLastError() != ERROR_ALREADY_EXISTS)
    {
        util::assign_errno(error);
    }
#else
    int mode = S_IRWXU | S_IRWXG | S_IRWXO;
    if((mkdir(path.c_str(), mode) != 0) && (errno != EEXIST))
    {
        util::assign_errno(error);
    }
#endif
}

// this is mostly a port of the function of the same name in boost::filesystem
// because boost::system::error_code does not interop with its std:: equivalent
void create_directories(const path& p, std::error_code& error)
{
    error.clear();
    if(p.filename_is_dot() || p.filename_is_dot_dot())
    {
        create_directories(p.parent_path(), error);
        return;
    }

    path parent = p.parent_path();
    if(!parent.empty()) { create_directories(parent, error); }

    if(!exists(p)) { create_directory(p, error); }
}

void move(const path& old_path, const path& new_path, std::error_code& error)
{
    error.clear();
    if(old_path == new_path) { return; }

    // TODO decide whether to create directory hierarchy or exit with error here
    path parent = new_path.parent_path();
    if(!parent.empty())
    {
        create_directories(parent, error);
        if(error) { return; }
    }

#ifdef _WIN32
    if(MoveFile(old_path.c_str(), new_path.c_str()) == 0)
    {
        util::assign_errno(error);
        return;
    }
#else // _WIN32
    if(::rename(old_path.c_str(), new_path.c_str()) != 0)
    {
        util::assign_errno(error);
        return;
    }
#endif // _WIN32
}

void rename(const path& old_path, const path& new_path, std::error_code& error)
{
    move(old_path, new_path, error);
}

} // namespace fs
} // namespace tide
