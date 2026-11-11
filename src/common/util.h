#pragma once

#include <sys/stat.h>
#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pg {

uint64_t mono_us();
std::string iso_time_now();  // UTC, millisecond precision
int64_t epoch_seconds();

std::string fd_path(int fd);  // readlink("/proc/self/fd/N"), "" on failure
std::string proc_exe(pid_t pid);
std::string proc_comm(pid_t pid);

std::string errno_text(int err);
std::string trim(const std::string& s);
std::vector<std::string> split(const std::string& s, char sep);
bool ends_with(const std::string& s, const std::string& suffix);
std::string parent_dir(const std::string& path);

bool write_all(int fd, const void* data, size_t len);
bool read_file(const std::string& path, std::string& out, std::string& err);
bool write_file_atomic(const std::string& path, const std::string& data, mode_t mode, std::string& err);
bool mkdir_p(const std::string& path, mode_t mode, std::string& err);
std::string random_hex(size_t bytes);

// Identity of a file's content state. Used to detect changes during a scan
// and as the scan-cache key.
struct FileId {
    uint64_t dev = 0, ino = 0, size = 0;
    int64_t mtime_sec = 0, mtime_nsec = 0, ctime_sec = 0, ctime_nsec = 0;

    bool operator==(const FileId& o) const;
    bool operator!=(const FileId& o) const { return !(*this == o); }
};
FileId file_id_from_stat(const struct stat& st);

struct FileIdHash {
    size_t operator()(const FileId& f) const;
};

// Writes "<N>pathguardd: msg" to stderr; journald maps the prefix to a priority.
enum class Level { Error = 3, Warning = 4, Info = 6 };
void note(Level level, const std::string& msg);

}  // namespace pg
