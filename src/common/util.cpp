#include "common/util.h"

#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

namespace pg {

uint64_t mono_us() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000ULL + static_cast<uint64_t>(ts.tv_nsec) / 1000;
}

std::string iso_time_now() {
    timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm {};
    gmtime_r(&ts.tv_sec, &tm);
    char date[32];
    strftime(date, sizeof date, "%Y-%m-%dT%H:%M:%S", &tm);
    char out[48];
    snprintf(out, sizeof out, "%s.%03ldZ", date, ts.tv_nsec / 1000000);
    return out;
}

int64_t epoch_seconds() { return static_cast<int64_t>(time(nullptr)); }

static std::string readlink_str(const std::string& path) {
    char buf[4096];
    ssize_t n = readlink(path.c_str(), buf, sizeof buf - 1);
    if (n < 0) return "";
    return std::string(buf, static_cast<size_t>(n));
}

std::string fd_path(int fd) { return readlink_str("/proc/self/fd/" + std::to_string(fd)); }

std::string proc_exe(pid_t pid) { return readlink_str("/proc/" + std::to_string(pid) + "/exe"); }

std::string proc_comm(pid_t pid) {
    std::string text, err;
    if (!read_file("/proc/" + std::to_string(pid) + "/comm", text, err)) return "";
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.pop_back();
    return text;
}

std::string errno_text(int err) { return std::strerror(err); }

std::string trim(const std::string& s) {
    const char* ws = " \t\r\n";
    size_t b = s.find_first_not_of(ws);
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    size_t start = 0;
    for (;;) {
        size_t pos = s.find(sep, start);
        if (pos == std::string::npos) {
            out.push_back(s.substr(start));
            return out;
        }
        out.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
}

bool ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string parent_dir(const std::string& path) {
    size_t slash = path.rfind('/');
    if (slash == std::string::npos) return ".";
    if (slash == 0) return "/";
    return path.substr(0, slash);
}

bool write_all(int fd, const void* data, size_t len) {
    const char* p = static_cast<const char*>(data);
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        p += n;
        len -= static_cast<size_t>(n);
    }
    return true;
}

bool read_file(const std::string& path, std::string& out, std::string& err) {
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        err = path + ": " + errno_text(errno);
        return false;
    }
    out.clear();
    char buf[65536];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            err = path + ": " + errno_text(errno);
            close(fd);
            return false;
        }
        if (n == 0) break;
        out.append(buf, static_cast<size_t>(n));
    }
    close(fd);
    return true;
}

bool write_file_atomic(const std::string& path, const std::string& data, mode_t mode, std::string& err) {
    std::string tmp = path + ".tmp";
    int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0) {
        err = tmp + ": " + errno_text(errno);
        return false;
    }
    bool ok = write_all(fd, data.data(), data.size()) && fsync(fd) == 0;
    int saved = errno;
    close(fd);
    if (!ok || rename(tmp.c_str(), path.c_str()) != 0) {
        err = path + ": " + errno_text(ok ? errno : saved);
        unlink(tmp.c_str());
        return false;
    }
    return true;
}

bool mkdir_p(const std::string& path, mode_t mode, std::string& err) {
    if (path.empty()) return true;
    std::string cur;
    for (const auto& part : split(path, '/')) {
        if (part.empty()) {
            if (cur.empty()) cur = "/";
            continue;
        }
        if (!cur.empty() && cur.back() != '/') cur += '/';
        cur += part;
        if (mkdir(cur.c_str(), mode) != 0 && errno != EEXIST) {
            err = cur + ": " + errno_text(errno);
            return false;
        }
    }
    return true;
}

std::string random_hex(size_t bytes) {
    std::vector<unsigned char> buf(bytes, 0);
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    bool ok = false;
    if (fd >= 0) {
        ok = read(fd, buf.data(), bytes) == static_cast<ssize_t>(bytes);
        close(fd);
    }
    if (!ok) {
        uint64_t seed = mono_us() ^ (static_cast<uint64_t>(getpid()) << 32);
        for (size_t i = 0; i < bytes; ++i) buf[i] = static_cast<unsigned char>(seed >> ((i % 8) * 8));
    }
    static const char* hex = "0123456789abcdef";
    std::string out;
    for (unsigned char c : buf) {
        out += hex[c >> 4];
        out += hex[c & 0xf];
    }
    return out;
}

bool FileId::operator==(const FileId& o) const {
    return dev == o.dev && ino == o.ino && size == o.size && mtime_sec == o.mtime_sec &&
           mtime_nsec == o.mtime_nsec && ctime_sec == o.ctime_sec && ctime_nsec == o.ctime_nsec;
}

FileId file_id_from_stat(const struct stat& st) {
    FileId f;
    f.dev = static_cast<uint64_t>(st.st_dev);
    f.ino = static_cast<uint64_t>(st.st_ino);
    f.size = static_cast<uint64_t>(st.st_size);
    f.mtime_sec = st.st_mtim.tv_sec;
    f.mtime_nsec = st.st_mtim.tv_nsec;
    f.ctime_sec = st.st_ctim.tv_sec;
    f.ctime_nsec = st.st_ctim.tv_nsec;
    return f;
}

size_t FileIdHash::operator()(const FileId& f) const {
    uint64_t h = 1469598103934665603ULL;
    auto mix = [&h](uint64_t v) {
        h ^= v;
        h *= 1099511628211ULL;
    };
    mix(f.dev);
    mix(f.ino);
    mix(f.size);
    mix(static_cast<uint64_t>(f.mtime_nsec));
    mix(static_cast<uint64_t>(f.ctime_nsec));
    return static_cast<size_t>(h);
}

void note(Level level, const std::string& msg) {
    fprintf(stderr, "<%d>pathguardd[%d]: %s\n", static_cast<int>(level), static_cast<int>(getpid()), msg.c_str());
}

}  // namespace pg
