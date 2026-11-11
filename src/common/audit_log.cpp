#include "common/audit_log.h"

#include "common/util.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>

namespace pg {

AuditLog::~AuditLog() {
    if (fd_ >= 0) close(fd_);
}

bool AuditLog::open(const std::string& path, uint64_t max_bytes, int keep, std::string& err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!mkdir_p(parent_dir(path), 0750, err)) return false;
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0640);
    if (fd < 0) {
        err = path + ": " + errno_text(errno);
        return false;
    }
    struct stat st {};
    fstat(fd, &st);
    if (fd_ >= 0) close(fd_);
    fd_ = fd;
    path_ = path;
    size_ = static_cast<uint64_t>(st.st_size);
    max_ = max_bytes;
    keep_ = keep;
    return true;
}

void AuditLog::rotate_locked() {
    close(fd_);
    fd_ = -1;
    int flags = O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW;
    if (keep_ == 0) {
        flags |= O_TRUNC;
    } else {
        for (int i = keep_ - 1; i >= 1; --i) {
            std::string from = path_ + "." + std::to_string(i);
            std::string to = path_ + "." + std::to_string(i + 1);
            rename(from.c_str(), to.c_str());
        }
        rename(path_.c_str(), (path_ + ".1").c_str());
    }
    fd_ = ::open(path_.c_str(), flags, 0640);
    size_ = 0;
}

void AuditLog::write(const std::string& json_line) {
    std::lock_guard<std::mutex> lk(mu_);
    if (fd_ < 0) return;
    std::string data = json_line + "\n";
    if (max_ > 0 && size_ > 0 && size_ + data.size() > max_) {
        rotate_locked();
        if (fd_ < 0) {
            note(Level::Error, "audit log rotation failed: " + errno_text(errno));
            return;
        }
    }
    if (write_all(fd_, data.data(), data.size())) {
        size_ += data.size();
        warned_ = false;
    } else if (!warned_) {
        note(Level::Error, "audit log write failed: " + errno_text(errno));
        warned_ = true;
    }
}

JsonObj audit_record(const char* type) {
    JsonObj j;
    j.add("ts", iso_time_now()).add("type", type);
    return j;
}

}  // namespace pg
