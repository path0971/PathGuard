#pragma once

#include "common/json.h"

#include <cstdint>
#include <mutex>
#include <string>

namespace pg {

// Append-only JSON Lines log with size-based rotation (path, path.1 ... path.N).
class AuditLog {
public:
    ~AuditLog();
    bool open(const std::string& path, uint64_t max_bytes, int keep, std::string& err);
    void write(const std::string& json_line);

private:
    void rotate_locked();

    std::mutex mu_;
    int fd_ = -1;
    std::string path_;
    uint64_t size_ = 0;
    uint64_t max_ = 0;
    int keep_ = 0;
    bool warned_ = false;
};

// Starts a record with "ts" and "type".
JsonObj audit_record(const char* type);

}  // namespace pg
