#pragma once

#include "common/util.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace pg {

struct QuarantineEntry {
    std::string id;
    std::string original_path;
    std::string sha256;
    std::string reason;
    std::string detail;
    std::string quarantined_at;
    uint64_t size = 0;
    uint32_t mode = 0;
    uint32_t uid = 0, gid = 0;
    uint64_t nlink = 0;
    bool original_removed = false;
    std::string removal_error;
    bool restored = false;
    std::string restored_to;
    std::string restored_at;
};

// Layout: <dir>/<id>.bin (content copy, 0400) and <id>.meta (key=value).
// Nothing is ever deleted automatically; restore never overwrites an existing file.
class QuarantineStore {
public:
    bool init(const std::string& dir, std::string& err);
    const std::string& dir() const { return dir_; }

    // fd is the descriptor that was scanned (not closed here). The copy is made
    // from fd, verified against expected_sha, and the original is unlinked only if
    // the path still names the same inode.
    bool quarantine(int fd, const std::string& path, const std::string& expected_sha, const FileId& scanned,
                    const std::string& reason, const std::string& detail, QuarantineEntry& out, std::string& err);

    bool list(std::vector<QuarantineEntry>& out, std::string& err);

    // dest "" restores to the original path.
    bool restore(const std::string& id, const std::string& dest, QuarantineEntry& out, std::string& err);

private:
    bool read_meta(const std::string& id, QuarantineEntry& e, std::string& err);
    bool write_meta(const QuarantineEntry& e, std::string& err);

    std::mutex mu_;
    std::string dir_;
};

bool valid_quarantine_id(const std::string& id);
std::string quarantine_entry_json(const QuarantineEntry& e);

}  // namespace pg
