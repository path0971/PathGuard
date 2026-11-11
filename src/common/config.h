#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pg {

struct Config {
    // Policy
    std::string mode = "enforce";      // enforce | audit
    std::string on_error = "allow";    // allow | deny   (scan could not complete)
    std::string on_overflow = "allow"; // allow | deny   (scan queue full)

    // Scope
    std::vector<std::string> watch_paths;
    std::string mark_type = "filesystem";  // filesystem | mount
    bool allow_non_mountpoint = false;
    bool allow_root_filesystem = false;

    // Scanning
    int workers = 2;
    int queue_max = 256;
    int scan_timeout_ms = 2000;
    uint64_t max_file_size = 64ULL << 20;
    uint64_t worker_memory_limit = 512ULL << 20;
    std::string worker_user = "pathguard";
    size_t cache_max = 4096;

    // Detection content
    std::string blocklist;
    std::string allowlist;
    std::vector<std::string> yara_rules;  // files or directories (*.yar, *.yara)

    // Records
    std::string log_file = "/var/log/pathguard/audit.jsonl";
    uint64_t log_max_bytes = 10ULL << 20;
    int log_keep = 5;
    bool quarantine = true;
    std::string quarantine_dir = "/var/lib/pathguard/quarantine";
    std::string state_file = "/var/lib/pathguard/state";

    // Management
    std::string control_socket = "/run/pathguard/control.sock";
    std::string admin_group = "pathguard-admin";

    bool enforce() const { return mode == "enforce"; }
};

bool load_config(const std::string& path, Config& cfg, std::string& err);

}  // namespace pg
