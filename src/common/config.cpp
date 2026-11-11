#include "common/config.h"

#include "common/util.h"

#include <cctype>
#include <cstdlib>

namespace pg {
namespace {

bool parse_bool(const std::string& v, bool& out) {
    if (v == "true" || v == "yes" || v == "1" || v == "on") {
        out = true;
        return true;
    }
    if (v == "false" || v == "no" || v == "0" || v == "off") {
        out = false;
        return true;
    }
    return false;
}

bool parse_u64(const std::string& v, uint64_t& out) {
    if (v.empty() || !isdigit(static_cast<unsigned char>(v[0]))) return false;
    char* end = nullptr;
    unsigned long long n = strtoull(v.c_str(), &end, 10);
    std::string suffix = end;
    uint64_t mult = 1;
    if (suffix == "K" || suffix == "k") mult = 1ULL << 10;
    else if (suffix == "M" || suffix == "m") mult = 1ULL << 20;
    else if (suffix == "G" || suffix == "g") mult = 1ULL << 30;
    else if (!suffix.empty()) return false;
    out = static_cast<uint64_t>(n) * mult;
    return true;
}

bool parse_int(const std::string& v, long min, long max, int& out) {
    uint64_t n = 0;
    if (!parse_u64(v, n) || n < static_cast<uint64_t>(min) || n > static_cast<uint64_t>(max)) return false;
    out = static_cast<int>(n);
    return true;
}

bool one_of(const std::string& v, std::initializer_list<const char*> allowed) {
    for (const char* a : allowed)
        if (v == a) return true;
    return false;
}

}  // namespace

bool load_config(const std::string& path, Config& cfg, std::string& err) {
    std::string text;
    if (!read_file(path, text, err)) return false;

    Config c;
    int lineno = 0;
    auto bad = [&](const std::string& msg) {
        err = path + ":" + std::to_string(lineno) + ": " + msg;
        return false;
    };

    for (const auto& raw : split(text, '\n')) {
        ++lineno;
        std::string line = raw;
        size_t hash = line.find('#');
        if (hash != std::string::npos) line.resize(hash);
        line = trim(line);
        if (line.empty()) continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) return bad("expected 'key = value'");
        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));
        uint64_t u = 0;

        if (key == "mode") {
            if (!one_of(val, {"enforce", "audit"})) return bad("mode must be enforce or audit");
            c.mode = val;
        } else if (key == "on_error") {
            if (!one_of(val, {"allow", "deny"})) return bad("on_error must be allow or deny");
            c.on_error = val;
        } else if (key == "on_overflow") {
            if (!one_of(val, {"allow", "deny"})) return bad("on_overflow must be allow or deny");
            c.on_overflow = val;
        } else if (key == "watch_path") {
            if (val.empty() || val[0] != '/') return bad("watch_path must be an absolute path");
            c.watch_paths.push_back(val);
        } else if (key == "mark_type") {
            if (!one_of(val, {"filesystem", "mount"})) return bad("mark_type must be filesystem or mount");
            c.mark_type = val;
        } else if (key == "allow_non_mountpoint") {
            if (!parse_bool(val, c.allow_non_mountpoint)) return bad("expected boolean");
        } else if (key == "allow_root_filesystem") {
            if (!parse_bool(val, c.allow_root_filesystem)) return bad("expected boolean");
        } else if (key == "workers") {
            if (!parse_int(val, 1, 64, c.workers)) return bad("workers must be 1..64");
        } else if (key == "queue_max") {
            if (!parse_int(val, 1, 65536, c.queue_max)) return bad("queue_max must be 1..65536");
        } else if (key == "scan_timeout_ms") {
            if (!parse_int(val, 50, 60000, c.scan_timeout_ms)) return bad("scan_timeout_ms must be 50..60000");
        } else if (key == "max_file_size") {
            if (!parse_u64(val, c.max_file_size) || c.max_file_size == 0) return bad("invalid size");
        } else if (key == "worker_memory_limit") {
            if (!parse_u64(val, c.worker_memory_limit)) return bad("invalid size");
        } else if (key == "worker_user") {
            c.worker_user = val;
        } else if (key == "cache_max") {
            if (!parse_u64(val, u) || u > 1000000) return bad("cache_max must be 0..1000000");
            c.cache_max = static_cast<size_t>(u);
        } else if (key == "blocklist") {
            c.blocklist = val;
        } else if (key == "allowlist") {
            c.allowlist = val;
        } else if (key == "yara_rules") {
            if (val.empty()) return bad("yara_rules needs a path");
            c.yara_rules.push_back(val);
        } else if (key == "log_file") {
            if (val.empty() || val[0] != '/') return bad("log_file must be an absolute path");
            c.log_file = val;
        } else if (key == "log_max_bytes") {
            if (!parse_u64(val, c.log_max_bytes)) return bad("invalid size");
        } else if (key == "log_keep") {
            if (!parse_int(val, 0, 100, c.log_keep)) return bad("log_keep must be 0..100");
        } else if (key == "quarantine") {
            if (!parse_bool(val, c.quarantine)) return bad("expected boolean");
        } else if (key == "quarantine_dir") {
            if (val.empty() || val[0] != '/') return bad("quarantine_dir must be an absolute path");
            c.quarantine_dir = val;
        } else if (key == "state_file") {
            if (val.empty() || val[0] != '/') return bad("state_file must be an absolute path");
            c.state_file = val;
        } else if (key == "control_socket") {
            if (val.empty() || val[0] != '/') return bad("control_socket must be an absolute path");
            c.control_socket = val;
        } else if (key == "admin_group") {
            c.admin_group = val;
        } else {
            return bad("unknown key '" + key + "'");
        }
    }

    lineno = 0;
    if (c.worker_memory_limit != 0 && c.worker_memory_limit < c.max_file_size + (64ULL << 20))
        return bad("worker_memory_limit must be at least max_file_size + 64M");

    cfg = c;
    return true;
}

}  // namespace pg
