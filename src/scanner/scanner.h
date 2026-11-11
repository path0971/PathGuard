#pragma once

#include "common/protocol.h"

#include <cstdint>
#include <string>
#include <vector>

struct YR_RULES;

namespace pg {

// RAII for yr_initialize()/yr_finalize(); one per process.
class YaraLibrary {
public:
    YaraLibrary();
    ~YaraLibrary();
    YaraLibrary(const YaraLibrary&) = delete;
    YaraLibrary& operator=(const YaraLibrary&) = delete;
    bool ok() const { return ok_; }

private:
    bool ok_ = false;
};

class YaraRules {
public:
    YaraRules() = default;
    ~YaraRules();
    YaraRules(const YaraRules&) = delete;
    YaraRules& operator=(const YaraRules&) = delete;

    // Compiles every source (a .yar file, or a directory of *.yar / *.yara files).
    // Any compile error fails the whole load, so a broken rule set is never half-applied.
    bool load(const std::vector<std::string>& sources, std::string& err);

    YR_RULES* get() const { return rules_; }
    const std::string& version() const { return version_; }  // sha256 over file names + contents
    int rule_count() const { return count_; }
    const std::vector<std::string>& files() const { return files_; }

private:
    YR_RULES* rules_ = nullptr;
    std::string version_;
    int count_ = 0;
    std::vector<std::string> files_;
};

struct ScanResult {
    ScanStatus status = ScanStatus::Error;
    ScanError error = ScanError::Internal;
    std::string sha256;
    std::vector<std::string> matches;
    std::string message;
    uint64_t size = 0;
    uint64_t scan_us = 0;
};

class Scanner {
public:
    Scanner(const YaraRules* rules, uint64_t max_size, int yara_timeout_s)
        : rules_(rules), max_size_(max_size), yara_timeout_s_(yara_timeout_s) {}

    // Reads the file through fd only (never re-opens by path), hashes it, runs
    // YARA, and reports Changed if the file's identity differs before/after.
    ScanResult scan_fd(int fd) const;

private:
    const YaraRules* rules_;
    uint64_t max_size_;
    int yara_timeout_s_;
};

}  // namespace pg
