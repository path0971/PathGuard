#pragma once

#include <cstdint>

namespace pg {

enum class ScanStatus : int32_t { Clean = 0, Match = 1, Error = 2 };

// "Could not scan" reasons. These are never treated as "clean"; the policy's
// on_error setting decides the verdict.
enum class ScanError : int32_t {
    None = 0,
    StatFailed,
    NotRegular,
    TooLarge,
    ReadFailed,
    Changed,
    YaraFailed,
    Timeout,
    WorkerCrashed,
    Internal,
};

inline const char* scan_status_name(ScanStatus s) {
    switch (s) {
        case ScanStatus::Clean: return "clean";
        case ScanStatus::Match: return "match";
        case ScanStatus::Error: return "error";
    }
    return "unknown";
}

inline const char* scan_error_name(ScanError e) {
    switch (e) {
        case ScanError::None: return "none";
        case ScanError::StatFailed: return "stat_failed";
        case ScanError::NotRegular: return "not_regular";
        case ScanError::TooLarge: return "too_large";
        case ScanError::ReadFailed: return "read_failed";
        case ScanError::Changed: return "changed_during_scan";
        case ScanError::YaraFailed: return "yara_failed";
        case ScanError::Timeout: return "timeout";
        case ScanError::WorkerCrashed: return "worker_crashed";
        case ScanError::Internal: return "internal";
    }
    return "unknown";
}

// Agent <-> scan worker messages over a SOCK_SEQPACKET socketpair.
// A request carries the file descriptor as SCM_RIGHTS ancillary data.
struct WorkerRequest {
    uint64_t req_id;
};

enum class WorkerMsg : int32_t { Ready = 1, Fatal = 2, Result = 3 };

struct WorkerReply {
    int32_t kind;         // WorkerMsg
    int32_t status;       // ScanStatus (Result)
    int32_t error;        // ScanError (Result)
    uint32_t count;       // matches (Result) or loaded rule count (Ready)
    uint64_t req_id;
    uint64_t size;
    uint64_t scan_us;
    char sha256[65];
    char detail[1024];    // comma-separated rule names, error message, or rules version (Ready)
};

}  // namespace pg
