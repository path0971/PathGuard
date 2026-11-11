#pragma once

#include "agent/control.h"
#include "agent/quarantine_worker.h"
#include "common/audit_log.h"
#include "common/config.h"
#include "common/hashlist.h"
#include "common/protocol.h"
#include "common/util.h"
#include "policy/policy.h"
#include "quarantine/store.h"
#include "scanner/scanner.h"

#include <deque>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

struct fanotify_event_metadata;

namespace pg {

// Resolves and checks a watch_path. Refuses paths that would silently widen the
// protected scope (non-mount-points, the root filesystem) unless the config allows it.
bool validate_watch_path(const std::string& path, const Config& cfg, std::string& real, std::string& err);

// pathguardd --check: validates config, hash lists, rules and watch paths.
int check_configuration(const Config& cfg);

class Agent {
public:
    Agent(std::string config_path, Config cfg);
    ~Agent();
    int run();

private:
    struct Worker {
        pid_t pid = -1;
        int sock = -1;
        int gen = 0;
        bool ready = false;
        bool busy = false;
        bool retiring = false;
        uint64_t req_id = 0;
        std::string rules_version;
        int rule_count = 0;
    };

    // One FAN_OPEN_EXEC_PERM request. It is answered exactly once, by finish().
    struct Pending {
        uint64_t id = 0;
        int fd = -1;
        pid_t pid = 0;
        std::string path, proc_exe, comm;
        FileId fid;
        uint64_t recv_us = 0, deadline_us = 0, dispatch_us = 0;
        bool queued = true;
        pid_t worker_pid = 0;
    };

    struct CachedScan {
        std::string sha256;
        std::vector<std::string> matches;
        uint64_t size = 0;
    };

    struct Counters {
        uint64_t events = 0, allowed = 0, denied = 0, audit_would_deny = 0;
        uint64_t scanned = 0, cache_hits = 0, scan_errors = 0, timeouts = 0;
        uint64_t queue_overflows = 0, kernel_overflows = 0, worker_crashes = 0;
        uint64_t response_errors = 0, quarantine_skipped = 0;
    };

    // setup / teardown
    bool setup(std::string& err);
    bool init_fanotify(std::string& err);
    void shutdown();
    void check_previous_state();
    void write_state(bool clean);
    void self_check_record();

    // generations of scan workers (a reload starts a new one)
    std::string begin_reload(const std::string& source);
    bool spawn_worker(int gen);
    void activate_generation();
    void abort_generation(const std::string& why);
    void retire_worker(pid_t pid, int sig);
    void worker_gone(pid_t pid, const std::string& why, bool expected);
    void maybe_respawn(uint64_t now);
    size_t current_workers() const;
    size_t ready_workers() const;

    // event loop
    void loop();
    int compute_timeout_ms(uint64_t now) const;
    void on_signal();
    void on_wake();
    void on_fanotify();
    void handle_exec(const fanotify_event_metadata* m);
    void on_worker_event(pid_t pid, short revents);
    void handle_reply(Worker& w, const struct WorkerReply& r);
    void dispatch();
    void check_deadlines(uint64_t now);
    void periodic(uint64_t now);
    void finish(uint64_t id, const Decision& d, const ScanResult* r, const char* source);
    void respond(int fd, Verdict v);
    void log_decision(const Pending& p, const Decision& d, const ScanResult* r, const char* source,
                      uint64_t latency_us);
    void cache_put(const FileId& fid, const ScanResult& r);
    void reap_children();

    // status
    std::vector<std::string> degraded_reasons(uint64_t now) const;
    std::string status_json();
    std::string call_main(std::function<std::string()> fn);

    std::string config_path_;
    Config cfg_;
    Config staged_cfg_;
    std::shared_ptr<const HashList> staged_block_, staged_allow_;
    PolicyEngine policy_;
    std::string block_digest_, allow_digest_;
    AuditLog log_;
    QuarantineStore qstore_;
    std::unique_ptr<QuarantineWorker> qworker_;
    std::unique_ptr<ControlServer> control_;
    bool control_ok_ = false;

    int fan_fd_ = -1, sig_fd_ = -1, wake_fd_ = -1;
    pid_t self_pid_ = 0;
    bool stop_ = false;
    std::vector<std::string> marks_;

    std::map<pid_t, Worker> workers_;
    int current_gen_ = 0, pending_gen_ = 0, gen_counter_ = 0;
    uint64_t pending_gen_deadline_us_ = 0;
    std::string yara_version_, policy_version_;
    int yara_rule_count_ = 0;
    bool rule_drift_ = false;
    std::deque<uint64_t> crash_times_us_;
    uint64_t next_respawn_us_ = 0;

    std::unordered_map<uint64_t, Pending> pending_;
    std::deque<uint64_t> queue_;
    uint64_t next_id_ = 0;
    std::unordered_map<FileId, CachedScan, FileIdHash> cache_;

    Counters c_;
    std::vector<uint32_t> lat_;
    size_t lat_pos_ = 0;
    uint64_t start_us_ = 0;
    std::string started_at_;
    uint64_t last_queue_overflow_us_ = 0, last_kernel_overflow_us_ = 0, last_read_error_us_ = 0;
    uint64_t overflow_unlogged_ = 0, overflow_logged_us_ = 0;
    uint64_t next_heartbeat_us_ = 0, hb_interval_us_ = 5000000;
    bool watchdog_ = false;
    std::string protection_state_;

    std::mutex call_mu_;
    std::deque<std::packaged_task<std::string()>> calls_;
};

}  // namespace pg
