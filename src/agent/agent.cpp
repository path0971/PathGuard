#include "agent/agent.h"

#include "agent/sdnotify.h"
#include "common/fdpass.h"
#include "common/json.h"
#include "common/sha256.h"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/fanotify.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdlib>
#include <cstring>

#ifndef FAN_OPEN_EXEC_PERM
#define FAN_OPEN_EXEC_PERM 0x00040000
#endif
#ifndef FAN_MARK_FILESYSTEM
#define FAN_MARK_FILESYSTEM 0x00000100
#endif

namespace pg {
namespace {

constexpr uint64_t kSec = 1000000;
constexpr uint64_t kRecentUs = 60 * kSec;             // window for "recent" degradations
constexpr uint64_t kGenerationStartUs = 15 * kSec;    // new workers must be ready by then
constexpr uint64_t kCrashWindowUs = 30 * kSec;
constexpr size_t kCrashLimit = 5;                     // crashes per window before backing off
constexpr uint64_t kCrashBackoffUs = 2 * kSec;
constexpr int64_t kCacheMinAgeSec = 2;                // recently changed files are not cached
constexpr size_t kLatencySamples = 4096;
constexpr int kMaxReadsPerWakeup = 8;

std::string decode_mountinfo(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 3 < s.size()) {
            out += static_cast<char>(std::strtol(s.substr(i + 1, 3).c_str(), nullptr, 8));
            i += 3;
        } else {
            out += s[i];
        }
    }
    return out;
}

bool is_mount_point(const std::string& real) {
    std::string text, err;
    if (!read_file("/proc/self/mountinfo", text, err)) return false;
    for (const auto& line : split(text, '\n')) {
        std::vector<std::string> f = split(line, ' ');
        if (f.size() > 4 && decode_mountinfo(f[4]) == real) return true;
    }
    return false;
}

std::string kernel_release() {
    struct utsname u {};
    uname(&u);
    return u.release;
}

void close_from(int lowfd, long maxfd) {
#ifdef SYS_close_range
    if (syscall(SYS_close_range, lowfd, ~0U, 0) == 0) return;
#endif
    for (long fd = lowfd; fd < maxfd; ++fd) close(static_cast<int>(fd));
}

std::string exit_text(int status) {
    if (WIFEXITED(status)) return "exit " + std::to_string(WEXITSTATUS(status));
    if (WIFSIGNALED(status)) return std::string("signal ") + strsignal(WTERMSIG(status));
    return "status " + std::to_string(status);
}

ScanResult result_from_reply(const WorkerReply& r) {
    ScanResult s;
    if (r.status < 0 || r.status > 2) {
        s.status = ScanStatus::Error;
        s.error = ScanError::Internal;
        s.message = "invalid worker reply";
        return s;
    }
    s.status = static_cast<ScanStatus>(r.status);
    s.error = static_cast<ScanError>(r.error);
    s.size = r.size;
    s.scan_us = r.scan_us;
    s.sha256.assign(r.sha256, strnlen(r.sha256, sizeof r.sha256));
    std::string detail(r.detail, strnlen(r.detail, sizeof r.detail));
    if (s.status == ScanStatus::Match) s.matches = split(detail, ',');
    else if (s.status == ScanStatus::Error) s.message = detail;
    return s;
}

std::string ok_json(const std::string& msg) {
    JsonObj j;
    j.add("ok", true).add("message", msg);
    return j.str();
}

std::string err_json(const std::string& msg) {
    JsonObj j;
    j.add("ok", false).add("error", msg);
    return j.str();
}

std::string short_version(const std::string& yara, const std::string& block, const std::string& allow) {
    return sha256_hex(yara + "|" + block + "|" + allow).substr(0, 16);
}

}  // namespace

// ---------------------------------------------------------------------------
// Configuration checks

bool validate_watch_path(const std::string& path, const Config& cfg, std::string& real, std::string& err) {
    char buf[PATH_MAX];
    if (!realpath(path.c_str(), buf)) {
        err = path + ": " + errno_text(errno);
        return false;
    }
    real = buf;
    struct stat st {}, root {};
    if (stat(real.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        err = real + ": not a directory";
        return false;
    }
    if (!cfg.allow_non_mountpoint && !is_mount_point(real)) {
        err = real + " is not a mount point; a " + cfg.mark_type +
              " mark would cover the whole containing " + cfg.mark_type +
              " (set allow_non_mountpoint = true to accept that)";
        return false;
    }
    if (!cfg.allow_root_filesystem && stat("/", &root) == 0 && root.st_dev == st.st_dev) {
        err = real + " is on the root filesystem; use a dedicated filesystem for the protected scope "
                     "(or set allow_root_filesystem = true)";
        return false;
    }
    return true;
}

int check_configuration(const Config& cfg) {
    bool ok = true;
    std::string err;
    auto fail = [&](const std::string& m) {
        fprintf(stderr, "error: %s\n", m.c_str());
        ok = false;
    };

    if (cfg.watch_paths.empty()) fail("no watch_path configured");
    for (const auto& p : cfg.watch_paths) {
        std::string real;
        if (validate_watch_path(p, cfg, real, err)) printf("watch_path  %s (%s mark)\n", real.c_str(), cfg.mark_type.c_str());
        else fail(err);
    }
    HashList block, allow;
    if (load_hash_list(cfg.blocklist, block, err)) printf("blocklist   %zu hashes\n", block.size());
    else fail(err);
    if (load_hash_list(cfg.allowlist, allow, err)) printf("allowlist   %zu hashes\n", allow.size());
    else fail(err);

    YaraLibrary lib;
    YaraRules rules;
    if (!lib.ok()) fail("yr_initialize failed");
    else if (rules.load(cfg.yara_rules, err))
        printf("yara        %d rules from %zu files (version %s)\n", rules.rule_count(), rules.files().size(),
               rules.version().substr(0, 16).c_str());
    else fail(err);

    printf("mode        %s, on_error=%s, on_overflow=%s\n", cfg.mode.c_str(), cfg.on_error.c_str(),
           cfg.on_overflow.c_str());
    printf("%s\n", ok ? "configuration OK" : "configuration INVALID");
    return ok ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Lifecycle

Agent::Agent(std::string config_path, Config cfg)
    : config_path_(std::move(config_path)), cfg_(std::move(cfg)), lat_(kLatencySamples, 0) {}

Agent::~Agent() {
    for (auto& [pid, w] : workers_) {
        close(w.sock);
        kill(pid, SIGKILL);
    }
    if (fan_fd_ >= 0) close(fan_fd_);
    if (sig_fd_ >= 0) close(sig_fd_);
    if (wake_fd_ >= 0) close(wake_fd_);
}

int Agent::run() {
    std::string err;
    if (!setup(err)) {
        note(Level::Error, "startup failed: " + err);
        JsonObj j = audit_record("agent_start_failed");
        j.add("error", err);
        log_.write(j.str());
        shutdown();
        return 1;
    }
    loop();
    shutdown();
    return 0;
}

bool Agent::setup(std::string& err) {
    self_pid_ = getpid();
    start_us_ = mono_us();
    started_at_ = iso_time_now();
    signal(SIGPIPE, SIG_IGN);

    // Block signals before any thread starts so they are only delivered via signalfd.
    sigset_t mask;
    sigemptyset(&mask);
    for (int s : {SIGTERM, SIGINT, SIGHUP, SIGCHLD}) sigaddset(&mask, s);
    sigprocmask(SIG_BLOCK, &mask, nullptr);
    sig_fd_ = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    wake_fd_ = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (sig_fd_ < 0 || wake_fd_ < 0) {
        err = "signalfd/eventfd: " + errno_text(errno);
        return false;
    }

    if (!log_.open(cfg_.log_file, cfg_.log_max_bytes, cfg_.log_keep, err)) return false;
    check_previous_state();
    {
        JsonObj j = audit_record("agent_start");
        j.add("pid", self_pid_).add("version", PATHGUARD_VERSION).add("config", config_path_);
        log_.write(j.str());
    }

    if (cfg_.watch_paths.empty()) {
        err = "no watch_path configured";
        return false;
    }
    if (!qstore_.init(cfg_.quarantine_dir, err)) return false;
    qworker_ = std::make_unique<QuarantineWorker>(qstore_, log_, 64);
    qworker_->start();

    // The first generation is started exactly like a reload, then awaited
    // before any execution can depend on it.
    std::string msg = begin_reload("startup");
    if (pending_gen_ == 0) {
        err = "could not start scan workers: " + msg;
        return false;
    }
    while (pending_gen_ != 0 && current_gen_ == 0) {
        std::vector<struct pollfd> pfds;
        std::vector<pid_t> pids;
        for (auto& [pid, w] : workers_) {
            pfds.push_back({w.sock, POLLIN, 0});
            pids.push_back(pid);
        }
        uint64_t now = mono_us();
        if (now >= pending_gen_deadline_us_) {
            abort_generation("timed out waiting for scan workers");
            break;
        }
        int n = poll(pfds.data(), pfds.size(), static_cast<int>((pending_gen_deadline_us_ - now) / 1000) + 1);
        if (n < 0 && errno != EINTR) break;
        for (size_t i = 0; i < pfds.size(); ++i)
            if (pfds[i].revents) on_worker_event(pids[i], pfds[i].revents);
    }
    if (current_gen_ == 0) {
        err = "scan workers failed to start (see the reload_failed record)";
        return false;
    }

    if (!init_fanotify(err)) return false;

    ControlHandlers h;
    h.status = [this] { return call_main([this] { return status_json(); }); };
    h.reload = [this] { return call_main([this] { return begin_reload("control"); }); };
    control_ = std::make_unique<ControlServer>(qstore_, h);
    std::string cerr;
    control_ok_ = control_->start(cfg_.control_socket, cfg_.admin_group, cerr);
    if (!control_ok_) {
        note(Level::Warning, "control socket unavailable: " + cerr);
        JsonObj j = audit_record("control_unavailable");
        j.add("error", cerr);
        log_.write(j.str());
    }

    uint64_t wd = sd_watchdog_usec();
    if (wd > 0) {
        watchdog_ = true;
        hb_interval_us_ = std::min<uint64_t>(hb_interval_us_, wd / 2);
    }
    next_heartbeat_us_ = 0;
    write_state(false);
    self_check_record();
    sd_notify_msg("READY=1\nSTATUS=protecting " + std::to_string(marks_.size()) + " path(s)");
    note(Level::Info, "protection active (mode=" + cfg_.mode + ", rules=" + policy_version_ + ")");
    return true;
}

bool Agent::init_fanotify(std::string& err) {
    fan_fd_ = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    if (fan_fd_ < 0) {
        err = "fanotify_init: " + errno_text(errno) + (errno == EPERM ? " (CAP_SYS_ADMIN required)" : "");
        return false;
    }
    unsigned int type = cfg_.mark_type == "mount" ? FAN_MARK_MOUNT : FAN_MARK_FILESYSTEM;
    for (const auto& p : cfg_.watch_paths) {
        std::string real;
        if (!validate_watch_path(p, cfg_, real, err)) return false;
        if (fanotify_mark(fan_fd_, FAN_MARK_ADD | type, FAN_OPEN_EXEC_PERM, AT_FDCWD, real.c_str()) != 0) {
            int e = errno;
            err = "fanotify_mark(" + real + "): " + errno_text(e);
            if (e == EINVAL) err += " (kernel without FAN_OPEN_EXEC_PERM / FAN_MARK_FILESYSTEM support? needs >= 5.1)";
            return false;
        }
        marks_.push_back(real);
    }
    return true;
}

void Agent::shutdown() {
    sd_notify_msg("STOPPING=1");
    // Answer everything still outstanding; closing the group would allow them anyway.
    std::vector<uint64_t> ids;
    for (auto& [id, p] : pending_) ids.push_back(id);
    Decision d;
    d.reason = "shutdown";
    for (uint64_t id : ids) finish(id, d, nullptr, "shutdown");

    if (fan_fd_ >= 0) {
        close(fan_fd_);
        fan_fd_ = -1;
    }
    if (control_) control_->stop();
    std::vector<pid_t> pids;
    for (auto& [pid, w] : workers_) pids.push_back(pid);
    for (pid_t pid : pids) retire_worker(pid, SIGKILL);
    for (pid_t pid : pids) waitpid(pid, nullptr, 0);
    if (qworker_) qworker_->stop();

    if (current_gen_ != 0) {
        JsonObj j = audit_record("agent_stop");
        j.add("pid", self_pid_).add("events", c_.events).add("denied", c_.denied);
        log_.write(j.str());
        write_state(true);
        note(Level::Info, "protection stopped");
    }
}

void Agent::check_previous_state() {
    std::string text, err;
    if (!read_file(cfg_.state_file, text, err)) return;  // first start
    int64_t last = 0, stopped = 0;
    bool clean = false;
    for (const auto& line : split(text, '\n')) {
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq), v = line.substr(eq + 1);
        if (k == "last_heartbeat") last = std::strtoll(v.c_str(), nullptr, 10);
        else if (k == "stopped_at") stopped = std::strtoll(v.c_str(), nullptr, 10);
        else if (k == "clean_shutdown") clean = v == "1";
    }
    int64_t since = clean ? stopped : last;
    if (since <= 0) return;
    JsonObj j = audit_record("protection_gap");
    j.add("cause", clean ? "agent_stopped" : "agent_crashed_or_killed")
        .add("unprotected_since_epoch", since)
        .add("gap_seconds", epoch_seconds() - since);
    if (!clean) j.add("note", "gap start is the last heartbeat; the real stop may be up to one heartbeat later");
    log_.write(j.str());
    note(Level::Warning, std::string("protection gap detected (") + (clean ? "agent stopped" : "agent crashed") +
                             ", " + std::to_string(epoch_seconds() - since) + "s)");
}

void Agent::write_state(bool clean) {
    std::string body = "pid=" + std::to_string(self_pid_) + "\nlast_heartbeat=" + std::to_string(epoch_seconds()) +
                       "\nclean_shutdown=" + (clean ? "1" : "0") + "\n";
    if (clean) body += "stopped_at=" + std::to_string(epoch_seconds()) + "\n";
    std::string err;
    if (!mkdir_p(parent_dir(cfg_.state_file), 0700, err) || !write_file_atomic(cfg_.state_file, body, 0600, err))
        note(Level::Warning, "state file: " + err);
}

void Agent::self_check_record() {
    std::vector<std::string> paths;
    for (const auto& m : marks_) paths.push_back(json_str(m));
    JsonObj j = audit_record("self_check");
    j.add("kernel", kernel_release())
        .add("fanotify", "ok")
        .add("event", "FAN_OPEN_EXEC_PERM")
        .add("mark_type", cfg_.mark_type)
        .raw("watch_paths", json_array(paths))
        .add("workers_ready", ready_workers())
        .add("worker_user", cfg_.worker_user)
        .add("rule_version", policy_version_)
        .add("yara_rules", yara_rule_count_)
        .add("blocklist", policy_.blocklist_size())
        .add("allowlist", policy_.allowlist_size())
        .add("mode", cfg_.mode)
        .add("on_error", cfg_.on_error)
        .add("on_overflow", cfg_.on_overflow)
        .add("scan_timeout_ms", cfg_.scan_timeout_ms)
        .add("control_socket", control_ok_);
    log_.write(j.str());
}

// ---------------------------------------------------------------------------
// Worker generations

std::string Agent::begin_reload(const std::string& source) {
    if (pending_gen_ != 0) return err_json("a reload is already in progress");

    auto failed = [&](const std::string& why) {
        JsonObj j = audit_record("reload_failed");
        j.add("source", source).add("error", why).add("active_rule_version", policy_version_);
        log_.write(j.str());
        note(Level::Error, "reload failed (" + source + "): " + why);
        return err_json(why);
    };

    Config nc;
    std::string err;
    if (!load_config(config_path_, nc, err)) return failed(err);
    auto block = std::make_shared<HashList>();
    auto allow = std::make_shared<HashList>();
    if (!load_hash_list(nc.blocklist, *block, err) || !load_hash_list(nc.allowlist, *allow, err))
        return failed(err);
    if (current_gen_ != 0 && (nc.watch_paths != cfg_.watch_paths || nc.mark_type != cfg_.mark_type ||
                              nc.control_socket != cfg_.control_socket || nc.log_file != cfg_.log_file)) {
        note(Level::Warning, "watch_path/mark_type/control_socket/log_file changes take effect after a restart");
    }

    staged_cfg_ = nc;
    staged_block_ = block;
    staged_allow_ = allow;
    pending_gen_ = ++gen_counter_;
    pending_gen_deadline_us_ = mono_us() + kGenerationStartUs;
    for (int i = 0; i < nc.workers; ++i) {
        if (!spawn_worker(pending_gen_)) {
            abort_generation("could not spawn scan worker: " + errno_text(errno));
            return err_json("could not spawn scan worker");
        }
    }
    JsonObj j = audit_record("reload_started");
    j.add("source", source).add("generation", pending_gen_);
    log_.write(j.str());
    return ok_json("reload started (generation " + std::to_string(pending_gen_) +
                   "); new rules apply once the new workers have compiled them");
}

bool Agent::spawn_worker(int gen) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) != 0) return false;

    // Everything the child needs is prepared before fork(); between fork() and
    // execv() the child only makes async-signal-safe calls.
    std::vector<std::string> args = {"pathguardd", "--worker", "--config", config_path_};
    std::vector<char*> argv;
    for (auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    long maxfd = sysconf(_SC_OPEN_MAX);
    sigset_t empty;
    sigemptyset(&empty);

    pid_t pid = fork();
    if (pid < 0) {
        close(sv[0]);
        close(sv[1]);
        return false;
    }
    if (pid == 0) {
        if (sv[1] == 3) fcntl(3, F_SETFD, 0);
        else if (dup2(sv[1], 3) < 0) _exit(127);
        close_from(4, maxfd);
        sigprocmask(SIG_SETMASK, &empty, nullptr);
        execv("/proc/self/exe", argv.data());
        _exit(127);
    }
    close(sv[1]);
    Worker w;
    w.pid = pid;
    w.sock = sv[0];
    w.gen = gen;
    workers_[pid] = w;
    return true;
}

void Agent::activate_generation() {
    int old_gen = current_gen_;
    current_gen_ = pending_gen_;
    pending_gen_ = 0;

    std::vector<pid_t> old;
    for (auto& [pid, w] : workers_)
        if (w.gen != current_gen_) old.push_back(pid);
    for (pid_t pid : old) {
        Worker& w = workers_[pid];
        if (w.busy) w.retiring = true;
        else retire_worker(pid, SIGKILL);
    }

    // Settings that can change at runtime. Scope, log and socket need a restart.
    const Config& n = staged_cfg_;
    cfg_.mode = n.mode;
    cfg_.on_error = n.on_error;
    cfg_.on_overflow = n.on_overflow;
    cfg_.workers = n.workers;
    cfg_.queue_max = n.queue_max;
    cfg_.scan_timeout_ms = n.scan_timeout_ms;
    cfg_.max_file_size = n.max_file_size;
    cfg_.cache_max = n.cache_max;
    cfg_.quarantine = n.quarantine;
    cfg_.blocklist = n.blocklist;
    cfg_.allowlist = n.allowlist;
    cfg_.yara_rules = n.yara_rules;
    cfg_.worker_user = n.worker_user;
    policy_.configure(policy_settings(cfg_), staged_block_, staged_allow_);
    block_digest_ = staged_block_->digest;
    allow_digest_ = staged_allow_->digest;

    for (auto& [pid, w] : workers_) {
        if (w.gen == current_gen_) {
            yara_version_ = w.rules_version;
            yara_rule_count_ = w.rule_count;
            break;
        }
    }
    policy_version_ = short_version(yara_version_, block_digest_, allow_digest_);
    rule_drift_ = false;
    cache_.clear();
    crash_times_us_.clear();
    next_respawn_us_ = 0;

    JsonObj j = audit_record("rules_activated");
    j.add("generation", current_gen_)
        .add("previous_generation", old_gen)
        .add("rule_version", policy_version_)
        .add("yara_version", yara_version_)
        .add("yara_rules", yara_rule_count_)
        .add("blocklist", policy_.blocklist_size())
        .add("allowlist", policy_.allowlist_size())
        .add("mode", cfg_.mode)
        .add("on_error", cfg_.on_error)
        .add("workers", cfg_.workers);
    log_.write(j.str());
    if (old_gen != 0) note(Level::Info, "rules reloaded, version " + policy_version_);
}

void Agent::abort_generation(const std::string& why) {
    int gen = pending_gen_;
    pending_gen_ = 0;
    std::vector<pid_t> pids;
    for (auto& [pid, w] : workers_)
        if (w.gen == gen) pids.push_back(pid);
    for (pid_t pid : pids) retire_worker(pid, SIGKILL);
    JsonObj j = audit_record("reload_failed");
    j.add("generation", gen).add("error", why).add("active_rule_version", policy_version_);
    log_.write(j.str());
    note(Level::Error, "new scan workers rejected: " + why + (current_gen_ ? "; keeping the active rules" : ""));
}

void Agent::retire_worker(pid_t pid, int sig) {
    auto it = workers_.find(pid);
    if (it == workers_.end()) return;
    close(it->second.sock);
    kill(pid, sig);
    workers_.erase(it);
}

void Agent::worker_gone(pid_t pid, const std::string& why, bool expected) {
    auto it = workers_.find(pid);
    if (it == workers_.end()) return;
    Worker w = it->second;
    retire_worker(pid, SIGKILL);

    if (w.busy && pending_.count(w.req_id)) {
        ScanResult r;
        r.error = ScanError::WorkerCrashed;
        r.message = why;
        finish(w.req_id, policy_.on_error(r.error, why), &r, "worker_crash");
    }
    if (!expected) {
        ++c_.worker_crashes;
        JsonObj j = audit_record("worker_exit");
        j.add("worker_pid", pid).add("generation", w.gen).add("reason", why).add("was_busy", w.busy);
        log_.write(j.str());
        note(Level::Warning, "scan worker " + std::to_string(pid) + " lost: " + why);
    }
    if (w.gen == pending_gen_ && !w.ready) {
        abort_generation("worker exited during startup: " + why);
        return;
    }
    if (w.gen == current_gen_ && !w.retiring && !expected) {
        uint64_t now = mono_us();
        crash_times_us_.push_back(now);
        while (!crash_times_us_.empty() && now - crash_times_us_.front() > kCrashWindowUs)
            crash_times_us_.pop_front();
        if (crash_times_us_.size() >= kCrashLimit) next_respawn_us_ = now + kCrashBackoffUs;
    }
}

size_t Agent::current_workers() const {
    size_t n = 0;
    for (const auto& [pid, w] : workers_)
        if (w.gen == current_gen_ && !w.retiring) ++n;
    return n;
}

size_t Agent::ready_workers() const {
    size_t n = 0;
    for (const auto& [pid, w] : workers_)
        if (w.gen == current_gen_ && !w.retiring && w.ready) ++n;
    return n;
}

void Agent::maybe_respawn(uint64_t now) {
    if (current_gen_ == 0 || stop_ || now < next_respawn_us_) return;
    while (current_workers() < static_cast<size_t>(cfg_.workers)) {
        if (!spawn_worker(current_gen_)) {
            next_respawn_us_ = now + kCrashBackoffUs;
            note(Level::Error, "respawning scan worker failed: " + errno_text(errno));
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Event loop

void Agent::loop() {
    std::vector<struct pollfd> pfds;
    std::vector<pid_t> pids;
    while (!stop_) {
        pfds.clear();
        pids.clear();
        pfds.push_back({fan_fd_, POLLIN, 0});
        pfds.push_back({sig_fd_, POLLIN, 0});
        pfds.push_back({wake_fd_, POLLIN, 0});
        for (auto& [pid, w] : workers_) {
            pfds.push_back({w.sock, POLLIN, 0});
            pids.push_back(pid);
        }
        int n = poll(pfds.data(), pfds.size(), compute_timeout_ms(mono_us()));
        if (n < 0 && errno != EINTR) {
            note(Level::Error, "poll: " + errno_text(errno));
            break;
        }
        if (n > 0) {
            if (pfds[1].revents) on_signal();
            if (pfds[2].revents) on_wake();
            for (size_t i = 0; i < pids.size(); ++i)
                if (pfds[3 + i].revents) on_worker_event(pids[i], pfds[3 + i].revents);
            if (pfds[0].revents & POLLIN) on_fanotify();
        }
        uint64_t now = mono_us();
        check_deadlines(now);
        maybe_respawn(now);
        dispatch();
        periodic(now);
    }
}

int Agent::compute_timeout_ms(uint64_t now) const {
    uint64_t next = next_heartbeat_us_;
    for (const auto& [id, p] : pending_) next = std::min(next, p.deadline_us);
    if (pending_gen_) next = std::min(next, pending_gen_deadline_us_);
    if (next_respawn_us_ > now && current_workers() < static_cast<size_t>(cfg_.workers))
        next = std::min(next, next_respawn_us_);
    if (overflow_unlogged_) next = std::min(next, overflow_logged_us_ + kSec);
    if (next <= now) return 0;
    return static_cast<int>(std::min<uint64_t>((next - now + 999) / 1000, 1000));
}

void Agent::on_signal() {
    struct signalfd_siginfo si {};
    while (read(sig_fd_, &si, sizeof si) == static_cast<ssize_t>(sizeof si)) {
        switch (si.ssi_signo) {
            case SIGTERM:
            case SIGINT: stop_ = true; break;
            case SIGHUP: begin_reload("SIGHUP"); break;
            case SIGCHLD: reap_children(); break;
            default: break;
        }
    }
}

void Agent::reap_children() {
    int status = 0;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
        if (workers_.count(pid)) worker_gone(pid, exit_text(status), false);
}

void Agent::on_wake() {
    uint64_t v;
    while (read(wake_fd_, &v, sizeof v) == static_cast<ssize_t>(sizeof v)) {
    }
    std::deque<std::packaged_task<std::string()>> tasks;
    {
        std::lock_guard<std::mutex> lk(call_mu_);
        tasks.swap(calls_);
    }
    for (auto& t : tasks) t();
}

std::string Agent::call_main(std::function<std::string()> fn) {
    std::packaged_task<std::string()> task(std::move(fn));
    std::future<std::string> fut = task.get_future();
    {
        std::lock_guard<std::mutex> lk(call_mu_);
        calls_.push_back(std::move(task));
    }
    uint64_t one = 1;
    (void)!write(wake_fd_, &one, sizeof one);
    if (fut.wait_for(std::chrono::seconds(3)) != std::future_status::ready)
        return err_json("agent did not answer in time");
    return fut.get();
}

void Agent::on_fanotify() {
    alignas(struct fanotify_event_metadata) char buf[16384];
    for (int reads = 0; reads < kMaxReadsPerWakeup; ++reads) {
        ssize_t len = read(fan_fd_, buf, sizeof buf);
        if (len < 0) {
            if (errno == EAGAIN) return;
            if (errno == EINTR) continue;
            // e.g. EMFILE: the kernel could not create an event fd
            uint64_t now = mono_us();
            if (now - last_read_error_us_ > kSec) {
                JsonObj j = audit_record("fanotify_read_error");
                j.add("error", errno_text(errno));
                log_.write(j.str());
                note(Level::Error, "fanotify read: " + errno_text(errno));
            }
            last_read_error_us_ = now;
            return;
        }
        if (len == 0) return;
        auto* m = reinterpret_cast<const struct fanotify_event_metadata*>(buf);
        while (FAN_EVENT_OK(m, len)) {
            if (m->vers != FANOTIFY_METADATA_VERSION) {
                note(Level::Error, "fanotify metadata version mismatch; stopping");
                stop_ = true;
                return;
            }
            if (m->mask & FAN_Q_OVERFLOW) {
                ++c_.kernel_overflows;
                last_kernel_overflow_us_ = mono_us();
                JsonObj j = audit_record("kernel_queue_overflow");
                j.add("note", "fanotify dropped events; some activity was not observed");
                log_.write(j.str());
                note(Level::Warning, "fanotify queue overflow");
            } else if (m->fd >= 0) {
                if (m->mask & FAN_OPEN_EXEC_PERM) handle_exec(m);
                else close(m->fd);
            }
            m = FAN_EVENT_NEXT(m, len);
        }
    }
}

void Agent::handle_exec(const struct fanotify_event_metadata* m) {
    ++c_.events;
    // The agent and its workers never wait on themselves.
    if (m->pid == self_pid_ || workers_.count(m->pid)) {
        respond(m->fd, Verdict::Allow);
        close(m->fd);
        return;
    }

    Pending p;
    p.id = ++next_id_;
    p.fd = m->fd;
    p.pid = m->pid;
    p.recv_us = mono_us();
    p.deadline_us = p.recv_us + static_cast<uint64_t>(cfg_.scan_timeout_ms) * 1000;

    struct stat st {};
    bool stat_ok = fstat(m->fd, &st) == 0;
    int stat_errno = errno;
    if (stat_ok && !S_ISREG(st.st_mode)) {
        respond(m->fd, Verdict::Allow);
        close(m->fd);
        return;
    }
    if (stat_ok) p.fid = file_id_from_stat(st);
    p.path = fd_path(m->fd);  // for records only; scanning uses the fd
    p.proc_exe = proc_exe(m->pid);
    p.comm = proc_comm(m->pid);
    pending_[p.id] = p;

    if (!stat_ok) {
        ScanResult r;
        r.error = ScanError::StatFailed;
        r.message = errno_text(stat_errno);
        finish(p.id, policy_.on_error(r.error, r.message), &r, "precheck");
        return;
    }
    auto hit = cache_.find(p.fid);
    if (hit != cache_.end()) {
        ++c_.cache_hits;
        ScanResult r;
        r.status = hit->second.matches.empty() ? ScanStatus::Clean : ScanStatus::Match;
        r.error = ScanError::None;
        r.sha256 = hit->second.sha256;
        r.matches = hit->second.matches;
        r.size = hit->second.size;
        finish(p.id, policy_.evaluate(r), &r, "cache");
        return;
    }
    if (p.fid.size > cfg_.max_file_size) {
        ScanResult r;
        r.error = ScanError::TooLarge;
        r.size = p.fid.size;
        r.message = "file size " + std::to_string(p.fid.size) + " exceeds max_file_size";
        finish(p.id, policy_.on_error(r.error, r.message), &r, "precheck");
        return;
    }
    if (queue_.size() >= static_cast<size_t>(cfg_.queue_max)) {
        ++c_.queue_overflows;
        ++overflow_unlogged_;
        last_queue_overflow_us_ = p.recv_us;
        finish(p.id, policy_.on_overflow(), nullptr, "overflow");
        return;
    }
    queue_.push_back(p.id);
}

void Agent::on_worker_event(pid_t pid, short revents) {
    auto it = workers_.find(pid);
    if (it == workers_.end()) return;
    if (revents & POLLIN) {
        for (;;) {
            WorkerReply r{};
            int fd = -1;
            ssize_t n = recv_msg(it->second.sock, &r, sizeof r, &fd, MSG_DONTWAIT);
            if (fd >= 0) close(fd);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            if (n <= 0) {
                worker_gone(pid, n == 0 ? "connection closed" : "recv: " + errno_text(errno), false);
                return;
            }
            if (n != static_cast<ssize_t>(sizeof r)) {
                worker_gone(pid, "malformed reply", false);
                return;
            }
            handle_reply(it->second, r);
            it = workers_.find(pid);  // handle_reply may retire the worker
            if (it == workers_.end()) return;
        }
    }
    if (revents & (POLLHUP | POLLERR | POLLNVAL)) worker_gone(pid, "connection closed", false);
}

void Agent::handle_reply(Worker& w, const WorkerReply& r) {
    switch (static_cast<WorkerMsg>(r.kind)) {
        case WorkerMsg::Ready: {
            w.ready = true;
            w.rules_version.assign(r.detail, strnlen(r.detail, sizeof r.detail));
            w.rule_count = static_cast<int>(r.count);
            if (w.gen == pending_gen_) {
                size_t total = 0, ready = 0;
                for (const auto& [pid, o] : workers_) {
                    if (o.gen != pending_gen_) continue;
                    ++total;
                    if (o.ready) ++ready;
                }
                if (ready == total && total == static_cast<size_t>(staged_cfg_.workers)) activate_generation();
            } else if (w.gen == current_gen_ && w.rules_version != yara_version_ && !rule_drift_) {
                // A respawned worker re-reads the rule files; they changed on disk without a reload.
                rule_drift_ = true;
                JsonObj j = audit_record("rule_drift");
                j.add("worker_pid", w.pid).add("expected", yara_version_).add("loaded", w.rules_version);
                log_.write(j.str());
                note(Level::Warning, "rule files changed on disk without a reload; run 'pathguardctl reload'");
            }
            return;
        }
        case WorkerMsg::Fatal: {
            std::string msg(r.detail, strnlen(r.detail, sizeof r.detail));
            pid_t pid = w.pid;
            if (w.gen == pending_gen_) {
                abort_generation(msg);  // retires the worker
            } else {
                worker_gone(pid, "fatal: " + msg, false);
            }
            return;
        }
        case WorkerMsg::Result: {
            if (!w.busy || r.req_id != w.req_id) return;  // stale
            w.busy = false;
            pid_t pid = w.pid;
            bool retiring = w.retiring;
            ScanResult s = result_from_reply(r);
            if (pending_.count(r.req_id)) {
                ++c_.scanned;
                if (s.status != ScanStatus::Error) cache_put(pending_[r.req_id].fid, s);
                finish(r.req_id, policy_.evaluate(s), &s, "scan");
            }
            if (retiring) retire_worker(pid, SIGKILL);
            return;
        }
    }
    worker_gone(w.pid, "unknown message kind", false);
}

void Agent::dispatch() {
    while (!queue_.empty()) {
        Worker* idle = nullptr;
        for (auto& [pid, w] : workers_) {
            if (w.gen == current_gen_ && w.ready && !w.busy && !w.retiring) {
                idle = &w;
                break;
            }
        }
        if (!idle) return;
        uint64_t id = queue_.front();
        queue_.pop_front();
        auto it = pending_.find(id);
        if (it == pending_.end()) continue;  // already answered (deadline)
        WorkerRequest req{id};
        if (!send_msg(idle->sock, &req, sizeof req, it->second.fd, MSG_DONTWAIT)) {
            queue_.push_front(id);
            worker_gone(idle->pid, "send: " + errno_text(errno), false);
            continue;
        }
        it->second.queued = false;
        it->second.dispatch_us = mono_us();
        it->second.worker_pid = idle->pid;
        idle->busy = true;
        idle->req_id = id;
    }
}

void Agent::check_deadlines(uint64_t now) {
    std::vector<uint64_t> expired;
    for (const auto& [id, p] : pending_)
        if (now >= p.deadline_us) expired.push_back(id);
    for (uint64_t id : expired) {
        auto it = pending_.find(id);
        if (it == pending_.end()) continue;
        pid_t wpid = it->second.queued ? 0 : it->second.worker_pid;
        ++c_.timeouts;
        ScanResult r;
        r.error = ScanError::Timeout;
        r.message = wpid ? "scan did not finish within scan_timeout_ms" : "no worker became available in time";
        finish(id, policy_.on_error(r.error, r.message), &r, "timeout");
        // A worker stuck on this file cannot be interrupted; replace it.
        if (wpid && workers_.count(wpid)) {
            workers_[wpid].busy = false;
            JsonObj j = audit_record("worker_timeout");
            j.add("worker_pid", wpid).add("event_id", id);
            log_.write(j.str());
            worker_gone(wpid, "scan timeout", true);
        }
    }
}

void Agent::periodic(uint64_t now) {
    if (now >= next_heartbeat_us_) {
        write_state(false);
        if (watchdog_) sd_notify_msg("WATCHDOG=1");
        next_heartbeat_us_ = now + hb_interval_us_;
    }
    if (pending_gen_ && now >= pending_gen_deadline_us_) abort_generation("timed out waiting for new scan workers");
    if (overflow_unlogged_ && now - overflow_logged_us_ >= kSec) {
        JsonObj j = audit_record("queue_overflow");
        j.add("dropped_to_policy", overflow_unlogged_).add("queue_max", cfg_.queue_max).add("on_overflow", cfg_.on_overflow);
        log_.write(j.str());
        note(Level::Warning, "scan queue full: " + std::to_string(overflow_unlogged_) + " request(s) answered by on_overflow=" + cfg_.on_overflow);
        overflow_unlogged_ = 0;
        overflow_logged_us_ = now;
    }

    std::vector<std::string> reasons = degraded_reasons(now);
    std::string state = reasons.empty() ? "ok" : "degraded";
    std::string joined;
    for (const auto& r : reasons) joined += (joined.empty() ? "" : ",") + r;
    if (state + joined != protection_state_) {
        bool first = protection_state_.empty();
        protection_state_ = state + joined;
        if (!first || state != "ok") {
            JsonObj j = audit_record("protection_state");
            j.add("state", state).raw("reasons", json_str_array(reasons));
            log_.write(j.str());
            sd_notify_msg("STATUS=" + (reasons.empty() ? std::string("protecting") : "degraded: " + joined));
        }
    }
}

void Agent::respond(int fd, Verdict v) {
    struct fanotify_response resp {};
    resp.fd = fd;
    resp.response = v == Verdict::Allow ? FAN_ALLOW : FAN_DENY;
    if (fan_fd_ < 0 || write(fan_fd_, &resp, sizeof resp) != static_cast<ssize_t>(sizeof resp)) {
        ++c_.response_errors;
        if (fan_fd_ >= 0) note(Level::Error, "fanotify response failed: " + errno_text(errno));
    }
}

void Agent::finish(uint64_t id, const Decision& d, const ScanResult* r, const char* source) {
    auto it = pending_.find(id);
    if (it == pending_.end()) return;
    Pending p = std::move(it->second);
    pending_.erase(it);

    respond(p.fd, d.verdict);  // first: never hold the execution for bookkeeping
    uint64_t latency = mono_us() - p.recv_us;

    lat_[lat_pos_ % lat_.size()] = static_cast<uint32_t>(std::min<uint64_t>(latency, UINT32_MAX));
    ++lat_pos_;
    if (d.verdict == Verdict::Allow) ++c_.allowed;
    else ++c_.denied;
    if (d.policy == Verdict::Deny && d.verdict == Verdict::Allow) ++c_.audit_would_deny;
    if (r && r->status == ScanStatus::Error) ++c_.scan_errors;

    log_decision(p, d, r, source, latency);

    bool quarantine = d.verdict == Verdict::Deny && d.quarantine && cfg_.quarantine && r && !r->sha256.empty();
    if (quarantine) {
        QuarantineJob job;
        job.fd = p.fd;
        job.path = p.path;
        job.sha256 = r->sha256;
        job.reason = d.reason;
        job.detail = d.detail;
        job.fid = p.fid;
        job.event_id = p.id;
        if (qworker_->submit(std::move(job))) return;  // the job owns the fd now
        ++c_.quarantine_skipped;
        JsonObj j = audit_record("quarantine_failed");
        j.add("event_id", p.id).add("path", p.path).add("error", "quarantine queue full");
        log_.write(j.str());
    }
    close(p.fd);
}

void Agent::log_decision(const Pending& p, const Decision& d, const ScanResult* r, const char* source,
                         uint64_t latency_us) {
    JsonObj j = audit_record("exec_decision");
    j.add("event_id", p.id)
        .add("decision", verdict_name(d.verdict))
        .add("policy_decision", verdict_name(d.policy))
        .add("reason", d.reason)
        .add("detail", d.detail)
        .add("mode", cfg_.mode)
        .add("source", source)
        .add("path", p.path)
        .add("pid", p.pid)
        .add("process_exe", p.proc_exe)
        .add("comm", p.comm)
        .add("dev", p.fid.dev)
        .add("ino", p.fid.ino)
        .add("size", p.fid.size);
    if (r) {
        j.add("scan_result", scan_status_name(r->status));
        if (r->status == ScanStatus::Error) j.add("scan_error", scan_error_name(r->error));
        j.add("sha256", r->sha256).raw("matches", json_str_array(r->matches)).add("scan_us", r->scan_us);
    }
    j.add("latency_us", latency_us);
    if (p.dispatch_us) j.add("queue_wait_us", p.dispatch_us - p.recv_us);
    if (p.worker_pid) j.add("worker_pid", p.worker_pid);
    j.add("rule_version", policy_version_);
    log_.write(j.str());

    if (d.policy == Verdict::Deny || (r && r->status == ScanStatus::Error)) {
        note(d.verdict == Verdict::Deny ? Level::Warning : Level::Info,
             std::string(d.verdict == Verdict::Deny ? "DENY " : "ALLOW ") + p.path + " [" + d.reason +
                 (d.detail.empty() ? "" : ": " + d.detail) + "] pid=" + std::to_string(p.pid) +
                 (d.policy != d.verdict ? " (audit mode)" : ""));
    }
}

void Agent::cache_put(const FileId& fid, const ScanResult& r) {
    if (cfg_.cache_max == 0 || fid.dev == 0) return;
    if (epoch_seconds() - fid.ctime_sec < kCacheMinAgeSec) return;  // may still be changing
    if (cache_.size() >= cfg_.cache_max) cache_.clear();
    cache_[fid] = CachedScan{r.sha256, r.matches, r.size};
}

// ---------------------------------------------------------------------------
// Status

std::vector<std::string> Agent::degraded_reasons(uint64_t now) const {
    std::vector<std::string> r;
    if (ready_workers() < static_cast<size_t>(cfg_.workers)) r.push_back("workers_below_target");
    if (next_respawn_us_ > now) r.push_back("worker_crash_loop");
    if (last_queue_overflow_us_ && now - last_queue_overflow_us_ < kRecentUs) r.push_back("queue_overflow_recent");
    if (last_kernel_overflow_us_ && now - last_kernel_overflow_us_ < kRecentUs) r.push_back("kernel_overflow_recent");
    if (last_read_error_us_ && now - last_read_error_us_ < kRecentUs) r.push_back("fanotify_read_error_recent");
    if (rule_drift_) r.push_back("rule_drift");
    if (!control_ok_) r.push_back("control_unavailable");
    return r;
}

std::string Agent::status_json() {
    uint64_t now = mono_us();
    std::vector<std::string> reasons = degraded_reasons(now);

    size_t n = std::min(lat_pos_, lat_.size());
    std::vector<uint32_t> lat(lat_.begin(), lat_.begin() + static_cast<long>(n));
    uint64_t p50 = 0, p95 = 0, mx = 0;
    if (n > 0) {
        std::sort(lat.begin(), lat.end());
        p50 = lat[(n - 1) * 50 / 100];
        p95 = lat[(n - 1) * 95 / 100];
        mx = lat[n - 1];
    }

    std::vector<std::string> pids, paths;
    size_t busy = 0;
    for (const auto& [pid, w] : workers_) {
        if (w.gen != current_gen_ || w.retiring) continue;
        pids.push_back(std::to_string(pid));
        if (w.busy) ++busy;
    }
    for (const auto& m : marks_) paths.push_back(json_str(m));

    JsonObj workers;
    workers.add("target", cfg_.workers)
        .add("ready", ready_workers())
        .add("busy", busy)
        .raw("pids", json_array(pids))
        .add("generation", current_gen_)
        .add("reload_in_progress", pending_gen_ != 0)
        .add("crashes", c_.worker_crashes)
        .add("user", cfg_.worker_user);
    JsonObj queue;
    queue.add("length", queue_.size()).add("max", cfg_.queue_max).add("pending", pending_.size());
    JsonObj counters;
    counters.add("events", c_.events)
        .add("allowed", c_.allowed)
        .add("denied", c_.denied)
        .add("audit_would_deny", c_.audit_would_deny)
        .add("scanned", c_.scanned)
        .add("cache_hits", c_.cache_hits)
        .add("scan_errors", c_.scan_errors)
        .add("timeouts", c_.timeouts)
        .add("queue_overflows", c_.queue_overflows)
        .add("kernel_overflows", c_.kernel_overflows)
        .add("response_errors", c_.response_errors)
        .add("quarantined", qworker_ ? qworker_->done() : 0)
        .add("quarantine_failed", (qworker_ ? qworker_->failed() : 0) + c_.quarantine_skipped);
    JsonObj latency;
    latency.add("samples", n).add("p50", p50).add("p95", p95).add("max", mx);

    JsonObj j;
    j.add("ok", true)
        .add("version", PATHGUARD_VERSION)
        .add("pid", self_pid_)
        .add("started_at", started_at_)
        .add("uptime_s", (now - start_us_) / kSec)
        .add("mode", cfg_.mode)
        .add("on_error", cfg_.on_error)
        .add("on_overflow", cfg_.on_overflow)
        .add("protection", reasons.empty() ? "ok" : "degraded")
        .raw("degraded_reasons", json_str_array(reasons))
        .raw("watch_paths", json_array(paths))
        .add("mark_type", cfg_.mark_type)
        .add("rule_version", policy_version_)
        .add("yara_rules", yara_rule_count_)
        .add("blocklist", policy_.blocklist_size())
        .add("allowlist", policy_.allowlist_size())
        .add("scan_timeout_ms", cfg_.scan_timeout_ms)
        .raw("workers", workers.str())
        .raw("queue", queue.str())
        .raw("counters", counters.str())
        .raw("latency_us", latency.str());
    return j.str();
}

}  // namespace pg
