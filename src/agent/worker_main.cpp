#include "agent/worker_main.h"

#include "common/config.h"
#include "common/fdpass.h"
#include "common/protocol.h"
#include "common/util.h"
#include "scanner/scanner.h"

#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>

namespace pg {
namespace {

constexpr int kSock = 3;

void copy_str(char* dst, size_t cap, const std::string& s) {
    size_t n = std::min(s.size(), cap - 1);
    memcpy(dst, s.data(), n);
    dst[n] = '\0';
}

bool send_reply(const WorkerReply& r) { return send_msg(kSock, &r, sizeof r, -1, 0); }

int fatal(const std::string& msg) {
    WorkerReply r{};
    r.kind = static_cast<int32_t>(WorkerMsg::Fatal);
    copy_str(r.detail, sizeof r.detail, msg);
    send_reply(r);
    note(Level::Error, "worker: " + msg);
    return 2;
}

void set_limit(int resource, rlim_t value) {
    struct rlimit rl {
        value, value
    };
    setrlimit(resource, &rl);
}

bool drop_privileges(const Config& cfg, std::string& err) {
    if (geteuid() == 0) {
        if (cfg.worker_user.empty()) {
            note(Level::Warning, "worker: worker_user is empty; scan workers keep root privileges");
        } else {
            struct passwd* pw = getpwnam(cfg.worker_user.c_str());
            if (!pw) {
                err = "worker_user '" + cfg.worker_user + "' does not exist";
                return false;
            }
            if (setgroups(0, nullptr) != 0 || setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) != 0 ||
                setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) != 0) {
                err = "dropping privileges failed: " + errno_text(errno);
                return false;
            }
            if (pw->pw_uid != 0 && setuid(0) == 0) {
                err = "privileges could be regained after drop";
                return false;
            }
        }
    }
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    if (cfg.worker_memory_limit > 0) set_limit(RLIMIT_AS, cfg.worker_memory_limit);
    set_limit(RLIMIT_NOFILE, 16);
    set_limit(RLIMIT_FSIZE, 0);  // a worker never writes files
    set_limit(RLIMIT_CORE, 0);
    if (geteuid() != 0) set_limit(RLIMIT_NPROC, 0);
    return true;
}

}  // namespace

int worker_main(const std::string& config_path) {
    prctl(PR_SET_NAME, "pathguard-scan", 0, 0, 0);  // exec'd via /proc/self/exe, so comm would be "exe"
    prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    if (getppid() == 1) return 1;  // agent already gone
    signal(SIGPIPE, SIG_IGN);

    Config cfg;
    std::string err;
    if (!load_config(config_path, cfg, err)) return fatal("config: " + err);

    YaraLibrary lib;
    if (!lib.ok()) return fatal("yr_initialize failed");
    YaraRules rules;
    if (!rules.load(cfg.yara_rules, err)) return fatal("rules: " + err);
    if (!drop_privileges(cfg, err)) return fatal(err);

    int yara_timeout_s = std::max(1, (cfg.scan_timeout_ms + 999) / 1000);
    Scanner scanner(&rules, cfg.max_file_size, yara_timeout_s);

    WorkerReply ready{};
    ready.kind = static_cast<int32_t>(WorkerMsg::Ready);
    ready.count = static_cast<uint32_t>(rules.rule_count());
    copy_str(ready.detail, sizeof ready.detail, rules.version());
    if (!send_reply(ready)) return 1;

    for (;;) {
        WorkerRequest req{};
        int fd = -1;
        ssize_t n = recv_msg(kSock, &req, sizeof req, &fd, 0);
        if (n == 0) return 0;  // agent closed the socket
        if (n < 0) return 1;
        if (n != static_cast<ssize_t>(sizeof req) || fd < 0) {
            if (fd >= 0) close(fd);
            return 1;
        }

        ScanResult r = scanner.scan_fd(fd);
        close(fd);

        WorkerReply rep{};
        rep.kind = static_cast<int32_t>(WorkerMsg::Result);
        rep.req_id = req.req_id;
        rep.status = static_cast<int32_t>(r.status);
        rep.error = static_cast<int32_t>(r.error);
        rep.count = static_cast<uint32_t>(r.matches.size());
        rep.size = r.size;
        rep.scan_us = r.scan_us;
        copy_str(rep.sha256, sizeof rep.sha256, r.sha256);
        std::string detail;
        if (r.status == ScanStatus::Match) {
            for (const auto& m : r.matches) {
                if (!detail.empty()) detail += ',';
                detail += m;
            }
        } else {
            detail = r.message;
        }
        copy_str(rep.detail, sizeof rep.detail, detail);
        if (!send_reply(rep)) return 1;
    }
}

}  // namespace pg
