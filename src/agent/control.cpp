#include "agent/control.h"

#include "common/json.h"
#include "common/util.h"

#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <vector>

namespace pg {
namespace {

std::string error_json(const std::string& msg) {
    JsonObj j;
    j.add("ok", false).add("error", msg);
    return j.str();
}

}  // namespace

ControlServer::ControlServer(QuarantineStore& store, ControlHandlers handlers)
    : store_(store), h_(std::move(handlers)) {}

ControlServer::~ControlServer() { stop(); }

bool ControlServer::start(const std::string& path, const std::string& admin_group, std::string& err) {
    if (!admin_group.empty()) {
        if (struct group* g = getgrnam(admin_group.c_str())) {
            has_admin_gid_ = true;
            admin_gid_ = g->gr_gid;
        } else {
            note(Level::Warning, "admin_group '" + admin_group + "' not found; only root can use the control socket");
        }
    }

    struct sockaddr_un addr {};
    if (path.size() >= sizeof addr.sun_path) {
        err = "control socket path too long";
        return false;
    }
    if (!mkdir_p(parent_dir(path), 0755, err)) return false;
    struct stat st {};
    if (lstat(path.c_str(), &st) == 0) {
        if (!S_ISSOCK(st.st_mode)) {
            err = path + " exists and is not a socket";
            return false;
        }
        unlink(path.c_str());
    }

    lfd_ = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (lfd_ < 0) {
        err = "socket: " + errno_text(errno);
        return false;
    }
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path.c_str(), path.size());
    if (bind(lfd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof addr) != 0 || listen(lfd_, 16) != 0) {
        err = path + ": " + errno_text(errno);
        close(lfd_);
        lfd_ = -1;
        return false;
    }
    chmod(path.c_str(), has_admin_gid_ ? 0660 : 0600);
    if (has_admin_gid_ && chown(path.c_str(), 0, admin_gid_) != 0)
        note(Level::Warning, "chown control socket: " + errno_text(errno));
    path_ = path;

    stop_fd_ = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    th_ = std::thread([this] { run(); });
    return true;
}

void ControlServer::stop() {
    if (th_.joinable()) {
        uint64_t one = 1;
        (void)!write(stop_fd_, &one, sizeof one);
        th_.join();
    }
    if (lfd_ >= 0) {
        close(lfd_);
        lfd_ = -1;
        unlink(path_.c_str());
    }
    if (stop_fd_ >= 0) {
        close(stop_fd_);
        stop_fd_ = -1;
    }
}

void ControlServer::run() {
    for (;;) {
        struct pollfd p[2] = {{lfd_, POLLIN, 0}, {stop_fd_, POLLIN, 0}};
        if (poll(p, 2, -1) < 0) {
            if (errno == EINTR) continue;
            return;
        }
        if (p[1].revents) return;
        if (p[0].revents & POLLIN) {
            int cfd = accept4(lfd_, nullptr, nullptr, SOCK_CLOEXEC);
            if (cfd < 0) continue;
            handle(cfd);
            close(cfd);
        }
    }
}

ControlServer::Access ControlServer::authorize(int cfd, uid_t& uid) {
    struct ucred cred {};
    socklen_t len = sizeof cred;
    if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) return Access::None;
    uid = cred.uid;
    if (cred.uid == 0) return Access::Admin;
    if (!has_admin_gid_) return Access::None;
    if (cred.gid == admin_gid_) return Access::ReadOnly;
    if (struct passwd* pw = getpwuid(cred.uid)) {
        int n = 64;
        std::vector<gid_t> groups(static_cast<size_t>(n));
        if (getgrouplist(pw->pw_name, pw->pw_gid, groups.data(), &n) < 0) {
            groups.resize(static_cast<size_t>(n));
            getgrouplist(pw->pw_name, pw->pw_gid, groups.data(), &n);
        }
        for (int i = 0; i < n; ++i)
            if (groups[static_cast<size_t>(i)] == admin_gid_) return Access::ReadOnly;
    }
    return Access::None;
}

void ControlServer::handle(int cfd) {
    struct timeval tv {
        3, 0
    };
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    uid_t uid = static_cast<uid_t>(-1);
    Access access = authorize(cfd, uid);
    std::string reply;
    if (access == Access::None) {
        reply = error_json("permission denied");
    } else {
        std::string line;
        char buf[1024];
        while (line.find('\n') == std::string::npos && line.size() < 8192) {
            ssize_t n = recv(cfd, buf, sizeof buf, 0);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            line.append(buf, static_cast<size_t>(n));
        }
        size_t nl = line.find('\n');
        if (nl == std::string::npos) reply = error_json("malformed request");
        else reply = dispatch(line.substr(0, nl), access);
    }
    reply += "\n";
    write_all(cfd, reply.data(), reply.size());
}

std::string ControlServer::dispatch(const std::string& line, Access access) {
    std::vector<std::string> args = split(line, '\t');
    const std::string& cmd = args[0];
    bool admin = access == Access::Admin;

    if (cmd == "status") return h_.status();

    if (cmd == "quarantine-list") {
        std::vector<QuarantineEntry> entries;
        std::string err;
        if (!store_.list(entries, err)) return error_json(err);
        std::vector<std::string> items;
        for (const auto& e : entries) items.push_back(quarantine_entry_json(e));
        JsonObj j;
        j.add("ok", true).raw("entries", json_array(items));
        return j.str();
    }

    if (cmd == "reload") {
        if (!admin) return error_json("reload requires root");
        return h_.reload();
    }

    if (cmd == "quarantine-restore") {
        if (!admin) return error_json("restore requires root");
        if (args.size() < 2) return error_json("usage: quarantine-restore <id> [dest]");
        QuarantineEntry e;
        std::string err;
        if (!store_.restore(args[1], args.size() > 2 ? args[2] : "", e, err)) return error_json(err);
        note(Level::Info, "quarantine entry " + e.id + " restored to " + e.restored_to);
        JsonObj j;
        j.add("ok", true)
            .raw("entry", quarantine_entry_json(e))
            .add("warning",
                 "the restored file will be detected again on execution unless its sha256 is added to the allowlist");
        return j.str();
    }

    return error_json("unknown command '" + cmd + "'");
}

}  // namespace pg
