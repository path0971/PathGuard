// pathguardctl: management CLI. Talks to the agent over its local socket, or
// scans files offline with the configured hash lists and YARA rules.

#include "common/config.h"
#include "common/hashlist.h"
#include "common/json.h"
#include "common/sha256.h"
#include "common/util.h"
#include "policy/policy.h"
#include "scanner/scanner.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace {

const char* kDefaultConfig = "/etc/pathguard/pathguard.conf";
const char* kDefaultSocket = "/run/pathguard/control.sock";

void usage() {
    fprintf(stderr,
            "usage: pathguardctl [--socket PATH] [--config FILE] <command>\n"
            "\n"
            "agent commands:\n"
            "  status                               protection state, counters, latency\n"
            "  reload                               re-read config, hash lists and rules (root)\n"
            "  quarantine list                      list quarantined files\n"
            "  quarantine restore <id> [--to PATH]  restore a file without overwriting (root)\n"
            "\n"
            "offline commands (no agent needed):\n"
            "  scan <file>...                       scan with the configured hashes and rules\n"
            "  hash <file>...                       print SHA-256 in blocklist/allowlist format\n"
            "\n"
            "scan exit status: 0 all allowed, bit 1 = something denied, bit 2 = scan error\n");
}

int request(const std::string& sock_path, const std::vector<std::string>& args) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un addr {};
    if (fd < 0 || sock_path.size() >= sizeof addr.sun_path) {
        fprintf(stderr, "pathguardctl: cannot create socket\n");
        return 1;
    }
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, sock_path.c_str(), sock_path.size());
    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof addr) != 0) {
        fprintf(stderr, "pathguardctl: %s: %s (is pathguardd running?)\n", sock_path.c_str(), strerror(errno));
        close(fd);
        return 1;
    }
    std::string line;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i].find_first_of("\t\n") != std::string::npos) {
            fprintf(stderr, "pathguardctl: arguments may not contain tabs or newlines\n");
            close(fd);
            return 1;
        }
        if (i) line += '\t';
        line += args[i];
    }
    line += '\n';
    pg::write_all(fd, line.data(), line.size());
    std::string reply;
    char buf[4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        reply.append(buf, static_cast<size_t>(n));
    }
    close(fd);
    fputs(reply.c_str(), stdout);
    return reply.find("\"ok\":true") != std::string::npos ? 0 : 1;
}

int cmd_hash(const std::vector<std::string>& files) {
    int rc = 0;
    for (const auto& f : files) {
        int fd = open(f.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            fprintf(stderr, "%s: %s\n", f.c_str(), strerror(errno));
            rc = 2;
            continue;
        }
        pg::Sha256 h;
        char buf[1 << 16];
        ssize_t n;
        while ((n = read(fd, buf, sizeof buf)) > 0) h.update(buf, static_cast<size_t>(n));
        close(fd);
        if (n < 0) {
            fprintf(stderr, "%s: %s\n", f.c_str(), strerror(errno));
            rc = 2;
            continue;
        }
        printf("%s  %s\n", h.hex_digest().c_str(), f.c_str());
    }
    return rc;
}

int cmd_scan(const std::string& config_path, const std::vector<std::string>& files) {
    pg::Config cfg;
    std::string err;
    if (!pg::load_config(config_path, cfg, err)) {
        fprintf(stderr, "pathguardctl: %s\n", err.c_str());
        return 2;
    }
    auto block = std::make_shared<pg::HashList>();
    auto allow = std::make_shared<pg::HashList>();
    if (!pg::load_hash_list(cfg.blocklist, *block, err) || !pg::load_hash_list(cfg.allowlist, *allow, err)) {
        fprintf(stderr, "pathguardctl: %s\n", err.c_str());
        return 2;
    }
    pg::YaraLibrary lib;
    pg::YaraRules rules;
    if (!lib.ok() || !rules.load(cfg.yara_rules, err)) {
        fprintf(stderr, "pathguardctl: rules: %s\n", lib.ok() ? err.c_str() : "yr_initialize failed");
        return 2;
    }
    pg::PolicyEngine policy;
    pg::PolicySettings settings = pg::policy_settings(cfg);
    settings.enforce = true;  // report what enforcement would do
    policy.configure(settings, block, allow);
    pg::Scanner scanner(&rules, cfg.max_file_size, std::max(1, (cfg.scan_timeout_ms + 999) / 1000));

    int rc = 0;
    for (const auto& f : files) {
        pg::ScanResult r;
        int fd = open(f.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            r.error = pg::ScanError::ReadFailed;
            r.message = strerror(errno);
        } else {
            r = scanner.scan_fd(fd);
            close(fd);
        }
        pg::Decision d = policy.evaluate(r);
        pg::JsonObj j;
        j.add("path", f).add("result", pg::scan_status_name(r.status));
        if (r.status == pg::ScanStatus::Error) j.add("error", pg::scan_error_name(r.error)).add("message", r.message);
        j.add("sha256", r.sha256)
            .raw("matches", pg::json_str_array(r.matches))
            .add("decision", pg::verdict_name(d.policy))
            .add("reason", d.reason)
            .add("detail", d.detail)
            .add("size", r.size)
            .add("scan_us", r.scan_us);
        printf("%s\n", j.str().c_str());
        if (r.status == pg::ScanStatus::Error) rc |= 2;
        if (d.policy == pg::Verdict::Deny) rc |= 1;
    }
    return rc;
}

}  // namespace

int main(int argc, char** argv) {
    std::string config = kDefaultConfig, sock;
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--socket" && i + 1 < argc) sock = argv[++i];
        else if (a == "--config" && i + 1 < argc) config = argv[++i];
        else if (a == "-h" || a == "--help") {
            usage();
            return 0;
        } else args.push_back(a);
    }
    if (args.empty()) {
        usage();
        return 2;
    }
    if (sock.empty()) {
        pg::Config cfg;
        std::string err;
        sock = pg::load_config(config, cfg, err) ? cfg.control_socket : kDefaultSocket;
    }

    const std::string& cmd = args[0];
    std::vector<std::string> rest(args.begin() + 1, args.end());
    if (cmd == "status" && rest.empty()) return request(sock, {"status"});
    if (cmd == "reload" && rest.empty()) return request(sock, {"reload"});
    if (cmd == "quarantine" && !rest.empty()) {
        if (rest[0] == "list" && rest.size() == 1) return request(sock, {"quarantine-list"});
        if (rest[0] == "restore" && (rest.size() == 2 || (rest.size() == 4 && rest[2] == "--to"))) {
            std::vector<std::string> req = {"quarantine-restore", rest[1]};
            if (rest.size() == 4) req.push_back(rest[3]);
            return request(sock, req);
        }
    }
    if (cmd == "scan" && !rest.empty()) return cmd_scan(config, rest);
    if (cmd == "hash" && !rest.empty()) return cmd_hash(rest);
    usage();
    return 2;
}
