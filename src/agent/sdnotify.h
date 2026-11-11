#pragma once

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <string>

namespace pg {

// Minimal sd_notify(3) so the agent does not depend on libsystemd.
inline void sd_notify_msg(const std::string& msg) {
    const char* path = getenv("NOTIFY_SOCKET");
    if (!path || !*path) return;
    struct sockaddr_un addr {};
    size_t len = strlen(path);
    if (len >= sizeof addr.sun_path) return;
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path, len);
    if (addr.sun_path[0] == '@') addr.sun_path[0] = '\0';
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return;
    sendto(fd, msg.data(), msg.size(), MSG_NOSIGNAL, reinterpret_cast<struct sockaddr*>(&addr),
           static_cast<socklen_t>(offsetof(struct sockaddr_un, sun_path) + len));
    close(fd);
}

// Returns the watchdog interval in microseconds, or 0 if not enabled.
inline uint64_t sd_watchdog_usec() {
    const char* s = getenv("WATCHDOG_USEC");
    if (!s) return 0;
    const char* pid = getenv("WATCHDOG_PID");
    if (pid && std::strtol(pid, nullptr, 10) != static_cast<long>(getpid())) return 0;
    return std::strtoull(s, nullptr, 10);
}

}  // namespace pg
