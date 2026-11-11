#include "common/fdpass.h"

#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace pg {

bool send_msg(int sock, const void* data, size_t len, int fd, int flags) {
    struct msghdr msg {};
    struct iovec iov {
        const_cast<void*>(data), len
    };
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    alignas(struct cmsghdr) char ctrl[CMSG_SPACE(sizeof(int))];
    if (fd >= 0) {
        memset(ctrl, 0, sizeof ctrl);
        msg.msg_control = ctrl;
        msg.msg_controllen = sizeof ctrl;
        struct cmsghdr* c = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &fd, sizeof fd);
    }
    for (;;) {
        ssize_t n = sendmsg(sock, &msg, flags | MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        return n == static_cast<ssize_t>(len);
    }
}

ssize_t recv_msg(int sock, void* data, size_t len, int* fd_out, int flags) {
    *fd_out = -1;
    struct msghdr msg {};
    struct iovec iov {
        data, len
    };
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    alignas(struct cmsghdr) char ctrl[CMSG_SPACE(sizeof(int) * 4)];
    msg.msg_control = ctrl;
    msg.msg_controllen = sizeof ctrl;
    ssize_t n;
    do {
        n = recvmsg(sock, &msg, flags | MSG_CMSG_CLOEXEC);
    } while (n < 0 && errno == EINTR);
    if (n < 0) return n;
    for (struct cmsghdr* c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) continue;
        size_t nfds = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        for (size_t i = 0; i < nfds; ++i) {
            int fd;
            memcpy(&fd, CMSG_DATA(c) + i * sizeof(int), sizeof fd);
            if (*fd_out < 0) *fd_out = fd;
            else close(fd);  // only one descriptor is expected
        }
    }
    return n;
}

}  // namespace pg
