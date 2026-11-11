#pragma once

#include <sys/types.h>

#include <cstddef>

namespace pg {

// Sends one message, optionally carrying fd (pass -1 for none) via SCM_RIGHTS.
bool send_msg(int sock, const void* data, size_t len, int fd, int flags);

// Receives one message. *fd_out is set to a received descriptor (O_CLOEXEC) or -1.
ssize_t recv_msg(int sock, void* data, size_t len, int* fd_out, int flags);

}  // namespace pg
