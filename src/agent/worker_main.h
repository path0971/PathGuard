#pragma once

#include <string>

namespace pg {

// Entry point of a scan worker (pathguardd --worker). The agent passes the
// request socket as fd 3. The worker loads the rules, drops privileges, and
// then only reads the file descriptors it is sent.
int worker_main(const std::string& config_path);

}  // namespace pg
