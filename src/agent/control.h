#pragma once

#include "quarantine/store.h"

#include <sys/types.h>

#include <functional>
#include <string>
#include <thread>

namespace pg {

struct ControlHandlers {
    std::function<std::string()> status;  // returns a JSON object
    std::function<std::string()> reload;
};

// Local management socket. One request line per connection:
//   command \t arg1 \t arg2 ... \n   ->   one JSON object line
// Authorization uses SO_PEERCRED: root may do everything; members of
// admin_group may run read-only commands (status, quarantine-list).
class ControlServer {
public:
    ControlServer(QuarantineStore& store, ControlHandlers handlers);
    ~ControlServer();
    bool start(const std::string& path, const std::string& admin_group, std::string& err);
    void stop();

private:
    enum class Access { None, ReadOnly, Admin };
    void run();
    void handle(int cfd);
    Access authorize(int cfd, uid_t& uid);
    std::string dispatch(const std::string& line, Access access);

    QuarantineStore& store_;
    ControlHandlers h_;
    std::string path_;
    int lfd_ = -1;
    int stop_fd_ = -1;
    bool has_admin_gid_ = false;
    gid_t admin_gid_ = 0;
    std::thread th_;
};

}  // namespace pg
