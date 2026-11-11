#include "agent/agent.h"
#include "agent/worker_main.h"
#include "common/config.h"

#include <cstdio>
#include <cstring>
#include <string>

namespace {

void usage() {
    fprintf(stderr,
            "usage: pathguardd [--config FILE] [--check]\n"
            "  --config FILE  configuration file (default /etc/pathguard/pathguard.conf)\n"
            "  --check        validate configuration, hash lists, YARA rules and watch paths, then exit\n"
            "  --version      print version\n");
}

}  // namespace

int main(int argc, char** argv) {
    std::string config = "/etc/pathguard/pathguard.conf";
    bool worker = false, check = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--config" && i + 1 < argc) {
            config = argv[++i];
        } else if (a == "--worker") {
            worker = true;
        } else if (a == "--check") {
            check = true;
        } else if (a == "--version") {
            printf("pathguardd %s\n", PATHGUARD_VERSION);
            return 0;
        } else {
            usage();
            return 2;
        }
    }

    if (worker) return pg::worker_main(config);

    pg::Config cfg;
    std::string err;
    if (!pg::load_config(config, cfg, err)) {
        fprintf(stderr, "pathguardd: %s\n", err.c_str());
        return 1;
    }
    if (check) return pg::check_configuration(cfg);

    pg::Agent agent(config, cfg);
    return agent.run();
}
