#pragma once

#include "common/audit_log.h"
#include "common/util.h"
#include "quarantine/store.h"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>

namespace pg {

struct QuarantineJob {
    int fd = -1;  // owned by the job
    std::string path, sha256, reason, detail;
    FileId fid;
    uint64_t event_id = 0;
};

// Runs quarantine off the decision path: the kernel has already been answered
// by the time a job is queued.
class QuarantineWorker {
public:
    QuarantineWorker(QuarantineStore& store, AuditLog& log, size_t max_jobs);
    ~QuarantineWorker();
    void start();
    void stop();  // drains queued jobs, then joins
    bool submit(QuarantineJob&& job);  // false if full; the caller keeps ownership of job.fd

    uint64_t done() const { return done_; }
    uint64_t failed() const { return failed_; }

private:
    void run();
    void process(QuarantineJob& job);

    QuarantineStore& store_;
    AuditLog& log_;
    size_t max_;
    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<QuarantineJob> q_;
    bool stopping_ = false;
    std::thread th_;
    std::atomic<uint64_t> done_{0}, failed_{0};
};

}  // namespace pg
