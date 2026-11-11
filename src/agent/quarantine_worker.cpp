#include "agent/quarantine_worker.h"

#include <unistd.h>

namespace pg {

QuarantineWorker::QuarantineWorker(QuarantineStore& store, AuditLog& log, size_t max_jobs)
    : store_(store), log_(log), max_(max_jobs) {}

QuarantineWorker::~QuarantineWorker() { stop(); }

void QuarantineWorker::start() { th_ = std::thread([this] { run(); }); }

void QuarantineWorker::stop() {
    {
        std::lock_guard<std::mutex> lk(mu_);
        stopping_ = true;
    }
    cv_.notify_all();
    if (th_.joinable()) th_.join();
}

bool QuarantineWorker::submit(QuarantineJob&& job) {
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (stopping_ || q_.size() >= max_) return false;
        q_.push_back(std::move(job));
    }
    cv_.notify_one();
    return true;
}

void QuarantineWorker::run() {
    for (;;) {
        QuarantineJob job;
        {
            std::unique_lock<std::mutex> lk(mu_);
            cv_.wait(lk, [this] { return stopping_ || !q_.empty(); });
            if (q_.empty()) return;
            job = std::move(q_.front());
            q_.pop_front();
        }
        process(job);
        close(job.fd);
    }
}

void QuarantineWorker::process(QuarantineJob& job) {
    QuarantineEntry e;
    std::string err;
    if (store_.quarantine(job.fd, job.path, job.sha256, job.fid, job.reason, job.detail, e, err)) {
        ++done_;
        JsonObj j = audit_record("quarantine");
        j.add("event_id", job.event_id)
            .add("quarantine_id", e.id)
            .add("path", e.original_path)
            .add("sha256", e.sha256)
            .add("reason", e.reason)
            .add("original_removed", e.original_removed)
            .add("removal_error", e.removal_error);
        log_.write(j.str());
        note(Level::Info, "quarantined " + e.original_path + " as " + e.id +
                              (e.original_removed ? "" : " (original not removed: " + e.removal_error + ")"));
    } else {
        ++failed_;
        JsonObj j = audit_record("quarantine_failed");
        j.add("event_id", job.event_id).add("path", job.path).add("sha256", job.sha256).add("error", err);
        log_.write(j.str());
        note(Level::Warning, "quarantine of " + job.path + " failed: " + err);
    }
}

}  // namespace pg
