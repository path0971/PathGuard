#include "policy/policy.h"

namespace pg {

PolicySettings policy_settings(const Config& cfg) {
    PolicySettings s;
    s.enforce = cfg.enforce();
    s.deny_on_error = cfg.on_error == "deny";
    s.deny_on_overflow = cfg.on_overflow == "deny";
    return s;
}

PolicyEngine::PolicyEngine() : block_(std::make_shared<HashList>()), allow_(std::make_shared<HashList>()) {}

void PolicyEngine::configure(const PolicySettings& s, std::shared_ptr<const HashList> block,
                             std::shared_ptr<const HashList> allow) {
    s_ = s;
    block_ = block ? std::move(block) : std::make_shared<HashList>();
    allow_ = allow ? std::move(allow) : std::make_shared<HashList>();
}

Decision PolicyEngine::make(Verdict policy, std::string reason, std::string detail, bool quarantine) const {
    Decision d;
    d.policy = policy;
    d.verdict = (policy == Verdict::Deny && !s_.enforce) ? Verdict::Allow : policy;
    d.reason = std::move(reason);
    d.detail = std::move(detail);
    d.quarantine = quarantine;
    return d;
}

Decision PolicyEngine::evaluate(const ScanResult& r) const {
    if (r.status == ScanStatus::Error) return on_error(r.error, r.message);

    if (const std::string* c = block_->find(r.sha256)) return make(Verdict::Deny, "hash_blocklist", *c, true);
    if (const std::string* c = allow_->find(r.sha256)) return make(Verdict::Allow, "hash_allowlist", *c, false);
    if (!r.matches.empty()) {
        std::string names;
        for (const auto& m : r.matches) {
            if (!names.empty()) names += ',';
            names += m;
        }
        return make(Verdict::Deny, "yara_match", names, true);
    }
    return make(Verdict::Allow, "clean", "", false);
}

Decision PolicyEngine::on_error(ScanError e, const std::string& message) const {
    std::string detail = scan_error_name(e);
    if (!message.empty()) detail += ": " + message;
    return make(s_.deny_on_error ? Verdict::Deny : Verdict::Allow, "scan_error", detail, false);
}

Decision PolicyEngine::on_overflow() const {
    return make(s_.deny_on_overflow ? Verdict::Deny : Verdict::Allow, "queue_overflow", "scan queue full", false);
}

}  // namespace pg
