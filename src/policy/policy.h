#pragma once

#include "common/config.h"
#include "common/hashlist.h"
#include "scanner/scanner.h"

#include <memory>
#include <string>

namespace pg {

enum class Verdict { Allow, Deny };
inline const char* verdict_name(Verdict v) { return v == Verdict::Allow ? "allow" : "deny"; }

struct Decision {
    Verdict verdict = Verdict::Allow;  // what is sent to the kernel
    Verdict policy = Verdict::Allow;   // what the policy wanted (differs only in audit mode)
    std::string reason;                // clean | hash_blocklist | hash_allowlist | yara_match | scan_error | queue_overflow | shutdown
    std::string detail;
    bool quarantine = false;           // detection (not an error) -> eligible for quarantine
};

struct PolicySettings {
    bool enforce = true;
    bool deny_on_error = false;
    bool deny_on_overflow = false;
};
PolicySettings policy_settings(const Config& cfg);

// Priority: hash blocklist > hash allowlist (exception) > YARA match > clean.
// Scan errors are never "clean"; they follow on_error.
class PolicyEngine {
public:
    PolicyEngine();
    void configure(const PolicySettings& s, std::shared_ptr<const HashList> block,
                   std::shared_ptr<const HashList> allow);

    Decision evaluate(const ScanResult& r) const;
    Decision on_error(ScanError e, const std::string& message) const;
    Decision on_overflow() const;

    const PolicySettings& settings() const { return s_; }
    size_t blocklist_size() const { return block_->size(); }
    size_t allowlist_size() const { return allow_->size(); }

private:
    Decision make(Verdict policy, std::string reason, std::string detail, bool quarantine) const;

    PolicySettings s_;
    std::shared_ptr<const HashList> block_, allow_;
};

}  // namespace pg
