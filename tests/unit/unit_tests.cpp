// Unit tests for the parts that do not need fanotify or root.

#include "common/config.h"
#include "common/hashlist.h"
#include "common/json.h"
#include "common/sha256.h"
#include "common/util.h"
#include "policy/policy.h"
#include "quarantine/store.h"
#include "scanner/scanner.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace {

int g_failed = 0, g_checks = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        ++g_checks;                                                       \
        if (!(cond)) {                                                    \
            ++g_failed;                                                   \
            fprintf(stderr, "  FAILED %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                 \
    } while (0)

std::string g_tmp;

std::string write_tmp(const std::string& name, const std::string& content, mode_t mode = 0644) {
    std::string path = g_tmp + "/" + name;
    std::string err;
    pg::write_file_atomic(path, content, mode, err);
    return path;
}

const std::string kMarker = std::string("PATHGUARD-TEST-") + "MARKER-7f3a9c";

void test_sha256() {
    CHECK(pg::sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(pg::sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(pg::sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    std::string million(1000000, 'a');
    CHECK(pg::sha256_hex(million) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    pg::Sha256 h;  // incremental, odd chunk sizes
    for (size_t off = 0; off < million.size(); off += 997) h.update(million.data() + off, std::min<size_t>(997, million.size() - off));
    CHECK(h.hex_digest() == pg::sha256_hex(million));
}

void test_json() {
    CHECK(pg::json_escape("a\"b\\c\n") == "a\\\"b\\\\c\\n");
    CHECK(pg::json_escape("\x01") == "\\u0001");
    CHECK(pg::json_escape("\xed\x95\x9c") == "\xed\x95\x9c");  // valid UTF-8 kept
    CHECK(pg::json_escape("\xff") == "\\u00ff");                // invalid byte escaped
    pg::JsonObj j;
    j.add("s", "x").add("n", 42).add("b", true).add("u", static_cast<uint64_t>(7));
    CHECK(j.str() == "{\"s\":\"x\",\"n\":42,\"b\":true,\"u\":7}");
}

void test_config() {
    pg::Config c;
    std::string err;
    std::string ok = write_tmp("ok.conf",
                               "# comment\nmode = audit\non_error = deny\nwatch_path = /mnt/x\nworkers = 3\n"
                               "max_file_size = 8M\nyara_rules = /r1\nyara_rules = /r2\n");
    CHECK(pg::load_config(ok, c, err));
    CHECK(c.mode == "audit" && c.on_error == "deny" && c.workers == 3);
    CHECK(c.max_file_size == 8ULL << 20);
    CHECK(c.watch_paths.size() == 1 && c.yara_rules.size() == 2);
    CHECK(!c.enforce());

    CHECK(!pg::load_config(write_tmp("bad1.conf", "mode = maybe\n"), c, err));
    CHECK(err.find(":1:") != std::string::npos);
    CHECK(!pg::load_config(write_tmp("bad2.conf", "unknown_key = 1\n"), c, err));
    CHECK(!pg::load_config(write_tmp("bad3.conf", "workers = 0\n"), c, err));
    CHECK(!pg::load_config(write_tmp("bad4.conf", "watch_path = relative\n"), c, err));
    CHECK(!pg::load_config(write_tmp("bad5.conf", "max_file_size = 1G\nworker_memory_limit = 512M\n"), c, err));
}

void test_hashlist() {
    pg::HashList l;
    std::string err;
    std::string h = std::string(64, 'A');
    CHECK(pg::load_hash_list(write_tmp("h.sha256", "# x\n" + h + "  sample one\n\n"), l, err));
    CHECK(l.size() == 1);
    CHECK(l.find(std::string(64, 'a')) && *l.find(std::string(64, 'a')) == "sample one");
    CHECK(!l.digest.empty());
    CHECK(!pg::load_hash_list(write_tmp("h2.sha256", "1234\n"), l, err));
    CHECK(!pg::load_hash_list(g_tmp + "/missing", l, err));
    CHECK(pg::load_hash_list("", l, err) && l.size() == 0);
}

pg::ScanResult clean_result(const std::string& sha) {
    pg::ScanResult r;
    r.status = pg::ScanStatus::Clean;
    r.error = pg::ScanError::None;
    r.sha256 = sha;
    return r;
}

void test_policy() {
    std::string a(64, 'a'), b(64, 'b'), c(64, 'c');
    auto block = std::make_shared<pg::HashList>();
    auto allow = std::make_shared<pg::HashList>();
    block->entries[a] = "known bad";
    allow->entries[a] = "conflict";
    allow->entries[b] = "false positive";

    pg::PolicyEngine p;
    pg::PolicySettings s;
    p.configure(s, block, allow);

    pg::Decision d = p.evaluate(clean_result(a));  // blocklist beats allowlist
    CHECK(d.verdict == pg::Verdict::Deny && d.reason == "hash_blocklist" && d.quarantine);

    pg::ScanResult m = clean_result(b);
    m.status = pg::ScanStatus::Match;
    m.matches = {"R1", "R2"};
    d = p.evaluate(m);  // allowlist exception beats YARA
    CHECK(d.verdict == pg::Verdict::Allow && d.reason == "hash_allowlist");

    m.sha256 = c;
    d = p.evaluate(m);
    CHECK(d.verdict == pg::Verdict::Deny && d.reason == "yara_match" && d.detail == "R1,R2");

    d = p.evaluate(clean_result(c));
    CHECK(d.verdict == pg::Verdict::Allow && d.reason == "clean");

    pg::ScanResult e;
    e.error = pg::ScanError::Timeout;
    d = p.evaluate(e);  // errors are never "clean"
    CHECK(d.verdict == pg::Verdict::Allow && d.reason == "scan_error" && !d.quarantine);
    s.deny_on_error = true;
    p.configure(s, block, allow);
    CHECK(p.evaluate(e).verdict == pg::Verdict::Deny);

    s.enforce = false;  // audit mode
    p.configure(s, block, allow);
    d = p.evaluate(m);
    CHECK(d.verdict == pg::Verdict::Allow && d.policy == pg::Verdict::Deny);

    s = pg::PolicySettings{};
    s.deny_on_overflow = true;
    p.configure(s, block, allow);
    CHECK(p.on_overflow().verdict == pg::Verdict::Deny && p.on_overflow().reason == "queue_overflow");
}

void test_scanner() {
    pg::YaraLibrary lib;
    CHECK(lib.ok());
    std::string rule_dir = g_tmp + "/rules";
    std::string err;
    pg::mkdir_p(rule_dir, 0755, err);
    write_tmp("rules/test.yar", "rule Test_Marker { strings: $a = \"" + kMarker + "\" condition: $a }\n");
    write_tmp("rules/ignored.txt", "not a rule");

    pg::YaraRules rules;
    CHECK(rules.load({rule_dir}, err));
    CHECK(rules.rule_count() == 1);
    CHECK(rules.files().size() == 1);

    pg::Scanner scanner(&rules, 1 << 20, 2);
    auto scan = [&](const std::string& path) {
        int fd = open(path.c_str(), O_RDONLY);
        pg::ScanResult r = scanner.scan_fd(fd);
        close(fd);
        return r;
    };

    std::string marked = write_tmp("marked.bin", "header " + kMarker + " trailer");
    pg::ScanResult r = scan(marked);
    CHECK(r.status == pg::ScanStatus::Match);
    CHECK(r.matches.size() == 1 && r.matches[0] == "Test_Marker");
    CHECK(r.sha256 == pg::sha256_hex("header " + kMarker + " trailer"));

    r = scan(write_tmp("clean.bin", "nothing to see"));
    CHECK(r.status == pg::ScanStatus::Clean && r.error == pg::ScanError::None);

    r = scan(write_tmp("empty.bin", ""));
    CHECK(r.status == pg::ScanStatus::Clean && r.sha256 == pg::sha256_hex(""));

    r = scan(write_tmp("big.bin", std::string((1 << 20) + 1, 'x')));
    CHECK(r.status == pg::ScanStatus::Error && r.error == pg::ScanError::TooLarge);

    int dfd = open(g_tmp.c_str(), O_RDONLY | O_DIRECTORY);
    CHECK(scanner.scan_fd(dfd).error == pg::ScanError::NotRegular);
    close(dfd);

    pg::YaraRules broken;
    write_tmp("broken.yar", "rule Broken { condition: undefined_identifier }\n");
    CHECK(!broken.load({g_tmp + "/broken.yar"}, err));
    CHECK(err.find("broken.yar") != std::string::npos);

    pg::YaraRules none;  // no rules configured: hashing still works
    CHECK(none.load({}, err) && none.rule_count() == 0);
}

void test_quarantine() {
    pg::QuarantineStore store;
    std::string err;
    CHECK(store.init(g_tmp + "/quarantine", err));

    std::string content = "suspicious content";
    std::string victim = write_tmp("victim.bin", content, 0755);
    int fd = open(victim.c_str(), O_RDONLY);
    struct stat st {};
    fstat(fd, &st);
    pg::FileId fid = pg::file_id_from_stat(st);
    std::string sha = pg::sha256_hex(content);

    pg::QuarantineEntry e;
    CHECK(!store.quarantine(fd, victim, std::string(64, '0'), fid, "yara_match", "R", e, err));  // hash mismatch
    CHECK(access(victim.c_str(), F_OK) == 0);
    CHECK(store.quarantine(fd, victim, sha, fid, "yara_match", "R", e, err));
    close(fd);
    CHECK(e.original_removed);
    CHECK(access(victim.c_str(), F_OK) != 0);
    CHECK(pg::valid_quarantine_id(e.id));

    std::vector<pg::QuarantineEntry> list;
    CHECK(store.list(list, err) && list.size() == 1 && list[0].sha256 == sha && list[0].mode == 0755);

    write_tmp("victim.bin", "someone else's file");  // restore must not overwrite
    pg::QuarantineEntry r;
    CHECK(!store.restore(e.id, "", r, err));
    CHECK(err.find("already exists") != std::string::npos);

    std::string dest = g_tmp + "/restored.bin";
    CHECK(store.restore(e.id, dest, r, err));
    std::string back;
    pg::read_file(dest, back, err);
    CHECK(back == content);
    struct stat rst {};
    stat(dest.c_str(), &rst);
    CHECK((rst.st_mode & 0777) == 0755);
    CHECK(!store.restore(e.id, g_tmp + "/again.bin", r, err));  // already restored
    CHECK(!store.restore("../etc/passwd", "", r, err));         // id validation
}

}  // namespace

int main() {
    char tmpl[] = "/tmp/pathguard-unit-XXXXXX";
    if (!mkdtemp(tmpl)) return 1;
    g_tmp = tmpl;

    std::vector<std::pair<const char*, std::function<void()>>> tests = {
        {"sha256", test_sha256}, {"json", test_json},       {"config", test_config},
        {"hashlist", test_hashlist}, {"policy", test_policy}, {"scanner", test_scanner},
        {"quarantine", test_quarantine},
    };
    for (auto& [name, fn] : tests) {
        int before = g_failed;
        fn();
        printf("%-12s %s\n", name, g_failed == before ? "ok" : "FAILED");
    }
    std::string cmd = "rm -rf '" + g_tmp + "'";
    if (system(cmd.c_str()) != 0) fprintf(stderr, "cleanup of %s failed\n", g_tmp.c_str());
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
