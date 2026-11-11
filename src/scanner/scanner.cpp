#include "scanner/scanner.h"

#include "common/sha256.h"
#include "common/util.h"

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <yara.h>

#include <algorithm>
#include <cerrno>

namespace pg {
namespace {

struct CompileErrors {
    std::string current_file;
    std::string text;
};

void compiler_cb(int error_level, const char* /*file_name*/, int line_number, const YR_RULE* /*rule*/,
                 const char* message, void* user_data) {
    if (error_level != YARA_ERROR_LEVEL_ERROR) return;
    auto* ce = static_cast<CompileErrors*>(user_data);
    if (!ce->text.empty()) ce->text += "; ";
    ce->text += ce->current_file + ":" + std::to_string(line_number) + ": " + message;
}

int scan_cb(YR_SCAN_CONTEXT* /*context*/, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* rule = static_cast<YR_RULE*>(message_data);
        static_cast<std::vector<std::string>*>(user_data)->push_back(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

bool collect_rule_files(const std::string& source, std::vector<std::string>& out, std::string& err) {
    struct stat st {};
    if (stat(source.c_str(), &st) != 0) {
        err = source + ": " + errno_text(errno);
        return false;
    }
    if (!S_ISDIR(st.st_mode)) {
        out.push_back(source);
        return true;
    }
    DIR* d = opendir(source.c_str());
    if (!d) {
        err = source + ": " + errno_text(errno);
        return false;
    }
    std::vector<std::string> found;
    while (struct dirent* e = readdir(d)) {
        std::string name = e->d_name;
        if (name.empty() || name[0] == '.') continue;
        if (ends_with(name, ".yar") || ends_with(name, ".yara")) found.push_back(source + "/" + name);
    }
    closedir(d);
    std::sort(found.begin(), found.end());
    out.insert(out.end(), found.begin(), found.end());
    return true;
}

}  // namespace

YaraLibrary::YaraLibrary() { ok_ = yr_initialize() == ERROR_SUCCESS; }

YaraLibrary::~YaraLibrary() {
    if (ok_) yr_finalize();
}

YaraRules::~YaraRules() {
    if (rules_) yr_rules_destroy(rules_);
}

bool YaraRules::load(const std::vector<std::string>& sources, std::string& err) {
    std::vector<std::string> files;
    for (const auto& s : sources)
        if (!collect_rule_files(s, files, err)) return false;

    Sha256 version;
    if (files.empty()) {
        files_.clear();
        version_ = version.hex_digest();
        count_ = 0;
        return true;
    }

    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        err = "yr_compiler_create failed";
        return false;
    }
    CompileErrors ce;
    yr_compiler_set_callback(compiler, compiler_cb, &ce);

    for (const auto& f : files) {
        std::string text;
        if (!read_file(f, text, err)) {
            yr_compiler_destroy(compiler);
            return false;
        }
        version.update(f.data(), f.size() + 1);  // include the NUL as a separator
        version.update(text.data(), text.size());
        ce.current_file = f;
        if (yr_compiler_add_string(compiler, text.c_str(), nullptr) != 0) {
            err = ce.text.empty() ? f + ": compile error" : ce.text;
            yr_compiler_destroy(compiler);
            return false;
        }
    }

    YR_RULES* rules = nullptr;
    int rc = yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);
    if (rc != ERROR_SUCCESS) {
        err = "yr_compiler_get_rules failed (" + std::to_string(rc) + ")";
        return false;
    }
    int count = 0;
    YR_RULE* rule;
    yr_rules_foreach(rules, rule) { ++count; }

    if (rules_) yr_rules_destroy(rules_);
    rules_ = rules;
    count_ = count;
    files_ = files;
    version_ = version.hex_digest();
    return true;
}

ScanResult Scanner::scan_fd(int fd) const {
    ScanResult r;
    uint64_t t0 = mono_us();
    auto fail = [&](ScanError e, const std::string& msg) {
        r.status = ScanStatus::Error;
        r.error = e;
        r.message = msg;
        r.scan_us = mono_us() - t0;
        return r;
    };

    struct stat before {};
    if (fstat(fd, &before) != 0) return fail(ScanError::StatFailed, errno_text(errno));
    if (!S_ISREG(before.st_mode)) return fail(ScanError::NotRegular, "not a regular file");
    r.size = static_cast<uint64_t>(before.st_size);
    if (r.size > max_size_)
        return fail(ScanError::TooLarge,
                    "file size " + std::to_string(r.size) + " exceeds max_file_size " + std::to_string(max_size_));

    std::vector<uint8_t> buf(r.size > 0 ? r.size : 1);
    uint64_t off = 0;
    while (off < r.size) {
        ssize_t n = pread(fd, buf.data() + off, r.size - off, static_cast<off_t>(off));
        if (n < 0) {
            if (errno == EINTR) continue;
            return fail(ScanError::ReadFailed, errno_text(errno));
        }
        if (n == 0) return fail(ScanError::Changed, "file shrank during scan");
        off += static_cast<uint64_t>(n);
    }
    uint8_t extra;
    if (pread(fd, &extra, 1, static_cast<off_t>(r.size)) > 0) return fail(ScanError::Changed, "file grew during scan");

    r.sha256 = sha256_hex(buf.data(), r.size);

    if (rules_ && rules_->get()) {
        std::vector<std::string> matches;
        int rc = yr_rules_scan_mem(rules_->get(), buf.data(), r.size, SCAN_FLAGS_FAST_MODE, scan_cb, &matches,
                                   yara_timeout_s_);
        if (rc != ERROR_SUCCESS)
            return fail(ScanError::YaraFailed,
                        rc == ERROR_SCAN_TIMEOUT ? "yara scan timeout" : "yara scan error " + std::to_string(rc));
        r.matches = std::move(matches);
    }

    struct stat after {};
    if (fstat(fd, &after) != 0) return fail(ScanError::StatFailed, errno_text(errno));
    if (file_id_from_stat(before) != file_id_from_stat(after))
        return fail(ScanError::Changed, "file metadata changed during scan");

    r.status = r.matches.empty() ? ScanStatus::Clean : ScanStatus::Match;
    r.error = ScanError::None;
    r.scan_us = mono_us() - t0;
    return r;
}

}  // namespace pg
