#include "quarantine/store.h"

#include "common/json.h"
#include "common/sha256.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>

namespace pg {
namespace {

std::string esc(const std::string& v) {
    std::string out;
    for (char c : v) {
        if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else out += c;
    }
    return out;
}

std::string unesc(const std::string& v) {
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (v[i] == '\\' && i + 1 < v.size()) {
            ++i;
            out += v[i] == 'n' ? '\n' : v[i];
        } else {
            out += v[i];
        }
    }
    return out;
}

std::string make_id() {
    time_t t = time(nullptr);
    struct tm tm {};
    gmtime_r(&t, &tm);
    char buf[32];
    strftime(buf, sizeof buf, "%Y%m%dT%H%M%SZ", &tm);
    return std::string(buf) + "-" + random_hex(4);
}

// Copies everything readable from `in` (from offset 0) to `out`, hashing on the way.
bool copy_and_hash(int in, int out, std::string& sha, uint64_t& copied, std::string& err) {
    Sha256 h;
    std::vector<char> buf(1 << 20);
    off_t off = 0;
    copied = 0;
    for (;;) {
        ssize_t n = pread(in, buf.data(), buf.size(), off);
        if (n < 0) {
            if (errno == EINTR) continue;
            err = "read: " + errno_text(errno);
            return false;
        }
        if (n == 0) break;
        if (!write_all(out, buf.data(), static_cast<size_t>(n))) {
            err = "write: " + errno_text(errno);
            return false;
        }
        h.update(buf.data(), static_cast<size_t>(n));
        off += n;
        copied += static_cast<uint64_t>(n);
    }
    sha = h.hex_digest();
    return true;
}

}  // namespace

bool valid_quarantine_id(const std::string& id) {
    if (id.empty() || id.size() > 64) return false;
    for (char c : id)
        if (!(isalnum(static_cast<unsigned char>(c)) || c == '-')) return false;
    return true;
}

bool QuarantineStore::init(const std::string& dir, std::string& err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!mkdir_p(dir, 0700, err)) return false;
    chmod(dir.c_str(), 0700);
    dir_ = dir;
    return true;
}

bool QuarantineStore::write_meta(const QuarantineEntry& e, std::string& err) {
    std::string m;
    m += "id=" + esc(e.id) + "\n";
    m += "original_path=" + esc(e.original_path) + "\n";
    m += "sha256=" + e.sha256 + "\n";
    m += "reason=" + esc(e.reason) + "\n";
    m += "detail=" + esc(e.detail) + "\n";
    m += "quarantined_at=" + e.quarantined_at + "\n";
    m += "size=" + std::to_string(e.size) + "\n";
    m += "mode=" + std::to_string(e.mode) + "\n";
    m += "uid=" + std::to_string(e.uid) + "\n";
    m += "gid=" + std::to_string(e.gid) + "\n";
    m += "nlink=" + std::to_string(e.nlink) + "\n";
    m += std::string("original_removed=") + (e.original_removed ? "1" : "0") + "\n";
    m += "removal_error=" + esc(e.removal_error) + "\n";
    m += std::string("restored=") + (e.restored ? "1" : "0") + "\n";
    m += "restored_to=" + esc(e.restored_to) + "\n";
    m += "restored_at=" + e.restored_at + "\n";
    return write_file_atomic(dir_ + "/" + e.id + ".meta", m, 0600, err);
}

bool QuarantineStore::read_meta(const std::string& id, QuarantineEntry& e, std::string& err) {
    std::string text;
    if (!read_file(dir_ + "/" + id + ".meta", text, err)) return false;
    e = QuarantineEntry{};
    for (const auto& line : split(text, '\n')) {
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq), v = unesc(line.substr(eq + 1));
        if (k == "id") e.id = v;
        else if (k == "original_path") e.original_path = v;
        else if (k == "sha256") e.sha256 = v;
        else if (k == "reason") e.reason = v;
        else if (k == "detail") e.detail = v;
        else if (k == "quarantined_at") e.quarantined_at = v;
        else if (k == "size") e.size = strtoull(v.c_str(), nullptr, 10);
        else if (k == "mode") e.mode = static_cast<uint32_t>(strtoul(v.c_str(), nullptr, 10));
        else if (k == "uid") e.uid = static_cast<uint32_t>(strtoul(v.c_str(), nullptr, 10));
        else if (k == "gid") e.gid = static_cast<uint32_t>(strtoul(v.c_str(), nullptr, 10));
        else if (k == "nlink") e.nlink = strtoull(v.c_str(), nullptr, 10);
        else if (k == "original_removed") e.original_removed = v == "1";
        else if (k == "removal_error") e.removal_error = v;
        else if (k == "restored") e.restored = v == "1";
        else if (k == "restored_to") e.restored_to = v;
        else if (k == "restored_at") e.restored_at = v;
    }
    if (e.id != id) {
        err = "metadata id mismatch for " + id;
        return false;
    }
    return true;
}

bool QuarantineStore::quarantine(int fd, const std::string& path, const std::string& expected_sha,
                                 const FileId& scanned, const std::string& reason, const std::string& detail,
                                 QuarantineEntry& out, std::string& err) {
    std::lock_guard<std::mutex> lk(mu_);
    struct stat st {};
    if (fstat(fd, &st) != 0) {
        err = "fstat: " + errno_text(errno);
        return false;
    }
    if (file_id_from_stat(st) != scanned) {
        err = "file changed after it was scanned";
        return false;
    }
    if (path.empty() || path[0] != '/' || ends_with(path, " (deleted)")) {
        err = "original path is unavailable (file already removed or path unknown)";
        return false;
    }
    std::string parent = parent_dir(path);
    std::string base = path.substr(path.rfind('/') + 1);
    int dfd = open(parent.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) {
        err = parent + ": " + errno_text(errno);
        return false;
    }
    auto same_inode = [&](std::string& why) {
        struct stat cur {};
        if (fstatat(dfd, base.c_str(), &cur, AT_SYMLINK_NOFOLLOW) != 0) {
            why = "original path no longer exists";
            return false;
        }
        if (cur.st_dev != st.st_dev || cur.st_ino != st.st_ino) {
            why = "original path now refers to a different file";
            return false;
        }
        return true;
    };
    if (!same_inode(err)) {
        close(dfd);
        return false;
    }

    QuarantineEntry e;
    e.id = make_id();
    std::string bin = dir_ + "/" + e.id + ".bin";
    int ofd = open(bin.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0400);
    if (ofd < 0) {
        err = bin + ": " + errno_text(errno);
        close(dfd);
        return false;
    }
    std::string sha;
    uint64_t copied = 0;
    bool ok = copy_and_hash(fd, ofd, sha, copied, err);
    if (ok && fsync(ofd) != 0) {
        err = "fsync: " + errno_text(errno);
        ok = false;
    }
    close(ofd);
    if (ok && sha != expected_sha) {
        err = "content hash differs from the scanned hash";
        ok = false;
    }
    if (ok) {
        e.original_path = path;
        e.sha256 = sha;
        e.reason = reason;
        e.detail = detail;
        e.quarantined_at = iso_time_now();
        e.size = copied;
        e.mode = st.st_mode & 07777;
        e.uid = st.st_uid;
        e.gid = st.st_gid;
        e.nlink = st.st_nlink;
        ok = write_meta(e, err);
    }
    if (!ok) {
        unlink(bin.c_str());
        close(dfd);
        return false;
    }

    // The copy is safe; now remove the original if it is still the same inode.
    std::string why;
    if (!same_inode(why)) {
        e.removal_error = why;
    } else if (unlinkat(dfd, base.c_str(), 0) != 0) {
        e.removal_error = "unlink: " + errno_text(errno);
    } else {
        e.original_removed = true;
        if (e.nlink > 1) e.removal_error = "other hard links to this file still exist";
    }
    close(dfd);
    std::string merr;
    if (!write_meta(e, merr)) note(Level::Warning, "quarantine metadata update failed: " + merr);
    out = e;
    return true;
}

bool QuarantineStore::list(std::vector<QuarantineEntry>& out, std::string& err) {
    std::lock_guard<std::mutex> lk(mu_);
    out.clear();
    DIR* d = opendir(dir_.c_str());
    if (!d) {
        err = dir_ + ": " + errno_text(errno);
        return false;
    }
    std::vector<std::string> ids;
    while (struct dirent* de = readdir(d)) {
        std::string name = de->d_name;
        if (!ends_with(name, ".meta")) continue;
        std::string id = name.substr(0, name.size() - 5);
        if (valid_quarantine_id(id)) ids.push_back(id);
    }
    closedir(d);
    std::sort(ids.begin(), ids.end());
    for (const auto& id : ids) {
        QuarantineEntry e;
        std::string merr;
        if (read_meta(id, e, merr)) out.push_back(e);
        else note(Level::Warning, "skipping quarantine entry: " + merr);
    }
    return true;
}

bool QuarantineStore::restore(const std::string& id, const std::string& dest, QuarantineEntry& out,
                              std::string& err) {
    if (!valid_quarantine_id(id)) {
        err = "invalid quarantine id";
        return false;
    }
    std::lock_guard<std::mutex> lk(mu_);
    QuarantineEntry e;
    if (!read_meta(id, e, err)) return false;
    if (e.restored) {
        err = "already restored to " + e.restored_to;
        return false;
    }
    std::string target = dest.empty() ? e.original_path : dest;
    if (target.empty() || target[0] != '/') {
        err = "destination must be an absolute path";
        return false;
    }

    std::string bin = dir_ + "/" + id + ".bin";
    int in = open(bin.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (in < 0) {
        err = bin + ": " + errno_text(errno);
        return false;
    }
    // O_EXCL: never overwrite whatever now lives at the destination.
    int outfd = open(target.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (outfd < 0) {
        err = errno == EEXIST ? "destination already exists: " + target + " (choose another path with --to)"
                              : target + ": " + errno_text(errno);
        close(in);
        return false;
    }
    std::string sha;
    uint64_t copied = 0;
    bool ok = copy_and_hash(in, outfd, sha, copied, err);
    close(in);
    if (ok && sha != e.sha256) {
        err = "restored content hash does not match the quarantined hash";
        ok = false;
    }
    if (ok) {
        if (fchown(outfd, e.uid, e.gid) != 0)
            note(Level::Warning, "restore: could not restore owner of " + target + ": " + errno_text(errno));
        fchmod(outfd, e.mode & 0777);  // set-id bits are intentionally not restored
        if (fsync(outfd) != 0) {
            err = "fsync: " + errno_text(errno);
            ok = false;
        }
    }
    close(outfd);
    if (!ok) {
        unlink(target.c_str());
        return false;
    }

    e.restored = true;
    e.restored_to = target;
    e.restored_at = iso_time_now();
    if (!write_meta(e, err)) return false;
    unlink(bin.c_str());
    out = e;
    return true;
}

std::string quarantine_entry_json(const QuarantineEntry& e) {
    JsonObj j;
    j.add("id", e.id)
        .add("original_path", e.original_path)
        .add("sha256", e.sha256)
        .add("reason", e.reason)
        .add("detail", e.detail)
        .add("quarantined_at", e.quarantined_at)
        .add("size", e.size)
        .add("mode", e.mode)
        .add("uid", e.uid)
        .add("gid", e.gid)
        .add("original_removed", e.original_removed)
        .add("removal_error", e.removal_error)
        .add("restored", e.restored)
        .add("restored_to", e.restored_to)
        .add("restored_at", e.restored_at);
    return j.str();
}

}  // namespace pg
