#include "common/hashlist.h"

#include "common/sha256.h"
#include "common/util.h"

#include <cctype>

namespace pg {

bool load_hash_list(const std::string& path, HashList& out, std::string& err) {
    HashList list;
    if (path.empty()) {
        out = list;
        return true;
    }
    std::string text;
    if (!read_file(path, text, err)) return false;
    list.digest = sha256_hex(text);

    int lineno = 0;
    for (const auto& raw : split(text, '\n')) {
        ++lineno;
        std::string line = trim(raw);
        if (line.empty() || line[0] == '#') continue;
        size_t sp = line.find_first_of(" \t");
        std::string hash = line.substr(0, sp);
        std::string comment = sp == std::string::npos ? "" : trim(line.substr(sp));
        if (hash.size() != 64) {
            err = path + ":" + std::to_string(lineno) + ": expected a 64-character SHA-256 hex digest";
            return false;
        }
        for (char& ch : hash) {
            if (!isxdigit(static_cast<unsigned char>(ch))) {
                err = path + ":" + std::to_string(lineno) + ": invalid hex digit";
                return false;
            }
            ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
        }
        list.entries[hash] = comment;
    }
    out = std::move(list);
    return true;
}

}  // namespace pg
