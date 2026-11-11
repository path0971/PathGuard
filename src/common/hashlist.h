#pragma once

#include <string>
#include <unordered_map>

namespace pg {

// SHA-256 list file: one "<64 hex chars> [comment]" per line, '#' starts a comment line.
struct HashList {
    std::unordered_map<std::string, std::string> entries;  // lowercase hash -> comment
    std::string digest;                                    // sha256 of the file content ("" if no file)

    size_t size() const { return entries.size(); }
    const std::string* find(const std::string& sha256) const {
        auto it = entries.find(sha256);
        return it == entries.end() ? nullptr : &it->second;
    }
};

// An empty path yields an empty list. A configured but missing file is an error.
bool load_hash_list(const std::string& path, HashList& out, std::string& err);

}  // namespace pg
