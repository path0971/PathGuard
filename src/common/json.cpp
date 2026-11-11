#include "common/json.h"

#include <cstdio>

namespace pg {
namespace {

bool cont(unsigned char c) { return (c & 0xC0) == 0x80; }

// Length of a well-formed UTF-8 sequence starting at p, or 0.
size_t utf8_len(const unsigned char* p, size_t n) {
    unsigned char c = p[0];
    if (c >= 0xC2 && c <= 0xDF) return (n >= 2 && cont(p[1])) ? 2 : 0;
    if (c >= 0xE0 && c <= 0xEF) {
        if (n < 3 || !cont(p[1]) || !cont(p[2])) return 0;
        if (c == 0xE0 && p[1] < 0xA0) return 0;  // overlong
        if (c == 0xED && p[1] > 0x9F) return 0;  // surrogates
        return 3;
    }
    if (c >= 0xF0 && c <= 0xF4) {
        if (n < 4 || !cont(p[1]) || !cont(p[2]) || !cont(p[3])) return 0;
        if (c == 0xF0 && p[1] < 0x90) return 0;
        if (c == 0xF4 && p[1] > 0x8F) return 0;
        return 4;
    }
    return 0;
}

void append_u(std::string& out, unsigned char c) {
    char b[8];
    snprintf(b, sizeof b, "\\u%04x", c);
    out += b;
}

}  // namespace

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    size_t n = s.size();
    for (size_t i = 0; i < n;) {
        unsigned char c = p[i];
        if (c < 0x80) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20 || c == 0x7f) append_u(out, c);
                    else out += static_cast<char>(c);
            }
            ++i;
            continue;
        }
        size_t len = utf8_len(p + i, n - i);
        if (len > 0) {
            out.append(reinterpret_cast<const char*>(p + i), len);
            i += len;
        } else {
            append_u(out, c);
            ++i;
        }
    }
    return out;
}

std::string json_str_array(const std::vector<std::string>& v) {
    std::vector<std::string> items;
    items.reserve(v.size());
    for (const auto& s : v) items.push_back(json_str(s));
    return json_array(items);
}

std::string json_array(const std::vector<std::string>& raw_items) {
    std::string out = "[";
    for (size_t i = 0; i < raw_items.size(); ++i) {
        if (i) out += ',';
        out += raw_items[i];
    }
    return out + "]";
}

}  // namespace pg
