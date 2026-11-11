#pragma once

#include <string>
#include <type_traits>
#include <vector>

namespace pg {

// Escapes for a JSON string body. Bytes that are not valid UTF-8 (possible in
// Linux paths) are emitted as \u00XX so the output is always valid JSON.
std::string json_escape(const std::string& s);
inline std::string json_str(const std::string& s) { return "\"" + json_escape(s) + "\""; }
std::string json_str_array(const std::vector<std::string>& v);
std::string json_array(const std::vector<std::string>& raw_items);

class JsonObj {
public:
    JsonObj& raw(const char* key, const std::string& json) {
        if (!body_.empty()) body_ += ',';
        body_ += json_str(key);
        body_ += ':';
        body_ += json;
        return *this;
    }
    JsonObj& add(const char* key, const std::string& v) { return raw(key, json_str(v)); }
    JsonObj& add(const char* key, const char* v) { return raw(key, json_str(v ? v : "")); }
    JsonObj& add(const char* key, bool v) { return raw(key, v ? "true" : "false"); }
    template <typename T,
              typename std::enable_if<std::is_integral<T>::value && !std::is_same<T, bool>::value, int>::type = 0>
    JsonObj& add(const char* key, T v) {
        return raw(key, std::to_string(v));
    }
    std::string str() const { return "{" + body_ + "}"; }

private:
    std::string body_;
};

}  // namespace pg
