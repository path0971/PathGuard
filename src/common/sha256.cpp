#include "common/sha256.h"

#include <openssl/evp.h>

#include <cstdlib>

namespace pg {

Sha256::Sha256() : ctx_(EVP_MD_CTX_new()) {
    if (!ctx_) abort();
    reset();
}

Sha256::~Sha256() { EVP_MD_CTX_free(ctx_); }

void Sha256::reset() {
    if (EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr) != 1) abort();
}

void Sha256::update(const void* data, size_t len) {
    if (len > 0) EVP_DigestUpdate(ctx_, data, len);
}

std::string Sha256::hex_digest() {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n = 0;
    EVP_DigestFinal_ex(ctx_, md, &n);
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (unsigned int i = 0; i < n; ++i) {
        out += hex[md[i] >> 4];
        out += hex[md[i] & 0xf];
    }
    return out;
}

std::string sha256_hex(const void* data, size_t len) {
    Sha256 h;
    h.update(data, len);
    return h.hex_digest();
}

std::string sha256_hex(const std::string& data) { return sha256_hex(data.data(), data.size()); }

}  // namespace pg
