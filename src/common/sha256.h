#pragma once

#include <cstddef>
#include <string>

typedef struct evp_md_ctx_st EVP_MD_CTX;

namespace pg {

// SHA-256 via OpenSSL libcrypto (uses SHA-NI / AVX2 when the CPU has them).
class Sha256 {
public:
    Sha256();
    ~Sha256();
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;

    void reset();
    void update(const void* data, size_t len);
    std::string hex_digest();  // finalizes; call reset() before reuse

private:
    EVP_MD_CTX* ctx_;
};

std::string sha256_hex(const void* data, size_t len);
std::string sha256_hex(const std::string& data);

}  // namespace pg
