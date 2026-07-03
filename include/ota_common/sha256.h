// Self-contained SHA-256. Framework-agnostic, no external crypto dependency, so
// the merkle/verify core builds and unit-tests on host without mbedtls. The
// device may use this directly; throughput is ample for verifying KB-scale
// deltas and MB-scale images.
#pragma once

#include <cstddef>
#include <cstdint>

namespace ota_common {

inline constexpr size_t kSha256Len = 32;

class Sha256 {
public:
    Sha256() { reset(); }
    void reset();
    void update(const uint8_t* data, size_t len);
    // Writes kSha256Len bytes to out. The object must be reset() before reuse.
    void finish(uint8_t out[kSha256Len]);

    // One-shot helper.
    static void hash(const uint8_t* data, size_t len, uint8_t out[kSha256Len]);

private:
    void process(const uint8_t block[64]);

    uint32_t state_[8];
    uint64_t bitlen_;
    uint8_t buf_[64];
    size_t buflen_;
};

} // namespace ota_common
