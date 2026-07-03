// Manifest signature verifier bound to a node's admin keys, self-contained via
// the vendored XEdDSA. Accepts the update if the manifest signature verifies
// against ANY held admin key (Curve25519), using the fleet-wide OTA convention
// (from=0, id=0, portnum=LORA_OTA_APP). Fail closed: no keys -> reject.
//
// For the standalone loader (which has no CryptoEngine): the admin keys are
// handed to it (e.g. via the reboot-to-loader NVS handoff) and added here. The
// main firmware uses its own CryptoEngine-backed verifier instead, to avoid
// bundling a second crypto implementation.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "ota_common/signature.h"
#include "ota_common/xeddsa.h"

namespace ota_common {

class AdminKeyVerifier final : public ISignatureVerifier {
public:
    static constexpr size_t kMaxKeys = 3;

    // Add a 32-byte Curve25519 admin public key. Returns false if full.
    bool add_key(const uint8_t* key32) {
        if (count_ >= kMaxKeys) return false;
        std::memcpy(keys_[count_++], key32, kSignaturePubLen);
        return true;
    }

    size_t key_count() const { return count_; }

    bool verify(const uint8_t* msg, size_t msg_len, const uint8_t* sig,
                size_t sig_len) const override {
        if (sig_len != kSignatureLen || count_ == 0) return false; // fail closed
        for (size_t i = 0; i < count_; ++i) {
            if (xeddsa_verify(keys_[i], /*from=*/0, /*id=*/0, kOtaPortnum, msg, msg_len, sig))
                return true;
        }
        return false;
    }

private:
    uint8_t keys_[kMaxKeys][kSignaturePubLen];
    size_t count_ = 0;
};

} // namespace ota_common
