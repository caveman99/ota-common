// Self-contained XEdDSA (Signal) signature verification, built on the vendored
// TweetNaCl. Mirrors the firmware's CryptoEngine::xeddsa_verify so a signature
// the admin device produces verifies identically here (host tests, and the
// bare-IDF Path A loader which has no CryptoEngine).
#pragma once

#include <cstddef>
#include <cstdint>

namespace ota_common {

// The OTA domain-separation portnum (LORA_OTA_APP = 79), used in the signing
// buffer so an OTA signature cannot be replayed as another admin action.
inline constexpr uint32_t kOtaPortnum = 79;

// Longest payload the verifier will build a signing buffer for (manifest = 192).
inline constexpr size_t kXeddsaMaxPayload = 244; // 12-byte header + 244 <= 256

// Verify an XEdDSA signature `sig` (64 bytes) against the Curve25519 public key
// `curve_pub` (32 bytes), over the signing buffer that the firmware's
// buildSigningBuffer produces: little-endian [from][id][portnum] + payload.
bool xeddsa_verify(const uint8_t curve_pub[32], uint32_t from, uint32_t id, uint32_t portnum,
                   const uint8_t* payload, size_t payload_len, const uint8_t sig[64]);

} // namespace ota_common
