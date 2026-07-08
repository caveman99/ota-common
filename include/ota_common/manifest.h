// Update package manifest: the signed description of one firmware update. See
// docs/guide.md (Wire format reference) for the authoritative byte layout. The
// Python packager produces these; the device parses them read-only.
#pragma once

#include <cstddef>
#include <cstdint>

#include "ota_common/sha256.h"

namespace ota_common {

inline constexpr uint32_t kManifestMagic =
    0x4E414D4Du; // "MMAN" (little-endian on the wire)
inline constexpr uint16_t kManifestFormat = 1;

inline constexpr uint16_t kManifestFlagDelta =
    0x0001; // payload is a detools delta

inline constexpr size_t kMEnvLen = 32;
inline constexpr size_t kMVersionLen = 48;
inline constexpr size_t kMCommitLen = 16;

// Fixed binary layout, 4-byte aligned throughout (no 8-byte members), so it is
// 192 bytes with no padding and parses identically on host and device.
struct Manifest {
  uint32_t magic;  // 0:   kManifestMagic
  uint16_t format; // 4:   kManifestFormat
  uint16_t flags;  // 6:   kManifestFlag*
  // Expected base identity (soft gate) -- must equal the target's trailer.
  char env[kMEnvLen];              // 8
  char base_version[kMVersionLen]; // 40
  char base_commit[kMCommitLen];   // 88
  // Transmitted payload (delta or full image), verified incrementally.
  uint32_t block_size;     // 104: merkle/transport block size
  uint32_t block_count;    // 108: number of payload blocks
  uint32_t payload_length; // 112: payload bytes following the signature
  uint8_t payload_merkle_root[kSha256Len]; // 116: root over payload blocks
  // Reconstructed output image (hard gate, applied after detools).
  uint32_t output_length;            // 148
  uint8_t output_sha256[kSha256Len]; // 152: hash of the full output image
  uint32_t reserved0;                // 184
  uint32_t reserved1;                // 188
};

static_assert(sizeof(Manifest) == 192, "Manifest layout must be 192 bytes");

inline bool manifest_is_delta(const Manifest &m) {
  return (m.flags & kManifestFlagDelta) != 0;
}

} // namespace ota_common
