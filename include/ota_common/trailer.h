// Self-identity trailer: a fixed-layout structure appended to every firmware
// image at build time. See docs/guide.md (Wire format reference) for the spec.
//
// Framework-agnostic: no Arduino, no ESP-IDF. Compiles on host and device.
#pragma once

#include <cstddef>
#include <cstdint>

namespace ota_common {

inline constexpr uint32_t kTrailerMagic = 0x4F544231u; // "OTB1"
inline constexpr uint16_t kTrailerFormat = 1;

inline constexpr size_t kEnvLen = 32;
inline constexpr size_t kVersionLen = 48;
inline constexpr size_t kCommitLen = 16;
inline constexpr size_t kRepoLen = 48;

// Little-endian on every target we build for (xtensa, riscv, x86_64). The
// field order keeps every member naturally aligned with the maximum alignment
// at 4 bytes, so the struct is exactly 172 bytes with no trailing padding and
// no packing pragma is needed. (A uint64_t length would force 8-byte alignment
// and pad the tail to 176; a uint32_t length is ample for sub-4GB images.)
struct OtaTrailer {
    uint32_t magic;                // 0:   kTrailerMagic
    uint16_t format;               // 4:   kTrailerFormat
    uint16_t flags;                // 6:   reserved, 0
    char     env[kEnvLen];         // 8:   APP_ENV / PIOENV
    char     version[kVersionLen]; // 40:  APP_VERSION long, e.g. "2.8.0.54e0d8d"
    char     commit[kCommitLen];   // 88:  git short SHA
    char     repo[kRepoLen];       // 104: APP_REPO owner/name
    uint32_t hw_vendor;            // 152: HardwareModel id
    uint32_t image_length;         // 156: bytes of image preceding the trailer
    uint32_t reserved0;            // 160: reserved, 0
    uint32_t reserved1;            // 164: reserved, 0
    uint32_t crc32;                // 168: CRC-32 over the first (sizeof - 4) bytes
};

static_assert(sizeof(OtaTrailer) == 172, "OtaTrailer layout must be 172 bytes");

// CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320, init/xor 0xFFFFFFFF).
uint32_t crc32_ieee(const uint8_t* data, size_t len);

// Validate magic, format, and crc32 of a trailer-sized buffer.
bool trailer_is_valid(const OtaTrailer& t);

// Recompute and store crc32 over the populated fields. Used by host tooling /
// tests; the firmware build hook produces the same bytes in Python.
void trailer_finalize(OtaTrailer& t);

// Parse the trailer from the final sizeof(OtaTrailer) bytes of a whole image
// buffer (host / whole-.bin path). Returns false if too small or invalid.
bool trailer_from_image_tail(const uint8_t* image, size_t image_len, OtaTrailer& out);

// Identity comparison for the soft gate: env, version and commit must match.
// repo / hw_vendor are informational and not part of the gate.
bool trailer_identity_equal(const OtaTrailer& a, const OtaTrailer& b);

} // namespace ota_common
