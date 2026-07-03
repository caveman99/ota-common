// Update package container: header + manifest + signature + payload. Parsing is
// bounds-checked and read-only; the device never trusts the bytes until the
// signature verifies over the manifest and the manifest's payload merkle root
// matches the received blocks.
#pragma once

#include <cstddef>
#include <cstdint>

#include "ota_common/manifest.h"
#include "ota_common/signature.h"
#include "ota_common/trailer.h"

namespace ota_common {

inline constexpr uint32_t kPackageMagic = 0x41544F4Du; // "MOTA"
inline constexpr uint16_t kPackageFormat = 1;

// On-the-wire container header. Followed by manifest_length manifest bytes,
// signature_length signature bytes, then payload_length payload bytes.
struct PackageHeader {
    uint32_t magic;            // 0:  kPackageMagic
    uint16_t format;           // 4:  kPackageFormat
    uint16_t flags;            // 6:  reserved, 0
    uint32_t manifest_length;  // 8:  bytes of manifest (== sizeof(Manifest))
    uint32_t signature_length; // 12: bytes of signature (== kEd25519SigLen)
};

static_assert(sizeof(PackageHeader) == 16, "PackageHeader must be 16 bytes");

enum class PackageError {
    Ok,
    TooSmall,
    BadMagic,
    BadFormat,
    BadManifest,
    LengthMismatch,
};

// Read-only views into a caller-owned package buffer. No allocation, no copy.
struct ParsedPackage {
    const PackageHeader* header = nullptr;
    const Manifest* manifest = nullptr;
    const uint8_t* signature = nullptr;
    size_t signature_len = 0;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
};

// Bounds-checked structural parse. Validates magics, formats, and that the
// declared section lengths fit within buf_len. Does NOT verify the signature
// or merkle root -- call package_verify_signature and the merkle helpers next.
PackageError package_parse(const uint8_t* buf, size_t buf_len, ParsedPackage& out);

// Verify the Ed25519 signature over the manifest bytes using the injected
// verifier. Returns true only on a valid signature.
bool package_verify_signature(const ParsedPackage& pkg, const ISignatureVerifier& verifier);

// Soft identity gate: the manifest's expected base (env/version/commit) must
// equal the running firmware's trailer. Refuses a wrong delta before any write.
bool package_identity_matches(const Manifest& manifest, const OtaTrailer& running);

} // namespace ota_common
