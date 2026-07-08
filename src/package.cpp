#include "ota_common/package.h"

#include <cstring>

namespace ota_common {

PackageError package_parse(const uint8_t *buf, size_t buf_len,
                           ParsedPackage &out) {
  out = ParsedPackage{};
  if (buf == nullptr || buf_len < sizeof(PackageHeader))
    return PackageError::TooSmall;

  const auto *hdr = reinterpret_cast<const PackageHeader *>(buf);
  if (hdr->magic != kPackageMagic)
    return PackageError::BadMagic;
  if (hdr->format != kPackageFormat)
    return PackageError::BadFormat;
  if (hdr->manifest_length != sizeof(Manifest))
    return PackageError::BadManifest;
  if (hdr->signature_length != kEd25519SigLen)
    return PackageError::BadManifest;

  // Compute section offsets with overflow-safe accumulation.
  size_t off = sizeof(PackageHeader);
  if (hdr->manifest_length > buf_len - off)
    return PackageError::LengthMismatch;
  const auto *manifest = reinterpret_cast<const Manifest *>(buf + off);
  off += hdr->manifest_length;

  if (hdr->signature_length > buf_len - off)
    return PackageError::LengthMismatch;
  const uint8_t *signature = buf + off;
  off += hdr->signature_length;

  // Remaining bytes are the payload; validate against the manifest's claim.
  const size_t payload_len = buf_len - off;
  if (manifest->magic != kManifestMagic)
    return PackageError::BadManifest;
  if (manifest->format != kManifestFormat)
    return PackageError::BadManifest;
  if (manifest->payload_length != payload_len)
    return PackageError::LengthMismatch;

  out.header = hdr;
  out.manifest = manifest;
  out.signature = signature;
  out.signature_len = hdr->signature_length;
  out.payload = (payload_len > 0) ? (buf + off) : nullptr;
  out.payload_len = payload_len;
  return PackageError::Ok;
}

bool package_verify_signature(const ParsedPackage &pkg,
                              const ISignatureVerifier &verifier) {
  if (pkg.manifest == nullptr || pkg.signature == nullptr)
    return false;
  return verifier.verify(reinterpret_cast<const uint8_t *>(pkg.manifest),
                         sizeof(Manifest), pkg.signature, pkg.signature_len);
}

static bool field_eq(const char *a, const char *b, size_t n) {
  return std::strncmp(a, b, n) == 0;
}

bool package_identity_matches(const Manifest &manifest,
                              const OtaTrailer &running) {
  return field_eq(manifest.env, running.env, kMEnvLen) &&
         field_eq(manifest.base_version, running.version, kMVersionLen) &&
         field_eq(manifest.base_commit, running.commit, kMCommitLen);
}

} // namespace ota_common
