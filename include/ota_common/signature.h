// Signature verification seam. The manifest is signed by the operator's admin
// key and verified against the node's trusted admin keys -- the same trust
// anchor Meshtastic already uses for remote admin (config.security.admin_key).
// There is NO central firmware signing key: the operator's admin device signs;
// the node accepts the update if the signature verifies against any of its
// (up to 3) admin public keys.
//
// On device the scheme is XEdDSA (Signal): a 64-byte Ed25519-form signature
// produced from a 32-byte Curve25519 admin keypair, verified via
// CryptoEngine::xeddsa_verify. Verification is injected so this core stays free
// of a bundled crypto library:
//   - main firmware: an admin-key XEdDSA verifier over CryptoEngine.
//   - standalone loader (bare IDF) and host: the self-contained
//   AdminKeyVerifier.
//   - host tests: a test verifier.
#pragma once

#include <cstddef>
#include <cstdint>

namespace ota_common {

// XEdDSA/Ed25519 signature is 64 bytes; a Curve25519 admin public key is 32.
inline constexpr size_t kSignaturePubLen = 32;
inline constexpr size_t kSignatureLen = 64;
// Backwards-compatible aliases (the sizes are identical for XEdDSA and
// Ed25519).
inline constexpr size_t kEd25519PubLen = kSignaturePubLen;
inline constexpr size_t kEd25519SigLen = kSignatureLen;

struct ISignatureVerifier {
  virtual ~ISignatureVerifier() = default;

  // Verify sig (kSignatureLen bytes) over msg. The trusted key(s) are held by
  // the implementation (the node's admin keys), not passed in by the caller,
  // so an attacker-supplied key can never be substituted.
  virtual bool verify(const uint8_t *msg, size_t msg_len, const uint8_t *sig,
                      size_t sig_len) const = 0;
};

} // namespace ota_common
