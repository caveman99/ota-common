"""Reference XEdDSA signer for the OTA manifest.

This is the logic the operator's admin device / CLI must implement: sign the
manifest with the admin's Curve25519 private key so a target node accepts the
update when the signature verifies against its config.security.admin_key[]. The
private key is Meshtastic's node private key (config.security.private_key, 32
raw bytes).

It matches the firmware exactly:
  - key: ed scalar = clamp(curve_priv), sign-0 normalized
    (CryptoEngine -> XEdDSA::priv_curve_to_ed_keys), the admin public key is the
    node's X25519 public (Curve25519::dh1).
  - message: buildSigningBuffer(from=0, id=0, portnum=LORA_OTA_APP) + manifest.

`xeddsa` (the Python package) is imported lazily so importing the packager for
trailer/build work stays dependency-free.
"""

from __future__ import annotations

from . import package


def _clamp(curve_priv: bytes) -> bytes:
    if len(curve_priv) != 32:
        raise ValueError("curve private key must be 32 bytes")
    a = bytearray(curve_priv)
    a[0] &= 0xF8
    a[31] &= 0x7F
    a[31] |= 0x40
    return bytes(a)


def admin_public_key(curve_priv: bytes) -> bytes:
    """The 32-byte Curve25519 public key (what goes in admin_key[]) for a node
    private key. Equals Meshtastic's Curve25519::dh1(private_key)."""
    import xeddsa

    return bytes(xeddsa.priv_to_curve25519_pub(xeddsa.Priv(_clamp(curve_priv))))


def sign_signing_buffer(to_sign: bytes, curve_priv: bytes, nonce: bytes | None = None) -> bytes:
    """XEdDSA-sign already-built signing-buffer bytes; returns a 64-byte sig.
    nonce is the 64-byte XEdDSA Z (random when None; pass a fixed value only for
    deterministic tests/fixtures)."""
    import xeddsa

    priv = xeddsa.priv_force_sign(xeddsa.Priv(_clamp(curve_priv)), False)
    n = xeddsa.Nonce(nonce) if nonce is not None else None
    return bytes(xeddsa.ed25519_priv_sign(priv, to_sign, n))


def sign_package(package_bytes: bytes, curve_priv: bytes, nonce: bytes | None = None) -> bytes:
    """Sign an (unsigned) package's manifest and return the signed package."""
    to_sign = package.signing_buffer(package.manifest_bytes(package_bytes))
    sig = sign_signing_buffer(to_sign, curve_priv, nonce=nonce)
    return package.attach_signature(package_bytes, sig)
