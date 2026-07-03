"""Build and inspect OTA update packages.

A package is: PackageHeader | Manifest | signature (64 B) | payload. The payload
is either a full image or a detools delta. The manifest carries the expected-base
identity (soft gate), the payload merkle root (incremental receive gate), and the
reconstructed-image SHA-256 (hard output gate).

Trust model: there is NO central firmware signing key. The packager emits an
UNSIGNED package (signature zeroed); the operator's admin device signs the
manifest with XEdDSA over its Curve25519 admin key, and the target node verifies
against its configured admin keys (config.security.admin_key) -- the same trust
anchor Meshtastic uses for remote admin. Use signing_buffer() to get the exact
bytes the admin device signs, and attach_signature() to splice the result in.
"""

from __future__ import annotations

import hashlib
import io
import struct
from dataclasses import dataclass

from . import merkle
from .formats import (
    MANIFEST_SIZE,
    PKG_HDR_SIZE,
    Manifest,
    Trailer,
    pack_package_header,
    unpack_package_header,
)

DEFAULT_BLOCK_SIZE = 1024
SIGNATURE_LEN = 64  # XEdDSA / Ed25519 signature size

# The dedicated OTA PortNum (meshtastic/protobufs#969). Used as the domain
# separator in the XEdDSA signing buffer so an OTA signature can never be
# replayed as some other admin action.
LORA_OTA_PORTNUM = 79

# heatshrink is the embedded-friendly compressor: the detools C decoder we
# vendor on-device supports it, and it shrinks bsdiff's mostly-zero diff array
# (which "none" would store at ~full image size). The in-place/CRLE variant is
# selected separately when that sink is wired up.
DEFAULT_COMPRESSION = "heatshrink"


def make_delta(base: bytes, target: bytes, compression: str = DEFAULT_COMPRESSION) -> bytes:
    """Produce a detools delta that reconstructs target from base.

    Decoder-only on device. The default sequential bsdiff format is applied in
    normal mode (separate base and destination); the in-place patch_type is
    selected at the sink for a single-slot apply.
    """
    import detools

    out = io.BytesIO()
    detools.create_patch(
        ffrom=io.BytesIO(base),
        fto=io.BytesIO(target),
        fpatch=out,
        compression=compression,
    )
    return out.getvalue()


def apply_delta(base: bytes, delta: bytes) -> bytes:
    import detools

    out = io.BytesIO()
    detools.apply_patch(
        ffrom=io.BytesIO(base),
        fpatch=io.BytesIO(delta),
        fto=out,
    )
    return out.getvalue()


def make_inplace_delta(
    base: bytes,
    target: bytes,
    memory_size: int,
    segment_size: int = 4096,
    compression: str = DEFAULT_COMPRESSION,
) -> bytes:
    """Produce an in-place detools patch (base == destination flash).

    memory_size is the flash region the in-place apply operates within (a
    multiple of segment_size, >= the target size with headroom); segment_size is
    the flash erase block (4 KiB on ESP32).
    """
    import detools

    out = io.BytesIO()
    detools.create_patch(
        ffrom=io.BytesIO(base),
        fto=io.BytesIO(target),
        fpatch=out,
        compression=compression,
        patch_type="in-place",
        memory_size=memory_size,
        segment_size=segment_size,
    )
    return out.getvalue()


def _build(
    *,
    env: str,
    base_version: str,
    base_commit: str,
    payload: bytes,
    output_image: bytes,
    is_delta: bool,
    block_size: int = DEFAULT_BLOCK_SIZE,
) -> bytes:
    leaves = merkle.leaves_for(payload, block_size)
    root = merkle.merkle_root(leaves)
    manifest = Manifest(
        env=env,
        base_version=base_version,
        base_commit=base_commit,
        block_size=block_size,
        block_count=len(leaves),
        payload_length=len(payload),
        payload_merkle_root=root,
        output_length=len(output_image),
        output_sha256=hashlib.sha256(output_image).digest(),
        is_delta=is_delta,
    )
    manifest_bytes = manifest.pack()
    signature = b"\x00" * SIGNATURE_LEN  # unsigned; the admin device fills this in

    buf = bytearray()
    buf += pack_package_header(len(manifest_bytes), len(signature))
    buf += manifest_bytes
    buf += signature
    buf += payload
    return bytes(buf)


def build_full_package(
    *,
    image: bytes,
    base_version: str,
    base_commit: str,
    env: str,
    block_size: int = DEFAULT_BLOCK_SIZE,
) -> bytes:
    """Unsigned full-image package: payload is the image itself (payload == output)."""
    return _build(
        env=env,
        base_version=base_version,
        base_commit=base_commit,
        payload=image,
        output_image=image,
        is_delta=False,
        block_size=block_size,
    )


def build_delta_package(
    *,
    base_image: bytes,
    target_image: bytes,
    base_version: str = "",
    base_commit: str = "",
    env: str = "",
    block_size: int = DEFAULT_BLOCK_SIZE,
) -> bytes:
    """Unsigned delta package: payload is a detools delta; output is the target.

    The base identity is taken from base_image's trailer when present, falling
    back to the explicit arguments.
    """
    try:
        tr = Trailer.from_image_tail(base_image)
        env = tr.env or env
        base_version = tr.version or base_version
        base_commit = tr.commit or base_commit
    except ValueError:
        pass

    delta = make_delta(base_image, target_image)
    if apply_delta(base_image, delta) != target_image:
        raise RuntimeError("delta self-check failed: apply(base, delta) != target")

    return _build(
        env=env,
        base_version=base_version,
        base_commit=base_commit,
        payload=delta,
        output_image=target_image,
        is_delta=True,
        block_size=block_size,
    )


# ---- signing helpers (the admin device does the actual XEdDSA sign) ----------


def manifest_bytes(buf: bytes) -> bytes:
    """The 192 manifest bytes of a package (the signed region)."""
    return buf[PKG_HDR_SIZE : PKG_HDR_SIZE + MANIFEST_SIZE]


def signing_buffer(manifest: bytes) -> bytes:
    """The exact bytes the admin device signs, matching the firmware's
    CryptoEngine::buildSigningBuffer(from=0, id=0, portnum=LORA_OTA_APP, payload).
    Little-endian u32 header + manifest bytes."""
    if len(manifest) != MANIFEST_SIZE:
        raise ValueError("expected the 192-byte manifest")
    return struct.pack("<III", 0, 0, LORA_OTA_PORTNUM) + manifest


def attach_signature(buf: bytes, signature: bytes) -> bytes:
    """Return the package with the 64-byte signature spliced into its slot."""
    if len(signature) != SIGNATURE_LEN:
        raise ValueError(f"expected a {SIGNATURE_LEN}-byte signature")
    off = PKG_HDR_SIZE + MANIFEST_SIZE
    return buf[:off] + bytes(signature) + buf[off + SIGNATURE_LEN :]


def is_signed(buf: bytes) -> bool:
    """A package is signed once its signature slot is non-zero."""
    return parse_package(buf).signature != b"\x00" * SIGNATURE_LEN


# ---- parse / integrity -------------------------------------------------------


@dataclass
class ParsedPackage:
    manifest: Manifest
    signature: bytes
    payload: bytes


def parse_package(buf: bytes) -> ParsedPackage:
    if len(buf) < PKG_HDR_SIZE:
        raise ValueError("package too small")
    mlen, slen = unpack_package_header(buf)
    if mlen != MANIFEST_SIZE:
        raise ValueError(f"unexpected manifest length {mlen}")
    if slen != SIGNATURE_LEN:
        raise ValueError(f"unexpected signature length {slen}")
    off = PKG_HDR_SIZE
    manifest = Manifest.unpack(buf[off : off + mlen])
    off += mlen
    signature = buf[off : off + slen]
    off += slen
    payload = buf[off:]
    if len(payload) != manifest.payload_length:
        raise ValueError("payload length mismatch")
    return ParsedPackage(manifest=manifest, signature=signature, payload=payload)


def verify_integrity(buf: bytes) -> ParsedPackage:
    """Non-cryptographic integrity: structure + payload merkle root + (full image)
    output hash. The signature is verified on-device against the admin keys, not
    here. Raises on any failure."""
    pkg = parse_package(buf)
    leaves = merkle.leaves_for(pkg.payload, pkg.manifest.block_size)
    if merkle.merkle_root(leaves) != pkg.manifest.payload_merkle_root:
        raise ValueError("payload merkle root mismatch")
    if not pkg.manifest.is_delta:
        if hashlib.sha256(pkg.payload).digest() != pkg.manifest.output_sha256:
            raise ValueError("full-image output hash mismatch")
    return pkg


def output_gate_ok(reconstructed: bytes, manifest: Manifest) -> bool:
    """Hard output gate: hash the reconstructed image vs the manifest."""
    if len(reconstructed) != manifest.output_length:
        return False
    return hashlib.sha256(reconstructed).digest() == manifest.output_sha256
