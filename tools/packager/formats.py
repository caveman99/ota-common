"""Binary layouts for the OTA self-identity trailer and update package.

These mirror the C++ definitions in ota-common/include/ota_common byte-for-byte.
The struct format strings and the unit tests in tests/ are what keep the two
sides in lockstep; see docs/guide.md (Wire format reference).
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

# ----------------------------------------------------------------------------
# Self-identity trailer (172 bytes). See trailer.h / docs/guide.md.
# ----------------------------------------------------------------------------

TRAILER_MAGIC = 0x4F544231  # "OTB1"
TRAILER_FORMAT = 1

ENV_LEN = 32
VERSION_LEN = 48
COMMIT_LEN = 16
REPO_LEN = 48

# magic, format, flags, env, version, commit, repo, hw_vendor, image_length,
# reserved0, reserved1, crc32
_TRAILER_FMT = f"<IHH{ENV_LEN}s{VERSION_LEN}s{COMMIT_LEN}s{REPO_LEN}sIIIII"
TRAILER_SIZE = struct.calcsize(_TRAILER_FMT)
assert TRAILER_SIZE == 172, TRAILER_SIZE


def _fixed(s: str, n: int) -> bytes:
    b = s.encode("utf-8")
    if len(b) >= n:
        return b[: n - 1] + b"\x00"  # always leave room for a NUL terminator
    return b + b"\x00" * (n - len(b))


def _cstr(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("utf-8", "replace")


@dataclass
class Trailer:
    env: str
    version: str
    commit: str
    repo: str = ""
    hw_vendor: int = 0
    image_length: int = 0
    flags: int = 0

    def pack(self) -> bytes:
        body = struct.pack(
            _TRAILER_FMT,
            TRAILER_MAGIC,
            TRAILER_FORMAT,
            self.flags,
            _fixed(self.env, ENV_LEN),
            _fixed(self.version, VERSION_LEN),
            _fixed(self.commit, COMMIT_LEN),
            _fixed(self.repo, REPO_LEN),
            self.hw_vendor,
            self.image_length,
            0,
            0,
            0,  # placeholder crc32
        )
        crc = zlib.crc32(body[:-4]) & 0xFFFFFFFF
        return body[:-4] + struct.pack("<I", crc)

    @staticmethod
    def unpack(data: bytes) -> "Trailer":
        if len(data) < TRAILER_SIZE:
            raise ValueError("trailer buffer too small")
        chunk = data[:TRAILER_SIZE]
        fields = struct.unpack(_TRAILER_FMT, chunk)
        (
            magic,
            fmt,
            flags,
            env,
            version,
            commit,
            repo,
            hw_vendor,
            image_len,
            _r0,
            _r1,
            crc,
        ) = fields
        if magic != TRAILER_MAGIC:
            raise ValueError(f"bad trailer magic 0x{magic:08x}")
        if fmt != TRAILER_FORMAT:
            raise ValueError(f"unsupported trailer format {fmt}")
        expect = zlib.crc32(chunk[:-4]) & 0xFFFFFFFF
        if expect != crc:
            raise ValueError("trailer crc mismatch")
        return Trailer(
            env=_cstr(env),
            version=_cstr(version),
            commit=_cstr(commit),
            repo=_cstr(repo),
            hw_vendor=hw_vendor,
            image_length=image_len,
            flags=flags,
        )

    @staticmethod
    def from_image_tail(image: bytes) -> "Trailer":
        return Trailer.unpack(image[-TRAILER_SIZE:])


# ----------------------------------------------------------------------------
# Manifest (192 bytes) + package header (16 bytes). See package.h.
# ----------------------------------------------------------------------------

MANIFEST_MAGIC = 0x4E414D4D  # "MMAN"
MANIFEST_FORMAT = 1
MANIFEST_FLAG_DELTA = 0x0001

# magic, format, flags, env, base_version, base_commit, block_size, block_count,
# payload_length, payload_merkle_root[32], output_length, output_sha256[32],
# reserved0, reserved1
_MANIFEST_FMT = f"<IHH{ENV_LEN}s{VERSION_LEN}s{COMMIT_LEN}sIII32sI32sII"
MANIFEST_SIZE = struct.calcsize(_MANIFEST_FMT)
assert MANIFEST_SIZE == 192, MANIFEST_SIZE

PACKAGE_MAGIC = 0x41544F4D  # "MOTA"
PACKAGE_FORMAT = 1

_PKG_HDR_FMT = "<IHHII"
PKG_HDR_SIZE = struct.calcsize(_PKG_HDR_FMT)
assert PKG_HDR_SIZE == 16, PKG_HDR_SIZE


@dataclass
class Manifest:
    env: str
    base_version: str
    base_commit: str
    block_size: int
    block_count: int
    payload_length: int
    payload_merkle_root: bytes
    output_length: int
    output_sha256: bytes
    is_delta: bool

    def pack(self) -> bytes:
        assert len(self.payload_merkle_root) == 32
        assert len(self.output_sha256) == 32
        flags = MANIFEST_FLAG_DELTA if self.is_delta else 0
        return struct.pack(
            _MANIFEST_FMT,
            MANIFEST_MAGIC,
            MANIFEST_FORMAT,
            flags,
            _fixed(self.env, ENV_LEN),
            _fixed(self.base_version, VERSION_LEN),
            _fixed(self.base_commit, COMMIT_LEN),
            self.block_size,
            self.block_count,
            self.payload_length,
            self.payload_merkle_root,
            self.output_length,
            self.output_sha256,
            0,
            0,
        )

    @staticmethod
    def unpack(data: bytes) -> "Manifest":
        fields = struct.unpack(_MANIFEST_FMT, data[:MANIFEST_SIZE])
        (
            magic,
            fmt,
            flags,
            env,
            ver,
            commit,
            bs,
            bc,
            plen,
            root,
            olen,
            osha,
            _r0,
            _r1,
        ) = fields
        if magic != MANIFEST_MAGIC:
            raise ValueError(f"bad manifest magic 0x{magic:08x}")
        if fmt != MANIFEST_FORMAT:
            raise ValueError(f"unsupported manifest format {fmt}")
        return Manifest(
            env=_cstr(env),
            base_version=_cstr(ver),
            base_commit=_cstr(commit),
            block_size=bs,
            block_count=bc,
            payload_length=plen,
            payload_merkle_root=root,
            output_length=olen,
            output_sha256=osha,
            is_delta=bool(flags & MANIFEST_FLAG_DELTA),
        )


def pack_package_header(manifest_len: int, signature_len: int) -> bytes:
    return struct.pack(
        _PKG_HDR_FMT, PACKAGE_MAGIC, PACKAGE_FORMAT, 0, manifest_len, signature_len
    )


def unpack_package_header(data: bytes):
    magic, fmt, flags, mlen, slen = struct.unpack(_PKG_HDR_FMT, data[:PKG_HDR_SIZE])
    if magic != PACKAGE_MAGIC:
        raise ValueError(f"bad package magic 0x{magic:08x}")
    if fmt != PACKAGE_FORMAT:
        raise ValueError(f"unsupported package format {fmt}")
    return mlen, slen
