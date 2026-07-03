"""Format parity: the Python structs must match the C++ sizes and the trailer
CRC must match the canonical check value the C++ test pins."""

import struct
import zlib

from packager.formats import (
    MANIFEST_SIZE,
    PKG_HDR_SIZE,
    TRAILER_SIZE,
    Manifest,
    Trailer,
    pack_package_header,
    unpack_package_header,
)


def test_sizes_match_cpp():
    assert TRAILER_SIZE == 172
    assert MANIFEST_SIZE == 192
    assert PKG_HDR_SIZE == 16


def test_crc32_known_vector():
    # The same value pinned in test_trailer.cpp test_crc32_known_vector.
    assert (zlib.crc32(b"123456789") & 0xFFFFFFFF) == 0xCBF43926


def test_trailer_roundtrip():
    tr = Trailer(
        env="heltec-v3",
        version="2.8.0.54e0d8d",
        commit="54e0d8d",
        repo="meshtastic/firmware",
        hw_vendor=9,
        image_length=0x1234,
    )
    blob = tr.pack()
    assert len(blob) == TRAILER_SIZE
    back = Trailer.unpack(blob)
    assert back.env == "heltec-v3"
    assert back.version == "2.8.0.54e0d8d"
    assert back.commit == "54e0d8d"
    assert back.repo == "meshtastic/firmware"
    assert back.hw_vendor == 9
    assert back.image_length == 0x1234


def test_trailer_magic_at_offset_zero():
    blob = Trailer(env="e", version="v", commit="c").pack()
    (magic,) = struct.unpack("<I", blob[:4])
    assert magic == 0x4F544231  # "OTB1"


def test_trailer_crc_tamper_detected():
    blob = bytearray(Trailer(env="e", version="v", commit="c").pack())
    blob[10] ^= 0x01
    try:
        Trailer.unpack(bytes(blob))
        assert False, "expected crc mismatch"
    except ValueError:
        pass


def test_field_overlong_is_truncated_with_nul():
    long_env = "x" * 100
    tr = Trailer(env=long_env, version="v", commit="c")
    back = Trailer.unpack(tr.pack())
    assert len(back.env) == 31  # 32-byte field, always NUL-terminated
    assert back.env == "x" * 31


def test_manifest_roundtrip():
    m = Manifest(
        env="tbeam",
        base_version="2.8.0.abc1234",
        base_commit="abc1234",
        block_size=1024,
        block_count=5,
        payload_length=4500,
        payload_merkle_root=b"\x11" * 32,
        output_length=4500,
        output_sha256=b"\x22" * 32,
        is_delta=True,
    )
    back = Manifest.unpack(m.pack())
    assert back == m


def test_package_header_roundtrip():
    hdr = pack_package_header(192, 64)
    assert len(hdr) == PKG_HDR_SIZE
    assert unpack_package_header(hdr) == (192, 64)
