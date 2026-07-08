"""Packager acceptance (unsigned packages; the admin device signs on-device):
- apply(base, delta) == full, byte for byte
- a wrong-base apply fails the output gate
- integrity (structure + merkle + output hash) holds; tampering is caught
- the sign/attach helpers round-trip and match the firmware signing buffer
"""

import hashlib
import struct

import pytest
from packager import merkle, package
from packager.trailer_tool import append_trailer


def _img(n, seed):
    b = bytearray(n)
    x = seed
    for i in range(n):
        x = (1103515245 * x + 12345) & 0xFFFFFFFF
        b[i] = (x >> 16) & 0xFF
    return bytes(b)


def _target_from(base):
    t = bytearray(base)
    for i in range(1000, 1200):
        t[i] ^= 0x5A
    t += b"appended-section" * 8
    return bytes(t)


def test_full_package_roundtrip():
    image = _img(8000, 42)
    pkg = package.build_full_package(
        image=image,
        base_version="2.8.0.abc1234",
        base_commit="abc1234",
        env="heltec-v3",
    )
    parsed = package.verify_integrity(pkg)  # merkle + output hash
    assert not parsed.manifest.is_delta
    assert parsed.payload == image
    assert parsed.manifest.output_sha256 == hashlib.sha256(image).digest()
    assert not package.is_signed(pkg)  # emitted unsigned


def test_delta_roundtrip_and_apply():
    base = append_trailer(
        _img(8000, 7), env="heltec-v3", version="2.8.0.abc1234", commit="abc1234"
    )
    target = _target_from(base)
    pkg = package.build_delta_package(base_image=base, target_image=target)
    parsed = package.verify_integrity(pkg)
    assert parsed.manifest.is_delta
    # Identity lifted from the base trailer.
    assert parsed.manifest.env == "heltec-v3"
    assert parsed.manifest.base_commit == "abc1234"

    reconstructed = package.apply_delta(base, parsed.payload)
    assert reconstructed == target
    assert package.output_gate_ok(reconstructed, parsed.manifest)


def test_delta_is_smaller_than_full():
    base = _img(20000, 11)
    target = _target_from(base)
    pkg = package.build_delta_package(
        base_image=base, target_image=target, base_version="v", base_commit="c", env="e"
    )
    parsed = package.parse_package(pkg)
    assert parsed.manifest.payload_length < len(target)


def test_wrong_base_fails_output_gate():
    base = _img(8000, 7)
    target = _target_from(base)
    pkg = package.build_delta_package(
        base_image=base, target_image=target, base_version="v", base_commit="c", env="e"
    )
    parsed = package.parse_package(pkg)
    wrong_base = _img(8000, 999)
    try:
        reconstructed = package.apply_delta(wrong_base, parsed.payload)
    except Exception:
        return  # apply rejected the wrong base outright -- acceptable
    assert not package.output_gate_ok(reconstructed, parsed.manifest)


def test_tampered_payload_rejected_by_merkle():
    image = _img(5000, 5)
    pkg = bytearray(
        package.build_full_package(
            image=image, base_version="v", base_commit="c", env="e"
        )
    )
    # Corrupt a payload byte (after header + manifest + signature).
    payload_off = 16 + 192 + 64
    pkg[payload_off + 100] ^= 0xFF
    with pytest.raises(ValueError):
        package.verify_integrity(bytes(pkg))


def test_payload_blocks_verify_against_root():
    image = _img(4096 + 300, 5)
    pkg = package.build_full_package(
        image=image, base_version="v", base_commit="c", env="e"
    )
    parsed = package.parse_package(pkg)
    bs = parsed.manifest.block_size
    leaves = merkle.leaves_for(parsed.payload, bs)
    root = parsed.manifest.payload_merkle_root
    assert len(leaves) == parsed.manifest.block_count
    for i in range(len(leaves)):
        off = i * bs
        block = parsed.payload[off : off + bs]
        proof = merkle.merkle_proof(leaves, i)
        assert merkle.merkle_verify(
            merkle.hash_leaf(block), i, len(leaves), proof, root
        )


def test_signing_buffer_matches_firmware_convention():
    image = _img(1000, 3)
    pkg = package.build_full_package(
        image=image, base_version="v", base_commit="c", env="e"
    )
    mbytes = package.manifest_bytes(pkg)
    assert len(mbytes) == 192
    sb = package.signing_buffer(mbytes)
    # from=0, id=0, portnum=LORA_OTA_APP(79), then the manifest -- exactly what
    # CryptoEngine::buildSigningBuffer produces on device.
    assert sb[:12] == struct.pack("<III", 0, 0, 79)
    assert sb[12:] == mbytes


def test_attach_signature_roundtrip():
    image = _img(1000, 4)
    pkg = package.build_full_package(
        image=image, base_version="v", base_commit="c", env="e"
    )
    assert not package.is_signed(pkg)
    sig = bytes(range(64))
    signed = package.attach_signature(pkg, sig)
    assert package.is_signed(signed)
    assert package.parse_package(signed).signature == sig
    # Attaching a signature must not disturb the manifest or payload.
    assert package.manifest_bytes(signed) == package.manifest_bytes(pkg)
    assert package.parse_package(signed).payload == package.parse_package(pkg).payload
