"""Reference XEdDSA signer: signs a package with a node curve private key
(Meshtastic model) and the result verifies under the derived admin public key."""

import struct

import pytest

xeddsa = pytest.importorskip("xeddsa")

from packager import package, sign  # noqa: E402


def _img(n, seed):
    b = bytearray(n)
    x = seed
    for i in range(n):
        x = (1103515245 * x + 12345) & 0xFFFFFFFF
        b[i] = (x >> 16) & 0xFF
    return bytes(b)


NODE_PRIV = bytes(range(2, 34))  # a 32-byte node curve private key


def test_admin_public_key_matches_x25519():
    base = bytes([9]) + bytes(31)
    dh = bytes(xeddsa.x25519(xeddsa.Priv(NODE_PRIV), xeddsa.Curve25519Pub(base)))
    assert sign.admin_public_key(NODE_PRIV) == dh


def test_sign_package_verifies():
    pkg = package.build_full_package(
        image=_img(3000, 9), base_version="v", base_commit="c", env="e"
    )
    assert not package.is_signed(pkg)
    signed = sign.sign_package(pkg, NODE_PRIV)
    assert package.is_signed(signed)

    # The signature verifies under the derived admin public key, via the
    # mont->ed(sign0) path the device uses.
    parsed = package.parse_package(signed)
    to_sign = package.signing_buffer(package.manifest_bytes(signed))
    admin_pub = sign.admin_public_key(NODE_PRIV)
    ed = xeddsa.curve25519_pub_to_ed25519_pub(xeddsa.Curve25519Pub(admin_pub), False)
    assert xeddsa.ed25519_verify(parsed.signature, ed, to_sign)


def test_tampered_manifest_breaks_signature():
    pkg = package.build_full_package(
        image=_img(2000, 3), base_version="v", base_commit="c", env="e"
    )
    signed = bytearray(sign.sign_package(pkg, NODE_PRIV))
    signed[16 + 40] ^= 0x01  # a byte inside the manifest
    parsed = package.parse_package(bytes(signed))
    to_sign = package.signing_buffer(package.manifest_bytes(bytes(signed)))
    admin_pub = sign.admin_public_key(NODE_PRIV)
    ed = xeddsa.curve25519_pub_to_ed25519_pub(xeddsa.Curve25519Pub(admin_pub), False)
    assert not xeddsa.ed25519_verify(parsed.signature, ed, to_sign)


def test_signing_buffer_domain():
    pkg = package.build_full_package(image=_img(100, 1), base_version="v", base_commit="c", env="e")
    sb = package.signing_buffer(package.manifest_bytes(pkg))
    assert sb[:12] == struct.pack("<III", 0, 0, 79)  # from=0, id=0, portnum=LORA_OTA_APP


def test_clamp_is_idempotent():
    once = sign._clamp(NODE_PRIV)
    assert sign._clamp(once) == once
    assert sign.admin_public_key(once) == sign.admin_public_key(NODE_PRIV)
