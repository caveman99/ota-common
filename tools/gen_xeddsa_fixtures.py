#!/usr/bin/env python3
"""Generate XEdDSA interop fixtures: a signature the Python `xeddsa` package
produces (an independent Signal-XEdDSA implementation), which the vendored
ota-common verifier must accept. Deterministic (fixed seed + nonce).

    tools/.venv/bin/python tools/gen_xeddsa_fixtures.py

Convention matches the firmware: the signed bytes are the buildSigningBuffer
[from=0][id=0][portnum=79] (little-endian) + payload. We store only the payload;
the C++ verifier rebuilds the header.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import xeddsa

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from packager import package, sign  # noqa: E402

FIX = ROOT / "test" / "fixtures"
LORA_OTA_PORTNUM = 79


def keypair(seed: bytes):
    priv = xeddsa.seed_to_priv(xeddsa.Seed(seed))
    admin_pub = bytes(xeddsa.priv_to_curve25519_pub(priv))
    signing_priv = xeddsa.priv_force_sign(priv, False)  # XEdDSA: sign-0 normalize
    return priv, admin_pub, signing_priv


def main() -> int:
    FIX.mkdir(parents=True, exist_ok=True)

    _, admin_pub, signing_priv = keypair(bytes(range(32)))
    payload = bytes((i * 7 + 3) & 0xFF for i in range(192))  # manifest-sized blob
    to_sign = struct.pack("<III", 0, 0, LORA_OTA_PORTNUM) + payload
    nonce = xeddsa.Nonce(bytes(64))  # fixed -> deterministic
    sig = bytes(xeddsa.ed25519_priv_sign(signing_priv, to_sign, nonce))

    # Self-check against the package's own verify via the mont->ed path.
    ed = xeddsa.curve25519_pub_to_ed25519_pub(xeddsa.Curve25519Pub(admin_pub), False)
    if not xeddsa.ed25519_verify(sig, ed, to_sign):
        print("ERROR: package self-verify failed", file=sys.stderr)
        return 1

    # A second, unrelated admin key for the wrong-key negative test.
    _, other_pub, _ = keypair(bytes([0x5A]) * 32)

    (FIX / "xeddsa_admin_pub.bin").write_bytes(admin_pub)
    (FIX / "xeddsa_other_pub.bin").write_bytes(other_pub)
    (FIX / "xeddsa_payload.bin").write_bytes(payload)
    (FIX / "xeddsa_sig.bin").write_bytes(sig)

    # Full pipeline: a real package built by the packager, signed by the
    # reference signer with a node curve private key (Meshtastic's key model),
    # verified in C++ against the derived admin public key.
    node_priv = bytes([0x11]) * 32
    signed_admin_pub = sign.admin_public_key(node_priv)
    image = bytes((i * 3 + 1) & 0xFF for i in range(2500))
    pkg = package.build_full_package(
        image=image, base_version="2.8.0.abc1234", base_commit="abc1234", env="heltec-v3"
    )
    signed_pkg = sign.sign_package(pkg, node_priv, nonce=bytes(64))  # fixed nonce -> deterministic
    (FIX / "signed_package.bin").write_bytes(signed_pkg)
    (FIX / "signed_admin_pub.bin").write_bytes(signed_admin_pub)

    print(f"wrote XEdDSA fixtures to {FIX}")
    for n in ("xeddsa_admin_pub.bin", "xeddsa_other_pub.bin", "xeddsa_payload.bin",
              "xeddsa_sig.bin", "signed_package.bin", "signed_admin_pub.bin"):
        print(f"  {n:22s} {(FIX / n).stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
