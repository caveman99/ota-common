#!/usr/bin/env python3
"""Generate cross-language test fixtures.

Produces deterministic UNSIGNED packages and trailer-bearing images into
test/fixtures/, which the C++ test suite reads back to prove the Python and C++
binary formats agree. Signatures are verified on-device against admin keys (via
XEdDSA), not in these host fixtures, so the packages here are unsigned. Run:

    tools/.venv/bin/python tools/gen_fixtures.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from packager import package  # noqa: E402
from packager.trailer_tool import append_trailer  # noqa: E402

FIXTURES = ROOT / "test" / "fixtures"

ENV = "heltec-v3"
BASE_VERSION = "2.8.0.54e0d8d"
BASE_COMMIT = "54e0d8d"
TARGET_VERSION = "2.8.0.deadbee"
TARGET_COMMIT = "deadbee"

# In-place patch geometry (mirrored in test/test_detools). segment_size is the
# ESP32 flash erase block; memory_size is the region the in-place apply works in.
IN_PLACE_SEGMENT_SIZE = 4096
IN_PLACE_MEMORY_SIZE = 65536


def det_image(n: int, seed: int) -> bytes:
    b = bytearray(n)
    x = seed & 0xFFFFFFFF
    for i in range(n):
        x = (1103515245 * x + 12345) & 0xFFFFFFFF
        b[i] = (x >> 16) & 0xFF
    return bytes(b)


def main() -> int:
    FIXTURES.mkdir(parents=True, exist_ok=True)

    base_core = det_image(6000, 11)
    base_image = append_trailer(
        base_core, env=ENV, version=BASE_VERSION, commit=BASE_COMMIT,
        repo="meshtastic/firmware", hw_vendor=9,
    )
    (FIXTURES / "base_image.bin").write_bytes(base_image)

    t = bytearray(base_core)
    for i in range(2000, 2200):
        t[i] ^= 0x5A
    t += b"the-new-section" * 16
    target_image = append_trailer(
        bytes(t), env=ENV, version=TARGET_VERSION, commit=TARGET_COMMIT,
        repo="meshtastic/firmware", hw_vendor=9,
    )
    (FIXTURES / "target_image.bin").write_bytes(target_image)

    full_pkg = package.build_full_package(
        image=target_image, base_version=BASE_VERSION, base_commit=BASE_COMMIT, env=ENV,
    )
    (FIXTURES / "full_package.bin").write_bytes(full_pkg)

    delta_pkg = package.build_delta_package(base_image=base_image, target_image=target_image)
    (FIXTURES / "delta_package.bin").write_bytes(delta_pkg)

    # In-place patch: patches the whole flash region (base -> target) in place.
    # memory_size/segment_size are fixed here and mirrored in the C++ test.
    inplace = package.make_inplace_delta(
        base_image, target_image, memory_size=IN_PLACE_MEMORY_SIZE,
        segment_size=IN_PLACE_SEGMENT_SIZE,
    )
    (FIXTURES / "inplace_patch.bin").write_bytes(inplace)

    print(f"wrote fixtures to {FIXTURES}")
    for p in sorted(FIXTURES.glob("*.bin")):
        print(f"  {p.name:20s} {p.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
