"""Command-line entry point for the OTA packager.

Packages are emitted UNSIGNED; the operator's admin device signs the manifest
with XEdDSA over its Curve25519 admin key. Typical flow:

    python -m packager build-delta --base BASE.bin --target TARGET.bin --out pkg.bin
    python -m packager sign-info    pkg.bin --out to_sign.bin   # hand to admin device
    #  ... admin device XEdDSA-signs to_sign.bin -> sig.bin (64 bytes) ...
    python -m packager attach-sig   pkg.bin --sig sig.bin --out pkg.signed.bin

Other commands:
    python -m packager read-trailer  IMAGE.bin
    python -m packager add-trailer   IMAGE.bin --env heltec-v3 --version 2.8.0.abc1234 \
                                     --commit abc1234 --out OUT.bin
    python -m packager build-full    IMAGE.bin --env heltec-v3 \
                                     --base-version 2.8.0.abc1234 --base-commit abc1234 --out pkg.bin
    python -m packager inspect       pkg.bin
    python -m packager verify-delta  pkg.bin --base BASE.bin
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import package
from .trailer_tool import append_trailer, read_trailer


def _read(p: str) -> bytes:
    return Path(p).read_bytes()


def cmd_read_trailer(args) -> int:
    tr = read_trailer(_read(args.image))
    for k in ("env", "version", "commit", "repo", "hw_vendor", "image_length"):
        print(f"{k:13s}: {getattr(tr, k)}")
    return 0


def cmd_add_trailer(args) -> int:
    out = append_trailer(
        _read(args.image),
        env=args.env,
        version=args.version,
        commit=args.commit,
        repo=args.repo or "",
        hw_vendor=args.hw_vendor or 0,
    )
    Path(args.out).write_bytes(out)
    print(f"wrote {len(out)} bytes -> {args.out}")
    return 0


def cmd_build_full(args) -> int:
    pkg = package.build_full_package(
        image=_read(args.image),
        base_version=args.base_version,
        base_commit=args.base_commit,
        env=args.env,
        block_size=args.block_size,
    )
    Path(args.out).write_bytes(pkg)
    print(f"wrote UNSIGNED full package {len(pkg)} bytes -> {args.out}")
    print("next: `sign-info` then have the admin device sign, then `attach-sig`")
    return 0


def cmd_build_delta(args) -> int:
    target = _read(args.target)
    pkg = package.build_delta_package(
        base_image=_read(args.base),
        target_image=target,
        base_version=args.base_version or "",
        base_commit=args.base_commit or "",
        env=args.env or "",
        block_size=args.block_size,
    )
    parsed = package.parse_package(pkg)
    print(f"wrote UNSIGNED delta package {len(pkg)} bytes -> {args.out}")
    print(
        f"target {len(target)} bytes, delta payload {parsed.manifest.payload_length} bytes"
    )
    print("next: `sign-info` then have the admin device sign, then `attach-sig`")
    Path(args.out).write_bytes(pkg)
    return 0


def cmd_sign_info(args) -> int:
    buf = _read(args.package)
    to_sign = package.signing_buffer(package.manifest_bytes(buf))
    if args.out:
        Path(args.out).write_bytes(to_sign)
        print(f"wrote {len(to_sign)} bytes to sign -> {args.out}")
    else:
        print(to_sign.hex())
    print("Have the admin device XEdDSA-sign these bytes with its Curve25519 admin")
    print("key (from=0, id=0, portnum=LORA_OTA_APP). Result is a 64-byte signature.")
    return 0


def cmd_sign(args) -> int:
    from . import sign as signer

    key = _read(args.key)
    if len(key) != 32:
        print("admin private key must be 32 raw bytes (config.security.private_key)")
        return 2
    signed = signer.sign_package(_read(args.package), key)
    Path(args.out).write_bytes(signed)
    print(f"signed package -> {args.out}")
    print(
        f"admin public key (add to admin_key[]): {signer.admin_public_key(key).hex()}"
    )
    return 0


def cmd_admin_pubkey(args) -> int:
    from . import sign as signer

    key = _read(args.key)
    if len(key) != 32:
        print("admin private key must be 32 raw bytes")
        return 2
    print(signer.admin_public_key(key).hex())
    return 0


def cmd_attach_sig(args) -> int:
    buf = _read(args.package)
    sig = _read(args.sig)
    if len(sig) != package.SIGNATURE_LEN and len(sig) == 2 * package.SIGNATURE_LEN:
        sig = bytes.fromhex(sig.decode())
    out = package.attach_signature(buf, sig)
    Path(args.out).write_bytes(out)
    print(f"attached signature; wrote signed package {len(out)} bytes -> {args.out}")
    return 0


def cmd_inspect(args) -> int:
    buf = _read(args.package)
    pkg = package.verify_integrity(buf)
    m = pkg.manifest
    print(f"signed        : {package.is_signed(buf)}")
    print(f"is_delta      : {m.is_delta}")
    print(f"env           : {m.env}")
    print(f"base_version  : {m.base_version}")
    print(f"base_commit   : {m.base_commit}")
    print(f"block_size    : {m.block_size}")
    print(f"block_count   : {m.block_count}")
    print(f"payload_length: {m.payload_length}")
    print(f"output_length : {m.output_length}")
    print(f"output_sha256 : {m.output_sha256.hex()}")
    print(f"merkle_root   : {m.payload_merkle_root.hex()}")
    return 0


def cmd_verify_delta(args) -> int:
    buf = _read(args.package)
    base = _read(args.base)
    pkg = package.parse_package(buf)
    if not pkg.manifest.is_delta:
        print("not a delta package")
        return 2
    reconstructed = package.apply_delta(base, pkg.payload)
    if package.output_gate_ok(reconstructed, pkg.manifest):
        print("output gate: PASS (reconstructed image matches manifest)")
        return 0
    print("output gate: FAIL")
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="packager", description="Meshtastic LoRa OTA packager"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    rt = sub.add_parser("read-trailer")
    rt.add_argument("image")
    rt.set_defaults(func=cmd_read_trailer)

    at = sub.add_parser("add-trailer")
    at.add_argument("image")
    at.add_argument("--env", required=True)
    at.add_argument("--version", required=True)
    at.add_argument("--commit", required=True)
    at.add_argument("--repo")
    at.add_argument("--hw-vendor", type=int, dest="hw_vendor")
    at.add_argument("--out", required=True)
    at.set_defaults(func=cmd_add_trailer)

    bf = sub.add_parser("build-full")
    bf.add_argument("image")
    bf.add_argument("--env", required=True)
    bf.add_argument("--base-version", required=True)
    bf.add_argument("--base-commit", required=True)
    bf.add_argument("--block-size", type=int, default=package.DEFAULT_BLOCK_SIZE)
    bf.add_argument("--out", required=True)
    bf.set_defaults(func=cmd_build_full)

    bd = sub.add_parser("build-delta")
    bd.add_argument("--base", required=True)
    bd.add_argument("--target", required=True)
    bd.add_argument("--env")
    bd.add_argument("--base-version")
    bd.add_argument("--base-commit")
    bd.add_argument("--block-size", type=int, default=package.DEFAULT_BLOCK_SIZE)
    bd.add_argument("--out", required=True)
    bd.set_defaults(func=cmd_build_delta)

    si = sub.add_parser("sign-info")
    si.add_argument("package")
    si.add_argument("--out")
    si.set_defaults(func=cmd_sign_info)

    sg = sub.add_parser(
        "sign", help="reference signer: XEdDSA-sign a package with an admin key"
    )
    sg.add_argument("package")
    sg.add_argument(
        "--key",
        required=True,
        help="32-byte admin curve private key (node private_key)",
    )
    sg.add_argument("--out", required=True)
    sg.set_defaults(func=cmd_sign)

    ap = sub.add_parser(
        "admin-pubkey", help="derive the admin public key from a private key"
    )
    ap.add_argument("--key", required=True)
    ap.set_defaults(func=cmd_admin_pubkey)

    asig = sub.add_parser("attach-sig")
    asig.add_argument("package")
    asig.add_argument("--sig", required=True)
    asig.add_argument("--out", required=True)
    asig.set_defaults(func=cmd_attach_sig)

    ins = sub.add_parser("inspect")
    ins.add_argument("package")
    ins.set_defaults(func=cmd_inspect)

    vd = sub.add_parser("verify-delta")
    vd.add_argument("package")
    vd.add_argument("--base", required=True)
    vd.set_defaults(func=cmd_verify_delta)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
