# ota-common usage guide

This guide covers how to consume ota-common and wire it into a firmware update
flow. It does not document the internal algorithms; the public headers under
`include/ota_common/` are the API reference. The last section is a normative
reference for the on-wire formats, for anyone reimplementing the packager or a
verifier in another language.

Contents:

1. Consuming the library
2. The seams you implement
3. Receiving an update
4. Applying an update (full image and delta)
5. Verifying signatures
6. Seeding an update
7. Host packager
8. Signing workflow
9. Wire format reference

## 1. Consuming the library

The same source tree ships three manifests so it drops into any of the project
toolchains unchanged.

### ESP-IDF component

ota-common is a self-registering component (`CMakeLists.txt` +
`idf_component.yml`). Either add it as a git submodule under your project's
`components/` directory, in which case the checkout directory name becomes the
component name:

```
git submodule add <url> components/ota_common
```

or point `EXTRA_COMPONENT_DIRS` at the directory from your top-level
`CMakeLists.txt`:

```cmake
list(APPEND EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../ota-common")
```

Then list it in the requiring component's `idf_component_register(... REQUIRES
ota-common)` (use the component name that matches your checkout directory). The
component compiles with `-std=gnu++17 -fno-exceptions -fno-rtti` to stay small.

### PlatformIO

PlatformIO reads `library.json`. Reach the library through `lib_extra_dirs`,
and exclude sibling project directories from the dependency finder:

```ini
lib_extra_dirs = ${PROJECT_DIR}/..
lib_ignore =
  some-sibling-project
```

### Arduino

`library.properties` provides the Arduino manifest. Note that strict Arduino IDE
builds add only `src/` to the include path, while ota-common keeps its public
headers under `include/`. PlatformIO and ESP-IDF honor `include/` through the
two manifests above; a pure Arduino IDE build would need the headers relocated
under `src/`.

## 2. The seams you implement

ota-common holds no platform code. You provide implementations of the
interfaces it calls. A host build or a test can supply trivial in-memory
versions; a firmware build supplies flash-backed and radio-backed ones.

| Interface | Header | Responsibility |
|---|---|---|
| `IFlashTarget` | `flash_target.h` | Receive the reconstructed image, gate its hash, activate it |
| `IRadio` | `radio.h` | Apply an RF profile, send and receive whole frames |
| `IFrameOut` | `transport.h` | Send one outgoing frame (a subset of `IRadio` for the receiver) |
| `IBlockStore` | `transport.h` | Persist verified payload blocks, report which survived a reboot |
| `ISignatureVerifier` | `signature.h` | Verify a signature over the manifest against trusted keys |
| `IByteSink` | `detools_apply.h` | Sequential sink for a decoded image |
| `IFlashMem` / `IStepJournal` | `detools_apply.h` | Random-access flash and a resume journal, for in-place delta |

`IFlashTarget` is the central apply seam:

```cpp
struct IFlashTarget {
    virtual FlashStatus begin(uint32_t expected_output_size, const Manifest& manifest) = 0;
    virtual FlashStatus write(uint32_t offset, const uint8_t* bytes, size_t len) = 0;
    virtual FlashStatus commit() = 0; // verify output hash, then activate
    virtual void abort() = 0;
};
```

`commit()` must verify the reconstructed image against the manifest's
`output_sha256` and refuse to activate on a mismatch. Two implementations exist
in the firmware trees for reference: an in-place target that patches a single
partition (4 MB boards, no spare slot) and an inactive-slot target that writes
the other slot and arms an A/B swap.

## 3. Receiving an update

`OtaReceiver` drives the target side of the transport: it requests the manifest,
verifies each payload block against the merkle root as it arrives, journals
verified blocks, and reports completion. You feed it received frames and give it
a block store and an outgoing frame channel.

```cpp
BufferBlockStore store;                    // or FlashTargetBlockStore for full images
OtaReceiver receiver(store, frameOut, session, &verifier);

for (;;) {
    uint8_t buf[kMaxFramePayload];
    int n = radio.receive(buf, sizeof(buf));
    if (n > 0) receiver.on_frame(buf, n);
    else receiver.poll();                  // re-request if the seeder went quiet

    if (receiver.aborted()) { /* signature or geometry failure */ break; }
    if (receiver.complete()) { /* all blocks verified and journaled */ break; }
}
```

`manifest_ready()` becomes true once the manifest is received and its signature
(if a verifier was supplied) is checked. At that point the manifest describes the
image geometry and identity; gate on it before applying. `blocks_have()` and
`blocks_total()` report progress.

## 4. Applying an update

Two payload shapes, selected by `manifest_is_delta(manifest)`.

### Full image

The payload is the output image. Use `FlashTargetBlockStore` as the receiver's
store; it streams each verified block straight into your `IFlashTarget`:

```cpp
FlashTargetBlockStore store(flashTarget);
OtaReceiver receiver(store, frameOut, session, &verifier);
// once the manifest arrives:
store.set_manifest(&receiver.manifest());
// after receiver.complete():
FlashStatus s = store.commit();            // runs the target's output-hash gate
```

### Delta

The payload is a detools delta. Buffer it with `BufferBlockStore`, then decode
it against the current firmware. For a target with a spare slot, decode into it:

```cpp
int out = detools_apply(baseReader, store.data(), store.size(), sink);
// then flashTarget.commit();
```

For a 4 MB board that must patch a partition against itself, use the in-place
apply with a step journal so it resumes after a reboot:

```cpp
int out = detools_apply_in_place(flashMem, stepJournal, store.data(), store.size());
```

Persist the journal to NVS or flash. On a resume, re-fetch the delta and call
the same function; the journal makes the decoder skip segments already written.
Never boot a partition that is mid-apply until `commit()` has confirmed the hash.

## 5. Verifying signatures

An update is authorized like a remote admin command: it is signed by an operator
whose Curve25519 public key is in the target node's admin key set. There is no
central firmware signing key. Supply an `ISignatureVerifier` to the receiver;
it holds the trusted keys, so an attacker-supplied key can never be substituted.

On a device that has the Meshtastic `CryptoEngine`, wrap `xeddsa_verify` from it.
On a bare loader or a host build, use the bundled `AdminKeyVerifier`:

```cpp
AdminKeyVerifier verifier;
verifier.add_key(admin_pubkey_32);         // up to 3 keys; no keys means reject
OtaReceiver receiver(store, frameOut, session, &verifier);
```

`AdminKeyVerifier` fails closed: a session is refused unless at least one key is
configured and the manifest signature verifies against one of them.

## 6. Seeding an update

`OtaSeeder` owns a signed package buffer and answers a receiver's requests. Drive
it symmetrically to the receiver:

```cpp
OtaSeeder seeder(package, package_len, frameOut, session);
seeder.begin();                            // emits START
for (;;) {
    int n = radio.receive(buf, sizeof(buf));
    if (n > 0) seeder.on_frame(buf, n);
    if (seeder.done()) break;
}
```

The seeder is stateless across the target's reboots: a returning receiver simply
requests the blocks it is missing.

## 7. Host packager

`tools/packager` is the Python reference tool that builds and inspects packages
and reads or writes trailers. Set up its virtualenv and run the CLI:

```
bash tools/run_tests.sh          # creates tools/.venv and runs the packager tests
python -m packager --help        # from tools/, with the venv active
```

Common commands:

```
python -m packager build-full  --image FW.bin --out pkg.bin
python -m packager build-delta --base BASE.bin --target TARGET.bin --out pkg.bin
python -m packager inspect      pkg.bin
python -m packager read-trailer FW.bin
```

`build-full` and `build-delta` emit unsigned packages. Building and inspecting
require no crypto dependency; signing does.

## 8. Signing workflow

The operator's admin device holds the private key and produces the signature;
the key never has to leave the device. The packager provides both a direct
reference signer (for bench work) and a detached flow.

```
# derive the admin public key to provision into a node's admin key set
python -m packager admin-pubkey --key node_private_key.bin

# direct: sign with a local admin key file (bench)
python -m packager sign pkg.bin --key node_private_key.bin --out pkg.signed.bin

# detached: emit the bytes to sign, sign them on the admin device, splice back in
python -m packager sign-info   pkg.bin --out to_sign.bin
#   ... admin device XEdDSA-signs to_sign.bin into sig.bin ...
python -m packager attach-sig  pkg.bin --sig sig.bin --out pkg.signed.bin
```

The signature is XEdDSA (Signal scheme) over the admin device's Curve25519 key.
The signed message is the fleet-wide OTA convention: the little-endian header
`[from=0][id=0][portnum=LORA_OTA_APP]` followed by the 192-byte manifest, which
matches the firmware's signing buffer. Signing requires `pip install xeddsa`.

## 9. Wire format reference

Normative byte layouts. All integers are little-endian. Each format has three
consumers that must agree byte for byte: the C++ definition in
`include/ota_common/`, the Python packager in `tools/packager/`, and this
document.

### Self-identity trailer (172 bytes)

Appended to the end of an application image so a peer can identify the exact
build a partition holds without a radio, NVS, or network. The ESP image format
is self-describing, so trailing bytes after the image are ignored by the
bootloader. Definition: `trailer.h`.

| Offset | Size | Field | Description |
|-------:|-----:|-------|-------------|
| 0 | 4 | `magic` | `0x4F544231` ("OTB1") |
| 4 | 2 | `format` | 1 |
| 6 | 2 | `flags` | reserved, 0 |
| 8 | 32 | `env` | PlatformIO env, e.g. `heltec-v3` |
| 40 | 48 | `version` | `APP_VERSION` long, e.g. `2.8.0.54e0d8d` |
| 88 | 16 | `commit` | git short SHA, NUL-padded |
| 104 | 48 | `repo` | `owner/name`, e.g. `meshtastic/firmware` |
| 152 | 4 | `hw_vendor` | HardwareModel id |
| 156 | 4 | `image_length` | length of the image preceding this trailer |
| 160 | 8 | `reserved0/1` | 0 |
| 168 | 4 | `crc32` | CRC-32 (IEEE 802.3) over bytes `[0, 168)` |

Strings are NUL-padded and need not be NUL-terminated when they fill the field;
readers treat them as `strnlen`-bounded.

### Update package

A container carrying one full or delta update. Definitions: `package.h`,
`manifest.h`.

```
PackageHeader (16 bytes)
  magic   u32  0x41544F4D ("MOTA")
  format  u16  1
  flags   u16  reserved 0
  manifest_length   u32  == sizeof(Manifest) == 192
  signature_length  u32  == 64
Manifest    192 bytes   the signed region
signature    64 bytes   XEdDSA over the 192 manifest bytes
payload     payload_length bytes   detools delta, or full image
```

The signature covers only the manifest. The payload is authenticated
transitively: the manifest carries `payload_merkle_root` over the payload blocks
and `output_sha256` over the reconstructed image, both inside the signed region.

Manifest (192 bytes):

| Offset | Size | Field | Description |
|-------:|-----:|-------|-------------|
| 0 | 4 | `magic` | `0x4E414D4D` ("MMAN") |
| 4 | 2 | `format` | 1 |
| 6 | 2 | `flags` | bit0 = payload is a detools delta |
| 8 | 32 | `env` | expected base env (soft gate) |
| 40 | 48 | `base_version` | expected base `APP_VERSION` long |
| 88 | 16 | `base_commit` | expected base git short SHA |
| 104 | 4 | `block_size` | payload merkle/transport block size |
| 108 | 4 | `block_count` | number of payload blocks |
| 112 | 4 | `payload_length` | payload bytes following the signature |
| 116 | 32 | `payload_merkle_root` | SHA-256 merkle root over payload blocks |
| 148 | 4 | `output_length` | reconstructed image length |
| 152 | 32 | `output_sha256` | SHA-256 of the full reconstructed image |
| 184 | 8 | `reserved0/1` | 0 |

Device verification order: structural parse, signature over the manifest, soft
identity gate against the running trailer, per-block merkle verification as
blocks arrive, apply, then the hard output-hash gate before activation. For a
full-image package `payload_length == output_length` and the payload blocks are
the output blocks.

### Transport frame

Point-to-point delivery over a Meshtastic PortNum: one seeder, one target,
single hop. Definition: `transport.h`. Every frame is an 8-byte header followed
by a payload, total at most 233 bytes (one Meshtastic data payload).

| Offset | Size | Field | Meaning |
|-------:|-----:|-------|---------|
| 0 | 1 | `type` | frame type (below) |
| 1 | 1 | `session` | point-to-point session id, echoed by both sides |
| 2 | 2 | `index` | block index, or `0xFFFF` for the manifest unit |
| 4 | 2 | `off` | byte offset of this fragment within its unit |
| 6 | 2 | `total` | total byte length of the logical unit |

Frame types: `Start(1) Manifest(2) Block(3) Proof(4)` from seeder to target;
`Request(5) Ack(6) Done(7)` from target to seeder; `Abort(8)` either way.
Logical units (the manifest plus signature, each payload block, each block's
merkle proof) are fragmented across frames of at most 225 payload bytes and
reassembled in order.

The exchange is stop-and-wait per unit. START carries geometry hints that are
cross-checked against the signed manifest; a mismatch aborts the session, and
the manifest is authoritative. Each block is verified against
`payload_merkle_root` with its proof before being journaled; a failing block is
re-requested. Resume is driven by the block store: `has_block()` reports what
survived a reboot, so a fresh receiver requests only the missing blocks.
