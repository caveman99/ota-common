# ota-common

Framework-agnostic C++17 core for Meshtastic LoRa firmware updates. It carries
the update package format, the point-to-point transport, delta apply, signature
verification, and the self-identity trailer. All platform specifics (flash,
radio, crypto) are injected through interfaces, so the same sources compile on a
host, on a bare ESP-IDF loader, and inside PlatformIO/Arduino firmware.

## Components

| Header                                       | Provides                                                               |
| -------------------------------------------- | ---------------------------------------------------------------------- |
| `trailer.h`                                  | Self-identity trailer: build metadata appended to an image             |
| `package.h` / `manifest.h`                   | Update package container, read-only bounds-checked parse               |
| `transport.h`                                | `OtaSeeder` / `OtaReceiver`: fragment, block, ACK, resume              |
| `merkle.h`                                   | Merkle tree over payload blocks: root, proof, per-block verify         |
| `detools_apply.h`                            | Delta apply (full-slot and in-place), decoder only                     |
| `flash_target.h` / `radio.h` / `signature.h` | The `IFlashTarget`, `IRadio`, `ISignatureVerifier` seams you implement |
| `admin_key_verifier.h` / `xeddsa.h`          | Self-contained XEdDSA verify over a node's admin keys                  |
| `sha256.h` / `esp_image.h`                   | SHA-256, ESP image-length parser                                       |

Include `ota_common/ota_common.h` for the whole surface, or the individual
headers you use.

## Consuming the library

One source tree, three parallel manifests:

- **ESP-IDF**: `CMakeLists.txt` + `idf_component.yml`. Self-registering: add as
  a git submodule under a consumer's `components/`, or point
  `EXTRA_COMPONENT_DIRS` at this directory.
- **PlatformIO**: `library.json`. Reached via `lib_extra_dirs`.
- **Arduino**: `library.properties`.

See [docs/guide.md](docs/guide.md) for integration details and the packager and
signing workflows.

## Host tests

```
pio test -e native
```

Covers SHA-256, the trailer, merkle, package parse, the transport FSM, delta
apply, and the ESP image parser. Two suites are cross-language: `test_fixtures`
and `test_detools` check the Python packager against the C++/C decoders, and
`test_xeddsa` verifies a signature produced by the independent Python `xeddsa`
package. Regenerate fixtures with
`tools/.venv/bin/python tools/gen_fixtures.py` and `gen_xeddsa_fixtures.py`.

## License

GPL-3.0-only. Vendored third-party code and its licenses are inventoried in
[third_party/VENDORED.md](third_party/VENDORED.md).
