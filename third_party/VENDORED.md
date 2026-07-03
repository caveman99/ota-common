# Vendored third-party code

Inventory of code copied into this repository, for license compliance and
supply-chain tracking. Everything vendored lives under
`ota-common/third_party/` and is compiled into `ota-common` via the
`src/vendor_*.c` unity translation units. All of it is permissively licensed and
compatible with GPL-3.0-only.

| Library | Path | Version | License | Upstream |
|---|---|---|---|---|
| TweetNaCl | `tweetnacl/` | 20140427 | Public domain | https://tweetnacl.cr.yp.to |
| detools (C decoder) | `detools/detools.{c,h}` | 0.53.0 | BSD-2-Clause | https://github.com/eerimoq/detools |
| heatshrink | `detools/heatshrink_*.{c,h}` | bundled by detools 0.53.0 | ISC | https://github.com/atomicobject/heatshrink |

Non-vendored third-party code, listed for completeness: RadioLib (MIT, git
dependency via `firmware-ota-lora/src/idf_component.yml`), Unity (MIT, provided
by PlatformIO for tests), ESP-IDF / mbedTLS (platform), and the Python host
tools `detools` / `xeddsa` / `pytest` (dev-only, via `tools/requirements.txt`).

## TweetNaCl

- Files: `tweetnacl/tweetnacl.{c,h}` (+ `PROVENANCE.txt` with SHA-256).
  Unmodified upstream.
- Upstream: https://tweetnacl.cr.yp.to/20140427/ (D. J. Bernstein et al.).
- Used for: self-contained XEdDSA manifest-signature verification against admin
  keys (`ota_common::xeddsa_verify` / `AdminKeyVerifier`), via `crypto_sign_open`
  plus a Curve25519 to Ed25519 conversion (`src/vendor_tweetnacl.c`).
  `randombytes` (keygen only) is stubbed.

## detools

- Files: `detools/detools.{c,h}`, decoder only. `DETOOLS_VERSION == "0.53.0"`,
  matching the Python `detools` used to create patches.
- Upstream: https://github.com/eerimoq/detools. See `detools/LICENSE`. The
  create-side `sais.c` (MIT) is not vendored.
- Used for: applying full/delta/in-place patches on device
  (`ota_common::detools_apply` / `detools_apply_in_place`), compiled with
  `DETOOLS_CONFIG_FILE_IO=0` and `DETOOLS_CONFIG_COMPRESSION_LZMA=0`
  (`src/vendor_detools.c`).

## heatshrink

- Files: `detools/heatshrink_{common,config,decoder}.{c,h}`, bundled inside
  detools' `c_source`.
- Upstream: https://github.com/atomicobject/heatshrink (Scott Vokes). ISC text
  shipped as `detools/HEATSHRINK-LICENSE`.
- Used for: decompressing the heatshrink-compressed detools patch payload
  (`src/vendor_heatshrink.c`).

## Reproducibility

- TweetNaCl is pinned by date + SHA-256 in `tweetnacl/PROVENANCE.txt`.
- detools/heatshrink are pinned by `DETOOLS_VERSION 0.53.0`. SHA-256 of the
  vendored files:
  - `detools.c`            f59c9be04e98675f1a4b0653b542ef15a03868b7921a1a432ab9b790d6fcd0b0
  - `detools.h`            98d633a448e900014aa9e682af95153d8fbc21a0129fff2324e5cc74d235d823
  - `heatshrink_decoder.c` 5ced6bb057741a5772edaf46f7c8466b5da1751d7e704ffdb79eedd5aadf7821
  - `heatshrink_decoder.h` 8a96982256132f557e5db0321ee10c37bbef5e07e4b4ac08a18664e0ee544461
  - `heatshrink_common.h`  bedf2a51b6e0d7febd537b96dbb3ef372c3d911440d2740397e9fdf8b796181f
  - `heatshrink_config.h`  02ed2fcac7fccdccc95d00b262fba1850662433a9b2c07de5ac44413cb48d254
