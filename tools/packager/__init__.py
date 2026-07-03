"""Host-side OTA packager for Meshtastic LoRa OTA.

Mirrors the ota-common C++ binary formats. Emits UNSIGNED packages; the
operator's admin device signs the manifest with XEdDSA (see package.signing_buffer
/ package.attach_signature). See docs/guide.md.
"""

from .formats import Manifest, Trailer  # noqa: F401
from .package import (  # noqa: F401
    ParsedPackage,
    apply_delta,
    attach_signature,
    build_delta_package,
    build_full_package,
    is_signed,
    make_delta,
    manifest_bytes,
    output_gate_ok,
    parse_package,
    signing_buffer,
    verify_integrity,
)
