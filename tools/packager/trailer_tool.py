"""Append / read the self-identity trailer on a firmware image.

Shared by the PlatformIO post-build hook (firmware/extra_scripts/ota_trailer.py)
and standalone inspection. Keeping the trailer-building logic here means the
hook and the packager produce identical bytes.
"""

from __future__ import annotations

from .formats import TRAILER_SIZE, Trailer


def append_trailer(
    image: bytes,
    *,
    env: str,
    version: str,
    commit: str,
    repo: str = "",
    hw_vendor: int = 0,
) -> bytes:
    """Return image with a finalized trailer appended.

    image_length records the length of the image preceding the trailer, so a
    reader can locate it either from the file tail or via the ESP image header.
    """
    if has_trailer(image):
        # Idempotent: strip an existing trailer before re-appending.
        image = image[:-TRAILER_SIZE]
    tr = Trailer(
        env=env,
        version=version,
        commit=commit,
        repo=repo,
        hw_vendor=hw_vendor,
        image_length=len(image),
    )
    return image + tr.pack()


def has_trailer(image: bytes) -> bool:
    if len(image) < TRAILER_SIZE:
        return False
    try:
        Trailer.from_image_tail(image)
        return True
    except ValueError:
        return False


def read_trailer(image: bytes) -> Trailer:
    return Trailer.from_image_tail(image)
