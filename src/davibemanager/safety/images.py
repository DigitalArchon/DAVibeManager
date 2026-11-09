"""Clean images before they are stored or sent to a model.

Every attached photo or screenshot is decoded to pixels and re-encoded from those pixels
alone, into a fresh image with no metadata. Whatever the page sent, nothing but the visible
pixels survives: no EXIF (GPS, camera, timestamps, the embedded EXIF thumbnail), no XMP,
ICC profile, PNG text chunks or JPEG comments, no extra APNG frames, and no bytes appended
after the image. The redaction editor has already painted black boxes into those pixels, so
what is cleaned here is exactly what the technician saw. A photo is turned upright from its
EXIF orientation first, so it is sent the way it looks.

Only the readers of the formats expected are let near the bytes: Pillow would otherwise try
the header of whatever arrives with each of the few dozen formats it knows."""

from __future__ import annotations

from io import BytesIO
from typing import NamedTuple

from PIL import Image, ImageOps, UnidentifiedImageError

MAX_PIXELS = 40_000_000
MAX_SIDE = 10_000
Image.MAX_IMAGE_PIXELS = MAX_PIXELS          # refuse decompression bombs

# pictures the user attaches may come in these too: they become PNGs (first frame only)
CONVERTED = ("WEBP", "GIF", "BMP", "TIFF")
# greyscale deeper than 8 bits (a scan, a microscope's or a camera's export, a 16-bit PNG)
SIXTEEN_BIT = ("I;16", "I;16B", "I;16L", "I;16N", "I")


class Cleaned(NamedTuple):
    """An image re-encoded from its pixels: `data` in `ext` ("png" | "jpg"), unpacked as (data, ext)."""
    data: bytes
    ext: str


def is_image(raw: bytes) -> bool:
    """Whether this is a picture of any kind Pillow knows (whether or not it can be cleaned)."""
    try:
        with Image.open(BytesIO(raw)) as im:
            return bool(im.format)
    except Exception:  # noqa: BLE001 - whatever it is, not a picture Pillow reads
        return False


def _eight_bit(im: Image.Image) -> Image.Image:
    """A 16-bit (or 32-bit integer) greyscale picture as 8-bit grey, every shade kept: convert("RGB")
    clips such values at 255 rather than scaling them, so it came out black and white. (From DA
    Assistant's imaging.py.)"""
    wide = im if im.mode == "I" else im.convert("I")
    _low, high = wide.getextrema()
    scale = 1 / 256 if high > 255 else 1
    return wide.point(lambda value: value * scale).convert("L")


def clean(raw: bytes, convert: bool = False) -> Cleaned:
    """Return the image re-encoded from its pixels. PNG stays lossless (screenshots); JPEG is
    re-encoded at quality 90 (photos); with `convert` (the user's own pictures), WebP, GIF, BMP and
    TIFF become PNG. Raises ValueError for anything else. Without `convert`, no reader but PNG's
    and JPEG's ever looks at it."""
    formats = ("PNG", "JPEG", *(CONVERTED if convert else ()))
    try:
        with Image.open(BytesIO(raw), formats=formats) as im:
            fmt = im.format
            if fmt not in formats:
                raise ValueError(f"unsupported image format {fmt}")
            im.seek(0)                                   # first frame only (APNG, GIF)
            if max(im.size) > MAX_SIDE:
                raise ValueError(f"image is {im.size[0]}x{im.size[1]}, over {MAX_SIDE}px")
            # Pillow itself refuses only past twice MAX_IMAGE_PIXELS (it warns in between)
            if im.size[0] * im.size[1] > MAX_PIXELS:
                raise ValueError(f"image is {im.size[0]}x{im.size[1]}, over {MAX_PIXELS // 1_000_000} million pixels")
            alpha = fmt != "JPEG" and (im.mode in ("RGBA", "LA", "PA") or "transparency" in im.info)
            # upright, as it's seen: the orientation a phone writes in its EXIF goes with the rest of that
            upright = ImageOps.exif_transpose(im)
            if upright.mode in SIXTEEN_BIT:
                upright = _eight_bit(upright)
            pixels = upright.convert("RGBA" if alpha else "RGB")
            fmt = "JPEG" if fmt == "JPEG" else "PNG"
    except UnidentifiedImageError as e:
        raise ValueError(f"unsupported image format: not {', '.join(formats[:-1])} or {formats[-1]}") from e
    except (OSError, Image.DecompressionBombError, SyntaxError) as e:
        raise ValueError(f"not a readable PNG or JPEG image ({e})") from e
    # a brand-new image from raw pixel bytes: no .info, so nothing can be carried over
    fresh = Image.frombytes(pixels.mode, pixels.size, pixels.tobytes())
    out = BytesIO()
    if fmt == "JPEG":
        fresh.save(out, "JPEG", quality=90)
        return Cleaned(out.getvalue(), "jpg")
    fresh.save(out, "PNG")
    return Cleaned(out.getvalue(), "png")
