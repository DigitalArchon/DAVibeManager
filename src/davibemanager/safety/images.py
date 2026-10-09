"""Clean images before they are stored or sent to a model.

Every attached photo or screenshot is decoded to pixels and re-encoded from those pixels
alone, into a fresh image with no metadata. Whatever the page sent, nothing but the visible
pixels survives: no EXIF (GPS, camera, timestamps, the embedded EXIF thumbnail), no XMP,
ICC profile, PNG text chunks or JPEG comments, no extra APNG frames, and no bytes appended
after the image. The redaction editor has already painted black boxes into those pixels, so
what is cleaned here is exactly what the technician saw."""

from __future__ import annotations

from io import BytesIO

from PIL import Image

MAX_PIXELS = 40_000_000
MAX_SIDE = 10_000
Image.MAX_IMAGE_PIXELS = MAX_PIXELS          # refuse decompression bombs


# pictures the user attaches may come in these too: they become PNGs (first frame only)
CONVERTED = ("WEBP", "GIF", "BMP", "TIFF")


def is_image(raw: bytes) -> bool:
    """Whether this is a picture of any kind Pillow knows (whether or not it can be cleaned)."""
    try:
        with Image.open(BytesIO(raw)) as im:
            return bool(im.format)
    except Exception:  # noqa: BLE001 - whatever it is, not a picture Pillow reads
        return False


def clean(raw: bytes, convert: bool = False) -> tuple[bytes, str]:
    """Return (re-encoded bytes, "png" | "jpg"). PNG stays lossless (screenshots); JPEG is
    re-encoded at quality 90 (photos); with `convert` (the user's own pictures), WebP, GIF, BMP and
    TIFF become PNG. Raises ValueError for anything else. Without `convert` (an image the assistant
    made in its sandbox), no reader but PNG's and JPEG's ever looks at it."""
    try:
        with Image.open(BytesIO(raw), formats=("PNG", "JPEG", *(CONVERTED if convert else ()))) as im:
            fmt = im.format
            if fmt not in ("PNG", "JPEG") and not (convert and fmt in CONVERTED):
                raise ValueError(f"unsupported image format {fmt}")
            im.seek(0)                                   # first frame only (APNG, GIF)
            if max(im.size) > MAX_SIDE:
                raise ValueError(f"image is {im.size[0]}x{im.size[1]}, over {MAX_SIDE}px")
            alpha = fmt != "JPEG" and (im.mode in ("RGBA", "LA", "PA") or "transparency" in im.info)
            pixels = im.convert("RGBA" if alpha else "RGB")
            fmt = "JPEG" if fmt == "JPEG" else "PNG"
    except (OSError, Image.DecompressionBombError, SyntaxError) as e:
        raise ValueError(f"not a readable PNG or JPEG image ({e})") from e
    # a brand-new image from raw pixel bytes: no .info, so nothing can be carried over
    fresh = Image.frombytes(pixels.mode, pixels.size, pixels.tobytes())
    out = BytesIO()
    if fmt == "JPEG":
        fresh.save(out, "JPEG", quality=90)
        return out.getvalue(), "jpg"
    fresh.save(out, "PNG")
    return out.getvalue(), "png"
