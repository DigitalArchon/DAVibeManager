"""Clean images before they are stored or sent to a model.

Every attached photo or screenshot is decoded to pixels and re-encoded from those pixels
alone, into a fresh image with no metadata. Whatever the page sent, nothing but the visible
pixels survives: no EXIF (GPS, camera, timestamps, the embedded EXIF thumbnail), no XMP,
ICC profile, PNG text chunks or JPEG comments, no extra APNG frames, and no bytes appended
after the image. The redaction editor has already painted black boxes into those pixels, so
what is cleaned here is exactly what the technician saw. A photo is turned upright from its
EXIF orientation first, so it is sent the way it looks.

Only the readers of the formats expected are let near the bytes: Pillow would otherwise try
the header of whatever arrives with each of the few dozen formats it knows.

A few kilobytes can say they are a very large picture, and decoding costs memory by the pixel,
not by the byte: the size is read from the header and held to what a photo of a screen needs
before anything is decoded, and the new image is made from the decoded one directly, with no
copies of the pixels in between."""

from __future__ import annotations

from io import BytesIO
from typing import NamedTuple

from PIL import Image, ImageOps, UnidentifiedImageError

# The page shrinks what it attaches to 2048 px on its long side (4 million pixels at most), and a
# phone's full 12-megapixel photo is 4032 x 3024: that much and no more. Until Nov 2026 the limits
# were 10,000 px and 40 million pixels, and a 5 KB PNG that said it was 8000 x 5000 took 460 MB
# to clean, as four copies of its pixels were alive at once; the largest picture now taken costs
# about 100 MB (a 16-bit greyscale one 150).
MAX_SIDE = 4096
MAX_PIXELS = 4096 * 3072
Image.MAX_IMAGE_PIXELS = MAX_PIXELS          # refuse decompression bombs

# pictures the user attaches may come in these too: they become PNGs (first frame only)
CONVERTED = ("WEBP", "GIF", "BMP", "TIFF")
# greyscale deeper than 8 bits (a scan, a microscope's or a camera's export, a 16-bit PNG)
SIXTEEN_BIT = ("I;16", "I;16B", "I;16L", "I;16N", "I")


class _Refused(ValueError):
    """An image clean() won't take, said in words for the technician."""


class Cleaned(NamedTuple):
    """An image re-encoded from its pixels: `data` in `ext` ("png" | "jpg"), unpacked as (data, ext)."""
    data: bytes
    ext: str


# pictures Pillow can't read at all, by their first bytes: HEIF and AVIF (an iPhone's photos), JPEG XL
_HEIF_BRANDS = (b"heic", b"heix", b"heim", b"heis", b"hevc", b"hevx", b"hevm", b"hevs", b"mif1", b"mif2", b"msf1",
                b"avif", b"avis")
_JXL = (b"\xff\x0a", b"\x00\x00\x00\x0cJXL \r\n\x87\n")


def is_image(raw: bytes) -> bool:
    """Whether this is a picture of any kind Pillow knows (whether or not it can be cleaned), or one of
    those it doesn't (HEIF, AVIF, JPEG XL): one that can't be cleaned of where and when it was taken."""
    if raw[4:8] == b"ftyp" and raw[8:12] in _HEIF_BRANDS or raw.startswith(_JXL):
        return True
    try:
        with Image.open(BytesIO(raw)) as im:
            return bool(im.format)
    except Image.DecompressionBombError:         # a picture, and a very large one
        return True
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
    TIFF become PNG. Raises ValueError for anything else, and for whatever a damaged file makes
    Pillow raise. Without `convert`, no reader but PNG's and JPEG's ever looks at it."""
    formats = ("PNG", "JPEG", *(CONVERTED if convert else ()))
    too_large = f"image is over {MAX_PIXELS // 1_000_000} million pixels"
    try:
        with Image.open(BytesIO(raw), formats=formats) as im:
            # a multi-picture JPEG (a phone's or a 3D camera's) is read by JPEG's reader: its first picture
            fmt = "JPEG" if im.format == "MPO" else im.format
            if fmt not in formats:
                raise _Refused(f"unsupported image format {fmt}")
            im.seek(0)                                   # first frame only (APNG, GIF, MPO)
            # before anything is decoded. Pillow itself refuses only past twice MAX_IMAGE_PIXELS (it
            # warns in between)
            if im.size[0] * im.size[1] > MAX_PIXELS:
                raise _Refused(f"image is {im.size[0]}x{im.size[1]}, over {MAX_PIXELS // 1_000_000} million pixels")
            if max(im.size) > MAX_SIDE:
                raise _Refused(f"image is {im.size[0]}x{im.size[1]}, over {MAX_SIDE}px")
            alpha = fmt != "JPEG" and (im.mode in ("RGBA", "LA", "PA") or "transparency" in im.info)
            # upright, as it's seen: the orientation a phone writes in its EXIF goes with the rest of
            # that. In place, and converted only when the mode differs: each was a copy of the pixels
            ImageOps.exif_transpose(im, in_place=True)
            pixels = _eight_bit(im) if im.mode in SIXTEEN_BIT else im
            mode = "RGBA" if alpha else "RGB"
            if pixels.mode != mode:
                pixels = pixels.convert(mode)
            # a brand-new image with the pixels copied into it: no .info, so nothing can be carried
            # over. (Until Nov 2026 by way of tobytes(), which held the pixels twice more.)
            fresh = Image.new(mode, pixels.size)
            fresh.paste(pixels)
            fmt = "JPEG" if fmt == "JPEG" else "PNG"
        del pixels                                       # the decoded picture is gone before it is encoded
        out = BytesIO()
        if fmt == "JPEG":
            fresh.save(out, "JPEG", quality=90)
            return Cleaned(out.getvalue(), "jpg")
        fresh.save(out, "PNG")
        return Cleaned(out.getvalue(), "png")
    except _Refused:
        raise
    except UnidentifiedImageError as e:
        raise ValueError(f"unsupported image format: not {', '.join(formats[:-1])} or {formats[-1]}") from e
    except Image.DecompressionBombError as e:
        raise ValueError(too_large) from e
    except Exception as e:  # noqa: BLE001
        # a damaged or crafted file: OSError and SyntaxError mostly, but a reader's struct.error or
        # TypeError on a field it didn't expect went past those, to the page as a server error
        raise ValueError(f"not a readable PNG or JPEG image ({type(e).__name__}: {e})") from e
