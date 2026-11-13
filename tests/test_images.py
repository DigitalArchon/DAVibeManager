"""Attached images carry nothing but their pixels: no metadata, no embedded thumbnail, no
hidden frames or trailing bytes, and blacked-out areas stay black."""

import base64
import os
import random
import struct
import subprocess
import sys
import zlib
from io import BytesIO

import pytest
from PIL import Image, PngImagePlugin

from davibemanager.safety import images


SECRETS = [b"GPS-SECRET", b"THUMB-SECRET", b"XMP-SECRET", b"COMMENT-SECRET", b"PHOTOSHOP-SECRET",
           b"TRAILING-SECRET", b"PNGTEXT-SECRET", b"ICC-SECRET", b"FRAME2"]


def _segment(marker: int, payload: bytes) -> bytes:
    return struct.pack(">BBH", 0xFF, marker, len(payload) + 2) + payload


def jpeg_with_everything() -> bytes:
    """A real JPEG with EXIF (+ an embedded thumbnail JPEG), XMP, Photoshop IRB, a comment,
    and bytes after the end-of-image marker."""
    buf = BytesIO()
    Image.new("RGB", (64, 48), (200, 30, 30)).save(buf, "JPEG")
    body = buf.getvalue()
    thumb = BytesIO()
    Image.new("RGB", (8, 8), (0, 255, 0)).save(thumb, "JPEG", comment=b"THUMB-SECRET")
    exif = b"Exif\x00\x00" + b"GPS-SECRET " + thumb.getvalue()
    extra = (_segment(0xE1, exif) + _segment(0xE1, b"http://ns.adobe.com/xap/1.0/\x00XMP-SECRET")
             + _segment(0xED, b"Photoshop 3.0\x00PHOTOSHOP-SECRET") + _segment(0xFE, b"COMMENT-SECRET"))
    return body[:2] + extra + body[2:] + b"TRAILING-SECRET"


def png_chunks(data: bytes) -> list[str]:
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    out, i = [], 8
    while i < len(data):
        n = struct.unpack(">I", data[i:i + 4])[0]
        out.append(data[i + 4:i + 8].decode())
        i += 12 + n
    return out


def jpeg_markers(data: bytes) -> list[int]:
    """Marker bytes of the segments before the image data."""
    out, i = [], 2
    while i < len(data):
        assert data[i] == 0xFF
        m = data[i + 1]
        out.append(m)
        if m == 0xDA:          # start of scan: image data follows
            break
        i += 2 + struct.unpack(">H", data[i + 2:i + 4])[0]
    return out


def test_jpeg_metadata_thumbnail_and_trailing_bytes_are_gone():
    dirty = jpeg_with_everything()
    for s in (b"GPS-SECRET", b"THUMB-SECRET", b"XMP-SECRET", b"COMMENT-SECRET", b"PHOTOSHOP-SECRET", b"TRAILING-SECRET"):
        assert s in dirty
    clean, ext = images.clean(dirty)
    assert ext == "jpg"
    for s in SECRETS:
        assert s not in clean
    assert clean.count(b"\xff\xd8") == 1                        # exactly one image: no embedded thumbnail
    assert clean.endswith(b"\xff\xd9")                          # nothing after end-of-image
    markers = jpeg_markers(clean)
    assert not [m for m in markers if 0xE1 <= m <= 0xEF or m == 0xFE]   # no APP1-15, no comments
    with Image.open(BytesIO(clean)) as im:
        assert "exif" not in im.info and "comment" not in im.info and not im.getexif()
        assert im.size == (64, 48)


def test_png_text_icc_exif_and_trailing_bytes_are_gone():
    info = PngImagePlugin.PngInfo()
    info.add_text("Author", "PNGTEXT-SECRET")
    info.add_itxt("Comment", "PNGTEXT-SECRET", zip=True)
    info.add_text("Software", "PNGTEXT-SECRET", zip=True)
    exif = Image.Exif()
    exif[0x010F] = "GPS-SECRET"
    buf = BytesIO()
    Image.new("RGBA", (40, 30), (10, 20, 30, 128)).save(buf, "PNG", pnginfo=info, exif=exif,
                                                          icc_profile=b"ICC-SECRET" * 20)
    dirty = buf.getvalue() + b"TRAILING-SECRET"
    assert {"tEXt", "iTXt", "zTXt", "eXIf", "iCCP"} <= set(png_chunks(dirty[:-15]))
    clean, ext = images.clean(dirty)
    assert ext == "png"
    assert set(png_chunks(clean)) == {"IHDR", "IDAT", "IEND"}
    pixels = zlib.decompress(b"".join(_idat(clean)))
    for s in SECRETS:
        assert s not in clean and s not in pixels
    with Image.open(BytesIO(clean)) as im:
        assert im.mode == "RGBA" and im.getpixel((0, 0)) == (10, 20, 30, 128)   # transparency kept


def _idat(data: bytes) -> list[bytes]:
    out, i = [], 8
    while i < len(data):
        n = struct.unpack(">I", data[i:i + 4])[0]
        if data[i + 4:i + 8] == b"IDAT":
            out.append(data[i + 8:i + 8 + n])
        i += 12 + n
    return out


def test_animated_png_keeps_only_the_first_frame():
    frames = [Image.new("RGB", (20, 20), (0, 0, 0)), Image.new("RGB", (20, 20), (255, 255, 255))]
    buf = BytesIO()
    frames[0].save(buf, "PNG", save_all=True, append_images=frames[1:])
    assert "acTL" in png_chunks(buf.getvalue())
    clean, _ = images.clean(buf.getvalue())
    assert set(png_chunks(clean)) == {"IHDR", "IDAT", "IEND"}
    with Image.open(BytesIO(clean)) as im:
        assert im.getpixel((10, 10)) == (0, 0, 0) and getattr(im, "n_frames", 1) == 1


def test_blacked_out_pixels_are_black_after_cleaning():
    """The editor paints black into the bitmap; cleaning must keep exactly that, losslessly."""
    noise = Image.frombytes("RGB", (120, 80), os.urandom(120 * 80 * 3))
    for x in range(30, 70):                           # the redacted box, as the editor makes it
        for y in range(20, 50):
            noise.putpixel((x, y), (0, 0, 0))
    buf = BytesIO()
    noise.save(buf, "PNG")
    clean, _ = images.clean(buf.getvalue())
    with Image.open(BytesIO(clean)) as im:
        assert all(im.getpixel((x, y)) == (0, 0, 0) for x in range(30, 70) for y in range(20, 50))
        assert im.tobytes() == noise.tobytes()        # nothing else changed (lossless)


def test_other_formats_and_oversize_are_refused():
    for fmt in ("GIF", "WEBP", "BMP"):
        buf = BytesIO()
        Image.new("RGB", (4, 4)).save(buf, fmt)
        with pytest.raises(ValueError, match="unsupported"):
            images.clean(buf.getvalue())
    with pytest.raises(ValueError):
        images.clean(b"not an image")
    buf = BytesIO()
    Image.new("L", (12000, 1)).save(buf, "PNG")
    with pytest.raises(ValueError, match="over"):
        images.clean(buf.getvalue())


def bare_png(width: int, height: int, depth: int, colour: int, channels: int = 1) -> bytes:
    """A blank PNG written by hand, so that making it costs no memory to speak of: a few kilobytes
    that say they are width x height."""
    def chunk(tag: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body))
    row = b"\0" * (1 + (width * channels * depth + 7) // 8)
    packer = zlib.compressobj(9)
    data = b"".join(packer.compress(row) for _ in range(height)) + packer.flush()
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, depth, colour, 0, 0, 0))
            + chunk(b"IDAT", data) + chunk(b"IEND", b""))


_MEASURE = """
import resource, sys
from davibemanager.safety import images
raw = open(sys.argv[1], "rb").read()
before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
try:
    said = images.clean(raw).ext
except ValueError as e:
    said = "refused: " + str(e)
print((resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before) // 1024, said)
"""


def _cost_of_cleaning(tmp_path, raw: bytes) -> tuple[int, str]:
    """(MB that cleaning `raw` added to a fresh process's peak memory, what clean() said)."""
    path = tmp_path / "picture.png"
    path.write_bytes(raw)
    out = subprocess.run([sys.executable, "-B", "-c", _MEASURE, str(path)], capture_output=True, text=True, timeout=120, check=True)
    mb, said = out.stdout.strip().split(" ", 1)
    return int(mb), said


def test_a_small_file_that_says_it_is_huge_costs_no_memory(tmp_path):
    # 5 KB of PNG, 1 bit a pixel, 8000 x 5000: cleaning it took 460 MB. It is refused by its header,
    # before a pixel is decoded
    bomb = bare_png(8000, 5000, 1, 0)
    assert len(bomb) < 10_000
    mb, said = _cost_of_cleaning(tmp_path, bomb)
    assert said.startswith("refused") and "million pixels" in said and mb < 30, (mb, said)
    with pytest.raises(ValueError, match="over 4096px"):
        images.clean(bare_png(5000, 100, 1, 0))


@pytest.mark.parametrize("depth,colour,channels", [(1, 0, 1), (8, 2, 3), (8, 6, 4)], ids=["1 bit", "RGB", "RGBA"])
def test_the_largest_picture_taken_is_cleaned_in_two_copies_of_its_pixels(tmp_path, depth, colour, channels):
    # 4096 x 3072, a phone's 12-megapixel photo: 50 MB of pixels as Pillow holds them. Four copies were
    # alive at once (decoded, upright, converted, and the bytes of the new image)
    mb, said = _cost_of_cleaning(tmp_path, bare_png(images.MAX_SIDE, images.MAX_PIXELS // images.MAX_SIDE, depth, colour, channels))
    assert said == "png" and mb < 180, (mb, said)


def _photo_with_exif() -> bytes:
    exif = Image.Exif()
    exif[0x0112] = 6                                       # Orientation: the phone was held sideways
    exif[0x010F] = "cam"                                   # Make
    buf = BytesIO()
    Image.effect_noise((40, 30), 50).convert("RGB").save(buf, "JPEG", exif=exif.tobytes())
    return buf.getvalue()


@pytest.mark.parametrize("tag", [0x011B, 0x0123, 0x014E], ids=["a text where a fraction belongs", "... a number", "... another"])
def test_exif_that_pillow_cant_write_back_is_a_refusal_not_a_server_error(tag):
    # one flipped byte: the camera's name stands under a tag that holds numbers. Turning the photo
    # upright writes its EXIF anew, which raised struct.error or TypeError past the ValueError the
    # caller turns into "Could not use an attached image"
    photo = _photo_with_exif()
    at = photo.index(b"\x01\x0f\x00\x02")                  # the Make tag, of type ASCII
    damaged = photo[:at] + struct.pack(">H", tag) + photo[at + 2:]
    assert images.clean(photo).ext == "jpg"
    with pytest.raises(ValueError, match="not a readable"):
        images.clean(damaged)


@pytest.mark.filterwarnings("ignore::UserWarning")                        # Pillow's, of the damage it reads past
def test_a_damaged_picture_is_cleaned_or_refused_and_nothing_else():
    # cut short at every length, and with bytes changed, dropped and added all over: whatever the
    # readers make of it, clean() returns a picture or raises ValueError
    def encoded(image, fmt, **kw):
        buf = BytesIO()
        image.save(buf, fmt, **kw)
        return buf.getvalue()
    noise = Image.effect_noise((40, 30), 50).convert("RGB")
    whole = [encoded(noise, "PNG"), encoded(noise.convert("P"), "PNG", transparency=0), encoded(noise.convert("RGBA"), "PNG"),
             encoded(Image.new("I;16", (40, 30), 3000), "PNG"), _photo_with_exif(), encoded(noise, "JPEG", progressive=True),
             encoded(noise.convert("CMYK"), "JPEG"), encoded(noise, "MPO", save_all=True, append_images=[noise]),
             encoded(noise, "PNG", save_all=True, append_images=[noise, noise])]
    rng = random.Random(7)
    damaged = [picture[:n] for picture in whole for n in range(0, len(picture), 7)]
    for picture in whole:
        for _ in range(400):
            raw = bytearray(picture)
            for _ in range(rng.choice((1, 1, 2, 4, 8))):
                k, how = rng.randrange(len(raw)), rng.random()
                if how < 0.5:
                    raw[k] = rng.randrange(256)
                elif how < 0.7:
                    del raw[k:k + rng.randrange(1, 20)]
                elif how < 0.85:
                    raw[k:k] = rng.randbytes(rng.randrange(1, 8))
                else:
                    raw[k:k + 4] = rng.choice((b"\xff\xff\xff\xff", b"\x00\x00\x00\x00", b"\x7f\xff\xff\xff", b"\x00\x00\x27\x10"))
            damaged.append(bytes(raw))
    cleaned = refused = 0
    for raw in damaged:
        try:
            images.clean(raw)
            cleaned += 1
        except ValueError:
            refused += 1
    assert cleaned + refused == len(damaged) and cleaned and refused

