"""Checks on a delivered AppImage before anything on this computer touches it.

Gear Lever and Shelly read an AppImage's menu entry and icon by running it with
--appimage-extract, which runs the AppImage's runtime: the ELF program in front of its squashfs.
That is code of the build's choosing. So a delivered AppImage must carry exactly the pinned type
2 runtime (workspace/pins.py), byte for byte, but for the sections appimagetool fills in itself
(update information, signature, key, digest). Then integrating it runs only known code; the app's
own code runs only when the user opens it.

The menu entry this app writes itself (when neither is there) is rebuilt from the AppImage's
own, keeping only keys that describe the app: its Exec is ours, and nothing in it can start by
itself.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

# filled in by appimagetool (update information, signature), so not compared
WRITABLE_SECTIONS = (".upd_info", ".sha256_sig", ".sig_key", ".digest_md5")


class AppImageError(ValueError):
    pass


def _elf64(data: bytes) -> tuple[int, int, int, int]:
    """(section header offset, entry size, count, index of the names section)."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise AppImageError("not a 64-bit little-endian ELF file")
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    return shoff, shentsize, shnum, shstrndx


def elf_end(data: bytes) -> int:
    """Where the ELF part ends: the end of its section headers (where an AppImage's squashfs starts)."""
    shoff, shentsize, shnum, _ = _elf64(data)
    return shoff + shentsize * shnum


def sections(data: bytes) -> dict[str, tuple[int, int]]:
    """Section name -> (file offset, size)."""
    shoff, shentsize, shnum, shstrndx = _elf64(data)
    if shentsize != 64 or shoff + shentsize * shnum > len(data) or shstrndx >= shnum:
        raise AppImageError("broken section headers")
    headers = [struct.unpack_from("<IIQQQQ", data, shoff + i * shentsize) for i in range(shnum)]
    str_off, str_size = headers[shstrndx][4], headers[shstrndx][5]
    names = data[str_off:str_off + str_size]
    out = {}
    for name_off, _type, _flags, _addr, off, size in headers:
        end = names.find(b"\0", name_off)
        out[names[name_off:end].decode("ascii", "replace")] = (off, size)
    return out


def _masked(data: bytes) -> bytes:
    buf = bytearray(data)
    for name, (off, size) in sections(data).items():
        if name in WRITABLE_SECTIONS and off + size <= len(buf):
            buf[off:off + size] = bytes(size)
    return bytes(buf)


def check_runtime(appimage: Path, runtime: bytes) -> None:
    """Raise unless `appimage` starts with exactly `runtime` (but for the writable sections)."""
    with appimage.open("rb") as f:
        head = f.read(len(runtime) + 1)
    try:
        end = elf_end(head)
    except AppImageError as e:
        raise AppImageError(f"its runtime isn't an ELF program ({e})") from None
    if end != len(runtime) or len(head) <= end:
        raise AppImageError("it doesn't use the pinned AppImage runtime (its runtime has a different size)")
    if _masked(head[:end]) != _masked(runtime):
        raise AppImageError("it doesn't use the pinned AppImage runtime (its runtime's code differs)")


# ---------------------------------------------------------------- its menu entry

# what may come over from the AppImage's own entry: what the app is and which files it opens
KEEP_KEYS = ("Name", "GenericName", "Comment", "Categories", "Keywords", "MimeType", "StartupWMClass",
             "Terminal", "StartupNotify", "SingleMainWindow")
_FIELD_CODES = re.compile(r"%[fFuU]")


def read_desktop(text: str) -> dict[str, str]:
    """The [Desktop Entry] group of a .desktop file: key -> value (localised keys too)."""
    out, group = {}, ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            group = line[1:-1]
            continue
        if group == "Desktop Entry" and "=" in line:
            k, v = line.split("=", 1)
            out.setdefault(k.strip(), v.strip())
    return out


def menu_entry(original: str, exec_path: str, icon: str, app_id: str) -> str:
    """Our .desktop file for an installed AppImage, from its own: our Exec and Icon, its descriptive keys."""
    src = read_desktop(original)
    if src.get("Type", "Application") != "Application":
        raise AppImageError("its menu entry isn't for an application")
    codes = _FIELD_CODES.findall(src.get("Exec", ""))[:1]
    lines = ["[Desktop Entry]", "Type=Application",
             "Exec=" + " ".join([_quote(exec_path), *codes]), f"Icon={icon}", f"X-DVM-App={app_id}"]
    for key, value in src.items():
        base = key.split("[", 1)[0]
        if base in KEEP_KEYS and "\n" not in value and len(value) < 2000:
            lines.append(f"{key}={value}")
    if "Name" not in src:
        lines.append(f"Name={app_id}")
    return "\n".join(lines) + "\n"


def _quote(path: str) -> str:
    """A path as a .desktop Exec argument."""
    if re.fullmatch(r"[\w./+-]+", path):
        return path
    return '"' + re.sub(r'(["`$\\])', r"\\\1", path) + '"'
