"""What the builder hands over, and installing it.

A delivery is copied out of the container into the project's quarantine
(deliveries/D<n>/) together with what is needed to understand it and to make it again on a
future upstream version: the patch series against the upstream base, FEATURE.md and the
facts (upstream URL, base and head commits, sha256). Nothing in it is run. Installing copies
the AppImage (or the source tree, or the add-on) to where it belongs; starting it is the user's
click.

Kinds: "appimage" (a whole app), "source" (a tree to build), and "addon": files for an app
that loads them itself (an mpv script, a GIMP plug-in, a theme), copied into a folder of the
user's choosing under their home, never one that runs things at login or holds secrets.

An update of an earlier delivery ("replaces") belongs to the same line; installing it takes
the place of the one before.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
from pathlib import Path, PurePosixPath

from .config import data_dir

KINDS = ("appimage", "source", "addon")
# how deep a delivered change goes: an ordinary app, part of the desktop, or below it
INTEGRATIONS = ("app", "desktop", "system")
MAX_FEATURE = 64 * 1024
MAX_ADDON_FILES = 200

# folders (under the home) an add-on may never be installed into: what runs at login or with
# every shell, what is on PATH (and every folder on this computer's PATH: addon_dir), where keys,
# passwords and browser profiles are, and Podman's own settings and storage (the sandbox's wall:
# a containers.conf.d file could mount the home into the sandbox, or run hooks on this computer)
ADDON_FORBIDDEN = (
    # keys, passwords, tokens
    ".ssh", ".gnupg", ".pki", ".password-store", ".local/share/keyrings", ".aws", ".kube", ".docker",
    ".config/gcloud", ".config/gh", ".config/rclone", ".config/pip", ".netrc.d",
    # browsers and messengers (also as Flatpaks and Snaps: .var/app, snap)
    ".mozilla", ".thunderbird", ".librewolf", ".waterfox", ".config/google-chrome", ".config/chromium",
    ".config/BraveSoftware", ".config/vivaldi", ".config/microsoft-edge", ".config/opera", ".config/Signal",
    ".var", "snap",
    # what starts by itself: at login, with the session, on D-Bus activation, in every shell
    ".config/autostart", ".config/systemd", ".local/share/systemd", ".config/environment.d",
    ".config/plasma-workspace", ".kde/Autostart", ".local/share/dbus-1", ".config/fish", ".config/nushell",
    ".config/zsh", ".zsh", ".oh-my-zsh", ".config/bash", ".local/share/bash-completion", ".bashrc.d",
    ".config/sway", ".config/i3", ".config/hypr", ".config/openbox", ".config/labwc", ".config/niri",
    ".config/river", ".config/lxsession", ".config/xdg/autostart",
    # programs found by name (on PATH in many setups, whatever this one's PATH says)
    ".local/bin", "bin", ".cargo/bin", "go/bin", ".go/bin", ".npm-global", ".deno/bin", ".bun/bin", ".pyenv",
    ".nix-profile", ".local/share/flatpak", ".config/flatpak",
    # the sandbox's wall, and this app's own
    ".config/containers", ".local/share/containers", ".config/davibemanager", ".local/share/davibemanager",
    # the desktop's own records
    ".config/git", ".local/share/applications", ".config/dconf",
)


class DeliveryError(ValueError):
    pass


def root_dir() -> Path:
    d = data_dir() / "deliveries"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


def check_work_path(path: str) -> str:
    """A path inside the container's /work, normalised; anything else is refused."""
    p = PurePosixPath(str(path or "").strip())
    if not p.is_absolute() or ".." in p.parts or p.parts[:2] != ("/", "work") or len(p.parts) < 3:
        raise DeliveryError(f"{str(path)[:120]!r} isn't a path under /work")
    return str(p)


def check_ref(ref: str) -> str:
    """A git ref or commit as given to git: no options, no ranges, no shell."""
    ref = str(ref or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/@{}^~+-]{0,199}", ref) or ".." in ref:
        raise DeliveryError(f"{ref[:80]!r} isn't a tag or commit")
    return ref


def check_install_to(text: str) -> str:
    """Where an add-on goes, as "~/relative/folder": a folder at least two levels under the home,
    and none of ADDON_FORBIDDEN."""
    raw = str(text or "").strip()
    if not raw.startswith("~/"):
        raise DeliveryError(f"install_to must be a folder in the user's home, written ~/…, not {raw[:80]!r}")
    p = PurePosixPath(raw[2:])
    if not p.parts or p.is_absolute() or any(part in ("..", ".", "") for part in p.parts):
        raise DeliveryError(f"{raw[:80]!r} isn't a plain folder path")
    if len(p.parts) < 2:
        raise DeliveryError(f"{raw[:80]!r} is too close to the home folder; name the app's own folder")
    if forbidden_place(p):
        raise DeliveryError(f"Add-ons can't be installed into {raw[:80]}: things there run by themselves or hold secrets")
    return "~/" + str(p)


def forbidden_place(rel: PurePosixPath) -> bool:
    return any(rel.parts[:len(PurePosixPath(f).parts)] == PurePosixPath(f).parts for f in ADDON_FORBIDDEN)


def path_folders(home: Path, path: str | None = None) -> list[PurePosixPath]:
    """The folders on this computer's PATH that are in the home, relative to it: a program put
    there would run in place of a system one of the same name."""
    home = home.resolve()
    out = []
    for entry in (os.environ.get("PATH", "") if path is None else path).split(":"):
        if not entry:
            continue
        try:
            out.append(PurePosixPath(Path(os.path.expanduser(entry)).resolve().relative_to(home).as_posix()))
        except (ValueError, OSError):
            continue
    return out


def on_path(rel: PurePosixPath, home: Path, path: str | None = None) -> bool:
    return any(rel.parts[:len(p.parts)] == p.parts for p in path_folders(home, path) if p.parts)


def addon_dir(install_to: str, home: Path, path: str | None = None) -> Path:
    """The add-on's folder on this computer, checked again after symlinks are resolved, and
    against the folders on this computer's PATH."""
    rel = PurePosixPath(check_install_to(install_to)[2:])
    home = home.resolve()
    dest = (home / rel).resolve()
    try:
        real = PurePosixPath(dest.relative_to(home).as_posix())
    except ValueError:
        raise DeliveryError(f"{install_to} leads outside the home folder") from None
    if len(real.parts) < 2 or forbidden_place(real):
        raise DeliveryError(f"{install_to} leads to {dest}, where add-ons can't go")
    if on_path(real, home, path):
        raise DeliveryError(f"{install_to} is where this computer looks for programs to run (on PATH), so add-ons can't go there")
    return dest


def tree_sha256(root: Path) -> str:
    """One hash over a file or folder: every path and its content, in order."""
    h = hashlib.sha256()
    items = [root] if root.is_file() else sorted(p for p in root.rglob("*"))
    for p in items:
        rel = p.name if p == root else p.relative_to(root).as_posix()
        if p.is_symlink():
            h.update(b"L" + rel.encode() + b"\0" + os.readlink(p).encode() + b"\0")
        elif p.is_file():
            h.update(b"F" + rel.encode() + b"\0" + bytes.fromhex(sha256_file(p)) + bytes([p.stat().st_mode & 0o111 != 0]))
        elif p.is_dir():
            h.update(b"D" + rel.encode() + b"\0")
    return h.hexdigest()


def check_addon_files(root: Path) -> list[Path]:
    """The add-on's files: regular files and folders only, and not too many."""
    files = [root] if root.is_file() else sorted(root.rglob("*"))
    for p in files:
        if p.is_symlink() or not (p.is_file() or p.is_dir()):
            raise DeliveryError(f"{p.name}: add-ons may hold only ordinary files and folders")
    if len(files) > MAX_ADDON_FILES:
        raise DeliveryError(f"An add-on of more than {MAX_ADDON_FILES} files is an app: deliver it as appimage or source")
    return files


def safe_name(text: str, fallback: str = "app") -> str:
    return re.sub(r"[^A-Za-z0-9._+-]+", "-", str(text or "")).strip("-.")[:60] or fallback


def next_id(root: Path) -> str:
    nums = [int(m.group(1)) for d in root.iterdir() if (m := re.fullmatch(r"D(\d+)", d.name))] if root.is_dir() else []
    return f"D{max(nums, default=0) + 1}"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def is_appimage(path: Path) -> bool:
    """An ELF file carrying the type 2 AppImage magic (AI\\x02 at offset 8)."""
    try:
        with path.open("rb") as f:
            head = f.read(11)
    except OSError:
        return False
    return head[:4] == b"\x7fELF" and head[8:11] == b"AI\x02"


def record(dir_: Path, meta: dict) -> dict:
    meta = {**meta, "id": dir_.name}
    tmp = dir_ / "delivery.json.tmp"
    tmp.write_text(json.dumps(meta, indent=1, ensure_ascii=False), encoding="utf-8")
    tmp.replace(dir_ / "delivery.json")
    return meta


def load(dir_: Path) -> dict | None:
    try:
        return json.loads((dir_ / "delivery.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def list_all(root: Path) -> list[dict]:
    if not root.is_dir():
        return []
    out = [m for d in root.iterdir() if d.is_dir() and (m := load(d))]
    out.sort(key=lambda m: int(m["id"][1:]))
    return out


def patch_text(dir_: Path) -> str:
    try:
        return (dir_ / "changes.patch").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def install(dir_: Path, meta: dict, install_dir: Path, home: Path | None = None,
            previous: dict | None = None) -> dict:
    """Copy the delivery to where it belongs. `previous` is the installed delivery it updates:
    its AppImage is removed, and its add-on files are replaced without a backup. Returns the
    delivery's record."""
    install_dir = install_dir.expanduser()
    home = home or Path.home()
    name = safe_name(meta.get("name"))
    version = safe_name(meta.get("version"), "build")
    extra: dict = {}
    if meta["kind"] == "addon":
        src = dir_ / "addon"
        if tree_sha256(src) != meta["sha256"]:
            raise DeliveryError("The add-on in quarantine no longer matches its recorded sha256; not installed.")
        dest = addon_dir(meta["install_to"], home)
        ours = set((previous or {}).get("installed_files", []))
        dest.mkdir(parents=True, exist_ok=True)
        installed, backups = [], []
        for item in sorted(src.iterdir()):
            target = dest / item.name
            if target.exists() or target.is_symlink():
                if str(target) in ours:
                    shutil.rmtree(target) if target.is_dir() and not target.is_symlink() else target.unlink()
                else:
                    # the user's own file of that name: kept, beside it
                    backup = target.with_name(f"{target.name}.before-{meta['id']}")
                    if backup.exists():
                        raise DeliveryError(f"{target} and {backup} both exist; move one away first.")
                    target.rename(backup)
                    backups.append(str(backup))
            if item.is_dir():
                shutil.copytree(item, target)
            else:
                shutil.copy2(item, target)
            installed.append(str(target))
        extra = {"installed_files": installed, "backups": backups}
    elif meta["kind"] == "appimage":
        src = dir_ / meta["file"]
        if sha256_file(src) != meta["sha256"]:
            raise DeliveryError("The AppImage in quarantine no longer matches its recorded sha256; not installed.")
        install_dir.mkdir(parents=True, exist_ok=True)
        dest = install_dir / f"{name}-{version}-dvm.AppImage"
        tmp = dest.with_name(dest.name + ".part")
        shutil.copyfile(src, tmp)
        os.chmod(tmp, 0o755)
        tmp.replace(dest)
    else:
        src = dir_ / "source"
        dest = install_dir / "src" / f"{name}-{version}"
        if dest.exists():
            raise DeliveryError(f"{dest} already exists; move it away first.")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, dest, symlinks=True)
    if previous and previous.get("kind") == "appimage" and meta["kind"] == "appimage":
        old = Path(previous.get("installed_to") or "")
        if old != dest and old.is_file() and sha256_file(old) == previous.get("sha256"):
            old.unlink()                        # only the file as it was installed, never a changed one
            extra["removed"] = str(old)
    meta = {**meta, **extra, "status": "installed", "installed_to": str(dest), "installed_at": time.time()}
    record(dir_, meta)
    return meta


def line_of(meta: dict) -> str:
    """The first delivery of the line this one belongs to (itself, unless it is an update)."""
    return meta.get("line") or meta["id"]
