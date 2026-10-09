"""Omarchy (Arch with Hyprland and its own Quickshell desktop): knowing it's here, what it lacks for
the apps this app builds and for this app itself, and this app's own entry in its menu.

Omarchy has no AppImage manager. Its launcher (the menu's Apps, Super + Space) lists the desktop
entries in the XDG folders as they come and go, and finds an icon by name in the user's icon theme
folders; its own web apps and TUIs are a .desktop file in ~/.local/share/applications with an icon
in ~/.local/share/icons/hicolor/256x256/apps. Apps installed here go the same way (integrate.Omarchy).

What an app built here needs to start: FUSE 3's fusermount3, since every build carries the pinned
static AppImage runtime (workspace/pins.py), which brings its own libfuse. This app itself needs
WebKitGTK 4.1 for its window and an AppIndicator library for its tray icon. Omarchy 4.0.4 has all
three, so this is a check that usually finds nothing to do; what's missing is installed only on
the user's click, with the app's own fixed command, as administrator through pkexec.

Seen on Omarchy 4.0.4: /etc/os-release says ID=omarchy (ID_LIKE=arch), and the session has
OMARCHY_PATH=/usr/share/omarchy. Omarchy 3 kept Arch's os-release and lived in ~/.local/share/omarchy.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable

from . import appimage, sysinfo
from .hostenv import HOST_TYPELIB_DIRS, host_env

# package -> what it's for, in the user's words
PACKAGES = {
    "fuse3": "to start the apps DA Vibe Manager builds",
    "webkit2gtk-4.1": "for DA Vibe Manager's own window",
    "libayatana-appindicator": "for DA Vibe Manager's icon in the top bar",
}
# never -Sy alone: installing on a stale package list is a partial upgrade (Arch's rule)
INSTALL = "pacman -S --needed --noconfirm {pkgs}"
SELF_ENTRY = "davibemanager.desktop"
SELF_ICON = "davibemanager"

_detected: dict | None | bool = False      # False: not looked yet


def _home() -> Path:
    return Path(os.path.expanduser("~"))


def data_home() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME") or _home() / ".local/share")


def applications_dir() -> Path:
    return data_home() / "applications"


def icon_theme_dir() -> Path:
    """The user's own hicolor icon theme, where Omarchy's launcher looks for icons by name."""
    return data_home() / "icons" / "hicolor"


def detect(rel: dict | None = None, env: dict | None = None, roots: tuple[str, ...] | None = None) -> dict | None:
    """{"version", "path"} on Omarchy, else None. Read once per process unless given its inputs (tests)."""
    global _detected
    cached = rel is None and env is None and roots is None
    if cached and _detected is not False:
        return _detected  # type: ignore[return-value]
    rel = sysinfo._os_release() if rel is None else rel
    env = os.environ if env is None else env
    candidates = [env.get("OMARCHY_PATH", "")] + list(roots if roots is not None else
                                                     ("/usr/share/omarchy", str(_home() / ".local/share/omarchy")))
    path = next((p for p in candidates if p and Path(p, "bin", "omarchy-version").is_file()), "")
    found = None
    if rel.get("ID", "").lower() == "omarchy" or path:
        found = {"version": _version(path), "path": path}
    if cached:
        _detected = found
    return found


def _version(path: str) -> str:
    """Omarchy's version: what its own command says (the package's), else its checkout's version file."""
    cmd = shutil.which("omarchy-version") or (str(Path(path, "bin", "omarchy-version")) if path else "")
    if cmd:
        try:
            out = subprocess.run([cmd], env=host_env(), capture_output=True, text=True, timeout=5).stdout.strip()
            if out:
                return out.splitlines()[0][:40]
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        return Path(path, "version").read_text(encoding="utf-8").strip()[:40] if path else ""
    except OSError:
        return ""


def fuse_ok(which: Callable[[str], str | None] | None = None) -> bool:
    """Whether an AppImage with the static runtime can mount itself here."""
    which = which or shutil.which
    return bool(which("fusermount3") or which("fusermount"))


def missing(which: Callable[[str], str | None] | None = None,
            typelib_dirs: tuple[str, ...] = HOST_TYPELIB_DIRS) -> list[str]:
    """The packages Omarchy lacks for this app and the apps it builds ([] when all is there)."""
    def typelib(*names: str) -> bool:
        return any(os.path.exists(f"{d}/{n}.typelib") for d in typelib_dirs for n in names)
    out = []
    if not fuse_ok(which):
        out.append("fuse3")
    if not typelib("WebKit2-4.1"):
        out.append("webkit2gtk-4.1")
    if not typelib("AyatanaAppIndicator3-0.1", "AppIndicator3-0.1"):
        out.append("libayatana-appindicator")
    return out


def plan(which: Callable[[str], str | None] | None = None,
         typelib_dirs: tuple[str, ...] = HOST_TYPELIB_DIRS) -> dict | None:
    """What to install and how, for the window; None when nothing is missing."""
    which = which or shutil.which
    need = missing(which, typelib_dirs)
    if not need:
        return None
    command = INSTALL.format(pkgs=" ".join(need))
    return {
        "missing": [{"package": p, "for": PACKAGES[p]} for p in need],
        "packages": need,
        "command": command,
        "terminal": f"sudo {command}",
        "can_install": bool(which("pacman")) and bool(which("pkexec")),
    }


# ---------------------------------------------------------------- this app's own menu entry

SELF_DESKTOP = """[Desktop Entry]
Type=Application
Name=DA Vibe Manager
GenericName=Custom app creator and package manager
Comment=Add the features you wish your apps had, keep them up to date, and get them working on your computer
Exec={exec}
Icon={icon}
StartupWMClass=davibemanager
Terminal=false
Categories=Utility;
Keywords=help;assistant;ai;linux;settings;apps;packages;updates;vibe;
X-DVM-Self=true
"""


def self_entry_path() -> Path:
    return applications_dir() / SELF_ENTRY


def has_self_entry() -> bool:
    """Whether this app is in the menu under its own name (by us, or by whatever else put it there)."""
    return self_entry_path().is_file()


def _ours() -> bool:
    try:
        return "X-DVM-Self=true" in self_entry_path().read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False


def self_exec(argv: list[str]) -> str:
    """The Exec line for the command that starts this copy of the app (desktop-entry quoting)."""
    return " ".join(appimage._quote(a) for a in argv)


def add_self_entry(argv: list[str], icon: Path) -> Path:
    """Put this app in Omarchy's menu (the user's click): an entry that starts this copy of it, and
    its icon in the user's icon theme."""
    dest_icon = icon_theme_dir() / "scalable" / "apps" / f"{SELF_ICON}{icon.suffix}"
    dest_icon.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(icon, dest_icon)
    path = self_entry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".part")
    tmp.write_text(SELF_DESKTOP.format(exec=self_exec(argv), icon=SELF_ICON), encoding="utf-8")
    tmp.replace(path)
    refresh_caches()
    return path


def refresh_self_entry(argv: list[str], icon: Path) -> None:
    """At each start: if this app's own entry is there, have it start this copy (an AppImage may have
    been moved or replaced by a newer one). One the user removed in Omarchy stays removed."""
    try:
        if _ours() and self_entry_path().read_text(encoding="utf-8") != \
                SELF_DESKTOP.format(exec=self_exec(argv), icon=SELF_ICON):
            add_self_entry(argv, icon)
    except OSError:
        pass


def refresh_caches() -> None:
    """The icon theme's and the menu's caches (best effort: Omarchy's launcher finds both without)."""
    for argv in (["gtk-update-icon-cache", "-q", "-t", str(icon_theme_dir())],
                 ["update-desktop-database", str(applications_dir())]):
        if not shutil.which(argv[0]) or not Path(argv[-1]).is_dir():
            continue
        try:
            subprocess.run(argv, env=host_env(), capture_output=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            pass
