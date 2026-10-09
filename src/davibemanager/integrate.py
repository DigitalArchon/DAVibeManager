"""Where installed apps live on this computer: Gear Lever, Shelly, Omarchy's menu, or a menu entry of our own.

Each is run by this app's own code when the user clicks Install (or Roll back), never by the
assistant. Each takes a checked AppImage (appimage.check_runtime) under a stable file name, so
an update replaces the app in place and its menu entry and icon carry on:

- Gear Lever (Flatpak, any distro; or its native package): `--integrate <file> --replace`,
  answering its two questions (integrate: y; keep both or replace: r). Its `-y` skips the second
  question, and with it the record of which app is replaced, so `--replace -y` installs a second
  copy (Gear Lever 4.6.2, seen on CachyOS). Replacing keeps the file and desktop file names.
- Shelly (Arch-based distros, CachyOS's own): `shelly install appimage <file> -n` overwrites the
  AppImage of the same name in ~/.local/bin, with the same menu entry (Shelly 3.1.6, on CachyOS).
- Our own: the AppImage in the install folder, and a menu entry and icon from the ones the
  sandbox extracted from it (rebuilt from descriptive keys only: appimage.menu_entry).
- Omarchy (omarchy.py), which has no AppImage manager: our own, the Omarchy way. The icon goes in
  the user's icon theme by name, as Omarchy's web apps have theirs, and FUSE must be there first.
  Its launcher's own Remove deletes only the menu entry; the app's card then offers it back.

Removing an app (the user's click) undoes it the same way: Gear Lever's `--remove <file> -y`
(which puts the AppImage, its menu entry and icons in the Trash), Shelly's `remove appimage
<name> -n`, or our own files deleted (on Omarchy, its icon in the theme too).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from . import appimage, omarchy
from .hostenv import host_env

GEARLEVER_FLATPAK = "it.mijorus.gearlever"
TIMEOUT = 300
CHOICES = ("auto", "gearlever", "shelly", "menu", "omarchy")


class IntegrationError(RuntimeError):
    pass


def _which(name: str) -> str | None:
    """Where a program is (one place, so tests can make sure only their fakes are found)."""
    return shutil.which(name)


def _run(argv: list[str], timeout: float = TIMEOUT, answers: str | None = None) -> str:
    try:
        p = subprocess.run(argv, env=host_env(), input=answers, stdin=None if answers is not None else subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=timeout, cwd=os.path.expanduser("~"))
    except FileNotFoundError as e:
        raise IntegrationError(f"{argv[0]} isn't installed") from e
    except subprocess.TimeoutExpired as e:
        raise IntegrationError(f"{' '.join(argv[:3])} took too long") from e
    if p.returncode != 0:
        raise IntegrationError(f"{' '.join(argv[:4])} failed ({p.returncode}): {(p.stderr or p.stdout).strip()[-400:]}")
    return p.stdout


def _json_from(text: str):
    """The JSON a CLI printed, after anything it logged before it."""
    start = min((i for i in (text.find("{"), text.find("[")) if i >= 0), default=-1)
    if start < 0:
        raise IntegrationError("it printed no JSON")
    try:
        return json.loads(text[start:])
    except ValueError as e:
        raise IntegrationError(f"its JSON couldn't be read: {e}") from None


def desktop_name(desktop_dir: Path | None) -> str:
    """The app's name in its own menu entry (extracted from the AppImage in the sandbox)."""
    try:
        return appimage.read_desktop((desktop_dir / "app.desktop").read_text(encoding="utf-8", errors="replace")).get("Name", "")
    except (OSError, TypeError):
        return ""


# the short name in an app's file names and menu entry, and in its name there: "gThumb (DVM)"
TAG = "dvm"


def stable_name(app: dict) -> str:
    """The AppImage's file name for an app, the same for every version."""
    name = "".join(c if c.isalnum() or c in "._+-" else "-" for c in app["name"]).strip("-.") or app["id"]
    return f"{name}-{TAG}.AppImage"


class GearLever:
    key, label = "gearlever", "Gear Lever"

    @staticmethod
    def command() -> list[str] | None:
        if native := _which("gearlever"):
            return [native]
        if flatpak := _which("flatpak"):
            try:
                subprocess.run([flatpak, "info", GEARLEVER_FLATPAK], env=host_env(), capture_output=True,
                               timeout=20, check=True)
                return [flatpak, "run", GEARLEVER_FLATPAK]
            except (subprocess.SubprocessError, OSError):
                return None
        return None

    def available(self) -> bool:
        return self.command() is not None

    def install(self, staged: Path, app: dict, desktop_dir: Path | None) -> dict:
        cmd = self.command()
        if not cmd:
            raise IntegrationError("Gear Lever isn't installed")
        def listed() -> list[dict]:
            return _json_from(_run([*cmd, "--list-installed", "--json"])).get("installed", []) or []
        name = desktop_name(desktop_dir)
        before = listed()
        was = [e for e in before if name and e.get("name") == name]
        _run([*cmd, "--integrate", str(staged), "--replace"], answers="y\nr\n")
        after = listed()
        # Gear Lever names a new file itself, and keeps the name when it replaces one: ours is the
        # entry under our app's name, where it was, or the one that wasn't there before
        mine = [e for e in after if name and e.get("name") == name] or \
            [e for e in after if e.get("path") not in {b.get("path") for b in before}]
        if not mine:
            raise IntegrationError(f"Gear Lever doesn't list {name or staged.name} after integrating it")
        if was and (len(mine) > len(was) or mine[0].get("path") != was[0].get("path")):
            raise IntegrationError(f"Gear Lever added {name} again instead of replacing it: remove the extra copy in Gear Lever")
        return {"via": self.key, "path": mine[0]["path"], "desktop_id": mine[0].get("desktop_id") or ""}

    def uninstall(self, info: dict, app: dict, sha256: str) -> str:
        cmd = self.command()
        if not cmd:
            raise IntegrationError("Gear Lever isn't installed")
        if Path(info.get("path") or "").is_file():
            _run([*cmd, "--remove", info["path"], "-y"])
        return ""


class Shelly:
    key, label = "shelly", "Shelly"

    @staticmethod
    def command() -> list[str] | None:
        shelly = _which("shelly")
        return [shelly] if shelly else None

    def available(self) -> bool:
        return self.command() is not None

    def install(self, staged: Path, app: dict, desktop_dir: Path | None) -> dict:
        cmd = self.command()
        if not cmd:
            raise IntegrationError("Shelly isn't installed")
        _run([*cmd, "install", "appimage", str(staged), "-n"])
        # where Shelly put it (its listing's shape isn't documented: any entry naming our file)
        path, desktop_id = "", ""
        try:
            # [{"Name": "htop-dvm", "DesktopName": "htop (DVM)", "Path": "~/.local/bin/htop-dvm.AppImage", ...}]
            listed = _json_from(_run([*cmd, "list", "appimage", "--json"]))
            items = listed if isinstance(listed, list) else next((v for v in listed.values() if isinstance(v, list)), [])
            for e in items:
                if isinstance(e, dict) and Path(str(e.get("Path") or "")).name == staged.name:
                    path = e["Path"]
                    desktop_id = f"{e['Name']}.desktop" if e.get("Name") else ""
        except IntegrationError:
            pass
        return {"via": self.key, "path": path, "desktop_id": desktop_id}

    def uninstall(self, info: dict, app: dict, sha256: str) -> str:
        cmd = self.command()
        if not cmd:
            raise IntegrationError("Shelly isn't installed")
        desktop_id = info.get("desktop_id") or ""
        name = desktop_id.removesuffix(".desktop") if desktop_id else Path(info.get("path") or stable_name(app)).stem
        _run([*cmd, "remove", "appimage", name, "-n"])
        return ""


class Menu:
    """Our own: the AppImage in the install folder, a menu entry and an icon."""
    key, label = "menu", "a menu entry"

    def __init__(self, install_dir: Path, icons_dir: Path, applications: Path | None = None):
        self.install_dir = install_dir.expanduser()
        self.icons_dir = icons_dir
        self.applications = applications or Path(os.path.expanduser("~/.local/share/applications"))

    def available(self) -> bool:
        return True

    def install(self, staged: Path, app: dict, desktop_dir: Path | None) -> dict:
        self.install_dir.mkdir(parents=True, exist_ok=True)
        dest = self.install_dir / staged.name
        tmp = dest.with_name(dest.name + ".part")
        shutil.copyfile(staged, tmp)
        os.chmod(tmp, 0o755)
        tmp.replace(dest)
        desktop_id = ""
        desktop = (desktop_dir / "app.desktop") if desktop_dir else None
        if desktop and desktop.is_file():
            icon = next(iter(sorted(desktop_dir.glob("icon.*"))), None)
            icon_ref = self._place_icon(icon, app) if icon else "application-x-executable"
            entry = appimage.menu_entry(desktop.read_text(encoding="utf-8", errors="replace"), str(dest), icon_ref, app["id"])
            self.applications.mkdir(parents=True, exist_ok=True)
            desktop_id = self.desktop_id(app)
            (self.applications / desktop_id).write_text(entry, encoding="utf-8")
            self._refresh_menu()
        return {"via": self.key, "path": str(dest), "desktop_id": desktop_id}

    @staticmethod
    def desktop_id(app: dict) -> str:
        return f"{TAG}-{app['id']}.desktop"

    def _place_icon(self, icon: Path, app: dict) -> str:
        """Copy the app's icon where it stays; returns what its menu entry calls it (here, its path)."""
        self.icons_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        icon_dest = self.icons_dir / f"{TAG}-{app['id']}{icon.suffix}"
        shutil.copyfile(icon, icon_dest)
        return str(icon_dest)

    def _refresh_menu(self) -> None:
        if updb := _which("update-desktop-database"):
            try:
                _run([updb, str(self.applications)], timeout=60)
            except IntegrationError:
                pass                        # the entry works without the cache

    def present(self, info: dict) -> bool:
        """Whether the app's menu entry is still there (the desktop's own Remove may have deleted it)."""
        desktop_id = info.get("desktop_id") or ""
        return not desktop_id or (self.applications / desktop_id).is_file()

    def uninstall(self, info: dict, app: dict, sha256: str) -> str:
        """Our own files for the app: its menu entry and icon, and the AppImage if it's still the
        one installed (a file changed since stays). Returns what was left behind ("" if nothing)."""
        left = ""
        path = Path(info.get("path") or "")
        if path.is_file() and not path.is_symlink():
            if sha256 and _sha256(path) == sha256:
                path.unlink()
            else:
                left = f"{path} (it has changed since it was installed)"
        # the entry it was installed with (its name from then, which an older version may have named
        # otherwise), and the icon of ours it showed
        desktop_id = info.get("desktop_id") or ""
        entry = self.applications / desktop_id
        if desktop_id.endswith(f"-{app['id']}.desktop") and "/" not in desktop_id and entry.is_file():
            icon = appimage.read_desktop(entry.read_text(encoding="utf-8", errors="replace")).get("Icon", "")
            if icon and Path(icon).parent == self.icons_dir:
                Path(icon).unlink(missing_ok=True)
            entry.unlink()
            self._refresh_menu()
        # an install under today's names (not one an update just replaced): its icons, entry or not
        if desktop_id in ("", self.desktop_id(app)):
            for icon in self.icons_dir.glob(f"{TAG}-{app['id']}.*") if self.icons_dir.is_dir() else []:
                icon.unlink(missing_ok=True)
        return left


class Omarchy(Menu):
    """Omarchy's own way (omarchy.py): the AppImage in the install folder, a menu entry its launcher
    lists at once, and the icon in the user's icon theme, by name, as Omarchy's web apps have theirs.
    The same AppImage and entry names as our own menu entry's, so switching between the two replaces."""
    key, label = "omarchy", "the Omarchy menu"
    # the icon theme's size folders (an icon of another size goes in 256x256, as Omarchy's own do)
    SIZES = (16, 22, 24, 32, 48, 64, 96, 128, 256, 512)

    def __init__(self, install_dir: Path, icons_dir: Path, applications: Path | None = None,
                 icon_theme: Path | None = None):
        super().__init__(install_dir, icons_dir, applications or omarchy.applications_dir())
        self.icon_theme = icon_theme or omarchy.icon_theme_dir()

    def available(self) -> bool:
        return omarchy.detect() is not None

    def install(self, staged: Path, app: dict, desktop_dir: Path | None) -> dict:
        if not omarchy.fuse_ok(_which):
            raise IntegrationError("Omarchy needs FUSE (fuse3) to start apps, and it isn't installed: install it "
                                   "from the Omarchy card at the top of My apps")
        info = super().install(staged, app, desktop_dir)
        # what our own menu entry left, if it was installed that way before (another folder only
        # when XDG_DATA_HOME moves the user's)
        old = Menu(self.install_dir, self.icons_dir).applications / self.desktop_id(app)
        if old != self.applications / self.desktop_id(app) and old.is_file() and \
                f"X-DVM-App={app['id']}" in old.read_text(encoding="utf-8", errors="replace"):
            old.unlink()
        for icon in self.icons_dir.glob(f"{TAG}-{app['id']}.*") if self.icons_dir.is_dir() else []:
            icon.unlink(missing_ok=True)
        return info

    def _place_icon(self, icon: Path, app: dict) -> str:
        name = f"{TAG}-{app['id']}"
        self._remove_icons(app)
        dest = self.icon_theme / self._icon_folder(icon) / "apps" / f"{name}{icon.suffix.lower()}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(icon, dest)
        self._refresh_icons()
        return name

    def _icon_folder(self, icon: Path) -> str:
        if icon.suffix.lower() in (".svg", ".svgz"):
            return "scalable"
        try:
            with icon.open("rb") as f:
                head = f.read(24)
            if head[:8] == b"\x89PNG\r\n\x1a\n" and head[12:16] == b"IHDR":
                w, h = int.from_bytes(head[16:20], "big"), int.from_bytes(head[20:24], "big")
                if w == h and w in self.SIZES:
                    return f"{w}x{w}"
        except OSError:
            pass
        return "256x256"

    def _remove_icons(self, app: dict) -> bool:
        gone = False
        if self.icon_theme.is_dir():
            for icon in self.icon_theme.glob(f"*/apps/{TAG}-{app['id']}.*"):
                icon.unlink(missing_ok=True)
                gone = True
        return gone

    def _refresh_icons(self) -> None:
        if (cache := _which("gtk-update-icon-cache")) and self.icon_theme.is_dir():
            try:
                _run([cache, "-q", "-t", str(self.icon_theme)], timeout=60)
            except IntegrationError:
                pass                        # Omarchy's launcher finds icons without the cache

    def uninstall(self, info: dict, app: dict, sha256: str) -> str:
        left = super().uninstall(info, app, sha256)
        if self._remove_icons(app):
            self._refresh_icons()
        return left


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def by_key(key: str, install_dir: Path, icons_dir: Path):
    """The integrator an app was installed with (its record's "via"), to remove it the same way."""
    return _all(install_dir, icons_dir).get(key)


def _all(install_dir: Path, icons_dir: Path) -> dict:
    return {"gearlever": GearLever(), "shelly": Shelly(), "menu": Menu(install_dir, icons_dir),
            "omarchy": Omarchy(install_dir, icons_dir)}


def choose(setting: str, install_dir: Path, icons_dir: Path):
    """The integrator for a setting: "auto" is Omarchy's own way on Omarchy, else Shelly where it is
    (Arch), else Gear Lever, else ours."""
    options = _all(install_dir, icons_dir)
    if setting in options and setting != "auto":
        chosen = options[setting]
        if not chosen.available():
            raise IntegrationError(f"{chosen.label} isn't installed (Settings > Where your apps live)")
        return chosen
    for key in ("omarchy", "shelly", "gearlever"):
        if options[key].available():
            return options[key]
    return options["menu"]


def detect() -> dict[str, bool]:
    return {"gearlever": GearLever().available(), "shelly": Shelly().available(), "flatpak": bool(_which("flatpak")),
            "omarchy": omarchy.detect() is not None}
