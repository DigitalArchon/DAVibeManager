"""Where installed apps live on this computer: Gear Lever, Shelly, or a menu entry of our own.

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
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from . import appimage
from .hostenv import host_env

GEARLEVER_FLATPAK = "it.mijorus.gearlever"
TIMEOUT = 300
CHOICES = ("auto", "gearlever", "shelly", "menu")


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


def tag(app: dict) -> str:
    """The short name in an app's file names and menu entry: "dvm", or "dla" for apps made before the
    rename (DA Linux Agent), so an update replaces its install instead of adding a second one."""
    return app.get("tag") or "dla"


def stable_name(app: dict) -> str:
    """The AppImage's file name for an app, the same for every version."""
    name = "".join(c if c.isalnum() or c in "._+-" else "-" for c in app["name"]).strip("-.") or app["id"]
    return f"{name}-{tag(app)}.AppImage"


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
            icon_ref = "application-x-executable"
            if icon:
                self.icons_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                icon_dest = self.icons_dir / f"{tag(app)}-{app['id']}{icon.suffix}"
                shutil.copyfile(icon, icon_dest)
                icon_ref = str(icon_dest)
            entry = appimage.menu_entry(desktop.read_text(encoding="utf-8", errors="replace"), str(dest), icon_ref, app["id"])
            self.applications.mkdir(parents=True, exist_ok=True)
            desktop_id = f"{tag(app)}-{app['id']}.desktop"
            (self.applications / desktop_id).write_text(entry, encoding="utf-8")
            if updb := _which("update-desktop-database"):
                try:
                    _run([updb, str(self.applications)], timeout=60)
                except IntegrationError:
                    pass                        # the entry works without the cache
        return {"via": self.key, "path": str(dest), "desktop_id": desktop_id}


def choose(setting: str, install_dir: Path, icons_dir: Path):
    """The integrator for a setting: "auto" is Shelly where it is (Arch), else Gear Lever, else ours."""
    options = {"gearlever": GearLever(), "shelly": Shelly(), "menu": Menu(install_dir, icons_dir)}
    if setting in options and setting != "auto":
        chosen = options[setting]
        if not chosen.available():
            raise IntegrationError(f"{chosen.label} isn't installed (Settings > Where your apps live)")
        return chosen
    for key in ("shelly", "gearlever"):
        if options[key].available():
            return options[key]
    return options["menu"]


def detect() -> dict[str, bool]:
    return {"gearlever": GearLever().available(), "shelly": Shelly().available(), "flatpak": bool(_which("flatpak"))}
