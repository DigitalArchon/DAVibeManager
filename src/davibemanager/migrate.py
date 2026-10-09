"""Moving over from the app's old name (DA Linux Agent, "dalinuxagent") to DA Vibe Manager, once.

Run first thing at startup, before anything reads the config or the data folder. Each step does
nothing when there is nothing left to move, so running it again is harmless:

- the config and data folders are renamed (the same filesystem, so at once and whole);
- our own menu entries for the user's apps had their icons in the old data folder: pointed at
  the new one;
- starting with the computer: the old autostart entry is removed, and the caller makes a new one
  (it knows how this copy is started).

The API key moves on its first read (creds._moved: the keyring may be locked now), and the sandbox
container and its volumes when it first starts (podman.move_old_sandbox).
"""

from __future__ import annotations

import os
import socket
from pathlib import Path

from . import config

OLD_ID = "dalinuxagent"


def _old(path: Path) -> Path:
    return path.with_name(OLD_ID)


def old_copy_running() -> bool:
    """Is a copy of the app under its old name running (its single-instance socket answers)?"""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        try:
            s.connect(f"\0{OLD_ID}-{os.getuid()}".encode())
            return True
        except OSError:
            return False


def old_autostart() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "autostart" / f"{OLD_ID}.desktop"


def run(applications: Path | None = None) -> dict:
    """Move what is under the old name. Returns what was done: {"moved": [...], "autostart": bool}
    (autostart: it was on under the old name, so the caller turns it on under the new one)."""
    done: dict = {"moved": [], "autostart": False}
    for new in (config.config_dir(), config.data_dir()):
        old = _old(new)
        if old.is_dir() and not old.is_symlink() and not new.exists():
            new.parent.mkdir(parents=True, exist_ok=True)
            old.rename(new)
            done["moved"].append(str(new))
    old_data, new_data = str(_old(config.data_dir())), str(config.data_dir())
    apps_dir = applications or Path(os.path.expanduser("~/.local/share/applications"))
    for entry in sorted(apps_dir.glob("dla-*.desktop")) if apps_dir.is_dir() else []:
        try:
            text = entry.read_text(encoding="utf-8")
        except OSError:
            continue
        if "X-DLA-App=" in text and f"Icon={old_data}/" in text:
            entry.write_text(text.replace(f"Icon={old_data}/", f"Icon={new_data}/"), encoding="utf-8")
    auto = old_autostart()
    if auto.is_file():
        auto.unlink()
        done["autostart"] = True
    return done
