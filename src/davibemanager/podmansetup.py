"""Podman, for a computer that doesn't have it yet: what's missing, and how this distribution
installs it.

Podman isn't in the AppImage: it is the sandbox's wall, so it comes from the distribution, with
its security updates. Rootless Podman needs a helper to reach the network while it builds the
sandbox's image (the sandbox itself has none): pasta (passt) since Podman 5, or slirp4netns.
Debian's, Ubuntu's and Fedora's Podman usually bring one; Arch's leaves passt optional.

The install command is the app's own, fixed here per package manager: never the AI's. The user
sees it in full and runs it with one click, as administrator through pkexec (the desktop asks
for the password; the app never sees it), or copies it into a terminal.

Uninstalling it is the same, the other way: what the app installed is written down
(podman-installed.json), so removing it takes those packages, and leaves alone what was there before.
"""

from __future__ import annotations

import json
import shutil
from typing import Callable

from . import sysinfo
from .config import data_dir

# package manager -> (the binary that shows it's there, how it installs packages without asking)
MANAGERS = {
    "apt": ("apt-get", "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y {pkgs}"),
    "dnf": ("dnf", "dnf install -y {pkgs}"),
    # never -Sy alone: installing on a stale package list is a partial upgrade (Arch's rule)
    "pacman": ("pacman", "pacman -S --needed --noconfirm {pkgs}"),
    "zypper": ("zypper", "zypper --non-interactive install {pkgs}"),
}
# and how it removes them, with what only they needed (apt can't do that for some packages alone:
# its autoremove takes every package nothing needs, so their dependencies stay; the window says so)
REMOVE = {
    "apt": "apt-get remove -y {pkgs}",
    "dnf": "dnf remove -y {pkgs}",
    "pacman": "pacman -Rs --noconfirm {pkgs}",
    "zypper": "zypper --non-interactive remove --clean-deps {pkgs}",
}
# what os-release's ID or ID_LIKE says, for the manager it uses
FAMILIES = {
    "apt": ("debian", "ubuntu", "linuxmint", "pop", "elementary", "zorin", "neon", "kali", "raspbian"),
    "dnf": ("fedora", "rhel", "centos", "rocky", "almalinux", "nobara", "ultramarine"),
    "pacman": ("arch", "cachyos", "manjaro", "endeavouros", "garuda", "artix"),
    "zypper": ("opensuse", "suse", "opensuse-tumbleweed", "opensuse-leap", "sles"),
}


def missing(which: Callable[[str], str | None] | None = None) -> list[str]:
    """The packages this computer lacks for the sandbox: [] when it's all there."""
    which = which or shutil.which
    out = []
    if not which("podman"):
        out.append("podman")
    if not (which("pasta") or which("slirp4netns")):
        out.append("passt")
    return out


def _manager(rel: dict, which: Callable[[str], str | None]) -> str:
    ids = [rel.get("ID", "").lower(), *rel.get("ID_LIKE", "").lower().split()]
    if rel.get("VARIANT_ID", "").lower() in ("silverblue", "kinoite", "sericea", "onyx", "iot", "coreos") \
            or which("rpm-ostree"):
        return ""            # an image-based system: Podman comes with it, and installs there need a reboot
    for name, family in FAMILIES.items():
        if any(i in family for i in ids) and which(MANAGERS[name][0]):
            return name
    for name, (binary, _) in MANAGERS.items():        # an unknown distribution: its package manager
        if which(binary):
            return name
    return ""


def plan(rel: dict | None = None, which: Callable[[str], str | None] | None = None) -> dict | None:
    """What to install and how, for the window; None when nothing is missing."""
    which = which or shutil.which
    need = missing(which)
    if not need:
        return None
    rel = sysinfo._os_release() if rel is None else rel
    manager = _manager(rel, which)
    pkgs = list(need)
    if manager == "pacman" and "podman" in pkgs and "passt" not in pkgs:
        pkgs.append("passt")       # Arch's Podman needs it to build anything, but doesn't bring it
    command = MANAGERS[manager][1].format(pkgs=" ".join(pkgs)) if manager else ""
    return {
        "missing": need,
        "packages": pkgs,
        # what this install adds (pacman's --needed skips a passt that's there already)
        "new": [x for x in pkgs if x != "passt" or not which("pasta")],
        "distro": _name(rel),
        "manager": manager,
        "command": command,
        "terminal": _terminal(command),
        "can_install": bool(command) and bool(which("pkexec")),
    }


def _name(rel: dict) -> str:
    return rel.get("PRETTY_NAME") or " ".join(x for x in (rel.get("NAME"), rel.get("VERSION_ID")) if x) or "Linux"


def _terminal(command: str) -> str:
    return f"sudo sh -c '{command}'" if "&&" in command else f"sudo {command}" if command else ""


def _record_path():
    return data_dir() / "podman-installed.json"


def record_install(packages: list[str]) -> None:
    """Write down what the app installed, so uninstalling takes those (and only those) again."""
    path = _record_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    had = installed_by_app() or []
    path.write_text(json.dumps({"packages": sorted(set(had) | set(packages))}))


def installed_by_app() -> list[str] | None:
    """The packages the app installed, or None if it didn't install Podman here (or before it wrote it down)."""
    try:
        pkgs = json.loads(_record_path().read_text()).get("packages")
    except (OSError, ValueError, AttributeError):
        return None
    return [p for p in pkgs if p in ("podman", "passt")] if isinstance(pkgs, list) else None


def forget_install() -> None:
    _record_path().unlink(missing_ok=True)


def removal(rel: dict | None = None, which: Callable[[str], str | None] | None = None) -> dict | None:
    """How Podman is uninstalled here, for the window; None when it isn't installed."""
    which = which or shutil.which
    if not which("podman"):
        return None
    rel = sysinfo._os_release() if rel is None else rel
    manager = _manager(rel, which)
    ours = installed_by_app()
    pkgs = ours or ["podman"]       # passt only if the app put it there: something else may use it
    command = REMOVE[manager].format(pkgs=" ".join(pkgs)) if manager else ""
    return {
        "packages": pkgs,
        "installed_by_app": ours is not None,
        "distro": _name(rel),
        "manager": manager,
        "command": command,
        "terminal": _terminal(command),
        "can_remove": bool(command) and bool(which("pkexec")),
        # apt removes the packages named, not what only they needed
        "leaves_dependencies": manager == "apt",
    }


def message(p: dict | None = None) -> str:
    """The words for a sandbox that can't start for want of Podman."""
    p = p if p is not None else plan()
    if not p:
        return ""
    what = "Podman" if "podman" in p["missing"] else "Podman's network helper (passt)"
    how = (f"Install it from the app's window, or in a terminal: {p['terminal']}" if p["can_install"]
           else f"Install it in a terminal: {p['terminal']}" if p["command"]
           else "Install it with your system's software manager (see podman.io/docs/installation).")
    return (f"DA Vibe Manager needs {what}: it's the sealed sandbox the assistant works in, kept apart from "
            f"your computer. {how}")
