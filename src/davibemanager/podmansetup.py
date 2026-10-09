"""Podman, for a computer that doesn't have it yet: what's missing, and how this distribution
installs it.

Podman isn't in the AppImage: it is the sandbox's wall, so it comes from the distribution, with
its security updates. Rootless Podman needs a helper to reach the network while it builds the
sandbox's image (the sandbox itself has none): pasta (passt) since Podman 5, or slirp4netns.
Debian's, Ubuntu's and Fedora's Podman usually bring one; Arch's leaves passt optional.

The install command is the app's own, fixed here per package manager: never the AI's. The user
sees it in full and runs it with one click, as administrator through pkexec (the desktop asks
for the password; the app never sees it), or copies it into a terminal.
"""

from __future__ import annotations

import shutil
from typing import Callable

from . import sysinfo

# package manager -> (the binary that shows it's there, how it installs packages without asking)
MANAGERS = {
    "apt": ("apt-get", "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y {pkgs}"),
    "dnf": ("dnf", "dnf install -y {pkgs}"),
    # never -Sy alone: installing on a stale package list is a partial upgrade (Arch's rule)
    "pacman": ("pacman", "pacman -S --needed --noconfirm {pkgs}"),
    "zypper": ("zypper", "zypper --non-interactive install {pkgs}"),
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
    name = rel.get("PRETTY_NAME") or " ".join(x for x in (rel.get("NAME"), rel.get("VERSION_ID")) if x) or "Linux"
    return {
        "missing": need,
        "packages": pkgs,
        "distro": name,
        "manager": manager,
        "command": command,
        "terminal": f"sudo sh -c '{command}'" if "&&" in command else f"sudo {command}" if command else "",
        "can_install": bool(command) and bool(which("pkexec")),
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
