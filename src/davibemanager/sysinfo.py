"""What the user lets the assistant always know about this computer (Settings): its system and
its hardware, read here by the app itself, so the assistant needn't ask for them in every chat.

Only the system's own descriptions are read (os-release, /proc, lspci), never the user's files.
Each part is the user's choice; with both off nothing is gathered at all."""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

PARTS = ("system", "hardware")
HEADER = ("[About this computer: the user chose in Settings to share this with you in every chat; it comes "
          "from their computer]")


def _os_release() -> dict[str, str]:
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        out = {}
        for line in text.splitlines():
            key, sep, value = line.partition("=")
            if sep and re.fullmatch(r"[A-Z_]+", key):
                out[key] = value.strip().strip('"').strip("'")
        return out
    return {}


def _run(argv: list[str], timeout: float = 5) -> str:
    if not shutil.which(argv[0]):
        return ""
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              env={**os.environ, "LC_ALL": "C"}).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def system() -> list[tuple[str, str]]:
    rel = _os_release()
    name = rel.get("NAME", "Linux")
    version = rel.get("VERSION") or rel.get("VERSION_ID", "")
    line = f"{name} {version}".strip()
    based = rel.get("ID_LIKE", "")
    if rel.get("UBUNTU_CODENAME") and "ubuntu" in based:
        based += f"; Ubuntu {rel['UBUNTU_CODENAME']}"
    if based:
        line += f" (based on {based})"
    out = [("System", line), ("Kernel", f"{platform.release()} ({platform.machine()})")]
    desktop = os.environ.get("XDG_CURRENT_DESKTOP", "").removeprefix("X-").replace(":", ", ")
    session = os.environ.get("XDG_SESSION_TYPE", "")
    if desktop or session:
        out.append(("Desktop", f"{desktop or 'unknown'}{f' ({session})' if session else ''}"))
    formats = [f for f, tool in (("Flatpak", "flatpak"), ("Snap", "snap")) if shutil.which(tool)]
    out.append(("App formats", ", ".join(["AppImage", *formats])))
    return out


def hardware() -> list[tuple[str, str]]:
    out = []
    cpu = ""
    try:
        cpu = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                    if line.startswith(("model name", "Model"))), "")
    except OSError:
        pass
    out.append(("Processor", f"{cpu or platform.processor() or 'unknown'}, {os.cpu_count() or '?'} threads"))
    try:
        kb = int(re.search(r"MemTotal:\s+(\d+)", Path("/proc/meminfo").read_text()).group(1))
        out.append(("Memory", f"{kb / 1024 / 1024:.1f} GB"))
    except (OSError, AttributeError, ValueError):
        pass
    gpus = []
    for line in _run(["lspci", "-mm"]).splitlines():
        fields = re.findall(r'"([^"]*)"', line)
        if len(fields) >= 3 and fields[0] in ("VGA compatible controller", "3D controller", "Display controller"):
            gpus.append(f"{fields[1]} {fields[2]}")
    if gpus:
        out.append(("Graphics", "; ".join(gpus)))
    virt = _run(["systemd-detect-virt"]).strip()
    if virt and virt != "none":
        out.append(("Runs in", f"a virtual machine ({virt})"))
    return out


def gather(parts) -> str:
    """The text the assistant gets for the chosen parts ("" when none is chosen)."""
    rows = []
    if "system" in parts:
        rows += system()
    if "hardware" in parts:
        rows += hardware()
    return "\n".join(f"- {k}: {v}" for k, v in rows)
