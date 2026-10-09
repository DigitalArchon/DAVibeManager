"""The environment for programs DA Vibe Manager starts on the user's behalf (their shell, ssh,
the file manager). When DA Vibe Manager runs from an AppImage, the AppImage runtime adds variables
describing its own mount; they mean nothing to those programs, and another AppImage started
from a DA Vibe Manager terminal would misread them, so they are left out."""

from __future__ import annotations

import os

# where the system keeps its GObject introspection typelibs (Fedora, Debian/Ubuntu, Arch)
HOST_TYPELIB_DIRS = ("/usr/lib64/girepository-1.0", "/usr/lib/x86_64-linux-gnu/girepository-1.0",
                     "/usr/lib/girepository-1.0")
APPIMAGE_VARS = ("APPIMAGE", "APPDIR", "ARGV0", "OWD", "APPIMAGE_EXTRACT_AND_RUN")
# variables DA Vibe Manager changed for itself, with their values before (None: they weren't set)
ORIGINAL: dict[str, str | None] = {}


def set_for_self(name: str, value: str) -> None:
    """Set an environment variable for DA Vibe Manager's own process only: host_env() gives children
    the value it had before."""
    ORIGINAL.setdefault(name, os.environ.get(name))
    os.environ[name] = value


def host_env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in APPIMAGE_VARS}
    for name, value in ORIGINAL.items():
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value
    env.update(extra)
    return env
