"""Starting an app on this computer, on the user's click: a delivered AppImage tried once, or an
installed one opened.

An app whose menu entry says Terminal=true is a terminal program (htop, a TUI): started bare, with
no terminal, it ends at once and the user sees nothing. It is started in a terminal window the way
the menu starts it: with xdg-terminal-exec (the desktop's own choice, and GLib's first), else the
terminal $TERMINAL names, else the terminals the desktop in use and the common ones have, each
with its own way of taking a command.
"""

from __future__ import annotations

import os
import shlex
import shutil
from pathlib import Path
from typing import Callable

from . import appimage

# a terminal -> the words before the command ("rest": the command's words follow as they are;
# "string": the command as one shell string after them)
TERMINALS: dict[str, tuple[tuple[str, ...], str]] = {
    "xdg-terminal-exec": ((), "rest"),
    "ghostty": (("-e",), "rest"),
    "ptyxis": (("--",), "rest"),
    "kgx": (("--",), "rest"),
    "gnome-terminal": (("--",), "rest"),
    "mate-terminal": (("-x",), "rest"),
    "xfce4-terminal": (("-x",), "rest"),
    "tilix": (("-e",), "string"),
    "konsole": (("-e",), "rest"),
    "alacritty": (("-e",), "rest"),
    "kitty": ((), "rest"),
    "foot": ((), "rest"),
    "wezterm": (("start", "--"), "rest"),
    "x-terminal-emulator": (("-e",), "rest"),
    "xterm": (("-e",), "rest"),
    "urxvt": (("-e",), "rest"),
}
# the desktop's own terminal first (XDG_CURRENT_DESKTOP names it), then the rest in TERMINALS' order
PREFERRED = {
    "KDE": ("konsole",), "XFCE": ("xfce4-terminal",), "MATE": ("mate-terminal",),
    "GNOME": ("ptyxis", "kgx", "gnome-terminal"), "X-CINNAMON": ("gnome-terminal",), "CINNAMON": ("gnome-terminal",),
    "HYPRLAND": ("alacritty", "ghostty", "kitty", "foot"), "SWAY": ("foot", "alacritty", "kitty"),
}


def is_terminal_app(desktop_dir: Path | None) -> bool:
    """Whether the delivered app's own menu entry (extracted from its AppImage) says it runs in a terminal."""
    entry = (desktop_dir / "app.desktop") if desktop_dir else None
    if not entry or not entry.is_file():
        return False
    try:
        return appimage.read_desktop(entry.read_text(encoding="utf-8", errors="replace")).get("Terminal", "").strip().lower() == "true"
    except OSError:
        return False


def terminal_argv(command: list[str], env: dict | None = None,
                  which: Callable[[str], str | None] | None = None) -> list[str] | None:
    """`command` as started in a terminal window, or None when no terminal emulator is here."""
    env = os.environ if env is None else env
    which = which or shutil.which
    order = ["xdg-terminal-exec"]
    own = os.path.basename(env.get("TERMINAL", "").strip())
    if own:
        order.append(own)
    for part in env.get("XDG_CURRENT_DESKTOP", "").upper().split(":"):
        order += PREFERRED.get(part, ())
    order += [t for t in TERMINALS if t not in order]
    for name in order:
        if name.startswith(".") or "/" in name or not which(name):
            continue
        before, how = TERMINALS.get(name, (("-e",), "rest"))
        return [name, *before, *(command if how == "rest" else [shlex.join(command)])]
    return None
