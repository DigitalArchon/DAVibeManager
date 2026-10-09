"""The system tray icon, and making sure only one copy of the app runs.

The icon is an XApp StatusIcon where the desktop has XApp (Cinnamon, MATE, Xfce on Mint: a left
click opens the window), otherwise an Ayatana AppIndicator (a menu, as on GNOME with the
AppIndicator extension, KDE and most others), or the original AppIndicator with the same API (what
Arch and CachyOS ship). With none, there is no tray and closing the window quits the app, as any
other app.

A second launch (from the menu, or autostart) finds the first through an abstract Unix socket
named for this user and asks it to show its window, then exits.
"""

from __future__ import annotations

import os
import socket
import threading
from pathlib import Path
from typing import Callable

ICON = Path(__file__).parent / "web" / "icon.svg"


def _socket_name() -> bytes:
    return f"\0davibemanager-{os.getuid()}".encode()


def claim_single_instance(on_show: Callable[[], None]) -> bool:
    """True if this is the only copy (it then listens for later launches); False if another copy
    is running, which has been asked to show its window."""
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        srv.bind(_socket_name())
    except OSError:
        srv.close()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
                c.settimeout(2)
                c.connect(_socket_name())
                c.sendall(b"show\n")
            return False
        except OSError:
            return True          # a stale name nobody answers on: carry on (we just won't be found)
    srv.listen(4)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(2)
                try:
                    data = conn.recv(64)
                except OSError:
                    continue
                if data.startswith(b"show"):
                    on_show()
    threading.Thread(target=serve, daemon=True, name="single-instance").start()
    return True


class Tray:
    """A tray icon with Open / New chat / Quit. All callbacks run on the GTK main thread."""

    def __init__(self, *, on_open: Callable[[], None], on_new_chat: Callable[[], None], on_quit: Callable[[], None]):
        self.on_open, self.on_new_chat, self.on_quit = on_open, on_new_chat, on_quit
        self.kind = ""
        self._icon = None
        for make in (self._xapp, self._ayatana, self._appindicator):
            try:
                if make():
                    break
            except Exception:  # noqa: BLE001 - this kind isn't available here: try the next
                continue

    @property
    def available(self) -> bool:
        return bool(self.kind)

    def _menu(self):
        import gi
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk
        menu = Gtk.Menu()
        for label, fn in (("Open DA Vibe Manager", self.on_open), ("New chat", self.on_new_chat), (None, None),
                          ("Quit", self.on_quit)):
            item = Gtk.SeparatorMenuItem() if label is None else Gtk.MenuItem(label=label)
            if fn:
                item.connect("activate", lambda _w, f=fn: f())
            menu.append(item)
        menu.show_all()
        return menu

    def _xapp(self) -> bool:
        import gi
        gi.require_version("XApp", "1.0")
        from gi.repository import XApp
        if not XApp.StatusIcon.any_monitors():
            return False
        icon = XApp.StatusIcon()
        icon.set_name("davibemanager")
        icon.set_icon_name(str(ICON))
        icon.set_tooltip_text("DA Vibe Manager")
        icon.set_secondary_menu(self._menu())

        def activate(_icon, button, _time):
            if button == 1:
                self.on_open()
        icon.connect("activate", activate)
        icon.set_visible(True)
        self._icon, self.kind = icon, "xapp"
        return True

    def _ayatana(self) -> bool:
        return self._indicator("AyatanaAppIndicator3", "ayatana")

    def _appindicator(self) -> bool:
        # the original libappindicator, with the same API: what Arch and CachyOS ship (KDE's tray
        # speaks its protocol, StatusNotifierItem)
        return self._indicator("AppIndicator3", "appindicator")

    def _indicator(self, module: str, kind: str) -> bool:
        import importlib
        import gi
        gi.require_version(module, "0.1")
        AI = importlib.import_module(f"gi.repository.{module}")
        ind = AI.Indicator.new("davibemanager", str(ICON), AI.IndicatorCategory.APPLICATION_STATUS)
        ind.set_title("DA Vibe Manager")
        menu = self._menu()
        ind.set_menu(menu)
        ind.set_secondary_activate_target(menu.get_children()[0])   # middle click opens the window
        ind.set_status(AI.IndicatorStatus.ACTIVE)
        self._icon, self.kind = ind, kind
        return True

    def attention(self, on: bool) -> None:
        """Mark the icon while the assistant is waiting for the user (where the tray can show it)."""
        if self.kind == "xapp":
            self._icon.set_tooltip_text("DA Vibe Manager: waiting for you" if on else "DA Vibe Manager")


def notify(title: str, body: str) -> None:
    """A desktop notification (libnotify), or nothing if there is no notification service."""
    try:
        import gi
        gi.require_version("Notify", "0.7")
        from gi.repository import Notify
        if not Notify.is_initted():
            Notify.init("DA Vibe Manager")
        Notify.Notification.new(title, body, str(ICON)).show()
    except Exception:  # noqa: BLE001 - a missed notification is no reason to interrupt anything
        pass


AUTOSTART = """[Desktop Entry]
Type=Application
Name=DA Vibe Manager
Comment=Your Linux helper, in the tray
Exec={exec} --hidden
Icon={icon}
X-GNOME-Autostart-enabled=true
NoDisplay=false
"""


def autostart_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "autostart" / "davibemanager.desktop"


def _lasting_icon() -> str:
    """The icon for the autostart entry, where it stays: ICON is inside the AppImage's mount when
    running from one, a folder that is gone once the app quits."""
    from .config import data_dir
    dest = data_dir() / "icons" / "davibemanager.svg"
    try:
        data = ICON.read_bytes()
        if not dest.is_file() or dest.read_bytes() != data:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        return str(dest)
    except OSError:
        return str(ICON)


def set_autostart(on: bool, exec_line: str) -> None:
    path = autostart_path()
    if on:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(AUTOSTART.format(exec=exec_line, icon=_lasting_icon()))
    else:
        path.unlink(missing_ok=True)


def refresh_autostart(exec_line: str) -> None:
    """If the app starts with the computer, make that start this copy: the user may have turned it
    on in another (from source, or an AppImage since moved or replaced by a newer one)."""
    path = autostart_path()
    try:
        if path.is_file() and path.read_text() != AUTOSTART.format(exec=exec_line, icon=_lasting_icon()):
            set_autostart(True, exec_line)
    except OSError:
        pass
