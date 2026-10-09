"""Entry point: start the local server, the tray icon and the (small) app window."""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import shlex
import signal
import socket
import sys
import threading
import time
from pathlib import Path

import uvicorn

from . import config
from .engine import Engine
from .hostenv import set_for_self
from .server.app import create_app, runtime_dir


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Desktop:
    """What the page can't do itself inside the app window: the clipboard (WebKitGTK's async
    clipboard API is unreliable, so it goes through GTK on the main thread), hiding the window to
    the tray, and notifications while it is hidden. The page reaches these through the local
    server (/api/desktop/..., token only): pywebview's own JS bridge builds its functions with
    `new Function`, which the page's Content-Security-Policy rightly refuses."""

    def __init__(self, window=None):
        self._window = window
        self.visible = True
        self.tray = None

    @staticmethod
    def _on_main(fn, timeout: float = 5.0):
        from gi.repository import GLib

        result: dict = {}
        done = threading.Event()

        def run():
            try:
                result["value"] = fn()
            finally:
                done.set()
            return False

        GLib.idle_add(run)
        done.wait(timeout)
        return result.get("value")

    def clipboard_get(self) -> str:
        from gi.repository import Gdk, Gtk

        return self._on_main(lambda: Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).wait_for_text()) or ""

    def clipboard_set(self, text: str) -> None:
        from gi.repository import Gdk, Gtk

        def set_text():
            cb = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
            cb.set_text(text, -1)
            cb.store()

        self._on_main(set_text)

    def show(self) -> None:
        if self._window is not None:
            self._window.show()
            self._window.restore()
            self.visible = True

    def hide(self) -> None:
        if self._window is not None and self.tray and self.tray.available:
            self._window.hide()
            self.visible = False

    def notify(self, title: str, body: str) -> None:
        """Only while the window is hidden: with it open, the chat already says so."""
        if not self.visible:
            from .tray import notify
            notify(title, body)


WEBKIT_INSTALL = ("Ubuntu, Mint, Debian: sudo apt install gir1.2-webkit2-4.1 · Fedora: sudo dnf install webkit2gtk4.1 · "
                  "Arch, CachyOS: sudo pacman -S webkit2gtk-4.1")


HOST_TYPELIB_DIRS = ("/usr/lib64/girepository-1.0", "/usr/lib/x86_64-linux-gnu/girepository-1.0",
                     "/usr/lib/girepository-1.0")


def desktop_id() -> str:
    """The name the window identifies itself by (X11 WM_CLASS, Wayland app_id). Desktops find
    the window's icon by matching it to an installed .desktop file: KWin on Wayland only by
    exact file name. AppImage integrators (AppImageLauncher, Gear Lever, ...) install our
    davibemanager.desktop under a name of their own, so when running from an AppImage, use the name
    of the installed entry that launches this AppImage; otherwise "davibemanager"."""
    appimage = os.environ.get("APPIMAGE")
    if not appimage:
        return "davibemanager"
    target = os.path.realpath(appimage)
    data_home = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    dirs = [data_home] + (os.environ.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share").split(":")
    for base in dict.fromkeys(d for d in dirs if d):
        apps = Path(base) / "applications"
        try:
            entries = sorted(apps.rglob("*.desktop"))
        except OSError:
            continue
        for f in entries:
            try:
                lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for line in lines:
                key, _, value = line.partition("=")
                key, value = key.strip(), value.strip()
                if key == "TryExec" and value:
                    program = value                       # a plain path
                elif key == "Exec" and value:
                    try:
                        program = shlex.split(value)[0]   # a command line, the path maybe quoted
                    except (ValueError, IndexError):
                        continue
                else:
                    continue
                if os.path.realpath(os.path.expanduser(program)) == target:
                    # a desktop-file id: the path under applications/, with "/" as "-"
                    return str(f.relative_to(apps))[:-len(".desktop")].replace("/", "-")
    return "davibemanager"


def window_icon() -> str | None:
    """The icon file for the window itself (X11 shows it; Wayland takes the desktop entry's)."""
    appdir = os.environ.get("APPDIR")
    for path in ([Path(appdir) / "davibemanager.png"] if appdir else []) + [Path(__file__).parent / "web" / "icon.svg"]:
        if not path.is_file():
            continue
        try:
            import gi
            gi.require_version("GdkPixbuf", "2.0")
            from gi.repository import GdkPixbuf
            GdkPixbuf.Pixbuf.new_from_file(str(path))    # GTK would refuse a file it can't load
            return str(path)
        except Exception:  # noqa: BLE001 - no loader for it: try the next, or go without
            continue
    return None


def _bundled_girepository() -> None:
    """Fill gaps in the host's GObject introspection, from copies bundled in the AppImage (outside
    it there are none, and this does nothing). The host's own always win:
    - PyGObject is built against girepository-2.0, which Fedora and Arch ship inside GLib but
      Debian and Ubuntu package separately (libgirepository-2.0-0) and don't always install. If
      the host has none, the bundled copy is loaded under the same soname, so PyGObject's import
      finds it already loaded.
    - GTK's typelibs refer to base ones (xlib, cairo, freetype, ...) that Arch ships separately
      (gobject-introspection-runtime). Only those the host lacks are added to the search path,
      for this process only (child programs get the original, see hostenv)."""
    import ctypes

    fallback = Path(sys.executable).resolve().parents[2] / "lib/girepository-fallback"
    if not fallback.is_dir():
        return
    try:
        ctypes.CDLL("libgirepository-2.0.so.0")
    except OSError:
        ctypes.CDLL(str(fallback / "libgirepository-2.0.so.0"), mode=ctypes.RTLD_GLOBAL)
    missing = [str(d) for d in sorted((fallback / "typelibs").glob("*"))
               if not any(os.path.exists(f"{h}/{d.name}.typelib") for h in HOST_TYPELIB_DIRS)]
    if missing:
        current = os.environ.get("GI_TYPELIB_PATH")
        set_for_self("GI_TYPELIB_PATH", ":".join(missing + ([current] if current else [])))


def window_problem() -> str | None:
    """Why the app window can't open here (no WebKitGTK, no display), or None if it can."""
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return "There is no graphical display."
    try:
        _bundled_girepository()
        import gi

        gi.require_version("Gtk", "3.0")
        gi.require_version("WebKit2", "4.1")
        from gi.repository import Gtk, WebKit2  # noqa: F401
    except Exception as e:  # noqa: BLE001 - a missing typelib, an old GLib, a broken install: all mean "no window"
        return f"The app window needs WebKitGTK 4.1, which isn't installed ({e}). Install it ({WEBKIT_INSTALL})"
    return None


def launch_command() -> str:
    """How to start this app again (for the autostart entry)."""
    appimage = os.environ.get("APPIMAGE")
    if appimage:
        return shlex.quote(appimage)
    return f"{shlex.quote(sys.executable)} -m davibemanager"


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="davibemanager", description="Your Linux helper, in the tray")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--browser", action="store_true",
                      help="open in the default web browser instead of the app window")
    mode.add_argument("--window", action="store_true",
                      help="open the app window even if Settings say to use the browser")
    ap.add_argument("--hidden", action="store_true", help="start in the tray, without showing the window")
    ap.add_argument("--no-open", action="store_true",
                    help="with the browser: only print the URL (for opening it yourself)")
    ap.add_argument("--port", type=int, default=0, help="port to listen on (default: random)")
    args = ap.parse_args(argv)

    from . import tray as tray_mod
    shown = threading.Event()
    desktop_ref: dict = {}

    def show_from_elsewhere():
        d = desktop_ref.get("desktop")
        if d is not None:
            from gi.repository import GLib
            GLib.idle_add(lambda: (d.show(), False)[1])
        else:
            shown.set()
    if not tray_mod.claim_single_instance(show_from_elsewhere):
        print("DA Vibe Manager is already running; its window was brought up.", file=sys.stderr)
        return

    token = secrets.token_urlsafe(32)
    port = args.port or _free_port()
    cfg = config.load()
    use_browser = args.browser or args.no_open or (cfg.settings.ui_mode == "browser" and not args.window)
    notice = ""
    if not use_browser:
        problem = window_problem()
        if problem:
            use_browser, notice = True, f"{problem}. Running in your web browser until then."
            print(notice, file=sys.stderr)
    desktop = None if use_browser else Desktop()
    desktop_ref["desktop"] = desktop

    runtime = runtime_dir()

    def make_engine(emit):
        engine = Engine(cfg, emit, runtime, notify=desktop.notify if desktop else None)
        engine.ui_notice = notice
        engine.launch_command = launch_command()
        tray_mod.refresh_autostart(engine.launch_command)
        holder["engine"] = engine
        return engine

    holder: dict = {}
    app = create_app(token, make_engine, desktop, on_quit=lambda: quit_all())
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning",
                                           ws_max_size=16 * 1024 * 1024))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        if not thread.is_alive():
            raise SystemExit("Server failed to start.")
        time.sleep(0.05)

    url = f"http://127.0.0.1:{port}/?t={token}"

    def quit_all():
        server.should_exit = True
        if desktop is not None and desktop._window is not None:
            from gi.repository import GLib
            GLib.idle_add(lambda: (desktop._window.destroy(), False)[1])

    try:
        if use_browser:
            print(f"DA Vibe Manager running. Open this URL (keep it private - it grants access to the app):\n{url}",
                  flush=True)
            if not args.no_open:
                import webbrowser

                webbrowser.open(url)
            while thread.is_alive():  # until Quit in the page, or Ctrl+C
                thread.join(0.5)
        else:
            import webview
            from gi.repository import GLib

            # the window's class and Wayland app_id, which desktops match to our desktop entry (and its
            # icon); under `python -m davibemanager` it would otherwise be "__main__.py"
            GLib.set_prgname(desktop_id())
            GLib.set_application_name("DA Vibe Manager")
            window = webview.create_window("DA Vibe Manager", url + "&desktop=1", width=460, height=720,
                                           min_size=(380, 480), hidden=args.hidden, text_select=True,
                                           background_color=config.WINDOW_BACKGROUND.get(cfg.settings.theme, "#111418"))
            desktop._window = window
            desktop.visible = not args.hidden

            def on_closing():
                if desktop.tray and desktop.tray.available and server.started and not server.should_exit:
                    desktop.hide()
                    return False          # keep running in the tray
                server.should_exit = True
                return True
            window.events.closing += on_closing

            def new_chat():
                engine = holder.get("engine")
                if engine is not None and engine.loop is not None:
                    import asyncio
                    asyncio.run_coroutine_threadsafe(engine.new_chat(), engine.loop)
                desktop.show()

            def on_started():
                desktop.tray = tray_mod.Tray(on_open=desktop.show, on_new_chat=new_chat, on_quit=quit_all)
                if not desktop.tray.available:
                    desktop.show()            # no tray to come back from: never start hidden
                if shown.is_set():
                    desktop.show()

                def close(*_):
                    quit_all()
                    return False

                for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
                    GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, sig, close)

            webview.start(on_started, gui="gtk", private_mode=True, icon=window_icon())
    except KeyboardInterrupt:
        pass
    finally:
        server.should_exit = True
        # the engine stops the sandbox first (well under a second), then Claude Code and the gateway
        thread.join(timeout=20)
        shutil.rmtree(runtime, ignore_errors=True)


if __name__ == "__main__":
    main()
