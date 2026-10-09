"""Smoke test for an extracted AppImage, run by the AppImage's own Python inside a distro
container with a virtual display (see packaging/test-appimage.sh).

    smoke.py <AppDir> <out-dir> <name> fallback   WebKitGTK absent: opens in the browser, says why
    smoke.py <AppDir> <out-dir> <name> full       WebKitGTK present: app window, the API, the
                                                  bundled Claude Code CLI, and a screenshot of the page"""

import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request

APPDIR, OUT, NAME, MODE = sys.argv[1:5]
ENV = {**os.environ, "XDG_CONFIG_HOME": "/tmp/smoke/config", "XDG_DATA_HOME": "/tmp/smoke/data"}


def start(*args: str) -> tuple[subprocess.Popen, str, str]:
    """Run the app, return (process, base URL, token) once it prints its URL."""
    proc = subprocess.Popen([f"{APPDIR}/AppRun", "--port", "8790", *args], env=ENV, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in proc.stdout:
        print(f"  | {line.rstrip()}")
        if line.startswith("http://"):
            return proc, "http://127.0.0.1:8790", line.strip().split("t=", 1)[1]
    raise SystemExit("the app exited before printing its URL")


def api(base: str, token: str, method: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(base + path, method=method, headers={"X-Token": token, "Content-Type": "application/json"},
                                 data=json.dumps(body).encode() if body is not None else None)
    return json.load(urllib.request.urlopen(req, timeout=10))


def check(ok: bool, what: str) -> None:
    print(("PASS " if ok else "FAIL ") + what, flush=True)
    if not ok:
        raise SystemExit(1)


if MODE == "fallback":
    # webbrowser honours $BROWSER: "echo" stands in for opening a browser
    proc, base, token = start()
    st = api(base, token, "GET", "/api/state")
    check("WebKitGTK" in st["ui_notice"] and "Running in your web browser" in st["ui_notice"],
          f"{NAME}: without WebKitGTK it opens in the browser and says why")
    api(base, token, "POST", "/api/quit")
    proc.wait(10)
    check(proc.returncode is not None, f"{NAME}: Quit ends the process")
    sys.exit(0)

# --- full: the app window first
win = subprocess.Popen([f"{APPDIR}/AppRun"], env=ENV, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
time.sleep(8)
alive = win.poll() is None
win.terminate()
log = win.communicate(timeout=10)[0]
ok = alive and "Traceback" not in log and "Running in your web browser" not in log
check(ok, f"{NAME}: the app window starts and stays up" + ("" if ok else "\n" + "\n".join(f"  | {x}" for x in log.splitlines()[-15:])))

# the API, as the window drives it: not set up yet (no key), settings saved, this computer described
proc, base, token = start("--no-open")
st = api(base, token, "GET", "/api/state")
check(st["ready"] is False and st["config"]["settings"]["theme"] == "dark", f"{NAME}: the API answers, not set up yet")
api(base, token, "POST", "/api/settings", {"theme": "light"})
check(api(base, token, "GET", "/api/state")["config"]["settings"]["theme"] == "light", f"{NAME}: settings are saved")
about = api(base, token, "GET", "/api/about-computer?parts=system,hardware")["text"]
check("- System: " in about and "- Processor: " in about, f"{NAME}: it describes this computer\n" + about)

# the Claude Code CLI the sandbox image is built from: in the AppImage, and exactly the pinned one
sys.path.insert(0, f"{APPDIR}/usr/python/lib/python3.12/site-packages")
from davibemanager.workspace import pins, podman  # noqa: E402

cli = podman.bundled_cli()
digest = hashlib.sha256(cli.read_bytes()).hexdigest()
check(digest == pins.CLAUDE_SHA256 and os.access(cli, os.X_OK), f"{NAME}: the bundled Claude Code CLI is the pinned one")

# the page itself, rendered by the host's WebKitGTK through the bundled PyGObject
from davibemanager.app import _bundled_girepository  # noqa: E402

_bundled_girepository()
import gi  # noqa: E402

gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.1")
from gi.repository import GLib, Gtk, WebKit2  # noqa: E402

shot = f"{OUT}/{NAME}.png"
window = Gtk.OffscreenWindow()
view = WebKit2.WebView()
view.set_size_request(1300, 850)
window.add(view)
window.show_all()


def snap() -> bool:
    view.get_snapshot(WebKit2.SnapshotRegion.VISIBLE, WebKit2.SnapshotOptions.NONE, None,
                      lambda v, r: (v.get_snapshot_finish(r).write_to_png(shot), Gtk.main_quit()))
    return False


view.connect("load-changed", lambda v, e: e == WebKit2.LoadEvent.FINISHED and GLib.timeout_add(2500, snap))
view.load_uri(f"{base}/?t={token}")
GLib.timeout_add(30000, Gtk.main_quit)
Gtk.main()
check(os.path.exists(shot), f"{NAME}: the page renders ({shot})")
api(base, token, "POST", "/api/quit")
proc.wait(10)
