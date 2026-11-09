"""Starting with the computer: the autostart entry starts the copy that is running now."""

import os
import socket
import threading

from davibemanager import config, tray


def test_autostart_follows_the_running_copy_and_keeps_an_icon_that_lasts(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(config, "data_dir", lambda: tmp_path / "data")
    tray.refresh_autostart("'/home/u/Applications/DAVibeManager.AppImage'")
    assert not tray.autostart_path().exists()          # off stays off
    tray.set_autostart(True, "/usr/bin/python3 -m davibemanager")
    tray.refresh_autostart("'/home/u/AppImages/davibemanager.appimage'")   # moved by Gear Lever, say
    text = tray.autostart_path().read_text()
    assert "Exec='/home/u/AppImages/davibemanager.appimage' --hidden" in text
    icon = next(line.split("=", 1)[1] for line in text.splitlines() if line.startswith("Icon="))
    assert icon == str(tmp_path / "data" / "icons" / "davibemanager.svg")
    assert open(icon, "rb").read() == tray.ICON.read_bytes()


def _name(monkeypatch, tmp_path):
    """A single-instance name of the test's own, so the app running on this computer is never reached."""
    name = f"\0davibemanager-test-{os.getpid()}-{tmp_path.name}".encode()
    monkeypatch.setattr(tray, "_socket_name", lambda: name)
    return name


def test_a_second_launch_hands_over_to_the_first(monkeypatch, tmp_path):
    _name(monkeypatch, tmp_path)
    shown = threading.Event()
    assert tray.claim_single_instance(shown.set) is True
    assert tray.claim_single_instance(lambda: None) is False
    assert shown.wait(5)


def test_a_name_another_user_took_makes_no_copy_of_this_ones_exit(monkeypatch, tmp_path):
    """Anyone on this computer may bind an abstract name: taking this user's, another user made every launch
    think a copy was running, and exit."""
    name = _name(monkeypatch, tmp_path)
    squatter = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    squatter.bind(name)
    squatter.listen(1)
    real = tray.peer_uid
    monkeypatch.setattr(tray, "peer_uid", lambda sock: real(sock) + 1)      # as another user's would read
    try:
        assert tray.claim_single_instance(lambda: None) is True
        squatter.settimeout(2)
        conn, _ = squatter.accept()
        assert conn.recv(16) == b""                                          # nothing was handed to it
        conn.close()
    finally:
        squatter.close()


def test_only_this_users_launches_bring_the_window_up(monkeypatch, tmp_path):
    name = _name(monkeypatch, tmp_path)
    shown = threading.Event()
    real = tray.peer_uid
    monkeypatch.setattr(tray, "peer_uid", lambda sock: real(sock) + 1)
    assert tray.claim_single_instance(shown.set) is True
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:                  # "another user's" launch
        c.connect(name)
        c.sendall(b"show\n")
    assert not shown.wait(0.5)
    assert real(socket.socketpair()[0]) == os.getuid()


def test_an_appindicator_counts_only_where_something_shows_it(monkeypatch):
    """Stock GNOME has AppIndicator's library but nothing that shows one: closing the window would hide
    it to an icon no one can see."""
    import sys
    import types
    made = []
    module = types.SimpleNamespace(Indicator=types.SimpleNamespace(new=lambda *a: made.append(a)))
    monkeypatch.setitem(sys.modules, "gi.repository.FakeIndicator3", module)
    gi = types.SimpleNamespace(require_version=lambda *a: None)
    monkeypatch.setitem(sys.modules, "gi", gi)
    monkeypatch.setattr(tray, "_tray_host", lambda: False)
    t = tray.Tray.__new__(tray.Tray)
    t.kind, t._icon = "", None
    assert t._indicator("FakeIndicator3", "ayatana") is False and not made and t.kind == ""


def test_a_notification_names_the_apps_own_desktop_entry(monkeypatch):
    import sys
    import types
    hints, shown = {}, []

    class Notification:
        @staticmethod
        def new(title, body, icon):
            return Notification()

        def set_hint(self, key, value):
            hints[key] = value

        def show(self):
            shown.append(True)
            return True
    notify = types.SimpleNamespace(is_initted=lambda: True, init=lambda name: None, Notification=Notification)
    glib = types.SimpleNamespace(get_prgname=lambda: "davibemanager", Variant=lambda kind, v: (kind, v))
    monkeypatch.setitem(sys.modules, "gi", types.SimpleNamespace(require_version=lambda *a: None))
    monkeypatch.setitem(sys.modules, "gi.repository", types.SimpleNamespace(GLib=glib, Notify=notify))
    assert tray.notify("Built", "Ready") is True and shown
    assert hints["desktop-entry"] == ("s", "davibemanager")
