"""Starting with the computer: the autostart entry starts the copy that is running now."""

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
