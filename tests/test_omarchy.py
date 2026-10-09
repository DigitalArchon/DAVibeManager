"""Omarchy: knowing it's here, what it lacks (usually nothing), the app's own command to install it on
the user's click, and DA Vibe Manager's own entry in its menu."""

import asyncio
from pathlib import Path

import pytest

from davibemanager import hostrun, omarchy, sysinfo
from davibemanager.engine import UserError

OMARCHY_4 = {"NAME": "Omarchy", "ID": "omarchy", "ID_LIKE": "arch"}
ARCH = {"NAME": "Arch Linux", "ID": "arch"}


def omarchy_root(tmp_path, version="4.0.4") -> Path:
    root = tmp_path / "omarchy"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "omarchy-version").write_text("#!/bin/sh\n")
    (root / "version").write_text(version + "\n")
    return root


def test_omarchy_4_says_so_in_os_release(tmp_path, monkeypatch):
    monkeypatch.setattr(omarchy, "_version", lambda path: "4.0.4-1")
    assert omarchy.detect(OMARCHY_4, env={}, roots=()) == {"version": "4.0.4-1", "path": ""}


def test_omarchy_3_is_known_by_its_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(omarchy.shutil, "which", lambda n: None)          # its command isn't on PATH
    root = omarchy_root(tmp_path, "3.8.4")
    assert omarchy.detect(ARCH, env={}, roots=(str(root),)) == {"version": "3.8.4", "path": str(root)}
    assert omarchy.detect(ARCH, env={"OMARCHY_PATH": str(root)}, roots=())["path"] == str(root)


def test_another_arch_isnt_omarchy(tmp_path):
    assert omarchy.detect(ARCH, env={"OMARCHY_PATH": str(tmp_path / "nothing")}, roots=(str(tmp_path),)) is None


def test_it_is_looked_for_once(monkeypatch):
    calls = []
    monkeypatch.setattr(omarchy, "_detected", False)
    monkeypatch.setattr(sysinfo, "_os_release", lambda: calls.append(1) or OMARCHY_4)
    monkeypatch.setattr(omarchy, "_version", lambda path: "4.0.4-1")
    assert omarchy.detect() and omarchy.detect() and len(calls) == 1


def typelibs(tmp_path, *names) -> tuple[str, ...]:
    d = tmp_path / "girepository-1.0"
    d.mkdir(exist_ok=True)
    for n in names:
        (d / f"{n}.typelib").write_bytes(b"")
    return (str(d),)


def test_a_stock_omarchy_lacks_nothing(tmp_path):
    which = {"fusermount3": "/usr/bin/fusermount3", "pacman": "/usr/bin/pacman", "pkexec": "/usr/bin/pkexec"}.get
    dirs = typelibs(tmp_path, "WebKit2-4.1", "AyatanaAppIndicator3-0.1")
    assert omarchy.missing(which, dirs) == [] and omarchy.plan(which, dirs) is None


def test_what_is_missing_is_installed_with_one_fixed_command(tmp_path):
    which = {"pacman": "/usr/bin/pacman", "pkexec": "/usr/bin/pkexec"}.get
    p = omarchy.plan(which, typelibs(tmp_path))
    assert p["packages"] == ["fuse3", "webkit2gtk-4.1", "libayatana-appindicator"]
    assert p["command"] == "pacman -S --needed --noconfirm fuse3 webkit2gtk-4.1 libayatana-appindicator"
    assert p["terminal"] == "sudo " + p["command"] and p["can_install"]
    assert [m["for"] for m in p["missing"]][0] == "to start the apps DA Vibe Manager builds"
    # the old AppIndicator does for the tray too, and fusermount (FUSE 2's name) for FUSE
    which = {"fusermount": "/usr/bin/fusermount"}.get
    p = omarchy.plan(which, typelibs(tmp_path, "AppIndicator3-0.1"))
    assert p["packages"] == ["webkit2gtk-4.1"] and not p["can_install"]            # no pkexec: a terminal


# ---------------------------------------------------------------- DA Vibe Manager in Omarchy's menu

ICON = Path(__file__).parent.parent / "src/davibemanager/web/icon.svg"


def test_its_own_entry_starts_this_copy_and_follows_it(tmp_path):
    entry = tmp_path / "data/applications/davibemanager.desktop"
    assert not omarchy.has_self_entry()
    omarchy.refresh_self_entry(["/home/u/Apps/DAVibeManager.AppImage"], ICON)
    assert not entry.exists()                                   # only on the user's click
    omarchy.add_self_entry(["/home/u/My Apps/DAVibeManager.AppImage"], ICON)
    text = entry.read_text()
    assert 'Exec="/home/u/My Apps/DAVibeManager.AppImage"' in text and "Icon=davibemanager" in text
    assert "StartupWMClass=davibemanager" in text and omarchy.has_self_entry()
    assert (tmp_path / "data/icons/hicolor/scalable/apps/davibemanager.svg").read_bytes() == ICON.read_bytes()
    # a newer AppImage, somewhere else: the entry starts that one
    omarchy.refresh_self_entry(["/home/u/Downloads/DAVibeManager-0.2.AppImage"], ICON)
    assert "Exec=/home/u/Downloads/DAVibeManager-0.2.AppImage\n" in entry.read_text()
    # removed in Omarchy's launcher: it stays removed
    entry.unlink()
    omarchy.refresh_self_entry(["/home/u/Downloads/DAVibeManager-0.2.AppImage"], ICON)
    assert not entry.exists()


def test_an_entry_something_else_made_is_left_alone(tmp_path):
    entry = tmp_path / "data/applications/davibemanager.desktop"
    entry.parent.mkdir(parents=True)
    entry.write_text("[Desktop Entry]\nType=Application\nName=DA Vibe Manager\nExec=/opt/dvm/AppRun\n")
    omarchy.refresh_self_entry(["/home/u/DAVibeManager.AppImage"], ICON)
    assert "Exec=/opt/dvm/AppRun" in entry.read_text() and omarchy.has_self_entry()     # nothing to offer


# ---------------------------------------------------------------- the engine, on the user's clicks

@pytest.fixture
def on_omarchy(env, monkeypatch):
    engine, _, _ = env
    state = {"missing": ["fuse3"]}
    monkeypatch.setattr(omarchy, "_detected", {"version": "4.0.4-1", "path": "/usr/share/omarchy"})
    monkeypatch.setattr(omarchy, "missing", lambda which=None, typelib_dirs=(): list(state["missing"]))
    monkeypatch.setattr(omarchy.shutil, "which", lambda n: f"/usr/bin/{n}")
    return engine, state


async def wait_for(cond, what, timeout=5.0):
    for _ in range(int(timeout / 0.01)):
        if cond():
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"timed out waiting for {what}")


def test_elsewhere_there_is_no_omarchy_card(env):
    engine, _, _ = env
    assert engine.snapshot()["omarchy"] is None
    with pytest.raises(UserError, match="isn't running Omarchy"):
        engine.install_omarchy_setup()


async def test_what_omarchy_lacks_is_installed_on_the_users_click(on_omarchy, monkeypatch):
    engine, state = on_omarchy
    ran = []

    async def run(command, *, as_root=False, timeout=0, cancel=None):
        ran.append((command, as_root))
        state["missing"] = []
        return hostrun.RunResult(0, "installing fuse3...\n", False, 4.0)
    monkeypatch.setattr(hostrun, "run", run)
    view = engine.snapshot()["omarchy"]
    assert view["version"] == "4.0.4-1" and view["setup"]["packages"] == ["fuse3"] and not view["self_entry"]
    engine.install_omarchy_setup()
    assert engine.snapshot()["omarchy"]["install"]["state"] == "installing"
    with pytest.raises(UserError, match="already"):
        engine.install_omarchy_setup()
    await wait_for(lambda: not engine._omarchy_install, "the install")
    assert ran == [("pacman -S --needed --noconfirm fuse3", True)]
    assert engine.snapshot()["omarchy"]["setup"] is None


@pytest.mark.parametrize("code,after,said", [
    (126, ["fuse3"], "password prompt was closed"),
    (1, ["fuse3"], "ended with code 1"),
    (0, ["fuse3"], "fuse3 still isn't there"),
])
async def test_an_omarchy_install_that_didnt_work_says_why(on_omarchy, monkeypatch, code, after, said):
    engine, state = on_omarchy

    async def run(command, **kw):
        state["missing"] = after
        return hostrun.RunResult(code, "error: target not found: fuse3\n", False, 1.0)
    monkeypatch.setattr(hostrun, "run", run)
    engine.install_omarchy_setup()
    await wait_for(lambda: engine._omarchy_install.get("state") == "failed", "the failure")
    assert said in engine._omarchy_install["error"]


def test_dvm_is_put_in_omarchys_menu_on_the_users_click(on_omarchy, tmp_path):
    engine, _ = on_omarchy
    engine.launch_argv = ["/home/u/DAVibeManager.AppImage"]
    engine.add_omarchy_entry()
    assert "Exec=/home/u/DAVibeManager.AppImage" in (tmp_path / "data/applications/davibemanager.desktop").read_text()
    assert engine.snapshot()["omarchy"]["self_entry"]


def test_the_assistant_knows_its_omarchy(on_omarchy):
    assert ("Omarchy", "4.0.4-1 (apps go in its own menu, Hyprland desktop)") in sysinfo.system()
