"""Backups: everything the user has here, encrypted with their password, to restore on this computer
or another and go on having and looking after their apps."""

import io
import json
import os
import tarfile
import time

import pytest

from davibemanager import apps, backup, config, creds, delivery
from davibemanager.conversation import Conversation
from davibemanager.models import UserError

PASSWORD = "correct horse battery"


@pytest.fixture(autouse=True)
def quick_scrypt(monkeypatch):
    """The real cost is for people guessing; tests make many."""
    monkeypatch.setattr(backup, "SCRYPT", {"n": 1 << 10, "r": 8, "p": 1})


def an_app(name="gThumb", builds=("D1",), installed="D1", size=10):
    a = apps.create(name, "appimage", f"https://gitlab.gnome.org/GNOME/{name.lower()}.git", base_ref="3.12.6")
    apps.write_file(a["id"], "changes/zoom.patch", "From abc Mon Sep 17 00:00:00 2001\nSubject: [PATCH] Zoom\n")
    apps.write_file(a["id"], "build.sh", "meson setup build\n")
    for did in builds:
        d = delivery.root_dir() / did
        d.mkdir(parents=True)
        (d / f"{name}.AppImage").write_bytes(os.urandom(size))
        delivery.record(d, {"kind": "appimage", "name": name, "version": f"3.12.6-dvm{did[1:]}", "file": f"{name}.AppImage",
                            "status": "installed" if did == installed else "replaced", "app": a["id"],
                            "installed_to": "/home/u/Applications/x.AppImage", "installed_via": "menu"})
    return apps.save({**a, "changes": [{"id": "zoom", "title": "Drag a box to zoom", "patch_ids": []}], "builds": list(builds),
                      "installed": {"build": installed, "version": "3.12.6-dvm1", "via": "menu"} if installed else None})


def make(tmp_path, cfg=None, sessions=None, name="b.dvmbackup"):
    dest = tmp_path / name
    return dest, backup.write_backup(dest, PASSWORD, cfg or config.Config(), sessions)


def test_a_backup_opens_only_with_its_password_and_holds_each_apps_build(tmp_path):
    an_app(builds=("D1", "D2"), installed="D2", size=3 << 20)          # bigger than a chunk
    creds.set_secret("provider", "NanoGPT", "sk-1")
    cfg = config.Config(providers=[config.Provider("NanoGPT", "https://nano-gpt.com/api/v1")])
    dest, manifest = make(tmp_path, cfg)
    assert manifest["builds"] == ["D2"] and manifest["keys"] == ["NanoGPT"] and manifest["apps"][0]["name"] == "gThumb"
    assert oct(dest.stat().st_mode & 0o777) == "0o600"
    assert b"gThumb" not in dest.read_bytes() and b"sk-1" not in dest.read_bytes()     # all of it encrypted
    with pytest.raises(backup.BackupError, match="password doesn't open"):
        backup.read_backup(dest, "not the password")
    out = tmp_path / "out"
    assert backup.read_backup(dest, PASSWORD, out)["builds"] == ["D2"]
    assert (out / "data/deliveries/D2/gThumb.AppImage").read_bytes() == (delivery.root_dir() / "D2/gThumb.AppImage").read_bytes()
    assert not (out / "data/deliveries/D1").exists()                    # an older build: made again if wanted
    assert (out / "data/apps/gthumb/changes/zoom.patch").is_file()
    assert json.loads((out / "secrets.json").read_text())["providers"] == {"NanoGPT": "sk-1"}


def chunks(raw: bytes) -> tuple[bytes, list[bytes]]:
    head_len = len(backup.MAGIC) + 4 + int.from_bytes(raw[len(backup.MAGIC):len(backup.MAGIC) + 4], "big")
    head, rest, out = raw[:head_len], raw[head_len:], []
    while rest:
        n = int.from_bytes(rest[:4], "big")
        out.append(rest[:4 + n])
        rest = rest[4 + n:]
    return head, out


@pytest.mark.parametrize("damage", ["flip", "cut", "swap"])
def test_a_backup_changed_cut_short_or_reordered_is_refused(tmp_path, damage):
    an_app(size=3 << 20)
    dest, _ = make(tmp_path)
    head, parts = chunks(dest.read_bytes())
    assert len(parts) >= 3
    if damage == "flip":
        mid = bytearray(parts[1])
        mid[100] ^= 1
        parts[1] = bytes(mid)
    elif damage == "cut":
        parts = parts[:-1]                      # what's left still reads as chunks: but none is the last
    else:
        parts[0], parts[1] = parts[1], parts[0]
    dest.write_bytes(head + b"".join(parts))
    with pytest.raises(backup.BackupError, match="damaged|cut short|password"):
        backup.read_backup(dest, PASSWORD, tmp_path / "out")


@pytest.mark.parametrize("kdf", [{"r": 1 << 20}, {"p": 1 << 12}, {"n": 1 << 22}, {"n": 1000}, {"r": "8"}, {"nonce": "AAAAAAAA"}])
def test_a_backup_whose_header_asks_too_much_of_this_computer_is_refused(tmp_path, kdf):
    """The key's cost comes from the file: a made-up one must not take all the memory or hours."""
    an_app()
    dest, _ = make(tmp_path)
    raw = dest.read_bytes()
    head_len = int.from_bytes(raw[len(backup.MAGIC):len(backup.MAGIC) + 4], "big")
    info = json.loads(raw[len(backup.MAGIC) + 4:len(backup.MAGIC) + 4 + head_len])
    header = json.dumps({**info, **kdf}).encode()
    dest.write_bytes(backup.MAGIC + len(header).to_bytes(4, "big") + header + raw[len(backup.MAGIC) + 4 + head_len:])
    started = time.monotonic()
    with pytest.raises(backup.BackupError, match="damaged"):
        backup.read_backup(dest, PASSWORD)
    assert time.monotonic() - started < 2


def test_nothing_in_a_backup_goes_outside_its_own_layout(tmp_path):
    dest = tmp_path / "evil.dvmbackup"
    with open(dest, "wb") as f:
        sealed = backup.Sealed(f, PASSWORD, {})
        with tarfile.open(fileobj=sealed, mode="w|") as tar:
            def add(name, data=b"x", kind=tarfile.REGTYPE, link=""):
                ti = tarfile.TarInfo(name)
                ti.type, ti.linkname, ti.size = kind, link, len(data) if kind == tarfile.REGTYPE else 0
                tar.addfile(ti, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
            add("manifest.json", b'{"format": 1}')
            add("../outside.txt")
            add("/tmp/absolute.txt")
            add("data/link", kind=tarfile.SYMTYPE, link="/etc/passwd")
            add("elsewhere/file.txt")
            add("data/apps/ok.txt")
        sealed.close()
    out = tmp_path / "out"
    backup.read_backup(dest, PASSWORD, out)
    assert sorted(str(p.relative_to(out)) for p in out.rglob("*")) == ["data", "data/apps", "data/apps/ok.txt"]
    assert not (tmp_path / "outside.txt").exists()


async def test_restored_on_another_computer_the_apps_chats_and_key_are_back(env, tmp_path, memory_keyring):
    engine, _, _ = env
    engine.cfg.providers = [config.Provider("NanoGPT", "https://nano-gpt.com/api/v1")]
    creds.set_secret("provider", "NanoGPT", "sk-old-computer")
    engine.cfg.settings.theme = "light"
    an_app()
    engine.conv.title = "Zoom in gThumb"
    engine.conv.chat.append({"kind": "user", "text": "Make it zoom", "at": 1})
    engine.conv.session = "sess-1"
    engine._persist()
    sessions = tmp_path / "sessions" / "-work"
    sessions.mkdir(parents=True)
    (sessions / "sess-1.jsonl").write_text('{"type": "user"}\n')
    dest, _ = backup.write_backup(tmp_path / "b.dvmbackup", PASSWORD, engine.cfg, tmp_path / "sessions"), None
    # the other computer: its own folder for apps, a different app of its own, another key
    memory_keyring.store.clear()
    engine.cfg.settings.install_dir, engine.cfg.settings.theme = "/other/Apps", "dark"
    apps.create("mpv", "appimage", "https://github.com/mpv-player/mpv.git")
    out = await engine.backups.restore(tmp_path / "b.dvmbackup", PASSWORD)
    assert [a["name"] for a in out["apps"]] == ["gThumb"] and out["aside"].endswith(out["aside"][-15:])
    # its apps, ready to install here (not installed here yet)
    a = apps.load("gthumb")
    assert a["installed"] is None and a["restored"]["version"] == "3.12.6-dvm1"
    meta = delivery.load(delivery.root_dir() / "D1")
    assert meta["status"] == "new" and "installed_to" not in meta
    assert apps.load("mpv") is None                                    # what was here: moved aside, not lost
    assert (config.data_dir().with_name(os.path.basename(out["aside"])) / "apps" / "mpv" / "app.json").is_file()
    # its chats, settings and key; this computer's own settings kept
    assert engine.conv.title == "Zoom in gThumb" and engine.conv.session == "sess-1"
    assert (config.data_dir() / "restored-sessions" / "-work" / "sess-1.jsonl").is_file()    # into the sandbox when it runs
    assert engine.cfg.settings.theme == "light" and engine.cfg.settings.install_dir == "/other/Apps"
    assert creds.get_secret("provider", "NanoGPT") == "sk-old-computer"


async def test_a_chat_whose_session_didnt_come_along_starts_a_new_one(env, tmp_path):
    engine, _, _ = env
    engine.conv.chat.append({"kind": "user", "text": "hi", "at": 1})
    engine.conv.session = "sess-9"
    engine._persist()
    backup.write_backup(tmp_path / "b.dvmbackup", PASSWORD, engine.cfg, None)
    await engine.backups.restore(tmp_path / "b.dvmbackup", PASSWORD)
    assert engine.conv.chat[0]["text"] == "hi" and engine.conv.session == ""


async def test_a_wrong_password_changes_nothing(env, tmp_path):
    engine, _, _ = env
    an_app()
    backup.write_backup(tmp_path / "b.dvmbackup", PASSWORD, engine.cfg, None)
    apps.create("mpv", "appimage", "https://github.com/mpv-player/mpv.git")
    with pytest.raises(backup.BackupError, match="password"):
        await engine.backups.restore(tmp_path / "b.dvmbackup", "wrong password!")
    assert apps.load("mpv") and engine.conv is not None
    assert not list(config.data_dir().parent.glob("*.restoring-*"))


async def test_automatic_backups_go_to_the_folder_and_keep_the_newest(env, tmp_path):
    engine, _, _ = env
    s = engine.cfg.settings
    s.backup_dir, s.backup_auto, s.backup_keep = str(tmp_path / "usb"), "week", 2
    told = []
    engine.notify = lambda title, body: told.append(title)
    await engine.backups.tick(now=1e10)
    assert not (tmp_path / "usb").exists()                             # no password saved: nothing
    engine.backups.set_password(PASSWORD)
    await engine.backups.tick(now=1e10)
    assert told == ["Your apps weren't backed up"]                     # the drive isn't plugged in: said once
    await engine.backups.tick(now=1e10 + 1)
    assert told == ["Your apps weren't backed up"]
    (tmp_path / "usb").mkdir()
    made = []
    for _ in range(3):
        engine.backups._save_state(last={"at": 0})
        await engine.backups.tick(now=1e10)
        made.append(engine.backups.state()["last"]["path"])
    assert [f["name"] for f in engine.backups.found()] == [os.path.basename(p) for p in reversed(made[1:])]
    await engine.backups.tick(now=engine.backups.state()["last"]["at"] + 3600)
    assert len(engine.backups.found()) == 2                            # a week: not after an hour


async def test_after_each_change_a_backup_follows(env, tmp_path):
    engine, _, _ = env
    s = engine.cfg.settings
    s.backup_dir, s.backup_auto = str(tmp_path / "b"), "change"
    engine.backups.set_password(PASSWORD)
    (tmp_path / "b").mkdir()
    an_app()
    await engine.backups.tick()
    assert len(engine.backups.found()) == 1
    last = engine.backups.state()["last"]
    await engine.backups.tick(now=last["at"] + 3600)
    assert len(engine.backups.found()) == 1                            # nothing changed since
    apps.save(apps.load("gthumb"))                                     # a change after it
    await engine.backups.tick(now=time.time() + 3600)
    assert len(engine.backups.found()) == 2


def test_the_password_and_the_folder_are_checked(env):
    engine, _, _ = env
    with pytest.raises(UserError, match="at least 10"):
        engine.backups.set_password("short")
    with pytest.raises(UserError, match="inside the app's own data folder"):
        engine.save_settings({"backup_dir": str(config.data_dir() / "x")})
    with pytest.raises(UserError, match="full path"):
        engine.save_settings({"backup_dir": "backups"})
    engine.save_settings({"backup_dir": "~/Backups", "backup_auto": "day", "backup_keep": 3})
    assert engine.backups.view()["folder"].endswith("/Backups") and engine.cfg.settings.backup_auto == "day"
