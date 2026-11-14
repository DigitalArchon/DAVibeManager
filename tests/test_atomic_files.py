"""Every file that matters is written whole or not at all (the cross-app standard, Nov 2026;
config.write_private): to a temporary file of its own, 0600 from the start, flushed, renamed over the
file, the folder flushed after. A fixed ".tmp" shared by every write, never flushed, could leave an empty
chat, app or sync group after a crash, and two writes at once wrote into the same file. And the app's
folders are this user's alone, also when they were there already."""

import json
import os
import stat

import pytest

from davibemanager import apps, config, delivery, podmansetup
from davibemanager.builder import bridge
from davibemanager.conversation import Conversation
from davibemanager.safety.outside import OutsideData
from davibemanager.sync import store


@pytest.fixture
def writes(monkeypatch):
    """Every file write_private puts in place, and each flush: (what, path)."""
    seen = []
    real_fsync, real_replace = os.fsync, os.replace

    def fsync(fd):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            target = "?"
        seen.append(("fsync", target))
        return real_fsync(fd)

    def replace(src, dst):
        seen.append(("replace", str(dst)))
        return real_replace(src, dst)
    monkeypatch.setattr(config.os, "fsync", fsync)
    monkeypatch.setattr(config.os, "replace", replace)
    return seen


def mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def put_in_place_with_its_folder_flushed(seen, path) -> bool:
    """A flushed file renamed over `path`, then `path`'s folder flushed."""
    names = [what for what, _ in seen]
    at = max(i for i, (what, where) in enumerate(seen) if what == "replace" and where == str(path))
    return (names[at - 1] == "fsync" and seen[at - 1][1].startswith(str(path.parent) + "/.")
            and ("fsync", str(path.parent)) in seen[at + 1:])


def test_write_private_is_whole_or_nothing_this_users_alone_and_leaves_nothing_behind(tmp_path, writes):
    path = tmp_path / "f.json"
    config.write_private(path, '{"a": "é"}')
    assert path.read_bytes() == '{"a": "é"}'.encode() and mode(path) == 0o600
    assert put_in_place_with_its_folder_flushed(writes, path)
    config.write_private(path, b"run", mode=0o700)
    assert mode(path) == 0o700
    assert sorted(p.name for p in tmp_path.iterdir()) == ["f.json"]          # no temporary file left

    class Boom(Exception):
        pass

    def failing(src, dst):
        raise Boom
    os_replace = config.os.replace
    config.os.replace = failing
    try:
        with pytest.raises(Boom):
            config.write_private(path, b"half")
    finally:
        config.os.replace = os_replace
    assert path.read_bytes() == b"run" and sorted(p.name for p in tmp_path.iterdir()) == ["f.json"]


def test_the_chat_its_apps_its_builds_sync_and_the_rest_are_written_through_it(tmp_path, writes):
    """Each of these wrote a fixed temporary name (or the file itself) and flushed nothing."""
    conv = Conversation.create()
    conv.save()
    assert put_in_place_with_its_folder_flushed(writes, conv.dir / "state.json") and mode(conv.dir / "state.json") == 0o600
    a = apps.create("gThumb", "appimage", "https://gitlab.gnome.org/GNOME/gthumb.git", base_ref="3.12.6")
    apps.save(a)
    assert put_in_place_with_its_folder_flushed(writes, apps.dir_of(a["id"]) / "app.json")
    written = apps.write_file(a["id"], "build.sh", "meson setup build\n")
    assert put_in_place_with_its_folder_flushed(writes, written) and mode(written) == 0o644     # the builder reads it
    d = delivery.root_dir() / "D1"
    d.mkdir(parents=True)
    delivery.record(d, {"kind": "appimage"})
    assert put_in_place_with_its_folder_flushed(writes, d / "delivery.json")
    store._write(tmp_path / "group.json", {"members": []})
    assert put_in_place_with_its_folder_flushed(writes, tmp_path / "group.json") and mode(tmp_path / "group.json") == 0o600
    outside = OutsideData(tmp_path / "outside.json", names=[])
    outside.save()
    assert put_in_place_with_its_folder_flushed(writes, tmp_path / "outside.json")
    wrapper = bridge.write_wrapper(tmp_path / "bin" / "claude", "dvm-builder")
    assert put_in_place_with_its_folder_flushed(writes, wrapper) and mode(wrapper) == 0o700        # it is run
    podmansetup.record_install(["podman"])
    assert json.loads(podmansetup._record_path().read_text()) == {"packages": ["podman"]}
    assert put_in_place_with_its_folder_flushed(writes, podmansetup._record_path())


def test_the_apps_folders_are_this_users_alone_also_when_they_were_there_already(tmp_path):
    for folder in (config.config_dir(), config.data_dir(), config.state_dir()):
        folder.mkdir(parents=True, exist_ok=True)
        os.chmod(folder, 0o755)
    nested = tmp_path / "new" / "deeper" / "folder"
    config.private_folder(nested)
    assert mode(nested) == mode(nested.parent) == mode(nested.parent.parent) == 0o700
    config.private_folders()
    assert [mode(f) for f in (config.config_dir(), config.data_dir(), config.state_dir())] == [0o700] * 3
    os.chmod(store.state_dir(), 0o755)
    assert mode(store.state_dir()) == 0o700 and mode(store.folder()) == 0o700
