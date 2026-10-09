"""Moving over from DA Linux Agent (the app's old name): settings, apps and chats, the API key,
starting with the computer, our own menu entries, and the sandbox, each once."""

import os
import subprocess
import uuid

import pytest

from davibemanager import config, creds, integrate, migrate
from davibemanager.workspace import podman

# Podman keeps its images under XDG_DATA_HOME: it must see the real one, not the test's
REAL_DATA_HOME = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
REAL_CONFIG_HOME = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")


def old_install(tmp_path):
    (tmp_path / "config" / "dalinuxagent").mkdir(parents=True)
    (tmp_path / "config" / "dalinuxagent" / "config.toml").write_text('[settings]\ntheme = "light"\n')
    apps = tmp_path / "data" / "dalinuxagent" / "apps" / "gthumb"
    apps.mkdir(parents=True)
    (apps / "app.json").write_text('{"id": "gthumb"}')
    menu = tmp_path / "applications"
    menu.mkdir()
    old_icon = tmp_path / "data" / "dalinuxagent" / "icons" / "dla-gthumb.png"
    (menu / "dla-gthumb.desktop").write_text(f"[Desktop Entry]\nExec=/x\nIcon={old_icon}\nX-DLA-App=gthumb\n")
    (menu / "someone-else.desktop").write_text(f"[Desktop Entry]\nIcon={old_icon}\n")
    (tmp_path / "config" / "autostart").mkdir()
    (tmp_path / "config" / "autostart" / "dalinuxagent.desktop").write_text("[Desktop Entry]\n")
    return menu


def test_settings_apps_menu_entries_and_autostart_move_over_once(tmp_path):
    menu = old_install(tmp_path)
    done = migrate.run(menu)
    assert done["autostart"] and len(done["moved"]) == 2
    assert config.load().settings.theme == "light"
    assert (config.data_dir() / "apps" / "gthumb" / "app.json").is_file()
    assert not (tmp_path / "data" / "dalinuxagent").exists()
    assert f"Icon={config.data_dir()}/icons/dla-gthumb.png" in (menu / "dla-gthumb.desktop").read_text()
    assert "dalinuxagent" in (menu / "someone-else.desktop").read_text()      # not ours: left alone
    assert not migrate.old_autostart().exists()
    assert migrate.run(menu) == {"moved": [], "autostart": False}           # again: nothing to do


def test_nothing_is_moved_over_a_new_install(tmp_path):
    old_install(tmp_path)
    config.data_dir().mkdir(parents=True)
    migrate.run(tmp_path / "applications")
    assert (tmp_path / "data" / "dalinuxagent" / "apps").is_dir() and not (config.data_dir() / "apps").exists()


def test_the_api_key_moves_on_its_first_read(memory_keyring):
    memory_keyring.set_password("dalinuxagent", "provider:NanoGPT", "sk-1")
    assert creds.get_secret("provider", "NanoGPT") == "sk-1"
    assert memory_keyring.store == {("davibemanager", "provider:NanoGPT"): "sk-1"}
    creds.delete_secret("provider", "NanoGPT")
    assert creds.get_secret("provider", "NanoGPT") is None


def test_apps_made_before_the_rename_keep_their_names_so_updates_replace_them():
    assert integrate.stable_name({"id": "gthumb", "name": "gThumb"}) == "gThumb-dla.AppImage"
    assert integrate.stable_name({"id": "gthumb", "name": "gThumb", "tag": "dvm"}) == "gThumb-dvm.AppImage"


async def test_the_users_old_sandbox_goes_only_into_the_apps_own_sandbox(no_real_podman):
    """Never into a test's (or any other) sandbox: one took it once, and removed it with its own."""
    assert await podman.move_old_sandbox("dvm-test-sandbox") == ""
    assert no_real_podman == []                                            # not even asked whether it's there


@pytest.mark.podman
async def test_the_old_sandbox_moves_with_its_owners_and_links(monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", REAL_DATA_HOME)
    monkeypatch.setenv("XDG_CONFIG_HOME", REAL_CONFIG_HOME)
    old, new = f"dvmtest-{uuid.uuid4().hex[:6]}", f"dvmtest-{uuid.uuid4().hex[:6]}"
    pm = podman.podman()
    image = podman.image_tag()
    if not await podman.image_exists(image):     # any image with a shell will do: the one from before the rename
        listed = subprocess.run([pm, "images", "--format", "{{.Repository}}:{{.Tag}}", podman.OLD_IMAGE_REPO],
                                capture_output=True, text=True).stdout.split()
        if not listed:
            pytest.skip("the sandbox image isn't built")
        image = listed[0]
    try:
        subprocess.run([pm, "run", "--rm", "--entrypoint", "sh", "-u", "0", "-v", f"{old}-work:/w", "-v", f"{old}-home:/h",
                        image, "-c", "echo hi > /w/f && chown 1000:1000 /w/f && ln -s f /w/l && echo s > /h/s"], check=True)
        assert await podman.move_old_sandbox(new, old=old, old_images="localhost/none") == "moved"
        out = subprocess.run([pm, "run", "--rm", "--entrypoint", "sh", "-v", f"{new}-work:/w", "-v", f"{new}-home:/h",
                              image, "-c", "stat -c '%u %N' /w/f /w/l; cat /h/s"], capture_output=True, text=True).stdout
        assert out.split("\n")[:3] == ["1000 '/w/f'", "0 '/w/l' -> 'f'", "s"]
        assert subprocess.run([pm, "volume", "exists", f"{old}-work"]).returncode != 0
        assert await podman.move_old_sandbox(new, old=old, old_images="localhost/none") == ""
    finally:
        for v in (f"{old}-work", f"{old}-home", f"{new}-work", f"{new}-home"):
            subprocess.run([pm, "volume", "rm", "-f", v], capture_output=True)
