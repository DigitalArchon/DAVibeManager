"""The user's apps over time: one app with all their changes, new releases (change log, summary,
skip, stop watching), rebuilding by the app alone (or with the assistant when that fails), and
installing into Gear Lever, Shelly or a menu entry of our own, with a way back."""

import asyncio
import json
import os
import stat
from pathlib import Path

import pytest
from fakesandbox import DESKTOP, FakeSandbox, commit_patch, make_appimage, offered

from davibemanager import appmanager, apps, delivery, integrate
from davibemanager.workspace import scripts

GTHUMB = "https://gitlab.gnome.org/GNOME/gthumb.git"
ZOOM = commit_patch("bbbb222", "Drag a box to zoom", "-old zoom\n+box zoom")
COPY = commit_patch("bbbb333", "Copy the file path", "-old menu\n+copy path")
ZOOM_KEPT = ZOOM.replace("DVM-Change: new", "DVM-Change: drag-a-box-to-zoom")      # as the app keeps it, named
ARGS = {"kind": "appimage", "path": "/work/out/gThumb-DVM.AppImage", "name": "gThumb", "version": "3.12.6-dvm1",
        "repo": "/work/apps/gthumb", "base_ref": "3.12.6", "summary": "Drag a box to zoom.", "change_title": "Drag a box to zoom",
        "feature": "# Drag to zoom\nThe user asked…", "build_script": "/work/apps/gthumb/build.sh",
        "build_packages": ["meson", "libgtk-3-dev"],
        "integration": "app", "tested": "Opened it under xvfb and zoomed.", "not_tested": "The user's desktop and theme."}


@pytest.fixture
async def gthumb(env, monkeypatch, tmp_path):
    """gThumb with one change of the user's, delivered by the assistant."""
    engine, fake, _ = env

    class Builder:
        entry = {"parts": []}
        busy = False
        tasks: dict = {}             # its background tasks (Engine._watch_loop reads them)

        async def close(self):
            pass
    engine.builder = Builder()
    sb = FakeSandbox()
    sb.repo("/work/apps/gthumb", head="bbbb222", patch=ZOOM)
    sb.files["/work/apps/gthumb/build.sh"] = b"meson setup build && ninja -C build && make-appimage\n"
    sb.install(monkeypatch, engine)                     # the sandbox running, as made
    told = []
    engine.notify = lambda title, body: told.append((title, body))
    (tmp_path / "home").mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    engine.cfg.settings.second_opinion = "off"         # no review racing the tests (one has its own)
    engine.cfg.settings.install_dir = str(tmp_path / "home" / "Applications")
    engine.cfg.settings.app_home = "menu"
    offered(engine)
    await engine.builder_deliver(ARGS)
    return engine, sb, fake, told


async def test_a_delivery_starts_an_app_with_everything_needed_to_make_it_again(gthumb):
    engine, sb, _, _ = gthumb
    a = apps.load("gthumb")
    assert a["upstream"] == GTHUMB and a["base_ref"] == "3.12.6" and a["builds"] == ["D1"]
    assert [c["title"] for c in a["changes"]] == ["Drag a box to zoom"] and len(a["patch_ids"]) == 1
    assert apps.read_file("gthumb", "series.patch") == ZOOM_KEPT == apps.read_file("gthumb", "changes/drag-a-box-to-zoom.patch")
    assert apps.read_file("gthumb", "build.sh").startswith("meson setup")
    assert a["packages"] == ["libgtk-3-dev", "meson"]
    assert "The user asked" in apps.feature_text(a)
    # and the sandbox has it too, for the assistant and the app's own builds
    assert sb.files["/work/.dvm/apps/gthumb/series.patch"] == ZOOM_KEPT.encode()
    assert json.loads(sb.files["/work/.dvm/apps/gthumb/app.json"])["changes"][0]["title"] == "Drag a box to zoom"


async def test_another_change_makes_one_app_with_both_never_a_second_gthumb(gthumb):
    engine, sb, _, _ = gthumb
    # built on the release alone, without the user's first change: refused, and told how to fix it
    sb.repo("/work/apps/gthumb", head="bbbb333", patch=COPY)
    with pytest.raises(delivery.DeliveryError, match="(?s)already has the user's change.*Drag a box to zoom.*commits out.*tree the app prepared"):
        await engine.builder_deliver({**ARGS, "change_title": "Copy the file path"})
    # on top of it: one gThumb with both
    sb.repo("/work/apps/gthumb", head="bbbb333", patch=ZOOM_KEPT + COPY)
    await engine.builder_deliver({**ARGS, "change_title": "Copy the file path", "app": "gthumb", "version": "3.12.6-dvm2"})
    assert [a["id"] for a in apps.list_all()] == ["gthumb"]
    a = apps.load("gthumb")
    assert [c["title"] for c in a["changes"]] == ["Drag a box to zoom", "Copy the file path"]
    assert len(a["changes"][1]["patch_ids"]) == 1 and len(a["patch_ids"]) == 2
    assert apps.read_file("gthumb", "series.patch") == ZOOM_KEPT + COPY.replace("DVM-Change: new", "DVM-Change: copy-the-file-path")


async def test_an_app_chat_delivers_for_its_own_app_only(gthumb):
    engine, sb, _, _ = gthumb
    assert (engine.conv.app, engine.conv.app_name) == ("gthumb", "gThumb")   # its first delivery made the chat's app
    apps.create("mpv", "appimage", "https://github.com/mpv-player/mpv.git")
    with pytest.raises(delivery.DeliveryError, match=r"This chat is about gThumb \(app id gthumb\), not mpv"):
        await engine.builder_deliver({**ARGS, "change_title": "Copy the file path", "app": "mpv"})
    builder = engine.builder
    await engine.new_chat("app", app_name="Shotwell")
    engine.builder = builder                            # a new chat closes it; the fixture's stand-in comes back
    with pytest.raises(delivery.DeliveryError, match="hasn't built for the user before"):
        await engine.builder_deliver({**ARGS, "change_title": "Copy the file path", "app": "gthumb"})
    await engine.new_chat("computer")
    engine.builder = builder
    with pytest.raises(delivery.DeliveryError, match="Nothing is built in a chat about the computer"):
        await engine.builder_deliver({**ARGS, "change_title": "Copy the file path"})
    assert apps.load("gthumb")["builds"] == ["D1"]


async def test_a_change_the_user_chose_to_drop_is_left_out_only_once_they_confirm_it_on_a_card(gthumb):
    from davibemanager import engine as engine_mod
    from helpers import wait_for
    engine, sb, _, _ = gthumb
    engine.builder.entry = {"parts": [{"t": "text", "text": "Here is the clean build, as you chose."}]}
    sb.repo("/work/apps/gthumb", head="bbbb333", patch=COPY)
    args = {**ARGS, "change_title": "Copy the file path", "app": "gthumb", "version": "3.12.6-dvm2"}
    # not named: refused, and told both ways (no card: the user hasn't chosen anything)
    with pytest.raises(delivery.DeliveryError, match="(?s)leaves_out.*Never rebuild their commits only to revert them"):
        await engine.builder_deliver(args)
    assert not any(q.get("left_out") for q in engine.questions.values())

    async def deliver_and_answer(answer):
        task = asyncio.create_task(engine.builder_deliver({**args, "leaves_out": ["drag-a-box-to-zoom"]}))
        await wait_for(lambda: any(q["status"] == "pending" for q in engine.questions.values()), "the card")
        q = next(q for q in engine.questions.values() if q["status"] == "pending")
        assert "leaves out “Drag a box to zoom”" in q["questions"][0]["question"]
        engine.answer_question(q["id"], [answer])
        return await task
    # the user keeps it after all: not delivered, and nothing built
    with pytest.raises(delivery.DeliveryError, match="wants to keep"):
        await deliver_and_answer(engine_mod.KEEP_THEM)
    assert apps.load("gthumb")["builds"] == ["D1"]
    # the user confirms: the change comes off the record, and the series is the new one alone
    before = apps.load("gthumb")
    await deliver_and_answer(engine_mod.LEAVE_OUT)
    a = apps.load("gthumb")
    assert [c["title"] for c in a["changes"]] == ["Copy the file path"] and len(a["patch_ids"]) == 1
    assert a["left_out"][0]["title"] == "Drag a box to zoom"
    assert apps.read_file("gthumb", "series.patch") == COPY.replace("DVM-Change: new", "DVM-Change: copy-the-file-path")
    assert delivery.load(delivery.root_dir() / "D2")["left_out"] == ["Drag a box to zoom"]
    # delivered again in this chat (say its build failed after the card): the user said so already
    n = len(engine.questions)
    await engine._confirm_left_out(before, before["changes"])
    assert len(engine.questions) == n


async def test_a_new_release_brings_its_change_log_security_fixes_and_a_summary(gthumb):
    engine, sb, fake, told = gthumb
    fake.completions.append("A security fix for TIFF files, and faster thumbnails.\n"
                            "SUMMARY: Fixes a dangerous crash with crafted TIFF files.\n"
                            "SECURITY: crash on crafted TIFF files (CVE-2026-1234)\nIMPORTANCE: security")
    info = await engine.app_manager.check("gthumb", quiet=True)
    assert info["status"] == "available" and info["latest"] == "3.12.7"
    assert any("CVE-2026-1234" in line for line in info["security_lines"])         # found in code
    assert info["summary"]["importance"] == "security" and "TIFF" in info["summary"]["security"]
    assert info["page"] == "https://gitlab.gnome.org/GNOME/gthumb/-/releases/3.12.7"
    assert told[-1][0] == "gThumb 3.12.7 is out" and "security fixes" in told[-1][1]
    log = engine.app_manager.read_changelog("gthumb")
    assert "CVE-2026-1234" in log["news"]["NEWS"] and log["since"] == "3.12.6"
    # the summary saw the change log as untrusted text
    sent = fake.requests[-1]["messages"]
    assert "untrusted" in sent[0]["content"] and "CVE-2026-1234" in sent[1]["content"]
    # told once per release
    await engine.app_manager.check("gthumb", quiet=True)
    assert len([t for t in told if "is out" in t[0]]) == 1


async def test_summaries_can_wait_to_be_asked_for_and_versions_skipped_or_apps_unwatched(gthumb):
    engine, sb, fake, told = gthumb
    engine.cfg.settings.changelog_summary = "manual"
    info = await engine.app_manager.check("gthumb", quiet=True)
    assert "summary" not in info and info["changelog"] and fake.requests == []      # read, not summarised
    fake.completions.append("Faster thumbnails.\nSUMMARY: Mostly speed.\nSECURITY: none\nIMPORTANCE: optional")
    summary = await engine.app_manager.summarize("gthumb")                        # when the user asks
    assert summary["importance"] == "optional" and summary["security"] == ""
    engine.app_manager.skip("gthumb")
    assert apps.load("gthumb")["skip"] == "3.12.7"
    sb.tags.append("3.12.8")
    told.clear()
    await engine.app_manager.check("gthumb", quiet=True)
    assert told and told[-1][0] == "gThumb 3.12.8 is out"                         # a skip is for that version only
    engine.app_manager.set_watch("gthumb", False)               # only when the user asks: never looked by itself
    assert apps.load("gthumb")["check_every"] == "manual"
    sb.tags.append("3.12.9")
    told.clear()
    await engine.app_manager.tick(now=apps.load("gthumb")["update"]["checked"] + 40 * 86400)
    assert told == [] and apps.load("gthumb")["update"]["latest"] == "3.12.8"


async def test_a_rebuild_is_done_by_the_app_alone_when_the_changes_still_apply(gthumb):
    engine, sb, fake, told = gthumb
    engine.cfg.settings.changelog_summary = "manual"
    await engine.app_manager.check("gthumb")
    did = await engine.app_manager.rebuild("gthumb", by_user=True)
    # from the app's own copy of the official repository (root's, fetched from there only), change by change
    mirror = engine.app_manager.mirror_path(GTHUMB)
    assert mirror.startswith("/var/lib/dvm/mirrors/") and sb.mirrored[-1] == [GTHUMB, mirror]
    carry = sb.calls_of(scripts.CARRY)[-1]
    assert carry[4:9] == [mirror, GTHUMB, "/work/.dvm/build/gthumb/src", "3.12.6", "3.12.7"]
    # in a clean container, with the change and build script as this app keeps them (not the sandbox's copies,
    # which something the assistant left running there could change while nobody watches)
    assert sb.where[sb.calls.index(carry)] == "dvm-sandbox-check"
    assert carry[9:] == ["drag-a-box-to-zoom", "/work/.dvm/changes/drag-a-box-to-zoom.patch"]
    assert sb.files["box:/work/.dvm/changes/drag-a-box-to-zoom.patch"].decode() == \
        apps.read_file("gthumb", "changes/drag-a-box-to-zoom.patch")
    assert sb.built_with[-1] == apps.read_file("gthumb", "build.sh")
    builds = sb.calls_of(scripts.CHECK_BUILD)
    assert builds[-1][-1] == "build" and len(builds) == 2                         # once (and once at delivery)
    assert sb.snapshots[-1] == "box:/work/.dvm/build/gthumb/src"                  # what was carried, and nothing else
    # in a clean container with its own build tools (not the sandbox's, nor installed in it)
    assert sb.check_packages[-1] == ("dvm-sandbox-check", ["libgtk-3-dev", "meson"]) and not sb.installed_packages
    meta = delivery.load(delivery.root_dir() / did)
    assert meta["by"] == "app" and meta["base_ref"] == "3.12.7" and meta["version"] == "3.12.7-dvm1"
    assert meta["identical_to"] == "D1" and meta["port"]
    assert apps.load("gthumb")["update"]["status"] == "built" and apps.load("gthumb")["builds"] == ["D1", did]
    assert told[-1][0] == "gThumb 3.12.7 is ready" and "identical" in told[-1][1]
    assert engine.conv.chat == []                                                  # no AI involved
    # its changes, as they are now, named and with fresh patch ids
    a = apps.load("gthumb")
    assert a["base_ref"] == "3.12.7" and [c["id"] for c in a["changes"]] == ["drag-a-box-to-zoom"]
    assert a["changes"][0]["patch_ids"] == a["patch_ids"] and a["repo"] == "/work/apps/gthumb"
    # and again (another try, a later release): from the official copy again, made afresh
    again = await engine.app_manager.rebuild("gthumb", by_user=True)
    assert again and sb.calls_of(scripts.CARRY)[-1][4:9] == [mirror, GTHUMB, "/work/.dvm/build/gthumb/src", "3.12.7", "3.12.7"]


async def test_when_the_changes_dont_apply_the_assistant_is_asked_with_what_failed(gthumb, monkeypatch):
    engine, sb, fake, told = gthumb
    engine.cfg.settings.changelog_summary = "manual"
    await engine.app_manager.check("gthumb")
    sb.carry_fail["drag-a-box-to-zoom"] = "CONFLICT (content): Merge conflict in gthumb/gth-image-viewer.c"
    # by itself (rebuild set to automatic): only told
    await engine.app_manager.rebuild("gthumb", by_user=False)
    assert told[-1][0] == "gThumb 3.12.7 needs the assistant" and engine.conv.chat == []
    port = apps.load("gthumb")["update"]["port"]
    assert port["step"] == "apply" and port["changes"] == {"drag-a-box-to-zoom": "failed"}
    # by the user's click: the assistant, in a new app chat, in a tree the app prepared with what carried
    # over, told exactly which change didn't and why
    sent = []
    monkeypatch.setattr(engine, "_start_turn", lambda content, note=True: sent.append((content, note)))
    await engine.app_manager.rebuild("gthumb", by_user=True)
    assert engine.conv.chat[-1]["text"] == "Please update my gThumb to version 3.12.7, with the same changes."
    assert (engine.conv.mode, engine.conv.app) == ("app", "gthumb")
    content, note = sent[0]
    assert not note                                     # its own note: the tree is prepared for the update
    assert sb.calls_of(scripts.CARRY)[-1][6:9] == ["/work/apps/gthumb", "3.12.6", "3.12.7"]
    assert "gth-image-viewer.c" in content and 'updates="gthumb"' in content
    assert "These didn't carry over" in content and "drag-a-box-to-zoom (Drag a box to zoom)" in content
    assert "not all the saved changes carry over" in content


async def test_installing_makes_a_menu_entry_of_its_own_and_an_update_takes_its_place(gthumb, tmp_path):
    engine, sb, fake, told = gthumb
    home = tmp_path / "home"
    meta = engine.install_delivery("D1")
    app_file = home / "Applications" / "gThumb-dvm.AppImage"
    assert meta["installed_to"] == str(app_file) and app_file.read_bytes() == sb.appimage
    assert os.stat(app_file).st_mode & stat.S_IXUSR
    entry = (home / ".local/share/applications/dvm-gthumb.desktop").read_text()
    assert f"Exec={app_file} %U" in entry and "Name=gThumb (DLA)" in entry and "MimeType=image/png;" in entry
    assert "Autostart" not in entry and "curl" not in entry and "Actions" not in entry   # only what describes the app
    assert "Icon=" in entry and Path(entry.split("Icon=")[1].split()[0]).read_bytes().startswith(b"\x89PNG")
    # the update replaces it in place: same file, same menu entry
    engine.cfg.settings.changelog_summary = "manual"
    await engine.app_manager.check("gthumb")
    sb.appimage = sb.rebuilt = make_appimage(b"app v2")
    did = await engine.app_manager.rebuild("gthumb")
    engine.install_delivery(did)
    assert app_file.read_bytes() == make_appimage(b"app v2")
    a = apps.load("gthumb")
    assert a["installed"]["build"] == did and a["previous"]["build"] == "D1" and a["update"]["status"] == "current"
    assert delivery.load(delivery.root_dir() / "D1")["status"] == "replaced"
    # and back
    engine.app_manager.rollback("gthumb")
    assert app_file.read_bytes() == make_appimage(b"app v1") and apps.load("gthumb")["installed"]["build"] == "D1"


async def test_an_app_is_exported_as_its_appimage_to_run_elsewhere(gthumb, tmp_path):
    """The build as delivered (checked), in Downloads, under a name that says what it is: the installed
    one, else the newest; never one set aside, nor a changed file."""
    engine, sb, _, _ = gthumb
    downloads = tmp_path / "home" / "Downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    view = next(x for x in engine.app_manager.apps() if x["id"] == "gthumb")
    assert view["export_build"] == "D1"                       # not installed yet: the newest
    out = engine.app_manager.export_appimage("gthumb")
    f = downloads / "gThumb-3.12.6-dvm1-x86_64.AppImage"
    assert out["path"] == str(f) and f.read_bytes() == sb.appimage and os.stat(f).st_mode & stat.S_IXUSR
    assert engine.app_manager.export_appimage("gthumb")["name"] == "gThumb-3.12.6-dvm1-x86_64-2.AppImage"   # never over a file
    assert not [p for p in downloads.iterdir() if p.name.endswith(".part")]
    d = delivery.root_dir() / "D1"
    (d / delivery.load(d)["file"]).write_bytes(b"changed")
    with pytest.raises(appmanager.UserError, match="no longer matches"):
        engine.app_manager.export_appimage("gthumb")
    engine.reject_delivery("D1")
    assert next(x for x in engine.app_manager.apps() if x["id"] == "gthumb")["export_build"] == ""
    with pytest.raises(appmanager.UserError, match="no build to export"):
        engine.app_manager.export_appimage("gthumb")


def fake_cli(tmp_path, monkeypatch, name, script):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    f = bin_dir / name
    f.write_text("#!/usr/bin/env python3\n" + script)
    f.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setattr(integrate, "host_env", lambda: dict(os.environ))
    return tmp_path / f"{name}.log"


GEARLEVER = r'''
import json, os, shutil, sys
log = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))), "gearlever.log")
db = log + ".db"
apps = json.load(open(db)) if os.path.exists(db) else []
open(log, "a").write(json.dumps(sys.argv[1:]) + "\n")
if sys.argv[1] == "--integrate":
    # as Gear Lever 4.6.2 does: the old one is replaced only when the question is answered "r";
    # -y skips the question, and a second copy is made
    answers = [] if "-y" in sys.argv else sys.stdin.read().split()
    existing = [a for a in apps if a["name"] == "gThumb (DLA)"]
    replace = existing and len(answers) > 1 and answers[1] == "r"
    dest = existing[0]["path"] if replace else os.path.expanduser(f"~/AppImages/gthumb_dvm{'_0' if existing else ''}.appimage")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copy(sys.argv[2], dest)
    if not replace:
        apps.append({"name": "gThumb (DLA)", "path": dest, "desktop_id": os.path.basename(dest)[:-9] + ".desktop"})
    json.dump(apps, open(db, "w"))
    print(f"{dest} was integrated successfully")
elif sys.argv[1] == "--list-installed":
    print("Loading...")
    print(json.dumps({"schema_version": 1, "installed": apps}))
elif sys.argv[1] == "--remove":
    # without -y it asks first (Gear Lever's Cli.py): nothing answered, nothing removed
    if "-y" not in sys.argv:
        sys.exit(1)
    os.remove(sys.argv[2])
    json.dump([a for a in apps if a["path"] != sys.argv[2]], open(db, "w"))
'''


async def test_with_gear_lever_it_lives_there_and_an_update_replaces_it_there(gthumb, tmp_path, monkeypatch):
    engine, sb, fake, told = gthumb
    log = fake_cli(tmp_path, monkeypatch, "gearlever", GEARLEVER)
    engine.cfg.settings.app_home = "auto"
    meta = engine.install_delivery("D1")
    assert meta["installed_via"] == "gearlever" and meta["installed_to"].endswith("AppImages/gthumb_dvm.appimage")
    calls = [json.loads(l) for l in log.read_text().splitlines()]
    integrate_call = next(c for c in calls if c[0] == "--integrate")
    assert integrate_call[1].endswith("staging/gThumb-dvm.AppImage") and integrate_call[2:] == ["--replace"]
    assert not Path(integrate_call[1]).exists()                     # our staged copy is gone
    engine.cfg.settings.changelog_summary = "manual"
    await engine.app_manager.check("gthumb")
    sb.appimage = sb.rebuilt = make_appimage(b"app v2")
    did = await engine.app_manager.rebuild("gthumb")
    meta = engine.install_delivery(did)
    assert meta["installed_to"].endswith("AppImages/gthumb_dvm.appimage")          # the same app, in place
    assert Path(meta["installed_to"]).read_bytes() == make_appimage(b"app v2")
    assert len(json.load(open(str(log) + ".db"))) == 1                             # one gThumb in Gear Lever


SHELLY = r'''
import json, os, shutil, sys
log = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))), "shelly.log")
open(log, "a").write(json.dumps(sys.argv[1:]) + "\n")
dest = os.path.expanduser("~/.local/share/shelly/appimages/gThumb-dvm.AppImage")
if sys.argv[1:3] == ["install", "appimage"]:
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copy(sys.argv[3], dest)
elif sys.argv[1:3] == ["list", "appimage"]:
    print(json.dumps([{"Name": "gThumb-dvm", "DesktopName": "gThumb (DVM)", "Path": dest}]))
elif sys.argv[1:3] == ["remove", "appimage"]:
    if sys.argv[3] != "gThumb-dvm":
        sys.exit("no such app")
    os.remove(dest)
'''


async def test_on_arch_shelly_is_where_apps_live(gthumb, tmp_path, monkeypatch):
    engine, sb, fake, told = gthumb
    log = fake_cli(tmp_path, monkeypatch, "shelly", SHELLY)
    fake_cli(tmp_path, monkeypatch, "gearlever", GEARLEVER)
    engine.cfg.settings.app_home = "auto"                             # Shelly first where it is (Arch)
    meta = engine.install_delivery("D1")
    assert meta["installed_via"] == "shelly" and meta["installed_to"].endswith("shelly/appimages/gThumb-dvm.AppImage")
    assert apps.load("gthumb")["installed"]["desktop_id"] == "gThumb-dvm.desktop"
    call = json.loads(log.read_text().splitlines()[0])
    assert call[:2] == ["install", "appimage"] and call[-1] == "-n"


async def test_removing_an_app_uninstalls_it_and_deletes_its_builds_but_keeps_its_chats(gthumb, tmp_path):
    engine, sb, fake, told = gthumb
    home = tmp_path / "home"
    engine.install_delivery("D1")
    app_file = home / "Applications" / "gThumb-dvm.AppImage"
    entry = home / ".local/share/applications/dvm-gthumb.desktop"
    icon = Path(entry.read_text().split("Icon=")[1].split()[0])
    assert app_file.exists() and icon.exists()
    chat = engine.conv.id
    assert (engine.conv.mode, engine.conv.app) == ("app", "gthumb")
    assert engine.app_manager.remove("gthumb") == {"left": ""}
    assert not app_file.exists() and not entry.exists() and not icon.exists()
    assert apps.load("gthumb") is None and not engine.app_manager.apps() and not engine.deliveries()
    # its chat stays, about gThumb by name: a build delivered in it later makes it an app again
    assert (engine.conv.id, engine.conv.app, engine.conv.app_name) == (chat, "", "gThumb")
    saved = next(c for c in engine.list_chats() if c["id"] == chat)
    assert saved["app"] == "" and saved["app_name"] == "gThumb"
    # D1 is never another build's id: a chat that showed it shows nothing, not something else
    assert delivery.next_id(delivery.root_dir()) == "D2"
    await asyncio.sleep(0)
    assert ["rm", "-rf", "--", "/work/.dvm/apps/gthumb", "/work/apps/gthumb", "/work/apps/gthumb-clean",
            "/work/.dvm/build/gthumb"] in sb.root_calls                     # and its folders in the sandbox


async def test_removing_leaves_a_changed_appimage_and_says_so(gthumb, tmp_path):
    engine, sb, fake, told = gthumb
    meta = engine.install_delivery("D1")
    Path(meta["installed_to"]).write_bytes(b"the user's own file now")
    out = engine.app_manager.remove("gthumb")
    assert out["left"].startswith(meta["installed_to"]) and Path(meta["installed_to"]).exists()


@pytest.mark.parametrize("cli,script,call", [
    ("gearlever", GEARLEVER, lambda path: ["--remove", path, "-y"]),
    ("shelly", SHELLY, lambda path: ["remove", "appimage", "gThumb-dvm", "-n"]),
])
async def test_removing_an_app_uninstalls_it_where_it_lives(gthumb, tmp_path, monkeypatch, cli, script, call):
    engine, sb, fake, told = gthumb
    log = fake_cli(tmp_path, monkeypatch, cli, script)
    engine.cfg.settings.app_home = cli
    meta = engine.install_delivery("D1")
    engine.app_manager.remove("gthumb")
    assert json.loads(log.read_text().splitlines()[-1]) == call(meta["installed_to"])
    assert not Path(meta["installed_to"]).exists() and apps.load("gthumb") is None


async def test_an_app_that_cant_be_uninstalled_is_kept_unless_the_user_says_to_leave_it_installed(gthumb, tmp_path, monkeypatch):
    engine, sb, fake, told = gthumb
    fake_cli(tmp_path, monkeypatch, "shelly", SHELLY)
    engine.cfg.settings.app_home = "shelly"
    meta = engine.install_delivery("D1")
    a = apps.load("gthumb")
    apps.save({**a, "installed": {**a["installed"], "desktop_id": "Other-dvm.desktop"}})   # Shelly doesn't know it
    with pytest.raises(appmanager.UserError, match="couldn't be uninstalled"):
        engine.app_manager.remove("gthumb")
    assert apps.load("gthumb") and engine.deliveries()                    # nothing gone
    assert engine.app_manager.remove("gthumb", keep_installed=True) == {"left": meta["installed_to"]}
    assert apps.load("gthumb") is None and Path(meta["installed_to"]).exists()


async def test_an_app_isnt_removed_while_its_being_built_or_worked_on(gthumb):
    engine, sb, fake, told = gthumb
    engine.app_manager.building["gthumb"] = {"step": "build"}
    with pytest.raises(appmanager.UserError, match="being built"):
        engine.app_manager.remove("gthumb")
    engine.app_manager.building.clear()
    engine.builder.busy = True
    with pytest.raises(appmanager.UserError, match="assistant is working on gThumb"):
        engine.app_manager.remove("gthumb")
    assert apps.load("gthumb")


async def test_install_refuses_an_appimage_whose_runtime_was_never_checked(gthumb):
    engine, sb, fake, told = gthumb
    d = delivery.root_dir() / "D1"
    delivery.record(d, {**delivery.load(d), "runtime_checked": False})
    with pytest.raises(Exception, match="runtime wasn't checked"):
        engine.install_delivery("D1")


def test_security_fixes_are_found_in_a_change_log_by_code():
    lines = appmanager.security_lines("- Faster thumbnails\n- Fix heap overflow in the JPEG loader\n* CVE-2026-9999: crafted PNG\n")
    assert lines == ["Fix heap overflow in the JPEG loader", "CVE-2026-9999: crafted PNG"]
    assert appmanager.release_page("https://github.com/mpv-player/mpv.git", "v0.41.0") == \
        "https://github.com/mpv-player/mpv/releases/tag/v0.41.0"


async def test_apps_are_made_for_deliveries_from_before_apps_existed(env, tmp_path):
    engine, _, _ = env
    for did, extra in (("D1", {}), ("D2", {"line": "D1", "replaces": "D1", "status": "installed", "installed_to": "/x"})):
        d = delivery.root_dir() / did
        d.mkdir(parents=True)
        (d / "FEATURE.md").write_text("# Burst")
        (d / "changes.patch").write_text("From x\n")
        delivery.record(d, {"kind": "addon", "name": "mpv burst", "version": did, "upstream": "", "base_ref": "",
                            "status": "new", **extra})
    engine.app_manager.migrate()
    [a] = apps.list_all()
    assert a["builds"] == ["D1", "D2"] and a["installed"]["build"] == "D2" and len(a["changes"]) == 1
    assert delivery.load(delivery.root_dir() / "D1")["app"] == a["id"]
    engine.app_manager.migrate()
    assert len(apps.list_all()) == 1                                   # once


def test_the_menu_entry_keeps_only_what_describes_the_app():
    from davibemanager import appimage
    entry = appimage.menu_entry(DESKTOP, "/home/u/Applications/My App-dla.AppImage", "/i/x.png", "gthumb")
    assert 'Exec="/home/u/Applications/My App-dla.AppImage" %U' in entry
    assert "X-GNOME-Autostart" not in entry and "curl" not in entry and "Name[de]=gThumb (DLA)" in entry


# ---------------------------------------------------------------- an app is the official release with the user's changes


async def test_a_delivery_from_a_copy_in_the_sandbox_is_refused(gthumb):
    """What happened once: a feature built on the user's own version of another app in the sandbox."""
    engine, sb, _, _ = gthumb
    builder = engine.builder
    await engine.new_chat("app", app_name="Shotwell")
    engine.builder = builder
    sb.repo("/work/apps/shotwell", head="eeee555", remote="/work/apps/gthumb",
            patch=commit_patch("eeee555", "Zoom like gThumb", "-a\n+b"))
    args = {**ARGS, "name": "Shotwell", "repo": "/work/apps/shotwell", "change_title": "Zoom"}
    with pytest.raises(delivery.DeliveryError, match="origin must be the official repository.*not from a folder in /work"):
        await engine.builder_deliver(args)
    sb.repos["/work/apps/shotwell"]["remote"] = "https://gitlab.gnome.org/GNOME/shotwell.git"
    with pytest.raises(delivery.DeliveryError, match="hasn't been shown where it comes from: call offer_build"):
        await engine.builder_deliver(args)


async def test_a_branch_must_start_from_the_official_release_itself(gthumb):
    engine, sb, _, _ = gthumb
    sb.repo("/work/apps/gthumb", head="bbbb333", patch=ZOOM_KEPT + COPY)
    sb.official["3.12.6"] = "ffff999"          # what the official repository says 3.12.6 is: not this branch's start
    with pytest.raises(delivery.DeliveryError, match="3.12.6 in the official repository is ffff999.*starts from aaaa111"):
        await engine.builder_deliver({**ARGS, "change_title": "Copy the file path"})
    del sb.official["3.12.6"]
    sb.repos["/work/apps/gthumb"]["remote"] = "https://github.com/someone/gthumb-fork.git"
    with pytest.raises(delivery.DeliveryError, match="origin is https://github.com/someone/gthumb-fork.git.*never a copy or a fork"):
        await engine.builder_deliver({**ARGS, "change_title": "Copy the file path"})


async def test_a_branch_is_a_straight_line_of_commits_each_naming_its_change(gthumb):
    engine, sb, _, _ = gthumb
    sb.repo("/work/apps/gthumb", head="bbbb333", patch=ZOOM_KEPT + COPY, merges={"bbbb333"})
    with pytest.raises(delivery.DeliveryError, match="merge commits"):
        await engine.builder_deliver({**ARGS, "change_title": "Copy the file path"})
    unnamed = commit_patch("bbbb333", "Copy the file path", "-old menu\n+copy path", change=None)
    sb.repo("/work/apps/gthumb", head="bbbb333", patch=ZOOM_KEPT + unnamed)
    with pytest.raises(delivery.DeliveryError, match='must name its change in one trailer: "DVM-Change: new"'):
        await engine.builder_deliver({**ARGS, "change_title": "Copy the file path"})
    other = commit_patch("bbbb333", "Copy the file path", "-old menu\n+copy path", change="someone-elses")
    sb.repo("/work/apps/gthumb", head="bbbb333", patch=ZOOM_KEPT + other)
    with pytest.raises(delivery.DeliveryError, match="names a change 'someone-elses' this app doesn't have"):
        await engine.builder_deliver({**ARGS, "change_title": "Copy the file path"})


async def test_a_new_change_goes_on_the_release_the_app_is_built_on(gthumb):
    engine, sb, _, _ = gthumb
    sb.repo("/work/apps/gthumb", head="bbbb333", base_tag="3.12.7", base="tag-3.12.7", patch=ZOOM_KEPT + COPY)
    with pytest.raises(delivery.DeliveryError, match="built on 3.12.6: build the new change on it.*an update"):
        await engine.builder_deliver({**ARGS, "base_ref": "3.12.7", "change_title": "Copy the file path"})


async def test_after_an_update_the_changes_are_still_known_for_the_next_one(gthumb):
    """The bug before: after an update whose patch came out a little different, the change's old patch
    ids no longer matched, and the next new change was refused as leaving it out."""
    engine, sb, _, _ = gthumb
    engine.cfg.settings.changelog_summary = "manual"
    await engine.app_manager.check("gthumb")
    await engine.app_manager.rebuild("gthumb", by_user=True)
    # the user's zoom, as the update made it (other context: other patch ids), and a new change on top
    ported = commit_patch("cccc333", "Drag a box to zoom", "-old zoom (3.12.7)\n+box zoom", change="drag-a-box-to-zoom")
    sb.repo("/work/apps/gthumb", head="dddd444", base_tag="3.12.7", base="tag-3.12.7",
            patch=ported + commit_patch("dddd444", "Copy the file path", "-old menu\n+copy path"))
    await engine.builder_deliver({**ARGS, "base_ref": "3.12.7", "change_title": "Copy the file path", "version": "3.12.7-dvm2"})
    a = apps.load("gthumb")
    assert [c["id"] for c in a["changes"]] == ["drag-a-box-to-zoom", "copy-the-file-path"] and not a.get("left_out")


async def test_a_change_the_project_has_made_itself_comes_off_the_record_in_an_update(gthumb):
    engine, sb, _, told = gthumb
    sb.repo("/work/apps/gthumb", head="bbbb333", patch=ZOOM_KEPT + COPY)
    await engine.builder_deliver({**ARGS, "change_title": "Copy the file path", "version": "3.12.6-dvm2"})
    engine.cfg.settings.changelog_summary = "manual"
    await engine.app_manager.check("gthumb")
    sb.merged.add("drag-a-box-to-zoom")
    did = await engine.app_manager.rebuild("gthumb", by_user=True)
    a = apps.load("gthumb")
    assert [c["id"] for c in a["changes"]] == ["copy-the-file-path"] and a["left_out"][0]["id"] == "drag-a-box-to-zoom"
    meta = delivery.load(delivery.root_dir() / did)
    assert meta["merged"] == ["Drag a box to zoom"] and "left_out" not in meta     # not something the user chose
    # all of them in the release: nothing to build, and the user is told their app is the official one now
    sb.merged.add("copy-the-file-path")
    sb.tags.append("3.12.8")
    await engine.app_manager.check("gthumb")
    assert await engine.app_manager.rebuild("gthumb", by_user=True) == ""
    assert told[-1][0] == "gThumb 3.12.8 has your changes itself"
    assert apps.load("gthumb")["update"]["port"]["status"] == "merged"


async def test_an_app_from_before_gets_each_change_named_once(gthumb):
    """Recorded before changes had their own patches and trailers: made once from series.patch."""
    engine, sb, _, _ = gthumb
    a = apps.load("gthumb")
    plain = commit_patch("bbbb222", "Drag a box to zoom", "-old zoom\n+box zoom", change=None)
    apps.write_file("gthumb", "series.patch", plain)
    (apps.dir_of("gthumb") / "changes" / "drag-a-box-to-zoom.patch").unlink()
    apps.save({**a, "split": False})
    a = await engine.app_manager.ensure_split(apps.load("gthumb"))
    assert a["split"] and apps.read_file("gthumb", "changes/drag-a-box-to-zoom.patch") == ZOOM_KEPT
    assert apps.read_file("gthumb", "series.patch") == ZOOM_KEPT


async def test_an_app_chat_starts_in_a_tree_the_app_prepared_from_the_official_release(gthumb):
    engine, sb, _, _ = gthumb
    note = await engine._app_note()
    carry = sb.calls_of(scripts.CARRY)[-1]
    assert carry[5:9] == [GTHUMB, "/work/apps/gthumb", "3.12.6", "3.12.6"]
    assert "prepared its source for you in /work/apps/gthumb" in note and "drag-a-box-to-zoom: Drag a box to zoom" in note
    sb.fail["mirror"] = "fatal: unable to access"
    note = await engine._app_note()
    assert "couldn't prepare its source (fetch" in note and "git am -3" in note


# ---------------------------------------------------------------- starting an app again, cleanly

FORK = "https://github.com/someone/gthumb-fork.git"


async def remake_chat(engine, sb):
    """gThumb as it was once built: on a fork. Its chat to make it again, cleanly, from the official source."""
    apps.save({**apps.load("gthumb"), "upstream": FORK})
    builder = engine.builder
    await engine.new_chat("app", app="gthumb", remake=True)
    engine.builder = builder
    sb.repo("/work/apps/gthumb-clean", head="eeee555", base_tag="3.12.7", base="tag-3.12.7",
            patch=commit_patch("eeee444", "Drag a box to zoom", "-old zoom\n+box zoom (clean)", change="drag-a-box-to-zoom")
            + commit_patch("eeee555", "Copy the file path", "-old menu\n+copy path"))
    return {**ARGS, "repo": "/work/apps/gthumb-clean", "base_ref": "3.12.7", "version": "3.12.7-dvm1",
            "change_title": "Copy the file path", "app": "gthumb",
            "change_notes": {"drag-a-box-to-zoom": {"notes": "Drag a box over the picture to zoom to it (made afresh)."}}}


async def test_an_app_built_on_a_fork_cant_be_put_right_by_an_ordinary_change(gthumb):
    engine, sb, _, _ = gthumb
    apps.save({**apps.load("gthumb"), "upstream": FORK})
    sb.repo("/work/apps/gthumb", head="bbbb333", patch=ZOOM_KEPT + COPY)
    with pytest.raises(delivery.DeliveryError, match="official source is https://github.com/someone/gthumb-fork.git"):
        await engine.builder_deliver({**ARGS, "change_title": "Copy the file path"})


async def test_started_again_cleanly_it_is_the_official_release_with_each_change_made_afresh(gthumb):
    from davibemanager import engine as engine_mod
    from helpers import wait_for
    engine, sb, _, _ = gthumb
    args = await remake_chat(engine, sb)
    note = await engine._app_note()
    assert FORK in note and "drag-a-box-to-zoom: Drag a box to zoom" in note and "/work/apps/gthumb-clean" in note
    assert "name it exactly gThumb (DLA)" in note                      # the menu name of the build they have
    assert not sb.calls_of(scripts.CARRY)                               # the old changes aren't applied for it
    # the source the user is shown is the one the assistant names, never the old recorded one
    engine.builder.entry = {"parts": [{"t": "text", "text": "I'll make it again from GNOME's own gThumb."}]}
    task = asyncio.create_task(engine.builder_offer({"app": "gThumb", "change": "Start again", "upstream": GTHUMB}))
    await wait_for(lambda: any(q.get("offer") and q["status"] == "pending" for q in engine.questions.values()), "the offer")
    q = next(q for q in engine.questions.values() if q.get("offer") and q["status"] == "pending")
    assert q["offer"]["upstream"] == GTHUMB
    engine.answer_question(q["id"], [engine_mod.OFFER_YES])
    await task
    # delivered: the user confirms it takes the place of theirs
    task = asyncio.create_task(engine.builder_deliver(args))
    await wait_for(lambda: any(q.get("remake") and q["status"] == "pending" for q in engine.questions.values()), "the card")
    card = next(q for q in engine.questions.values() if q.get("remake") and q["status"] == "pending")
    assert "official 3.12.7 from gitlab.gnome.org/GNOME/gthumb" in card["questions"][0]["question"]
    engine.answer_question(card["id"], [engine_mod.REMAKE_YES])
    await task
    a = apps.load("gthumb")
    assert (a["upstream"], a["base_ref"]) == (GTHUMB, "3.12.7") and a["remade"]["was"]["upstream"] == FORK
    assert [c["id"] for c in a["changes"]] == ["drag-a-box-to-zoom", "copy-the-file-path"] and a["update"] == {}
    assert "box zoom (clean)" in apps.read_file("gthumb", "changes/drag-a-box-to-zoom.patch")
    assert delivery.load(delivery.root_dir() / "D2")["remake"]["upstream"] == FORK


async def test_the_user_can_keep_the_one_they_have(gthumb):
    from davibemanager import engine as engine_mod
    from helpers import wait_for
    engine, sb, _, _ = gthumb
    args = await remake_chat(engine, sb)
    offered(engine, GTHUMB)
    engine.builder.entry = {"parts": [{"t": "text", "text": "Here it is."}]}
    task = asyncio.create_task(engine.builder_deliver(args))
    await wait_for(lambda: any(q.get("remake") and q["status"] == "pending" for q in engine.questions.values()), "the card")
    card = next(q for q in engine.questions.values() if q.get("remake") and q["status"] == "pending")
    engine.answer_question(card["id"], [engine_mod.REMAKE_NO])
    with pytest.raises(delivery.DeliveryError, match="wants to keep the gThumb they have"):
        await task
    assert apps.load("gthumb")["upstream"] == FORK and apps.load("gthumb")["builds"] == ["D1"]


# ---------------------------------------------------------------- each change's notes, as the code is now

async def test_a_change_whose_code_a_delivery_changes_gets_notes_as_it_is_now(gthumb):
    """The bug: notes were written when a change was new, and never again, so a shared app described
    code it no longer had. Now a delivery that changes a change's own code must say what it is now,
    and that's checked before anything is built."""
    engine, sb, _, _ = gthumb
    rev = apps.load("gthumb")["changes"][0]["rev"]
    reworked = commit_patch("bbbb444", "Drag a box to zoom", "-old zoom\n+box zoom, or pan with the hand tool",
                            change="drag-a-box-to-zoom")
    sb.repo("/work/apps/gthumb", head="bbbb333", patch=reworked + COPY)
    builds = len(sb.calls_of(scripts.CHECK_BUILD))
    args = {**ARGS, "change_title": "Copy the file path", "version": "3.12.6-dvm2"}
    with pytest.raises(delivery.DeliveryError, match=r"drag-a-box-to-zoom \(Drag a box to zoom\).*change_notes"):
        await engine.builder_deliver(args)
    assert len(sb.calls_of(scripts.CHECK_BUILD)) == builds                         # refused before the build
    await engine.builder_deliver({**args, "change_notes": {"drag-a-box-to-zoom": {
        "notes": "Drag a box over the picture to zoom to it, or pan with the hand tool.", "title": "Drag to zoom, or pan"}}})
    a = apps.load("gthumb")
    zoom = a["changes"][0]
    assert zoom["title"] == "Drag to zoom, or pan" and "hand tool" in apps.read_file("gthumb", "changes/drag-a-box-to-zoom.md")
    assert zoom["rev"]["id"] != rev["id"] and rev["id"] in zoom["rev"]["history"]   # a newer version of it
    assert apps.read_file("gthumb", "changes/copy-the-file-path.md").startswith("# Drag to zoom")   # the new one's: feature
    with pytest.raises(delivery.DeliveryError, match="has no change 'nope'"):
        await engine.builder_deliver({**args, "change_notes": {"nope": {"notes": "x"}}})


async def test_the_assistant_corrects_a_changes_notes_without_building_anything(gthumb):
    engine, sb, _, _ = gthumb
    engine.conv.app = "gthumb"
    rev = apps.load("gthumb")["changes"][0]["rev"]
    builds = len(sb.calls_of(scripts.CHECK_BUILD))
    out = await engine.builder_change_notes({"changes": {"drag-a-box-to-zoom": {"notes": "Drag a box over the picture to zoom to it."}}})
    assert out.startswith("Updated, for drag-a-box-to-zoom (Drag a box to zoom)")
    assert apps.read_file("gthumb", "changes/drag-a-box-to-zoom.md") == "Drag a box over the picture to zoom to it.\n"
    a = apps.load("gthumb")
    assert a["changes"][0]["rev"]["id"] != rev["id"] and len(sb.calls_of(scripts.CHECK_BUILD)) == builds
    assert b"Drag a box over the picture" in sb.files["/work/.dvm/apps/gthumb/FEATURE.md"]   # the assistant reads it so
    again = await engine.builder_change_notes({"changes": {"drag-a-box-to-zoom": {"notes": "Drag a box over the picture to zoom to it."}}})
    assert again and apps.load("gthumb")["changes"][0]["rev"] == a["changes"][0]["rev"]       # the same: no new version
    with pytest.raises(ValueError, match="has no change 'nope'"):
        await engine.builder_change_notes({"changes": {"nope": {"notes": "x"}}})
    with pytest.raises(ValueError, match="empty"):
        await engine.builder_change_notes({"changes": {"drag-a-box-to-zoom": {"notes": "  "}}})
    engine.conv.app = ""
    with pytest.raises(ValueError, match="no app of the user's yet"):
        await engine.builder_change_notes({"changes": {"drag-a-box-to-zoom": {"notes": "x"}}})


async def test_a_build_that_stops_with_an_error_says_so_and_never_just_vanishes(gthumb, env, monkeypatch):
    """A build the user started that ends any other way than its changes not fitting (a delivery check,
    Podman, the AppImage runtime): the card says what stopped it, the user is told, and the assistant
    can be asked to look, told what happened (not that there's no build script)."""
    engine, sb, fake, told = gthumb
    events = env[2]
    engine.cfg.settings.changelog_summary = "manual"
    await engine.app_manager.check("gthumb")

    async def refused(args, entry):
        raise delivery.DeliveryError("Its AppImage runtime isn't the pinned one.")
    monkeypatch.setattr(engine, "make_delivery", refused)
    assert await engine.app_manager.rebuild("gthumb", by_user=True) == ""
    a = apps.load("gthumb")
    assert not engine.app_manager.building and a["update"]["port"]["step"] == "error"
    assert "runtime isn't the pinned one" in a["update"]["port"]["log"] and a["update"]["port"]["tag"] == "3.12.7"
    assert told[-1][0] == "gThumb 3.12.7 wasn't built"
    assert any(e["type"] == "toast" and "runtime isn't the pinned one" in e["text"] for e in events)
    assert engine.conv.chat == []                                    # nobody was asked to pay for it unasked
    sent = []
    monkeypatch.setattr(engine, "_start_turn", lambda content, note=True: sent.append(content))
    await engine.app_manager.assistant("gthumb")
    assert "it stopped with an error" in sent[0] and "runtime isn't the pinned one" in sent[0]
    assert "no saved build script" not in sent[0] and "3.12.7" in sent[0]


async def test_when_the_assistant_cant_take_over_now_the_user_is_told(gthumb, env, monkeypatch):
    engine, sb, fake, told = gthumb
    events = env[2]
    engine.cfg.settings.changelog_summary = "manual"
    await engine.app_manager.check("gthumb")
    sb.carry_fail["drag-a-box-to-zoom"] = "CONFLICT (content)"
    engine.builder.busy = True                                       # answering in another chat
    assert await engine.app_manager.rebuild("gthumb", by_user=True) == ""
    assert apps.load("gthumb")["update"]["port"]["step"] == "apply"  # the card offers it again
    assert any(e["type"] == "toast" and "can't take it over now" in e["text"] for e in events)


async def test_work_started_in_the_background_that_fails_is_logged_and_shown(env):
    engine, _, events = env

    async def fails():
        raise RuntimeError("the clean container went away")
    task = engine._spawn(fails())
    await asyncio.gather(task, return_exceptions=True)
    await asyncio.sleep(0)
    assert any(e["type"] == "toast" and e["text"] == "the clean container went away" for e in events)
    logged = (engine.conv.dir / "events.jsonl").read_text()
    assert "background_failed" in logged and "the clean container went away" in logged


async def test_the_open_chat_can_be_deleted_but_not_while_the_assistant_answers_in_it(gthumb):
    engine, sb, fake, told = gthumb
    chat = engine.conv.id
    engine.builder.busy = True
    with pytest.raises(appmanager.UserError, match="Wait for the assistant"):
        await engine.delete_chats([chat])
    engine.builder.busy = False
    assert (await engine.delete_chats([chat]))["deleted"] == [chat]
    assert engine.conv.id != chat and chat not in {c["id"] for c in engine.list_chats()}
