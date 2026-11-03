"""The workspace container's run command: no network, no host paths, no capabilities."""

import asyncio
import json
import os
import re
import time
from pathlib import Path

import pytest

from davibemanager.workspace import pins, podman

REAL_RUN = podman.run          # before no_real_podman stands in for it (a test runs a fake podman)


@pytest.fixture(autouse=True)
def fake_podman(monkeypatch):
    monkeypatch.setattr(podman, "podman", lambda: "/usr/bin/podman")


def test_the_container_has_no_network_no_capabilities_and_no_host_paths():
    argv = podman.run_argv("dvm-x", "localhost/img:1", Path("/run/user/1000/davibemanager/gw/x"), project_id="x")
    assert "--network=none" in argv
    assert "--cap-drop=ALL" in argv and not any(a.startswith("--cap-add") for a in argv)
    assert "--security-opt=no-new-privileges" in argv and "--privileged" not in argv
    assert argv[argv.index("--user") + 1] == "1000:1000"
    mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "-v"]
    assert mounts == ["dvm-x-work:/work", "dvm-x-home:/home/agent", "dvm-x-mirrors:/var/lib/dvm",
                      "/run/user/1000/davibemanager/gw/x:/run/dvm:ro,z"]
    forbidden = {"--volume", "--mount", "--device", "--env-file", "--pid", "--ipc", "--userns", "--privileged", "--net"}
    assert not any(a.split("=")[0] in forbidden for a in argv)


async def test_the_clean_container_reads_the_sandbox_but_cant_change_it(no_real_podman):
    """What the app checks and builds is copied out of /sandbox first: it may only read it."""
    await podman.start_check("dvm-sandbox", "localhost/img:1", Path("/run/gw"), memory="2g", cpus="2", pids=1024)
    argv = no_real_podman[-1]
    mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "-v"]
    assert mounts == ["dvm-sandbox-work:/sandbox:ro", "dvm-sandbox-mirrors:/var/lib/dvm:ro", "/run/gw:/run/dvm:ro,z"]
    assert "--cap-drop=ALL" in argv and "--network=none" in argv and argv[argv.index("--name") + 1] == "dvm-sandbox-check"


def test_limits_are_checked_before_they_reach_podman():
    with pytest.raises(podman.PodmanError):
        podman.run_argv("dvm-x", "img", Path("/g"), project_id="x", memory="8g --privileged")
    with pytest.raises(podman.PodmanError):
        podman.run_argv("dvm-x", "img", Path("/g"), project_id="x", cpus="all")


def test_the_users_terminal_in_the_workspace_runs_as_the_agent_not_root():
    argv = podman.shell_argv("dvm-x")
    assert "-u" not in argv and "--privileged" not in argv and argv[-2:] == ["bash", "-l"]


def test_the_image_tag_follows_what_it_is_built_from():
    tag = podman.image_tag()
    assert tag.startswith("localhost/davibemanager-workspace:") and len(tag.rsplit(":", 1)[1]) == 12


def test_everything_the_image_downloads_is_pinned_by_hash():
    for url, digest in ((pins.APPIMAGETOOL_URL, pins.APPIMAGETOOL_SHA256), (pins.RUNTIME_URL, pins.RUNTIME_SHA256)):
        assert url.startswith("https://") and len(digest) == 64
    assert "@sha256:" in pins.BASE_IMAGE and len(pins.CLAUDE_SHA256) == 64
    containerfile = (podman.IMAGE_DIR / "Containerfile").read_text()
    assert "http://" not in re.sub(r"http://127\.0\.0\.1:\d+", "", containerfile)     # loopback only
    instructions = "\n".join(l for l in containerfile.splitlines() if not l.lstrip().startswith("#"))
    assert "sudo" not in instructions


@pytest.fixture
def fake_sandbox(monkeypatch, tmp_path):
    """podman as the engine's sandbox start sees it, scripted."""
    calls, script = [], {"source": "", "sees": [True], "states": ["running"], "fail": 0}

    async def build_image(progress=None, *, source=podman.SNAPSHOT_URI):
        script.setdefault("builds", []).append(source)
        for line in script.get("lines", []):
            progress(line)
        if script.get("build_errors"):
            raise script["build_errors"].pop(0)
        if script["fail"]:
            script["fail"] -= 1
            raise podman.PodmanError("podman start: container is still stopping")
        return "localhost/img:1"

    async def image_source(tag):
        return script.get("built_from", podman.SNAPSHOT_URI)

    async def gateway_source(name):
        return script["source"]

    async def has_mount(name, destination):
        return script.get("mirrors", True)

    async def limits(name):
        return script.get("limits") or podman.wanted_limits("8g", "4", 4096)     # the settings' defaults

    async def recreate(name):
        calls.append("recreate")

    async def ensure_running(name, image, gw, **kw):
        calls.append(("ensure", str(gw)))
        return script["states"].pop(0) if len(script["states"]) > 1 else script["states"][0]

    async def sees_gateway(name):
        return script["sees"].pop(0) if len(script["sees"]) > 1 else script["sees"][0]

    async def stop(name):
        calls.append("stop")

    async def inspect_image(name):
        return "localhost/img:1"

    async def logs(name, lines=30):
        return "socat: no such file"
    for fn in (build_image, image_source, gateway_source, has_mount, limits, recreate, ensure_running, sees_gateway, stop,
               inspect_image, logs):
        monkeypatch.setattr(podman, fn.__name__, fn)
    return calls, script


async def _engine(tmp_path):
    from davibemanager.config import Config
    from davibemanager.engine import Engine
    e = Engine(Config(), lambda ev: None, tmp_path / "rt", save_config=lambda c: None)
    e._gateway_dir = lambda: tmp_path / "gw"
    return e


async def test_a_sandbox_made_with_another_gateway_directory_is_made_again(fake_sandbox, tmp_path):
    calls, script = fake_sandbox
    script["source"] = "/tmp/old-gateway"
    e = await _engine(tmp_path)
    await e._start_workspace()
    assert e.workspace["state"] == "running" and calls[0] == "recreate"
    await e.gateway.stop()


async def test_a_sandbox_made_before_the_mirrors_had_a_volume_is_made_again_once(fake_sandbox, tmp_path):
    """The app's clean containers read the official sources' copies from that volume."""
    calls, script = fake_sandbox
    script["source"], script["mirrors"] = str(tmp_path / "gw"), False
    e = await _engine(tmp_path)
    await e._start_workspace()
    assert e.workspace["state"] == "running" and calls[0] == "recreate"
    await e.gateway.stop()
    calls.clear()
    script["mirrors"] = True
    e = await _engine(tmp_path)
    await e._start_workspace()
    assert "recreate" not in calls
    await e.gateway.stop()


async def test_new_limits_apply_at_once_and_stay_when_the_sandbox_starts_again(fake_sandbox, tmp_path, no_real_podman):
    """Podman changes a running container's limits but gives it the ones it was made with when it starts
    again: so they're applied at once, and the sandbox is made again with them (its files kept) at its next start."""
    calls, script = fake_sandbox
    script["source"] = str(tmp_path / "gw")
    e = await _engine(tmp_path)
    assert e.cfg.settings.container_memory == "8g"
    await e._start_workspace()
    assert e.workspace["state"] == "running" and "recreate" not in calls      # as it was made: nothing to do
    e.cfg.settings.container_memory, e.cfg.settings.container_cpus = "2g", "2"
    assert await e.apply_limits() == "now"
    update = no_real_podman[-1]
    assert update[1:2] == ["update"] and update[-1] == "dvm-sandbox"
    assert update[update.index("--memory") + 1] == str(2 << 30) and update[update.index("--cpus") + 1] == "2"
    assert update[update.index("--memory-swap") + 1] == str(4 << 30) and update[update.index("--pids-limit") + 1] == "4096"
    await e.gateway.stop()
    calls.clear()
    script["limits"] = podman.wanted_limits("8g", "4", 4096)                  # what it was made with
    e2 = await _engine(tmp_path)
    e2.cfg.settings.container_memory, e2.cfg.settings.container_cpus = "2g", "2"
    await e2._start_workspace()
    assert calls[0] == "recreate"                                              # made again with them
    e2.workspace = {"state": "stopped"}
    assert await e2.apply_limits() == "next start"
    await e2.gateway.stop()


def test_limits_are_read_as_podman_records_them():
    assert podman.wanted_limits("8g", "4", 4096) == {"memory": 8 << 30, "cpus": 4_000_000_000, "pids": 4096}
    assert podman.wanted_limits("4096m", "2.5", 512) == {"memory": 4 << 30, "cpus": 2_500_000_000, "pids": 512}
    with pytest.raises(podman.PodmanError):
        podman.wanted_limits("8g; rm -rf /", "4", 1)


async def test_a_sandbox_that_cant_see_the_gateway_is_restarted(fake_sandbox, tmp_path):
    calls, script = fake_sandbox
    script["source"] = str(tmp_path / "gw")
    script["sees"] = [False, True]
    e = await _engine(tmp_path)
    await e._start_workspace()
    assert e.workspace["state"] == "running" and "stop" in calls and "recreate" not in calls
    await e.gateway.stop()


async def test_a_failed_start_is_tried_again_once_and_then_explained(fake_sandbox, tmp_path, monkeypatch):
    import asyncio as aio
    calls, script = fake_sandbox
    monkeypatch.setattr(aio, "sleep", _no_sleep)
    script["fail"] = 1
    e = await _engine(tmp_path)
    await e._start_workspace()
    assert e.workspace["state"] == "running"                         # the second try worked
    script["fail"] = 2
    e2 = await _engine(tmp_path)
    await e2._start_workspace()
    assert e2.workspace["state"] == "failed" and "still stopping" in e2.workspace["error"]
    from davibemanager.config import data_dir
    assert "sandbox_start_failed" in (data_dir() / "app.log").read_text()
    await e.gateway.stop()


_real_sleep = __import__("asyncio").sleep


async def _no_sleep(s):
    await _real_sleep(0)


async def test_a_command_that_leaves_something_holding_its_output_still_returns(monkeypatch):
    """`podman start` in the app: it exited at once, but conmon kept its output open for good."""
    import time
    monkeypatch.setattr(podman, "LINGER", 0.3)
    t = time.monotonic()
    rc, out = await podman.run(["sh", "-c", "echo started; sleep 30 & exit 0"], timeout=10)
    assert rc == 0 and out == "started\n" and time.monotonic() - t < 3


async def test_output_written_just_before_exit_is_all_read():
    rc, out = await podman.run(["sh", "-c", "seq 1 20000; exit 3"], timeout=10)
    assert rc == 3 and out.splitlines()[-1] == "20000" and len(out.splitlines()) == 20000


async def test_the_apps_root_commands_never_take_a_program_from_the_agents_folders(no_real_podman):
    """The image's PATH starts with the agent's ~/.local/bin: an "apt-get" or "sh" the agent put there
    would run as root."""
    await podman.exec_root("dvm-sandbox", ["apt-get", "install", "-y", "hello"])
    argv = no_real_podman[-1]
    path = argv[argv.index("-e") + 1]
    assert path.startswith("PATH=/usr/local/sbin:") and "/home/agent" not in path and "HOME=/root" in argv


async def test_the_apps_own_commands_as_the_agent_take_nothing_of_the_agents(no_real_podman):
    """What these print is what a delivery is checked by: no "git" or "python3" of the agent's, no
    ~/.gitconfig of its (url.*.insteadOf could send the official repository elsewhere), no repository
    settings that run programs or swap commits, and not /work, a repository the agent could make."""
    await podman.exec_agent("dvm-sandbox", ["git", "ls-remote", "https://gitlab.gnome.org/GNOME/gthumb.git"])
    argv = no_real_podman[-1]
    env = [argv[i + 1] for i, a in enumerate(argv) if a == "-e"]
    path = next(e for e in env if e.startswith("PATH="))
    assert "/home/agent" not in path and argv[argv.index("-w") + 1] == "/"
    assert {"GIT_CONFIG_GLOBAL=/dev/null", "GIT_NO_REPLACE_OBJECTS=1", "GIT_GRAFT_FILE=/nonexistent/dvm-no-grafts",
            "GIT_CONFIG_KEY_0=core.hooksPath", "GIT_CONFIG_VALUE_0=/dev/null", "GIT_CONFIG_KEY_1=core.fsmonitor"} <= set(env)
    assert argv[-3:] == ["git", "ls-remote", "https://gitlab.gnome.org/GNOME/gthumb.git"]
    await podman.put_file("dvm-sandbox", "/work/x", b"data")
    argv = no_real_podman[-1]
    assert "PATH=" + podman.SYSTEM_PATH in argv and "/bin/sh" in argv


async def test_mirrors_are_fetched_by_their_own_user_without_capabilities(no_real_podman):
    """Not root (a server a shared file names would talk to git with every capability), not the agent."""
    await podman.exec_mirror("dvm-sandbox", ["sh", "-c", "git fetch", "sh"])
    prepare, fetch = no_real_podman[-2], no_real_podman[-1]
    assert "--privileged" in prepare and podman.OWN_MIRRORS in prepare          # only its folder, made its own
    assert "--privileged" not in fetch and fetch[fetch.index("-u") + 1] == podman.MIRROR_USER
    assert podman.MIRROR_USER.split(":")[0] not in ("0", "1000") and "HOME=/var/lib/dvm" in fetch


async def test_only_earlier_sandbox_images_are_removed_and_none_in_use(monkeypatch):
    calls = []

    async def run(argv, **kw):
        calls.append(argv)
        if argv[1] == "images":
            repo = argv[-1]
            return 0, f"{repo}:aaa\n{repo}:now\n{repo}:old\n"
        return (1, "image is in use") if argv[-1].endswith(":old") else (0, "")
    monkeypatch.setattr(podman, "run", run)
    removed = await podman.prune_images(f"{podman.IMAGE_REPO}:now")
    assert removed == [f"{podman.IMAGE_REPO}:aaa"]
    assert all("-f" not in c and "--force" not in c for c in calls)            # never forced
    assert not any(c[-1] == f"{podman.IMAGE_REPO}:now" for c in calls if c[1:3] == ["image", "rm"])


# ---- building the image: Ubuntu's snapshot server, when it's slow or refuses

# what a build printed on a fresh CachyOS while snapshot.ubuntu.com answered 503 (the RUN command shortened)
SNAPSHOT_503 = """\
STEP 3/16: RUN rm -f /etc/apt/sources.list && printf ...
Get:55 https://snapshot.ubuntu.com/ubuntu/20260930T000000Z noble/main amd64 libgl1 amd64 1.7.0-1build1 [102 kB]
Get:56 https://snapshot.ubuntu.com/ubuntu/20260930T000000Z noble/main amd64 socat amd64 1.8.0.0-4ubuntu0.1 [318 kB]
Err:57 https://snapshot.ubuntu.com/ubuntu/20260930T000000Z noble/main amd64 x11-utils amd64 7.7+6build2
  503  Service Unavailable [IP: 185.125.189.36 443]
E: Failed to fetch https://snapshot.ubuntu.com/ubuntu/20260930T000000Z/pool/main/s/socat/socat_1.8.0.0-4ubuntu0.1_amd64.deb  503  Service Unavailable [IP: 185.125.189.36 443]
E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?
Error: building at STEP "RUN rm -f /etc/apt/sources.list && printf '%s\\n' 'Types: deb' ... apt-get install -y --no-install-recommends ca-certificates curl git": while running runtime: exit status 100
"""


def test_a_failed_build_says_the_package_server_refused_not_the_command_it_ran():
    e = podman.build_failure(SNAPSHOT_503)
    assert e.kind == "server" and e.host == "snapshot.ubuntu.com"
    assert e.summary.startswith("Ubuntu's snapshot server (snapshot.ubuntu.com) is busy or down: it answered 503 Service Unavailable.")
    assert "Nothing is wrong with your computer" in e.summary
    assert "apt-get install -y" not in e.details and "exit status 100" in e.details
    assert str(e).startswith(e.summary)


@pytest.mark.parametrize("line,kind,said", [
    ("Err:1 https://snapshot.ubuntu.com/ubuntu/x noble InRelease\n  Temporary failure resolving 'snapshot.ubuntu.com'",
     "network", "couldn't be reached"),
    ("Err:1 https://mirror.lan/ubuntu noble InRelease\n  Certificate verification failed: The certificate is NOT trusted.",
     "certificate", "couldn't be verified"),
    ("E: Package 'xvfb' has no installation candidate", "other", "Building the sandbox's image failed."),
])
def test_other_failures_say_what_they_are(line, kind, said):
    e = podman.build_failure(line + "\nError: building at STEP \"RUN ...\": while running runtime: exit status 100\n")
    assert e.kind == kind and said in e.summary


def test_the_build_is_followed_as_it_goes_downloads_and_trouble_alike():
    w = podman.BuildWatch()
    for line in ("STEP 3/16: RUN ...", "0 upgraded, 210 newly installed, 0 to remove and 0 not upgraded.",
                 "Get:56 https://snapshot.ubuntu.com/ubuntu/x noble/main amd64 socat amd64 1.8 [318 kB]"):
        w.feed(line)
    assert w.progress() == "Downloading packages: 56 of 210" and w.trouble() == ""
    for line in ("Err:57 https://snapshot.ubuntu.com/ubuntu/x noble/main amd64 x11-utils amd64 7.7",
                 "  503  Service Unavailable [IP: 185.125.189.36 443]",
                 "Err:58 https://snapshot.ubuntu.com/ubuntu/x noble/main amd64 xvfb amd64 21.1",
                 "  503  Service Unavailable [IP: 185.125.189.36 443]"):
        w.feed(line)
    assert w.trouble() == ("Ubuntu's snapshot server (snapshot.ubuntu.com) is busy or down (503 Service Unavailable): "
                           "2 downloads failed. It will be tried again…")
    w.feed("dvm-retry: try 2 of 8 in 15s")
    assert w.trouble().endswith("2 downloads failed. Waiting 15 s before trying again (try 2 of 8)…")
    w.feed("dvm-retry: try 2 of 8 now")
    assert w.trouble() == "Ubuntu's snapshot server (snapshot.ubuntu.com) is busy or down (503 Service Unavailable). Trying again (try 2 of 8)…"
    w.feed("STEP 4/16: RUN printf ...")                 # that step is done: so is its trouble
    assert w.trouble() == "" and w.progress() == ""


def test_the_image_retries_what_apt_doesnt_and_keeps_its_downloads():
    """apt gives up on a 503 at once (whatever Acquire::Retries says), and docker-clean empties its
    download cache after every update: the Containerfile retries itself, with docker-clean set aside."""
    containerfile = (podman.IMAGE_DIR / "Containerfile").read_text()
    assert "retry apt-get update --error-on=any" in containerfile and "retry apt-get install" in containerfile
    assert 'echo "dvm-retry: try $try of 8 in ${delay}s"' in containerfile and 'echo "dvm-retry: try $try of 8 now"' in containerfile
    assert "mv /etc/apt/apt.conf.d/docker-clean" in containerfile and "mv /etc/apt/docker-clean.off /etc/apt/apt.conf.d/docker-clean" in containerfile
    assert '"URIs: ${APT_URI}"' in containerfile
    assert podman.SNAPSHOT_URI == f"https://snapshot.ubuntu.com/ubuntu/{pins.APT_SNAPSHOT}/"


async def test_the_build_mounts_its_download_cache_and_names_its_source(no_real_podman, monkeypatch, tmp_path):
    async def missing(tag):
        return False
    monkeypatch.setattr(podman, "image_exists", missing)
    cli = tmp_path / "claude"
    cli.write_bytes(b"cli")
    monkeypatch.setattr(podman, "bundled_cli", lambda: cli)
    monkeypatch.setattr(pins, "CLAUDE_SHA256", __import__("hashlib").sha256(b"cli").hexdigest())
    monkeypatch.setattr(podman, "_ca_bundle", lambda: "/etc/ssl/certs/ca-certificates.crt")
    await podman.build_image(source=podman.ARCHIVE_URI)
    argv = no_real_podman[-1]
    assert f"{podman.apt_cache_dir()}:/var/cache/apt/archives:Z" in argv and podman.apt_cache_dir().is_dir()
    assert f"APT_URI={podman.ARCHIVE_URI}" in argv and f"{podman.SOURCE_LABEL}={podman.ARCHIVE_URI}" in argv


async def test_trouble_shows_while_it_builds_and_a_failure_says_why_once(fake_sandbox, tmp_path):
    calls, script = fake_sandbox
    script["lines"] = ["STEP 3/16: RUN ...", "Err:57 https://snapshot.ubuntu.com/ubuntu/x noble/main amd64 x11-utils",
                       "  503  Service Unavailable [IP: 185.125.189.36 443]", "dvm-retry: try 2 of 8 in 15s"]
    script["build_errors"] = [podman.build_failure(SNAPSHOT_503)]
    e = await _engine(tmp_path)
    seen, toasts = [], []
    e._set_workspace = lambda **st: (seen.append(st), setattr(e, "workspace", st))
    e.emit = lambda kind, **kw: toasts.append(kw.get("text")) if kind == "toast" else None
    await e._start_workspace()
    assert any("try 2 of 8" in st.get("trouble", "") for st in seen)
    assert not any(st.get("step", "").startswith("dvm-retry") for st in seen)      # trouble says it, in words
    assert seen[-2]["trouble"].startswith("Ubuntu's snapshot server (snapshot.ubuntu.com) is busy or down (503 Service Unavailable)")
    assert len(toasts) == 1 and toasts[0].startswith("Preparing the sandbox: Ubuntu's snapshot server")
    assert script["builds"] == [podman.SNAPSHOT_URI]         # it had tried for minutes: not once more at once
    assert e.workspace["state"] == "failed" and "busy or down" in e.workspace["summary"]
    assert "Settings → The sandbox" in e.workspace["summary"]


@pytest.mark.parametrize("fallback,mirror,source", [
    ("archive", "", podman.ARCHIVE_URI),
    ("mirror", "http://192.168.1.5/ubuntu/", "http://192.168.1.5/ubuntu/"),
])
async def test_when_the_snapshot_server_is_down_it_uses_the_source_settings_name(fake_sandbox, tmp_path, fallback, mirror, source):
    calls, script = fake_sandbox
    script["source"] = str(tmp_path / "gw")
    script["build_errors"] = [podman.build_failure(SNAPSHOT_503)]
    script["built_from"] = source
    e = await _engine(tmp_path)
    e.cfg.settings.image_fallback, e.cfg.settings.image_mirror = fallback, mirror
    await e._start_workspace()
    assert script["builds"] == [podman.SNAPSHOT_URI, source]
    assert e.workspace["state"] == "running" and e.workspace["unpinned_source"] == source
    await e.gateway.stop()


async def test_a_package_source_only_stands_in_for_the_snapshot_server_being_down(fake_sandbox, tmp_path):
    calls, script = fake_sandbox
    script["build_errors"] = [podman.BuildError("Building the sandbox's image failed.", "E: something else")]
    e = await _engine(tmp_path)
    e.cfg.settings.image_fallback = "archive"
    await e._start_workspace()
    assert script["builds"] == [podman.SNAPSHOT_URI] and e.workspace["state"] == "failed"
    assert "Settings" not in e.workspace["summary"]


@pytest.mark.parametrize("mirror,ok", [
    ("https://mirror.example.com/ubuntu", True),
    ("http://192.168.1.5:3142/ubuntu", True),             # the local network: http is fine there
    ("http://mirror.example.com/ubuntu", False),          # anywhere else: refused, not rewritten
    ("ftp://mirror.example.com/ubuntu", False),
    ("https://mirror.example.com/ubuntu\nTypes: deb", False),
    ('https://mirror.example.com/"ubuntu', False),
])
async def test_a_mirrors_address_is_checked_before_its_used(env, mirror, ok):
    from davibemanager.models import UserError
    engine, _, _ = env
    if ok:
        engine.save_settings({"image_mirror": mirror, "image_fallback": "mirror"})
        assert engine.cfg.settings.image_mirror == mirror + "/" and engine.cfg.settings.image_fallback == "mirror"
    else:
        with pytest.raises(UserError):
            engine.save_settings({"image_mirror": mirror})
        assert engine.cfg.settings.image_mirror == ""


async def test_the_mirror_choice_needs_a_mirror(env):
    from davibemanager.models import UserError
    engine, _, _ = env
    with pytest.raises(UserError, match="mirror's address first"):
        engine.save_settings({"image_fallback": "mirror"})
    with pytest.raises(UserError):
        engine.save_settings({"image_fallback": "anywhere"})
    engine.save_settings({"image_mirror": "https://m.example.com/ubuntu/", "image_fallback": "mirror"})
    engine.save_settings({"image_mirror": ""})              # no mirror any more: nor its choice
    assert engine.cfg.settings.image_fallback == ""


async def test_a_refused_setting_never_stays_in_the_running_settings(env):
    """Settings are checked before anything is set: the window's user shouldn't land on the setup screen
    (no model) or lose the sandbox (a memory limit that isn't one) over a slip in a field."""
    from davibemanager.models import UserError
    engine, _, _ = env
    s = engine.cfg.settings
    was = (s.builder_model, s.install_dir, s.container_memory, s.container_cpus)
    for bad, why in [({"builder_model": "  "}, "needs a model"), ({"install_dir": ""}, "full path"),
                     ({"install_dir": "Apps"}, "full path"), ({"install_dir": "~"}, "folder of their own"),
                     ({"container_memory": "lots"}, "8g or 4096m"), ({"container_cpus": "two"}, "a number"),
                     ({"ui_mode": "tty"}, "window or in the browser")]:
        with pytest.raises(UserError, match=why):
            engine.save_settings(bad)
        assert (s.builder_model, s.install_dir, s.container_memory, s.container_cpus) == was
        assert engine.ready
    engine.save_settings({"install_dir": "~/Apps", "container_memory": "4096m", "container_cpus": "2.5", "ui_mode": "browser"})
    assert (s.install_dir, s.container_memory, s.container_cpus, s.ui_mode) == ("~/Apps", "4096m", "2.5", "browser")


async def test_a_line_longer_than_64_kb_is_read_whole_and_what_follows_it_too():
    """A change log's JSON is one line, a build's progress bar can be one: neither is lost, and the
    command doesn't block on output nobody reads any more."""
    lines = []
    rc, out = await asyncio.wait_for(podman.run(
        ["python3", "-c", "import sys; sys.stdout.write('x' * 200000 + '\\n@@HEAD abc\\n' + 'y' * 300000 + '\\n')"],
        timeout=10, on_line=lines.append), 10)
    assert rc == 0 and out.splitlines() == ["x" * 200000, "@@HEAD abc", "y" * 300000] and lines[1] == "@@HEAD abc"


async def test_podmans_own_warnings_arent_taken_for_its_answer(tmp_path, monkeypatch):
    """In some setups Podman warns with every command (cgroups v1, a containers.conf key it doesn't
    know): "WARN[0000] …\nrunning" isn't a state, and the sandbox would never be seen to start."""
    fake = tmp_path / "bin" / "podman"
    fake.parent.mkdir()
    fake.write_text('#!/bin/sh\necho \'WARN[0000] "/" is not a shared mount, this could cause issues\' >&2\n'
                    'echo \'time="2026-11-03T21:00:00+01:00" level=warning msg="Failed to decode the keys"\' >&2\necho running\n')
    fake.chmod(0o755)
    monkeypatch.setattr(podman, "podman", lambda: str(fake))
    monkeypatch.setattr(podman, "run", REAL_RUN)            # the fake, run for real
    assert await podman.state("dvm-x") == "running"


async def test_a_command_that_times_out_is_not_waited_for_through_what_it_left_running():
    """asyncio's wait() ends only once the output pipe is closed too, and what a podman command starts
    (conmon) can hold it open after the command is killed: a timeout must not become a hang."""
    import time
    started = time.monotonic()
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(podman.run(["/bin/sh", "-c", "sleep 20 & exec sleep 20"], timeout=0.5), 5)
    assert time.monotonic() - started < 4


async def test_the_windows_size_is_remembered_and_fitted_to_the_screen(env, tmp_path):
    from davibemanager import app as app_mod
    engine, _, _ = env
    saved = []
    engine._save_config = saved.append
    engine.remember_window(700, 900)
    assert (engine.cfg.settings.window_width, engine.cfg.settings.window_height) == (700, 900) and len(saved) == 1
    engine.remember_window(700, 900)                                       # the same: nothing written
    engine.remember_window(0, 0)                                           # nonsense: ignored
    assert len(saved) == 1
    assert app_mod.window_size(engine.cfg, screen=(1920, 1080)) == (700, 900)
    assert app_mod.window_size(engine.cfg, screen=(1280, 720)) == (700, 620)     # fitted to a small screen
    engine.cfg.settings.window_width = engine.cfg.settings.window_height = 0
    assert app_mod.window_size(engine.cfg, screen=(1920, 1080)) == app_mod.WINDOW_SIZE
    assert app_mod.window_size(engine.cfg, screen=(400, 300)) == app_mod.MIN_SIZE


def test_trouble_reads_the_same_on_every_line_it_shows_on():
    """apt says the same trouble twice (Err:, then E: Failed to fetch with the address): the window shouldn't flicker."""
    w = podman.BuildWatch()
    w.feed("  Could not connect to snapshot.ubuntu.com:443 (185.125.189.36). - connect (111: Connection refused)")
    first = w.trouble()
    w.feed("E: Failed to fetch https://snapshot.ubuntu.com/ubuntu/x/dists/noble/InRelease  Could not connect to "
           "snapshot.ubuntu.com:443 (185.125.189.36). - connect (111: Connection refused)")
    assert w.trouble() == first and first.startswith("Ubuntu's snapshot server (snapshot.ubuntu.com) can't be reached (Could not connect")


async def test_a_flood_of_failures_doesnt_flood_the_window(fake_sandbox, tmp_path):
    """Each package refused is a line of its own: hundreds within a second, as on the CachyOS test."""
    calls, script = fake_sandbox
    script["lines"] = ["STEP 3/16: RUN ..."] + [
        x for i in range(200) for x in (f"Err:{i} https://snapshot.ubuntu.com/ubuntu/x noble/main amd64 p{i}",
                                         "  503  Service Unavailable [IP: 185.125.189.36 443]")]
    script["build_errors"] = [podman.build_failure(SNAPSHOT_503)]
    e = await _engine(tmp_path)
    seen = []
    e._set_workspace = lambda **st: (seen.append(st), setattr(e, "workspace", st))
    await e._start_workspace()
    assert len(seen) < 10
    from davibemanager.config import data_dir
    assert (data_dir() / "app.log").read_text().count("sandbox_build_trouble") == 1


def test_a_server_thats_not_ubuntus_is_named_as_it_is():
    w = podman.BuildWatch()
    w.feed("Err:1 http://192.168.1.5:3142/ubuntu noble InRelease")
    w.feed("  503  Service Unavailable [IP: 192.168.1.5 3142]")
    assert w.trouble().startswith("The package server 192.168.1.5 is busy or down (503 Service Unavailable)")


class FakePodman:
    """podman's answers for the build's clean-up, scripted: images (id -> (tag, parent[, its steps' history]))
    and Buildah's containers (id -> image id)."""

    def __init__(self, images, containers):
        self.images, self.containers, self.ran = dict(images), dict(containers), []

    async def run(self, argv, **kw):
        a = argv[1:]
        self.ran.append(a)
        if a[:2] == ["image", "inspect"] and a[3] == "{{.Id}}":
            return (0, "base\n") if "base" in self.images else (125, "no such image")
        if a[:2] == ["image", "inspect"]:
            history = "History" in a[3]
            return 0, "".join(f"{i}|{self.images[i][1]}" + (f"|{self.history(i)}" if history else "") + "\n"
                              for i in a[4:] if i in self.images)
        if a[:2] == ["images", "-a"]:
            return 0, "".join(f"sha256:{i}|{v[0]}\n" for i, v in self.images.items())
        if a[:2] == ["ps", "-a"]:
            return 0, "".join(f"{c}|{i}|Storage\n" for c, i in self.containers.items())
        if a[:1] == ["rm"]:
            for c in a[2:]:
                self.containers.pop(c, None)
            return 0, ""
        if a[:2] == ["image", "rm"]:
            if any(v[1] == a[2] for v in self.images.values()):
                return 2, "image has dependent child images"
            if a[2] not in self.images:
                return 1, "no such image"
            deleted, iid = [], a[2]             # as Podman does: and those below it left with nothing on them
            while iid in self.images and not any(v[1] == iid for k, v in self.images.items() if k not in deleted):
                deleted.append(iid)
                iid = self.images[iid][1] if self.images[iid][0] == "<none>:<none>" or iid == a[2] else ""
            for d in deleted:
                del self.images[d]
            return 0, "".join(f"Deleted: {d}\n" for d in deleted)
        if a[:1] == ["build"]:
            self.containers["c-step3"] = "l2"          # the step it was in when it failed
            return 1, "E: Failed to fetch https://snapshot.ubuntu.com/x  503  Service Unavailable [IP: 1.2.3.4 443]"
        return 0, ""

    def history(self, iid: str) -> str:
        steps = []
        while iid in self.images:
            steps = list(self.images[iid][2:3] and self.images[iid][2]) + steps
            iid = self.images[iid][1]
        return json.dumps([{"created_by": step} for step in steps])


async def test_a_failed_build_removes_what_it_left_and_nothing_of_a_build_of_the_users_meanwhile(monkeypatch, tmp_path):
    """The user's own builds may be from the very same base image, and run while the app's does: their
    containers and scratch folders were new since it began too, and went with it when it failed."""
    fake = FakePodman({"base": ("docker.io/library/ubuntu:<none>", "")}, {"theirs": "someimage"})

    async def missing(tag):
        return False
    monkeypatch.setattr(podman, "image_exists", missing)
    cli = tmp_path / "claude"
    cli.write_bytes(b"cli")
    monkeypatch.setattr(podman, "bundled_cli", lambda: cli)
    monkeypatch.setattr(pins, "CLAUDE_SHA256", __import__("hashlib").sha256(b"cli").hexdigest())
    monkeypatch.setattr(podman, "_ca_bundle", lambda: "/etc/ssl/certs/ca-certificates.crt")
    tmp = tmp_path / "vartmp"
    (tmp / "buildah111").mkdir(parents=True)              # someone else's, from before
    monkeypatch.setenv("TMPDIR", str(tmp))
    users_build_too = False

    async def run(argv, **kw):
        if argv[1:2] == ["build"]:
            scratch = Path(kw["env"]["TMPDIR"])
            assert scratch.parent == tmp and scratch.name.startswith(podman.SCRATCH_PREFIX)
            (scratch / "buildah222" / "overlay").mkdir(parents=True)     # this build's, left when it failed
            for line in ("STEP 1/9: FROM base", "STEP 2/9: ARG APT_URI", "--> 0123456789ab",
                         "STEP 3/9: ENV LANG=C.UTF-8", "--> Using cache " + "ab" * 32, "--> " + "ab" * 6, "STEP 4/9: RUN x"):
                kw["on_line"](line)
            fake.containers.update({"c-from": "base", "c-arg": "0123456789ab" + "0" * 52, "c-run": "ab" * 32})
            if users_build_too:                                 # the user's, begun from the same base meanwhile
                fake.containers.update({"u-from": "base", "u-run": "cd" * 32})
                (tmp / "buildah333").mkdir()
            return 1, "E: Failed to fetch https://snapshot.ubuntu.com/x  503  Service Unavailable [IP: 1.2.3.4 443]"
        if argv[1:3] == ["unshare", "sh"]:
            assert argv[4] == podman.UNMOUNT_AND_REMOVE
            import shutil
            for p in argv[6:]:
                shutil.rmtree(p)
        return await fake.run(argv, **kw)
    monkeypatch.setattr(podman, "run", run)
    with pytest.raises(podman.BuildError):
        await podman.build_image()
    assert fake.containers == {"theirs": "someimage"}
    assert [p.name for p in tmp.iterdir()] == ["buildah111"]
    users_build_too = True
    with pytest.raises(podman.BuildError):
        await podman.build_image()
    # its FROM's container and the user's are alike: both are kept (they hold nothing)
    assert fake.containers == {"theirs": "someimage", "c-from": "base", "u-from": "base", "u-run": "cd" * 32}
    assert sorted(p.name for p in tmp.iterdir()) == ["buildah111", "buildah333"]


async def test_a_builds_scratch_left_by_an_app_that_ended_meanwhile_goes_once_its_old(monkeypatch, tmp_path):
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    old, new, users = (tmp_path / f"{podman.SCRATCH_PREFIX}old"), (tmp_path / f"{podman.SCRATCH_PREFIX}new"), tmp_path / "buildah1"
    for d in (old, new, users):
        (d / "buildah9").mkdir(parents=True)
    os.utime(old, (time.time() - podman.STALE_SCRATCH - 60,) * 2)
    os.utime(users, (time.time() - podman.STALE_SCRATCH - 60,) * 2)

    async def run(argv, **kw):
        assert argv[1:3] == ["unshare", "sh"]
        import shutil
        for p in argv[6:]:
            shutil.rmtree(p)
        return 0, ""
    monkeypatch.setattr(podman, "run", run)
    assert await podman._remove_stale_scratch() == [str(old)]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["buildah1", f"{podman.SCRATCH_PREFIX}new"]


async def test_removing_takes_the_builds_leftovers_and_nothing_of_the_users_built_on_the_same_base(monkeypatch, tmp_path):
    """The user's own builds may be on the very image the app's is (their `ubuntu:24.04` is that one):
    the app's layers are told by their history, which has its build's arguments."""
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    ubuntu = ["/bin/sh -c #(nop)  ARG RELEASE", "/bin/sh -c #(nop) ADD file:43d4 in / "]
    fake = FakePodman({
        "base": ("docker.io/library/ubuntu:<none>", "", ubuntu),
        "l1": ("<none>:<none>", "base", ["/bin/sh -c #(nop) ARG APT_URI"]),          # below one that has them
        "l2": ("<none>:<none>", "l1", ["/bin/sh -c #(nop) ARG APPIMAGETOOL_URL APPIMAGETOOL_SHA256 RUNTIME_URL "
                                       "RUNTIME_SHA256 CLAUDE_SHA256"]),
        "l3": ("<none>:<none>", "l2", ["|6 APPIMAGETOOL_SHA256=ed4c APT_URI=https://snapshot.ubuntu.com/ubuntu/x/ "
                                       "CLAUDE_SHA256=98ab RUNTIME_SHA256=27c1 /bin/sh -c apt-get install"]),
        "mine": ("localhost/my-app:1", "l3", ["/bin/sh -c make"]),     # the user's own, tagged: never
        "u1": ("<none>:<none>", "base", ["/bin/sh -c apt-get install -y build-essential"]),   # the user's own
        "u2": ("<none>:<none>", "u1", ["/bin/sh -c #(nop) COPY file:aa in /build "]),
        "other": ("<none>:<none>", "elsewhere"), "elsewhere": ("docker.io/library/debian:13", ""),
    }, {"w0": "base", "w2": "l2", "users": "elsewhere", "users-step": "u2"})
    monkeypatch.setattr(podman, "run", fake.run)
    removed = await podman._remove_build_leftovers()
    assert set(fake.containers) == {"w0", "users", "users-step"} and removed == ["build container w2"]
    assert set(fake.images) == {"base", "l1", "l2", "l3", "mine", "u1", "u2", "other", "elsewhere"}     # l3 has a child
    del fake.images["mine"]
    removed = await podman._remove_build_leftovers()
    assert set(fake.images) == {"base", "u1", "u2", "other", "elsewhere"} and removed == [
        "build layer l3", "build layer l2", "build layer l1"]


async def test_what_the_app_runs_in_the_sandbox_is_stopped_there_when_it_runs_out_of_time(no_real_podman):
    """Stopping `podman exec` doesn't stop what it runs in the container (a clone, apt-get holding its lock):
    each command has a time limit of its own there, a little inside the app's, ending its whole group."""
    await podman.exec_agent("dvm-x", ["git", "fetch"], timeout=120)
    await podman.exec_root("dvm-x", ["apt-get", "update"], timeout=1800)
    await podman.exec_mirror("dvm-x", ["sh", "-c", "x"], timeout=20)
    agent, root, mirror = no_real_podman[0], no_real_podman[1], no_real_podman[-1]
    assert agent[agent.index("dvm-x") + 1:] == ["/usr/bin/timeout", "--kill-after=7.5", "105", "git", "fetch"]
    assert root[root.index("dvm-x") + 1:] == ["/usr/bin/timeout", "--kill-after=7.5", "1785", "apt-get", "update"]
    assert mirror[mirror.index("dvm-x") + 1:] == ["/usr/bin/timeout", "--kill-after=2", "16", "sh", "-c", "x"]


async def test_input_for_a_command_that_ended_without_reading_it_isnt_an_error_of_its_own():
    """The container isn't running: podman exec ends at once, saying so, and that's what is returned."""
    rc, out = await podman.run(["sh", "-c", "echo 'Error: no container' >&2; exit 125"], input=b"x" * (4 << 20), timeout=10)
    assert rc == 125 and "no container" in out
