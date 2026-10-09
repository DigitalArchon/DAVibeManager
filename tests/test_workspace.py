"""The workspace container's run command: no network, no host paths, no capabilities."""

import re
from pathlib import Path

import pytest

from davibemanager.workspace import pins, podman


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

    async def build_image(progress=None):
        if script["fail"]:
            script["fail"] -= 1
            raise podman.PodmanError("podman start: container is still stopping")
        return "localhost/img:1"

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
    for fn in (build_image, gateway_source, has_mount, limits, recreate, ensure_running, sees_gateway, stop, inspect_image, logs):
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
