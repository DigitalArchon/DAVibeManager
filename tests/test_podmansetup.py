"""A computer without Podman: the window says what's missing and installs it with the app's own
command for the distribution, as administrator, only on the user's click."""

import pytest

from davibemanager import hostrun, podmansetup
from davibemanager.models import UserError
from davibemanager.workspace import podman
from helpers import wait_for

UBUNTU = {"ID": "ubuntu", "ID_LIKE": "debian", "PRETTY_NAME": "Ubuntu 24.04.3 LTS"}
MINT = {"ID": "linuxmint", "ID_LIKE": "ubuntu debian", "PRETTY_NAME": "Linux Mint 22.3"}
FEDORA = {"ID": "fedora", "PRETTY_NAME": "Fedora Linux 43 (Workstation Edition)"}
SILVERBLUE = {"ID": "fedora", "VARIANT_ID": "silverblue", "PRETTY_NAME": "Fedora Linux 43 (Silverblue)"}
CACHYOS = {"ID": "cachyos", "ID_LIKE": "arch", "PRETTY_NAME": "CachyOS"}
TUMBLEWEED = {"ID": "opensuse-tumbleweed", "ID_LIKE": "opensuse suse", "PRETTY_NAME": "openSUSE Tumbleweed"}


def has(*names):
    return lambda n: f"/usr/bin/{n}" if n in names else None


@pytest.mark.parametrize("rel,tools,command", [
    (UBUNTU, ("apt-get", "pkexec"), "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y podman passt"),
    (MINT, ("apt-get", "pkexec", "slirp4netns"), "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y podman"),
    (FEDORA, ("dnf", "pkexec", "pasta"), "dnf install -y podman"),
    # Arch's Podman doesn't bring passt, and can't build the sandbox without it
    (CACHYOS, ("pacman", "pkexec", "slirp4netns"), "pacman -S --needed --noconfirm podman passt"),
    (TUMBLEWEED, ("zypper", "pkexec", "pasta"), "zypper --non-interactive install podman"),
])
def test_each_distribution_gets_its_own_install_command(rel, tools, command):
    p = podmansetup.plan(rel, has(*tools))
    assert p["command"] == command and p["can_install"] and p["distro"] == rel["PRETTY_NAME"]
    assert p["terminal"].startswith("sudo ") and command in p["terminal"]


def test_nothing_is_asked_for_when_its_all_there():
    assert podmansetup.plan(UBUNTU, has("podman", "pasta", "apt-get")) is None
    assert podmansetup.missing(has("podman", "slirp4netns")) == []


def test_podman_without_a_network_helper_needs_just_that():
    p = podmansetup.plan(CACHYOS, has("podman", "pacman", "pkexec"))
    assert p["missing"] == ["passt"] and p["command"] == "pacman -S --needed --noconfirm passt"
    assert "network helper" in podmansetup.message(p)


def test_where_the_app_cant_install_it_it_says_how():
    p = podmansetup.plan(SILVERBLUE, has("rpm-ostree", "dnf", "pkexec"))     # image-based: not by package
    assert not p["can_install"] and p["command"] == "" and "software manager" in podmansetup.message(p)
    p = podmansetup.plan(UBUNTU, has("apt-get"))                              # no pkexec: the terminal
    assert not p["can_install"] and "sudo sh -c 'apt-get update" in podmansetup.message(p)
    p = podmansetup.plan({"ID": "gentoo"}, has("emerge", "pkexec"))
    assert not p["can_install"] and p["distro"] == "Linux"


@pytest.fixture
def no_podman(env, monkeypatch):
    engine, _, events = env
    state = {"missing": ["podman"]}
    monkeypatch.setattr(podmansetup, "missing", lambda which=None: list(state["missing"]))
    monkeypatch.setattr(podmansetup.sysinfo, "_os_release", lambda: UBUNTU)
    monkeypatch.setattr(podmansetup.shutil, "which", lambda n: "/usr/bin/pkexec" if n in ("pkexec", "apt-get") else None)
    started = []
    engine.start_workspace = lambda: started.append(1)
    return engine, state, started, events


async def test_without_podman_the_sandbox_waits_for_it_and_says_so_once(no_podman):
    engine, _, _, _ = no_podman
    told = []
    engine.notify = lambda title, body: told.append(title)
    for _ in range(2):
        await engine._start_workspace()
    assert engine.workspace["state"] == "needs_podman" and "needs Podman" in engine.workspace["error"]
    assert told == ["DA Vibe Manager needs Podman"]
    view = engine.snapshot()["podman"]
    assert view["can_install"] and view["command"].endswith("install -y podman") and view["install"] == {}


async def test_installed_on_the_users_click_then_the_sandbox_starts(no_podman, monkeypatch):
    engine, state, started, _ = no_podman
    ran = []

    async def run(command, *, as_root=False, timeout=0, cancel=None):
        ran.append((command, as_root))
        state["missing"] = []
        return hostrun.RunResult(0, "Setting up podman (4.9.3)…\n", False, 42.0)

    async def works():
        return ""
    monkeypatch.setattr(hostrun, "run", run)
    monkeypatch.setattr(podman, "works", works)
    engine.install_podman()
    assert engine.snapshot()["podman"]["install"]["state"] == "installing"
    with pytest.raises(UserError, match="already"):
        engine.install_podman()
    await wait_for(lambda: started, "the sandbox's start")
    assert ran == [("apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y podman", True)]
    assert engine.snapshot()["podman"] is None


@pytest.mark.parametrize("code,after,works,said", [
    (126, ["podman"], "", "password prompt was closed"),
    (100, ["podman"], "", "ended with code 100"),
    (0, ["podman"], "", "still isn't there"),
    (0, [], "cannot find newuidmap", "doesn't run for your user"),
])
async def test_an_install_that_didnt_work_says_why(no_podman, monkeypatch, code, after, works, said):
    engine, state, started, _ = no_podman

    async def run(command, **kw):
        state["missing"] = after
        return hostrun.RunResult(code, "E: Unable to locate package podman\n", False, 3.0)

    async def podman_works():
        return works
    monkeypatch.setattr(hostrun, "run", run)
    monkeypatch.setattr(podman, "works", podman_works)
    engine.install_podman()
    await wait_for(lambda: engine._podman_install.get("state") == "failed", "the failure")
    assert said in engine._podman_install["error"] and not started


def test_where_it_cant_be_installed_from_the_window_its_refused(no_podman, monkeypatch):
    engine, _, _, _ = no_podman
    monkeypatch.setattr(podmansetup.shutil, "which", lambda n: None)      # no pkexec, no package manager
    with pytest.raises(UserError, match="can't install it here"):
        engine.install_podman()


# ---- removing the sandbox, and Podman with it (Settings → The sandbox)

@pytest.mark.parametrize("rel,tools,command", [
    (UBUNTU, ("podman", "apt-get", "pkexec"), "apt-get remove -y podman"),
    (FEDORA, ("podman", "dnf", "pkexec"), "dnf remove -y podman"),
    (CACHYOS, ("podman", "pacman", "pkexec"), "pacman -Rs --noconfirm podman"),
    (TUMBLEWEED, ("podman", "zypper", "pkexec"), "zypper --non-interactive remove --clean-deps podman"),
])
def test_each_distribution_gets_its_own_uninstall_command(rel, tools, command):
    p = podmansetup.removal(rel, has(*tools))
    assert p["command"] == command and p["can_remove"] and not p["installed_by_app"]
    assert p["leaves_dependencies"] == (rel is UBUNTU)


def test_uninstalling_takes_what_the_app_installed_and_nothing_that_was_there_before():
    # pacman's install names passt even where it's there already (--needed skips it): it isn't new then
    p = podmansetup.plan(CACHYOS, has("pacman", "pkexec", "pasta"))
    assert p["packages"] == ["podman", "passt"] and p["new"] == ["podman"]
    podmansetup.record_install(p["new"])
    assert podmansetup.removal(CACHYOS, has("podman", "pacman", "pkexec"))["command"] == "pacman -Rs --noconfirm podman"
    p = podmansetup.plan(CACHYOS, has("pacman", "pkexec"))
    assert p["new"] == ["podman", "passt"]
    podmansetup.record_install(p["new"])
    r = podmansetup.removal(CACHYOS, has("podman", "pacman", "pkexec"))
    assert r["command"] == "pacman -Rs --noconfirm passt podman" and r["installed_by_app"]
    podmansetup.forget_install()
    assert podmansetup.installed_by_app() is None
    assert podmansetup.removal(CACHYOS, has("pacman")) is None          # no Podman: nothing to uninstall


async def test_a_successful_install_is_written_down(no_podman, monkeypatch):
    engine, state, started, _ = no_podman

    async def run(command, **kw):
        state["missing"] = []
        return hostrun.RunResult(0, "", False, 1.0)

    async def works():
        return ""
    monkeypatch.setattr(hostrun, "run", run)
    monkeypatch.setattr(podman, "works", works)
    engine.install_podman()
    await wait_for(lambda: started, "the sandbox's start")
    assert podmansetup.installed_by_app() == ["podman"]


@pytest.fixture
def removable(env, monkeypatch):
    """An engine whose sandbox can be removed: Podman's side scripted."""
    engine, _, events = env
    did = {"ran": [], "others": [], "reset": 0, "podman": True}
    monkeypatch.setattr(podmansetup.sysinfo, "_os_release", lambda: CACHYOS)
    which = lambda n: f"/usr/bin/{n}" if n in ("pacman", "pkexec") or (n == "podman" and did["podman"]) else None
    monkeypatch.setattr(podmansetup.shutil, "which", which)

    async def remove_all(sandbox):
        did["removed"] = sandbox
        return ["dvm-sandbox", "localhost/davibemanager-workspace:abc"]

    async def anything_else():
        return did["others"]

    async def reset_storage():
        did["reset"] += 1
        return 0, ""

    async def run(command, *, as_root=False, timeout=0, cancel=None):
        did["ran"].append((command, as_root))
        did["podman"] = False
        return hostrun.RunResult(0, "removing podman…", False, 2.0)
    monkeypatch.setattr(podman, "remove_all", remove_all)
    monkeypatch.setattr(podman, "anything_else", anything_else)
    monkeypatch.setattr(podman, "reset_storage", reset_storage)
    monkeypatch.setattr(hostrun, "run", run)
    return engine, did


async def test_removing_the_sandbox_leaves_podman_unless_asked(removable):
    engine, did = removable
    engine.remove_sandbox(False)
    await wait_for(lambda: engine._removal.get("state") == "done", "the removal")
    assert did["removed"] == "dvm-sandbox" and did["ran"] == [] and did["reset"] == 0
    assert engine.workspace["state"] == "removed" and engine.snapshot()["podman"] is None


async def test_removing_podman_too_uninstalls_it_as_administrator_and_wipes_only_an_empty_store(removable):
    engine, did = removable
    engine.remove_sandbox(True)
    await wait_for(lambda: engine._removal.get("state") == "done", "the removal")
    assert did["ran"] == [("pacman -Rs --noconfirm podman", True)] and did["reset"] == 1
    assert engine._removal == {"state": "done", "podman": True, "kept": [], "leaves_dependencies": False}


async def test_the_users_own_containers_keep_podmans_store(removable):
    engine, did = removable
    did["others"] = ["container my-db", "image docker.io/library/postgres:17"]
    engine.remove_sandbox(True)
    await wait_for(lambda: engine._removal.get("state") == "done", "the removal")
    assert did["reset"] == 0 and engine._removal["kept"] == did["others"]


async def test_an_uninstall_that_didnt_work_says_why(removable, monkeypatch):
    engine, did = removable

    async def refused(command, **kw):
        return hostrun.RunResult(126, "", False, 1.0)
    monkeypatch.setattr(hostrun, "run", refused)
    engine.remove_sandbox(True)
    await wait_for(lambda: engine._removal.get("state") == "failed", "the failure")
    assert "nothing was uninstalled" in engine._removal["error"]


async def test_removing_is_refused_while_the_assistant_works(removable):
    engine, _ = removable
    engine.builder = type("Busy", (), {"busy": True})()
    with pytest.raises(UserError, match="Wait for the assistant"):
        engine.remove_sandbox(True)
    engine.builder = None


async def test_a_removed_sandbox_isnt_made_again_at_launch_only_when_wanted(removable):
    engine, did = removable
    engine.remove_sandbox(False)
    await wait_for(lambda: engine._removal.get("state") == "done", "the removal")
    started = []
    engine.start_workspace = lambda: started.append(1)
    engine._start_workspace_at_launch()
    assert not started and engine.workspace["state"] == "removed"
    from davibemanager.engine import Engine
    Engine.start_workspace(engine)                  # the user wants it: the marker goes
    assert not engine._removed_marker().exists()
