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
