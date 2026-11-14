"""Starting and stopping: a keyring that isn't open yet, and the sandbox never left running."""

import asyncio
import os
import subprocess
import time

import keyring
import pytest
from keyring.errors import KeyringLocked

from davibemanager import creds, engine as engine_mod
from davibemanager.app import no_core_dumps as REAL_NO_CORE_DUMPS          # before conftest stands in for it
from davibemanager.hostenv import browsers_get_the_original_environment as REAL_BROWSERS
from davibemanager.models import KeyringWait, UserError
from davibemanager.workspace import scripts


def locked(*a, **k):
    raise KeyringLocked("Failed to unlock the collection!")


def test_a_key_that_cant_be_read_is_not_a_key_that_isnt_there(memory_keyring, monkeypatch):
    monkeypatch.setattr(memory_keyring, "get_password", locked)
    with pytest.raises(creds.KeyringUnavailable, match="unlock"):
        creds.get_secret("provider", "NanoGPT")
    monkeypatch.undo()
    assert creds.get_secret("provider", "NanoGPT") is None          # a read that failed isn't kept


def test_a_key_once_read_doesnt_ask_the_keyring_again(memory_keyring, monkeypatch):
    """Every model request and redraw needs it: a keyring that locked itself again (KWallet's timeout)
    mustn't stop the whole app on its password prompt."""
    creds.set_secret("provider", "NanoGPT", "sk-1")
    creds.forget()
    assert creds.get_secret("provider", "NanoGPT") == "sk-1"
    monkeypatch.setattr(memory_keyring, "get_password", locked)
    assert creds.get_secret("provider", "NanoGPT") == "sk-1"
    creds.set_secret("provider", "NanoGPT", "sk-2")                 # stored or deleted here: known at once
    assert creds.get_secret("provider", "NanoGPT") == "sk-2"
    creds.delete_secret("provider", "NanoGPT")
    assert creds.get_secret("provider", "NanoGPT") is None


def test_no_keyring_yet_is_looked_for_again(monkeypatch):
    """keyring chooses its backend once per process: started before the Secret Service, it would
    have none for the whole session."""
    from keyring.backends import fail
    keyring.set_keyring(fail.Keyring())
    found = []
    monkeypatch.setattr(keyring.core, "init_backend", lambda *a: found.append(1))
    with pytest.raises(creds.KeyringUnavailable):
        creds.get_secret("provider", "NanoGPT")
    assert found


async def test_after_login_it_waits_for_the_keyring_instead_of_asking_for_the_key(env, memory_keyring, monkeypatch):
    engine, _, events = env
    assert engine.ready
    real = memory_keyring.get_password
    monkeypatch.setattr(memory_keyring, "get_password", locked)
    creds.forget()                                              # as at a start just after login: nothing read yet
    assert not engine.ready and "isn't open yet" in engine.keyring_wait
    snap = engine.snapshot()
    assert not snap["ready"] and snap["keyring_wait"]           # the window waits; it doesn't ask for a key
    with pytest.raises(KeyringWait):
        engine.models.builder_target()
    started = []
    engine.start_workspace = lambda: started.append(1)
    engine.workspace = {"state": "stopped"}
    waiting = asyncio.ensure_future(engine._wait_for_keyring(every=0.01))
    await asyncio.sleep(0.05)
    assert not waiting.done()
    monkeypatch.setattr(memory_keyring, "get_password", real)   # the user unlocked it
    await asyncio.wait_for(waiting, 2)
    assert engine.ready and not engine.keyring_wait and started
    assert events[-1]["type"] == "state" and events[-1]["state"]["ready"]


async def test_a_key_that_isnt_stored_still_asks_for_one(env, memory_keyring):
    engine, _, _ = env
    memory_keyring.store.clear()
    creds.forget()                                              # (gone from the keyring by other means)
    assert not engine.ready and engine.keyring_wait == ""


def test_a_key_the_keyring_wont_take_is_said_and_nothing_is_saved(env, memory_keyring, monkeypatch):
    engine, _, _ = env
    before = [p.name for p in engine.cfg.providers]
    monkeypatch.setattr(memory_keyring, "set_password", locked)
    with pytest.raises(UserError, match="Unlock your keyring"):
        engine.models.save_provider({"name": "Other", "base_url": "https://other.example/v1"}, "sk-other")
    assert [p.name for p in engine.cfg.providers] == before


def _guard(tmp_path, pid: int, start: str) -> subprocess.Popen:
    fake = tmp_path / "podman"
    fake.write_text(f'#!/bin/sh\necho "$@" >> {tmp_path}/calls\n')
    fake.chmod(0o755)
    return subprocess.Popen(["/bin/sh", "-c", scripts.GUARD, "dvm-sandbox-guard", str(pid), start, str(fake), "dvm-x"])


def _start(pid: int) -> str:
    return open(f"/proc/{pid}/stat").read().rsplit(") ", 1)[1].split()[19]


def test_the_sandbox_is_stopped_when_the_app_dies_without_stopping_it(tmp_path):
    app = subprocess.Popen(["sleep", "60"])
    guard = _guard(tmp_path, app.pid, _start(app.pid))
    time.sleep(0.5)
    assert guard.poll() is None and not (tmp_path / "calls").exists()      # alive: nothing happens
    app.kill()
    app.wait()
    guard.wait(10)
    assert (tmp_path / "calls").read_text() == "stop --ignore -t 3 dvm-x\n"


def test_another_process_with_the_apps_number_doesnt_count(tmp_path):
    guard = _guard(tmp_path, os.getpid(), "1")                            # this pid, started at another time
    guard.wait(10)
    assert (tmp_path / "calls").read_text() == "stop --ignore -t 3 dvm-x\n"


def test_a_dead_copys_watcher_is_ended_before_the_sandbox_starts(tmp_path):
    guard = _guard(tmp_path, os.getpid(), _start(os.getpid()))
    time.sleep(0.3)
    assert guard.poll() is None
    engine_mod._end_old_guards("dvm-x")
    assert guard.wait(5) != 0 and not (tmp_path / "calls").exists()       # ended, without stopping anything


async def test_on_quit_the_sandbox_is_stopped_before_claude_code_is_closed(env, monkeypatch):
    engine, _, _ = env
    order = []
    engine.workspace = {"state": "running"}

    async def stop(name):
        order.append("sandbox")

    async def close():
        order.append("claude code")
    monkeypatch.setattr(engine_mod.podman, "stop", stop)
    monkeypatch.setattr(engine, "_close_builder", close)
    await engine.stop()
    assert order == ["sandbox", "claude code"]


# --- a crash writes nothing out (SealedLore's gui/app.py _no_core_dumps) ------------------------------------

def test_a_crash_writes_no_core_and_nothing_reads_the_apps_memory():
    """A core file would hold the API key, the conversation and a private model's replies opened in memory. Run in
    a process of its own: the flag is the process's. As every DA app sets it (the cross-app standard, Nov 2026):
    not dumpable, RLIMIT_CORE's soft limit 1 (the kernel aborts a core at exactly 1, where systemd-coredump's pipe
    ignores 0) with the hard limit as it was, and nothing of its memory in a core (coredump_filter 0)."""
    import sys
    import textwrap

    code = textwrap.dedent("""
        import ctypes, os, resource, subprocess, sys
        hard = resource.getrlimit(resource.RLIMIT_CORE)[1]
        from davibemanager.app import no_core_dumps
        no_core_dumps()
        libc = ctypes.CDLL(None, use_errno=True)
        soft, after = resource.getrlimit(resource.RLIMIT_CORE)
        print(soft == (1 if hard == resource.RLIM_INFINITY or hard >= 1 else hard), after == hard,
              libc.prctl(3, 0, 0, 0, 0))   # PR_GET_DUMPABLE
        print(int(open("/proc/self/coredump_filter").read(), 16))
        # the sandbox's guard, another program, still reads when the app started
        pid = str(os.getpid())
        mine = open(f"/proc/{pid}/stat").read().rsplit(") ", 1)[1].split()[19]
        seen = subprocess.run(["/bin/sh", "-c", "sed 's/.*) //' /proc/$1/stat | cut -d' ' -f20", "x", pid],
                              capture_output=True, text=True).stdout.strip()
        print(seen == mine)
        # a program it starts is dumpable again: the flag isn't handed on
        print(subprocess.run([sys.executable, "-c", "import ctypes; print(ctypes.CDLL(None).prctl(3, 0, 0, 0, 0))"],
                             capture_output=True, text=True).stdout.strip())
    """)
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.split("\n")[:4] == ["True True 0", "0", "True", "1"], out.stdout


def _calls_with_hard_limit(monkeypatch, hard) -> tuple[list, list, list]:
    """What the real no_core_dumps asks of the system with RLIMIT_CORE's hard limit at `hard`: the limits it
    sets, what it writes to coredump_filter, and its prctl calls, none of them made (the test run stays
    dumpable)."""
    import builtins
    import ctypes
    import io
    import resource

    from davibemanager import app
    set_to, written, prctl = [], [], []

    class Filter(io.StringIO):
        def close(self):
            written.append(self.getvalue())
            super().close()

    class Libc:
        def prctl(self, option, value, *rest):
            prctl.append((option, value))
    real_open = builtins.open
    monkeypatch.setattr(resource, "getrlimit", lambda what: (0, hard))
    monkeypatch.setattr(resource, "setrlimit", lambda what, limits: set_to.append(limits))
    monkeypatch.setattr(builtins, "open", lambda path, *a, **k: Filter() if path == "/proc/self/coredump_filter"
                        else real_open(path, *a, **k))
    monkeypatch.setattr(app.sys, "platform", "linux")
    monkeypatch.setattr(ctypes, "CDLL", lambda *a, **k: Libc())
    try:
        REAL_NO_CORE_DUMPS()                             # the real one, not conftest's stand-in
    finally:
        monkeypatch.setattr(builtins, "open", real_open)
    return set_to, written, prctl


def test_core_dumps_are_set_off_as_the_standard_says_whatever_the_hard_limit(monkeypatch):
    """The calls themselves, on a hard limit of 0 too (a soft limit can't go above it), and none elsewhere."""
    import resource

    from davibemanager import app
    for hard, want in ((resource.RLIM_INFINITY, 1), (5, 1), (0, 0)):
        assert _calls_with_hard_limit(monkeypatch, hard) == ([(want, hard)], ["0"], [(4, 0)]), hard
    monkeypatch.setattr(app.sys, "platform", "darwin")
    monkeypatch.setattr(resource, "setrlimit", lambda *a: pytest.fail("not on another system"))
    REAL_NO_CORE_DUMPS()


def test_a_browser_is_started_with_the_environment_as_it_was_not_the_apps_own(monkeypatch):
    """GTK_USE_PORTAL=0 is the app's own (the portal refuses an undumpable process): webbrowser hands the browser
    the process's environment, so the app's browser, and every link the window opened (pywebview's
    webbrowser.open), lost the portal's dialogs the desktop asked for (the cross-app standard, Nov 2026)."""
    import webbrowser

    from davibemanager import app, hostenv

    seen = []

    def browser(url, new=0, autoraise=True):
        seen.append((url, new, os.environ.get("GTK_USE_PORTAL"), os.environ.get("GI_TYPELIB_PATH")))
        return True
    monkeypatch.setattr(hostenv, "ORIGINAL", {})
    monkeypatch.setattr(hostenv, "_REAL_OPEN", None)
    monkeypatch.setattr(webbrowser, "open", browser)
    monkeypatch.setenv("GTK_USE_PORTAL", "1")
    monkeypatch.delenv("GI_TYPELIB_PATH", raising=False)
    app.own_dialogs()
    hostenv.set_for_self("GI_TYPELIB_PATH", "/opt/app/girepository-1.0")
    REAL_BROWSERS()                                               # conftest's stands in for the rest of the run
    assert webbrowser.open is hostenv.open_url
    webbrowser.open_new_tab("https://example.org/")               # as pywebview opens a link the user clicked
    app.browser_opener(8123, app.Launches())()
    assert [(n, portal, typelib) for _, n, portal, typelib in seen] == [(2, "1", None), (0, "1", None)]
    assert os.environ["GTK_USE_PORTAL"] == "0" and os.environ["GI_TYPELIB_PATH"] == "/opt/app/girepository-1.0"


def test_the_app_turns_core_dumps_off_before_anything_else(monkeypatch):
    from davibemanager import app

    class First(Exception):
        pass

    def first():
        raise First

    monkeypatch.setattr(app, "no_core_dumps", first)
    monkeypatch.setattr(app.argparse.ArgumentParser, "parse_args", lambda *a, **k: pytest.fail("arguments read first"))
    with pytest.raises(First):
        app.main(["--browser"])


def test_the_window_asks_gtk_for_its_own_file_dialogs_where_the_desktop_asks_for_the_portals(monkeypatch):
    """xdg-desktop-portal refuses every request of a process that isn't dumpable ("Unable to open /proc/PID/root"):
    where GTK_USE_PORTAL=1 (some KDE desktops) the window's dialogs for attaching a file, importing a .vibe or
    restoring a backup would never open (DA Toolkit's app.own_dialogs). For the app's own process only."""
    from davibemanager import app, hostenv

    monkeypatch.setattr(hostenv, "ORIGINAL", {})
    monkeypatch.setenv("GTK_USE_PORTAL", "1")
    app.own_dialogs()
    assert os.environ["GTK_USE_PORTAL"] == "0" and hostenv.host_env()["GTK_USE_PORTAL"] == "1"
    hostenv.put_back("GTK_USE_PORTAL")                  # the browser instead: as the desktop asks
    assert os.environ["GTK_USE_PORTAL"] == "1" and hostenv.ORIGINAL == {}
    monkeypatch.delenv("GTK_USE_PORTAL")
    app.own_dialogs()
    assert "GTK_USE_PORTAL" not in os.environ and hostenv.ORIGINAL == {}


def test_the_test_run_stays_dumpable():
    """An entry point a test calls turns core dumps off for its process: here that would be the test run's own
    (conftest keeps app.no_core_dumps a stand-in; the real one is tested in a process of its own)."""
    import ctypes

    assert ctypes.CDLL(None).prctl(3, 0, 0, 0, 0) == 1
