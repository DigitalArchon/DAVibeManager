"""Starting and stopping: a keyring that isn't open yet, and the sandbox never left running."""

import asyncio
import os
import subprocess
import time

import keyring
import pytest
from keyring.errors import KeyringLocked

from davibemanager import creds, engine as engine_mod
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
    a process of its own: the flag is the process's."""
    import sys
    import textwrap

    code = textwrap.dedent("""
        import ctypes, os, resource, subprocess, sys
        from davibemanager.app import no_core_dumps
        no_core_dumps()
        libc = ctypes.CDLL(None, use_errno=True)
        print(resource.getrlimit(resource.RLIMIT_CORE), libc.prctl(3, 0, 0, 0, 0))   # PR_GET_DUMPABLE
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
    assert out.stdout.split("\n")[:3] == ["(0, 0) 0", "True", "1"], out.stdout


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
