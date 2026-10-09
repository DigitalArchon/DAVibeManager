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
    assert creds.get_secret("provider", "NanoGPT") is None
    monkeypatch.setattr(memory_keyring, "get_password", locked)
    with pytest.raises(creds.KeyringUnavailable, match="unlock"):
        creds.get_secret("provider", "NanoGPT")


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
    return subprocess.Popen(["/bin/sh", "-c", scripts.GUARD, "dvm-sandbox-guard", str(pid), start, str(fake), "dla-x"])


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
    assert (tmp_path / "calls").read_text() == "stop --ignore -t 3 dla-x\n"


def test_another_process_with_the_apps_number_doesnt_count(tmp_path):
    guard = _guard(tmp_path, os.getpid(), "1")                            # this pid, started at another time
    guard.wait(10)
    assert (tmp_path / "calls").read_text() == "stop --ignore -t 3 dla-x\n"


def test_a_dead_copys_watcher_is_ended_before_the_sandbox_starts(tmp_path):
    guard = _guard(tmp_path, os.getpid(), _start(os.getpid()))
    time.sleep(0.3)
    assert guard.poll() is None
    engine_mod._end_old_guards()
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
