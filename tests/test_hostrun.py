"""Commands for this computer: nothing runs without the user, and the AI gets only what they send."""

import asyncio
import os
import signal

import pytest

from davibemanager import hostrun
from davibemanager.hostrun import HostRequest
from helpers import wait_for


def test_a_request_is_classified_by_local_rules_whatever_the_ai_says():
    r = HostRequest.create(1, {"command": "rm -rf ~/.config/gthumb", "purpose": "reset", "risk": "read_only"})
    assert r.risk != "read_only" and r.risk_reasons
    r = HostRequest.create(2, {"command": "cat ~/.ssh/id_ed25519", "purpose": "x", "risk": "read_only"})
    assert r.sensitive


def test_sudo_is_refused_in_favour_of_as_root_and_hidden_characters_are_removed():
    with pytest.raises(ValueError, match="as_root"):
        HostRequest.create(1, {"command": "sudo apt update", "purpose": "x", "risk": "modifying"})
    r = HostRequest.create(1, {"command": "ls‮ -la", "purpose": "x", "risk": "read_only"})
    assert "‮" not in r.command and r.hidden
    argv = hostrun.argv_for("apt update", True)
    assert argv[:2] == ["pkexec", "/bin/sh"] and argv[-1] == "apt update"     # the command is an argument, never pasted in


def test_only_a_command_that_has_not_run_can_be_edited():
    r = HostRequest.create(1, {"command": "ls", "purpose": "x", "risk": "read_only"})
    r.edit("ls -la ~")
    assert r.edited and r.command == "ls -la ~"
    r.status = "done"
    with pytest.raises(ValueError):
        r.edit("rm -rf ~")


async def test_running_is_bounded_and_has_no_terminal():
    res = await hostrun.run("echo out; echo err >&2; test -t 0 && echo TTY || echo NOTTY")
    assert res.exit_code == 0 and "out" in res.output and "err" in res.output and "NOTTY" in res.output
    res = await hostrun.run("sleep 30", timeout=1)
    assert res.timed_out and res.exit_code is None and res.seconds < 10
    stop = asyncio.Event()
    task = asyncio.ensure_future(hostrun.run("sleep 30; echo late", cancel=stop))
    await asyncio.sleep(0.3)
    stop.set()
    res = await task
    assert "late" not in res.output and not res.timed_out


def root_like(command: str) -> list[str]:
    """How an administrator's command is started, without pkexec (the wrapper as root runs it)."""
    return ["/bin/sh", "-c", hostrun.ROOT_WRAPPER, "sh", command]


async def test_an_administrators_command_is_stopped_by_roots_side_when_asked_or_out_of_time(tmp_path):
    """pkexec becomes root's program, which this app can't signal: the wrapper must stop the command
    (and what it started) itself when the app closes its pipe."""
    mark = tmp_path / "late"
    cmd = f"echo started; sleep 30 & sleep 30; touch {mark}"
    stop = asyncio.Event()
    task = asyncio.ensure_future(hostrun.run(cmd, as_root=True, cancel=stop, argv=root_like(cmd)))
    await asyncio.sleep(0.5)
    stop.set()
    res = await task
    assert "started" in res.output and not res.still_running and not res.timed_out and res.seconds < 5
    await asyncio.sleep(0.3)
    assert not mark.exists()
    res = await hostrun.run("sleep 30", as_root=True, timeout=1, argv=root_like("sleep 30"))
    assert res.timed_out and not res.still_running and res.seconds < 5
    res = await hostrun.run("echo hi; exit 3", as_root=True, argv=root_like("echo hi; exit 3"))
    assert res.exit_code == 3 and res.output == "hi\n"


async def test_a_command_that_wont_stop_is_reported_as_maybe_still_running(monkeypatch):
    """Say so, rather than that it ended: e.g. root's side that ignores the closed pipe."""
    signalled = []
    monkeypatch.setattr(hostrun, "_signal", signalled.append)       # as with root's processes: no effect
    monkeypatch.setattr(hostrun, "STOP_GRACE", 0.2)
    monkeypatch.setattr(hostrun, "STOP_WAIT", 0.2)
    res = await hostrun.run("x", as_root=True, timeout=1, argv=["/bin/sh", "-c", "exec sleep 20"])
    assert res.still_running and res.exit_code is None and res.seconds < 5
    proc = signalled[0]
    os.killpg(proc.pid, signal.SIGKILL)
    await proc.wait()


# ---- through the engine, as the assistant's tool sees it

async def ask(engine, args):
    """Start a request as the assistant's tool would, without the sandbox: returns the waiting task."""
    if engine.builder is None:
        engine.builder = type("B", (), {"entry": {"parts": []}, "busy": True, "close": staticmethod(_noop)})()
    before = max(engine.requests, default=0)
    task = asyncio.ensure_future(engine.builder_host_command(args))
    await wait_for(lambda: max(engine.requests, default=0) > before, "request")
    return task, max(engine.requests)


async def _noop():
    pass


async def test_nothing_runs_until_the_user_says_so_and_the_output_waits_for_review(env, tmp_path):
    engine, _, _ = env
    marker = tmp_path / "ran"
    task, rid = await ask(engine, {"command": f"touch {marker}; echo secret_token=abcdefghijklmnopqrstuvwx", "purpose": "test", "risk": "modifying"})
    await asyncio.sleep(0.2)
    assert not marker.exists() and not task.done()
    engine.run_request(rid)
    await wait_for(lambda: engine.requests[rid].status == "done", "run")
    r = engine.requests[rid]
    assert marker.exists() and "abcdefghijklmnopqrstuvwx" not in r.preview and r.redactions
    assert not task.done()                                   # review first: nothing sent yet
    engine.send_request(rid, r.preview + "\nadded by me")
    result = await task
    assert "Exit code 0" in result and "added by me" in result and "edited the output" in result
    assert "abcdefghijklmnopqrstuvwx" not in result


async def test_declining_tells_the_assistant_and_runs_nothing(env, tmp_path):
    engine, _, _ = env
    marker = tmp_path / "ran"
    task, rid = await ask(engine, {"command": f"touch {marker}", "purpose": "test", "risk": "modifying", "rollback": "rm x"})
    engine.decline_request(rid, "not today")
    assert "chose not to run" in await task and "not today" in task.result()
    assert not marker.exists()


async def test_a_typed_message_while_a_command_waits_declines_it_with_those_words(env):
    engine, _, _ = env
    task, rid = await ask(engine, {"command": "ls ~", "purpose": "list", "risk": "read_only"})
    engine.send("Why do you need my home folder?")
    assert "Why do you need my home folder?" in await task
    assert engine.requests[rid].status == "declined"
    assert engine.conv.chat[-1]["text"] == "Why do you need my home folder?"


async def test_withholding_output_says_so_without_any_of_it(env):
    engine, _, _ = env
    task, rid = await ask(engine, {"command": "echo private-stuff", "purpose": "x", "risk": "read_only"})
    engine.run_request(rid)
    await wait_for(lambda: engine.requests[rid].status == "done", "run")
    engine.withhold_request(rid)
    result = await task
    assert "chose not to share" in result and "private-stuff" not in result


async def test_automatic_output_still_holds_back_anything_sensitive(env, tmp_path):
    engine, _, _ = env
    fake_ssh = tmp_path / ".ssh"
    fake_ssh.mkdir()
    (fake_ssh / "config").write_text("Host example\n")
    engine.cfg.settings.output_mode = "auto"
    task, rid = await ask(engine, {"command": "echo hello", "purpose": "x", "risk": "read_only"})
    engine.run_request(rid)
    assert "hello" in await asyncio.wait_for(task, 10)
    task, rid = await ask(engine, {"command": f"cat {fake_ssh}/config; echo done", "purpose": "x", "risk": "read_only"})
    engine.run_request(rid)
    await wait_for(lambda: engine.requests[rid].status == "done", "run")
    await asyncio.sleep(0.1)
    assert not task.done()                                   # sensitive: waits for the user
    engine.withhold_request(rid)
    await task


async def test_changes_get_an_automatic_second_opinion(env):
    engine, fake, _ = env
    fake.completions.append("Deletes settings.\nSUMMARY: removes your settings\nDATA: none\nVERDICT: proceed with care")
    task, rid = await ask(engine, {"command": "rm -rf ~/.config/gthumb", "purpose": "reset", "risk": "modifying",
                                   "rollback": "none"})
    await wait_for(lambda: engine.requests[rid].review.get("status") == "done", "review")
    assert engine.requests[rid].review["level"] == "care"
    sent = fake.requests[-1]["messages"][1]["content"]
    assert "rm -rf ~/.config/gthumb" in sent and "reset" in sent
    engine.decline_request(rid)
    await task


async def test_a_decision_after_the_assistant_stopped_waiting_goes_as_a_message(env):
    engine, _, _ = env
    task, rid = await ask(engine, {"command": "uname -r", "purpose": "kernel", "risk": "read_only"})
    task.cancel()                                            # e.g. the turn was stopped
    await asyncio.sleep(0)
    sent = []
    engine.workspace = {"state": "running"}
    engine._start_turn = lambda content: sent.append(content)
    engine.builder.busy = False
    engine.decline_request(rid, "no")
    assert sent and "earlier request #1" in sent[0] and "no" in sent[0]
