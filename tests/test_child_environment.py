"""Every program the app starts gets the environment as it was before the app changed it for
itself (hostenv.host_env): GTK_USE_PORTAL=0, which the portal's refusal of an undumpable process
asks of the app's own GTK, and the AppImage's own variables, are this process's alone (the DA
apps' security standard, Nov 2026). podman, the sandbox's guard and the system lookups were
started with this process's own environment, and so was Claude Code, which claude-agent-sdk starts
itself (builder/cli_transport.py)."""

import ast
import asyncio
import hashlib
import inspect
import json
import os
import sys
import time
from pathlib import Path

from davibemanager import hostenv, sysinfo
from davibemanager.builder import bridge
from davibemanager.workspace import podman

SRC = Path(__file__).resolve().parents[1] / "src" / "davibemanager"
STARTS = {("subprocess", "run"), ("subprocess", "Popen"), ("subprocess", "call"),
          ("subprocess", "check_call"), ("subprocess", "check_output"),
          ("asyncio", "create_subprocess_exec"), ("asyncio", "create_subprocess_shell")}


def test_every_program_started_is_given_an_environment_of_its_own():
    """None inherits this process's own: each names env= (host_env, or tor's built from nothing)."""
    bare = []
    for path in SRC.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and isinstance(node.func.value, ast.Name) \
                    and (node.func.value.id, node.func.attr) in STARTS \
                    and not any(keyword.arg == "env" for keyword in node.keywords):
                bare.append(f"{path.relative_to(SRC)}:{node.lineno}")
    assert bare == []


def test_podman_and_the_system_lookups_get_the_portal_setting_back(monkeypatch):
    monkeypatch.setattr(hostenv, "ORIGINAL", {})
    monkeypatch.setenv("GTK_USE_PORTAL", "1")
    hostenv.set_for_self("GTK_USE_PORTAL", "0")
    code, out = asyncio.run(podman.run(["/bin/sh", "-c", 'printf "%s" "$GTK_USE_PORTAL"']))
    assert (code, out.strip()) == (0, "1")
    code, out = asyncio.run(podman.run(["/bin/sh", "-c", 'printf "%s %s" "$GTK_USE_PORTAL" "$EXTRA"'],
                                       env={"EXTRA": "x"}))
    assert out.strip() == "1 x"
    assert sysinfo._run(["/bin/sh", "-c", 'printf "%s %s" "$GTK_USE_PORTAL" "$LC_ALL"']) == "1 C"


def test_every_client_of_the_sdk_is_given_the_transport_that_starts_claude_code_so():
    """claude-agent-sdk starts the CLI itself, with os.environ: only a transport of our own gives it host_env()."""
    bare = []
    for path in SRC.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) == "ClaudeSDKClient" \
                    and not any(keyword.arg == "transport" for keyword in node.keywords):
                bare.append(f"{path.relative_to(SRC)}:{node.lineno}")
    assert bare == []


def test_the_transport_follows_the_pinned_sdks_own_connect():
    """HostEnvironmentTransport.connect is claude-agent-sdk 0.2.164's own but for the environment and the version
    probe. A bump that changes the SDK's connect fails here: read it again and bring ours in step, then update this."""
    from claude_agent_sdk._internal.transport.subprocess_cli import SubprocessCLITransport

    source = inspect.getsource(SubprocessCLITransport.connect).encode()
    assert hashlib.sha256(source).hexdigest() == "77a86450f9f8c68d2b3346211c5933e617bf1c7eec0207a87a870ba35b3ad0c3"


def _started_claude_code(tmp_path, monkeypatch, *, before: str | None) -> dict:
    """The environment a stand-in CLI is started with by the transport, GTK_USE_PORTAL `before` the app's own
    set_for_self, as the window does."""
    from claude_agent_sdk import ClaudeAgentOptions

    from davibemanager.builder.cli_transport import HostEnvironmentTransport

    monkeypatch.setattr(hostenv, "ORIGINAL", {})
    if before is None:
        monkeypatch.delenv("GTK_USE_PORTAL", raising=False)
    else:
        monkeypatch.setenv("GTK_USE_PORTAL", before)
    hostenv.set_for_self("GTK_USE_PORTAL", "0")
    monkeypatch.setenv("APPIMAGE", "/tmp/DA_Vibe_Manager.AppImage")      # the AppImage runtime's own
    monkeypatch.setenv("CLAUDECODE", "1")
    out = tmp_path / "env.json"
    runs = tmp_path / "runs"
    cli = tmp_path / "claude"
    cli.write_text("#!/bin/sh\n"
                   f'echo "$1" >> {runs}\n'
                   f"exec {sys.executable} -c 'import json, os; json.dump(dict(os.environ), open(\"{out}\", \"w\"))'\n")
    cli.chmod(0o700)
    options = ClaudeAgentOptions(cli_path=str(cli), env={"CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS": "1"})

    async def start():
        transport = HostEnvironmentTransport(options)
        await transport.connect()
        try:
            for _ in range(500):
                if out.exists() and out.stat().st_size:
                    break
                await asyncio.sleep(0.01)
        finally:
            await transport.close()

    asyncio.run(start())
    assert os.environ["GTK_USE_PORTAL"] == "0"           # the app's own stays as it set it
    # started once: no `claude -v` before it (the version probe, with this process's own environment)
    assert runs.read_text().split() == ["--output-format"]
    for _ in range(100):
        try:
            return json.loads(out.read_text())
        except ValueError:
            time.sleep(0.01)
    raise AssertionError("the stand-in CLI wrote no environment")


def test_claude_code_is_started_with_the_portal_setting_as_it_was(tmp_path, monkeypatch):
    env = _started_claude_code(tmp_path, monkeypatch, before="1")
    assert env["GTK_USE_PORTAL"] == "1"
    assert "APPIMAGE" not in env and "CLAUDECODE" not in env
    assert env["CLAUDE_CODE_ENTRYPOINT"] == "sdk-py" and env["CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS"] == "1"
    assert env["CLAUDE_CODE_SDK_READS_SESSION_STATE"] == "1" and env["CLAUDE_AGENT_SDK_VERSION"]


def test_a_portal_setting_the_desktop_never_made_is_not_there_at_all(tmp_path, monkeypatch):
    """Unset, not empty: GTK reads GTK_USE_PORTAL="" as on."""
    assert "GTK_USE_PORTAL" not in _started_claude_code(tmp_path, monkeypatch, before=None)


def test_the_bridge_starts_claude_code_through_that_transport(tmp_path, monkeypatch):
    import claude_agent_sdk

    from davibemanager.builder.cli_transport import HostEnvironmentTransport

    made = []

    class Client:
        def __init__(self, options, transport=None):
            made.append((options, transport))

        async def connect(self):
            pass

        async def receive_messages(self):
            await asyncio.Event().wait()
            yield

        async def disconnect(self):
            pass

    monkeypatch.setattr(claude_agent_sdk, "ClaudeSDKClient", Client)
    monkeypatch.setattr(bridge, "write_wrapper", lambda path, container: path)
    session = bridge.BuilderSession(container="c", wrapper=tmp_path / "claude", host=None, env=dict,
                                    emit=lambda *a, **k: None, on_session=print, on_change=print, on_turn_end=print)

    async def run():
        await session.connect()
        await session.close()

    asyncio.run(run())
    [(options, transport)] = made
    assert isinstance(transport, HostEnvironmentTransport) and transport._options is options
    assert options.cli_path == str(tmp_path / "claude")
