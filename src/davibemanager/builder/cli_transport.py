"""Claude Code started with the environment as it was before this app changed its own.

claude-agent-sdk starts the `claude` it is given (here the wrapper, bridge.write_wrapper, which runs
`podman exec`) with this process's own environment, os.environ, and ClaudeAgentOptions.env over it. So
podman, and what it started, got what DA Vibe Manager set for itself alone (hostenv.set_for_self:
GTK_USE_PORTAL=0, which the portal's refusal of an undumpable process asks of the app's own GTK, and
GI_TYPELIB_PATH) and the AppImage's own variables, where every other program the app starts gets
hostenv.host_env() (the DA apps' security standard, "Files and processes", Nov 2026; seen on all four lab
VMs with the portal forced). ClaudeAgentOptions.env can only add: it can't take a variable away, and an
empty GTK_USE_PORTAL isn't an unset one (GTK reads "" as on).

So the SDK is given a transport of our own (ClaudeSDKClient's `transport=`): its SubprocessCLITransport,
the CLI started as its connect() starts it, on host_env() where it reads os.environ. Its version probe
(`claude -v`, started with this process's own environment, no env= at all) is left out: the CLI in the
sandbox is the one bundled with this very SDK (podman.build_image checks its sha256 against
pins.CLAUDE_SHA256, and the image's tag carries pins.py), so it is never older than the SDK asks.

connect() follows claude-agent-sdk 0.2.164's own line for line but for those two things;
tests/test_child_environment.py fails when the pinned SDK's connect() changes, so a bump reads it again.
The options it reproduces are the ones the bridge uses: no can_use_tool (the SDK would add
--permission-prompt-tool), no session_store (the SDK would copy the session into a folder of its own
first); either is refused rather than started differently from the SDK.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from subprocess import PIPE
from typing import Any

import anyio
from anyio.streams.text import TextReceiveStream, TextSendStream
from claude_agent_sdk import ClaudeAgentOptions, CLIConnectionError, CLINotFoundError
from claude_agent_sdk._internal._task_compat import spawn_detached
from claude_agent_sdk._internal.transport.subprocess_cli import (
    _ACTIVE_CHILDREN,
    _SDK_READS_SESSION_STATE_ENV,
    SubprocessCLITransport,
)
from claude_agent_sdk._version import __version__

from ..hostenv import host_env


async def _no_prompt() -> AsyncIterator[dict[str, Any]]:
    """ClaudeSDKClient's own stand-in when it connects with no prompt: the prompt goes by write()."""
    return
    yield {}  # never reached: it makes this an async generator


def cli_environment(options: ClaudeAgentOptions, cwd: str | None) -> dict[str, str]:
    """The CLI's environment as the SDK's connect() builds it, on host_env() instead of os.environ."""
    inherited_env = {k: v for k, v in host_env().items() if k != "CLAUDECODE"}
    process_env = {
        **inherited_env,
        "CLAUDE_CODE_ENTRYPOINT": "sdk-py",
        **options.env,
        "CLAUDE_AGENT_SDK_VERSION": __version__,
    }
    # the active OTEL trace context, as the SDK passes it (a no-op without a span)
    try:
        from opentelemetry import propagate

        carrier: dict[str, str] = {}
        propagate.inject(carrier)
        if "traceparent" in carrier:
            for key in ("TRACEPARENT", "TRACESTATE"):
                if key not in options.env:
                    process_env.pop(key, None)
            for k, v in carrier.items():
                key = k.upper()
                if key not in options.env:
                    process_env[key] = v
    except Exception:  # noqa: BLE001 - best-effort tracing, as the SDK's, never stops the CLI starting
        pass
    if not any(key.upper() == _SDK_READS_SESSION_STATE_ENV for key in process_env):
        process_env[_SDK_READS_SESSION_STATE_ENV] = "1"
    if options.enable_file_checkpointing:
        process_env["CLAUDE_CODE_ENABLE_SDK_FILE_CHECKPOINTING"] = "true"
    if cwd:
        process_env["PWD"] = cwd
    return process_env


class HostEnvironmentTransport(SubprocessCLITransport):
    """The SDK's subprocess transport, its CLI given hostenv.host_env() (see the module's docstring)."""

    def __init__(self, options: ClaudeAgentOptions):
        if options.can_use_tool is not None or options.session_store is not None:
            raise ValueError("The assistant's transport starts Claude Code as the SDK does only without "
                             "can_use_tool and session_store.")
        super().__init__(prompt=_no_prompt(), options=options)

    async def connect(self) -> None:
        if self._process:
            return
        if self._cli_path is None:
            self._cli_path = await anyio.to_thread.run_sync(self._find_cli)
        self._reject_windows_batch_cli(self._cli_path)
        # no version probe: see the module's docstring
        cmd = self._build_command()
        try:
            process_env = cli_environment(self._options, self._cwd)
            stderr_dest = PIPE if self._options.stderr is not None else None
            self._process = await anyio.open_process(
                cmd, stdin=PIPE, stdout=PIPE, stderr=stderr_dest, cwd=self._cwd, env=process_env,
                user=self._options.user)
            _ACTIVE_CHILDREN.add(self._process)
            if self._process.stdout:
                self._stdout_stream = TextReceiveStream(self._process.stdout)
            if stderr_dest is PIPE and self._process.stderr:
                self._stderr_stream = TextReceiveStream(self._process.stderr)
                self._stderr_task = spawn_detached(self._handle_stderr())
            if self._process.stdin:
                self._stdin_stream = TextSendStream(self._process.stdin)
            self._ready = True
        except FileNotFoundError as e:
            if self._cwd and not Path(self._cwd).exists():
                error = CLIConnectionError(f"Working directory does not exist: {self._cwd}")
                self._exit_error = error
                raise error from e
            error = CLINotFoundError(f"Claude Code not found at: {self._cli_path}")
            self._exit_error = error
            raise error from e
        except Exception as e:
            error = CLIConnectionError(f"Failed to start Claude Code: {e}")
            self._exit_error = error
            raise error from e
