"""The assistant: Claude Code running in the sandbox container, driven from here.

claude-agent-sdk normally starts the `claude` binary on this machine. Its `cli_path` points at
a generated wrapper instead, which runs `podman exec -i` into the container, so the CLI's stdio
(the SDK's whole protocol: prompts, messages, permission checks and the in-process "host" MCP
tools of builder/tools.py) is the only channel between the container and this app.

The SDK hands its child the whole environment of this process; the wrapper passes only the
variables named in FORWARD into the container, so nothing else of the user's environment gets in.

A turn's chat entry is an ordered list of parts: text, the model's thinking, groups of steps in
the sandbox, the cards the host tools add (requests to run something here, questions,
screenshots, deliveries), and what the user wrote while it worked.

A result from the CLI ends one of its turns, not its work: a message the user wrote late in a turn
gets a turn of its own straight after, and something left running in the background wakes it for
another when it finishes. The CLI's session state says when it has really stopped ("idle"), and
an entry stays open until then; a turn the CLI starts by itself after that gets an entry of its own.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import time
from pathlib import Path
from typing import Callable

from ..llm.prompts import builder_prompt
from ..workspace import podman
from .tools import BuilderHost, make_server, tool_names

# set by the SDK, or by us below, and needed by the CLI in the container
FORWARD = (
    "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_AGENT_SDK_VERSION", "CLAUDE_CODE_SDK_READS_SESSION_STATE",
    "CLAUDE_CODE_ENABLE_SDK_FILE_CHECKPOINTING", "CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS",
    "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL", "ANTHROPIC_SMALL_FAST_MODEL", "CLAUDE_CODE_SUBAGENT_MODEL", "MCP_TOOL_TIMEOUT",
    "CLAUDE_CODE_AUTO_BACKGROUND_TIMEOUT_MS", "BASH_DEFAULT_TIMEOUT_MS",
)
# A command still running after a minute (a build, a compile) goes on in the background by itself, so
# its turn can end and the user can talk with the assistant meanwhile; it is woken when the command
# finishes. A command run in the background may take two hours (Claude Code's own limit for one it
# moved is the default timeout, 30 minutes unless raised; plain sleeps are never moved).
AUTO_BACKGROUND_MS = 60_000
BACKGROUND_LIMIT_MS = 2 * 60 * 60 * 1000
# what each kind of tool call is summarised by in the steps list
_SUMMARY_KEYS = {"Bash": "command", "Read": "file_path", "Write": "file_path", "Edit": "file_path",
                 "MultiEdit": "file_path", "NotebookEdit": "notebook_path", "Glob": "pattern", "Grep": "pattern",
                 "WebFetch": "url", "WebSearch": "query", "mcp__host__web_search": "query", "Task": "description", "Agent": "description"}
# host tools show as their own cards, not as steps
CARD_TOOLS = {"mcp__host__ask_user", "mcp__host__offer_build", "mcp__host__request_host_command", "mcp__host__show_screenshot",
              "mcp__host__deliver"}


# Models that think before acting (Opus) sometimes put their whole answer in their thinking and go
# on to tool calls, or end the turn, without a word the user can see. Said once per turn.
NO_MESSAGE_NUDGE = (
    "[DA Vibe Manager] Your turn ended, but since your last {since} you wrote nothing the user can see "
    "({done}). Your thinking shows only as faint notes, and your steps only as a compact list. Write your "
    "message to them now: what you found or did, the answer to anything they asked, and what happens "
    "next. Everything above is already done; do not do it again.")


# ... and sometimes ask the user something in their message alone, with nothing to tap
QUESTION_NUDGE = (
    "[DA Vibe Manager] Your message asks the user something, but there's nothing for them to tap. Call "
    "ask_user now with the question(s) from your message, each with short quick replies (e.g. \"Yes, build "
    "it\" / \"No thanks\"); don't write your message again. If you weren't asking them anything, end your turn.")


def asks_in_text(entry: dict) -> bool:
    """Whether the turn ends on a message that asks the user something (a line ending in "?")."""
    shown = [p for p in entry["parts"] if p["t"] != "thinking"]
    if not shown or shown[-1]["t"] != "text":
        return False
    tail = shown[-1]["text"][-800:].splitlines()
    return any(line.strip().rstrip(" *_`)\"'").endswith("?") for line in tail)


def told_user(entry: dict) -> bool:
    """Whether the last thing in the chat for this turn (thinking aside) is a message to the user."""
    shown = [p for p in entry["parts"] if p["t"] != "thinking"]
    return bool(shown) and shown[-1]["t"] == "text"


def turn_summary(entry: dict) -> tuple[str, str]:
    """What this turn did, in the nudge's words: (what came last, what was done)."""
    done = []
    steps = sum(len(p["items"]) for p in entry["parts"] if p["t"] == "steps")
    if steps:
        done.append(f"{steps} step{'s' if steps > 1 else ''} in your sandbox")
    for kind, words in (("request", "asked to run a command on their computer"), ("question", "asked a question"),
                        ("screenshot", "showed a screenshot"), ("delivery", "delivered a build")):
        if any(p["t"] == kind for p in entry["parts"]):
            done.append(words)
    last = next((p["t"] for p in reversed(entry["parts"]) if p["t"] != "thinking"), "")
    since = {"steps": "step", "request": "command", "question": "question", "screenshot": "screenshot",
             "delivery": "delivery"}.get(last, "message from the user")
    return since, "; ".join(done) or "only thinking"


def write_wrapper(path: Path, container: str) -> Path:
    """The `claude` the SDK starts: podman exec into the container, passing only FORWARD."""
    lines = ["#!/bin/sh", "# Generated by DA Vibe Manager: runs Claude Code in the sandbox container.", 'E=""']
    for name in FORWARD:
        lines.append(f'[ -n "${{{name}+x}}" ] && E="$E -e {name}"')
    lines.append(f"exec {shlex.quote(podman.podman())} exec -i --detach-keys= -w /work $E {shlex.quote(container)} "
                 '/usr/local/bin/claude "$@"')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(".tmp")
    tmp.write_text("\n".join(lines) + "\n")
    os.chmod(tmp, 0o700)
    tmp.replace(path)
    return path


def summarize_tool(name: str, data: dict) -> str:
    if name == "mcp__host__install_packages":
        return " ".join(map(str, data.get("packages") or []))[:300]
    key = _SUMMARY_KEYS.get(name)
    if key and data.get(key):
        return str(data[key]).replace("\n", " ⏎ ")[:300]
    if name == "TodoWrite":
        todos = data.get("todos") or []
        active = next((t.get("activeForm") or t.get("content") for t in todos if t.get("status") == "in_progress"), "")
        return str(active)[:300]
    return ""


def _result_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(c.get("text", "")) for c in content if isinstance(c, dict))
    return ""


class BuilderSession:
    """One conversation's Claude Code session. `emit(type, **data)` reaches the UI; `on_change`
    is called with the entry whenever it changes, `on_turn_end` with the finished entry."""

    def __init__(self, *, container: str, wrapper: Path, host: BuilderHost, env: Callable[[], dict[str, str]],
                 resume: str = "", emit: Callable[..., None], on_session: Callable[[str], None],
                 on_change: Callable[[dict], None], on_turn_end: Callable[[dict], None],
                 on_wake: Callable[[], dict] | None = None, client_factory: Callable | None = None,
                 mode: str = "computer"):
        self.container = container
        self.mode = mode                           # the kind of chat: "computer" or "app" (its prompt and tools)
        self.wrapper = wrapper
        self.host = host
        self._env = env
        self.session_id = resume
        self._emit = emit
        self._on_session = on_session
        self._on_change = on_change
        self._on_turn_end = on_turn_end
        self._on_wake = on_wake                    # -> the entry for a turn the CLI started by itself
        self._client_factory = client_factory      # tests: (options) -> a ClaudeSDKClient look-alike
        self._client = None
        self._reader: asyncio.Task | None = None
        self.entry: dict | None = None             # the chat entry of the turn in progress
        self._tools: dict[str, dict] = {}          # tool_use id -> its step record
        # Claude Code's tasks still running: a command after its first few seconds, or work in the
        # background; id -> {description, since, background}. Their output is in the sandbox meanwhile.
        self.tasks: dict[str, dict] = {}
        self._state: str | None = None             # the CLI's session state: running, idle (None: not told)
        self._ended: list = []                     # [error] of the latest result, until the CLI is idle
        self.stderr_tail: list[str] = []

    @property
    def busy(self) -> bool:
        return self.entry is not None

    async def _before_fetch(self, data: dict, tool_use_id: str | None, context) -> dict:
        """WebFetch's address is checked here, in the app, before Claude Code reads the page: nothing
        from the user's computer may leave in it (a denial holds whatever the permission mode)."""
        reason = self.host.builder_fetch_check(str((data.get("tool_input") or {}).get("url", "")))
        if not reason:
            return {}
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": reason}}

    def _options(self):
        from claude_agent_sdk import ClaudeAgentOptions, HookMatcher
        return ClaudeAgentOptions(
            cli_path=str(self.wrapper),
            system_prompt={"type": "preset", "preset": "claude_code", "append": builder_prompt(self.mode)},
            # the container is the sandbox: everything in it is the assistant's to use
            permission_mode="bypassPermissions",
            mcp_servers={"host": make_server(self.host, self.mode)},
            allowed_tools=tool_names(self.mode),
            resume=self.session_id or None,
            include_partial_messages=True,
            # a message carrying an image the assistant looked at is easily over the SDK's 1 MB default
            max_buffer_size=64 * 1024 * 1024,
            # session_state_changed: when the CLI has nothing more to do (see the module's docstring)
            env={**self._env(), "CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS": "1",
                 "CLAUDE_CODE_AUTO_BACKGROUND_TIMEOUT_MS": str(AUTO_BACKGROUND_MS),
                 "BASH_DEFAULT_TIMEOUT_MS": str(BACKGROUND_LIMIT_MS)},
            stderr=self._stderr,
            # the user's patches carry no attribution lines of Claude Code's own (as JSON: a settings
            # file would be a path on this computer, not in the sandbox)
            # and WebFetch doesn't tell Anthropic each site it reads (its blocklist check)
            settings=json.dumps({"includeCoAuthoredBy": False, "attribution": {"commit": "", "pr": ""},
                                 "skipWebFetchPreflight": True}),
            # Anthropic's server-side search: nothing comes back through NanoGPT (web_search instead)
            disallowed_tools=["WebSearch"],
            hooks={"PreToolUse": [HookMatcher(matcher="WebFetch", hooks=[self._before_fetch])]},
        )

    def _stderr(self, line: str) -> None:
        self.stderr_tail = (self.stderr_tail + [line])[-40:]

    async def connect(self) -> None:
        if self._client is not None:
            return
        write_wrapper(self.wrapper, self.container)
        if self._client_factory:
            client = self._client_factory(self._options())
        else:
            from claude_agent_sdk import ClaudeSDKClient
            client = ClaudeSDKClient(self._options())
        try:
            await client.connect()
        except Exception as e:
            detail = "\n".join(self.stderr_tail[-8:])
            raise RuntimeError(f"Could not start the assistant in its sandbox: {e}" + (f"\n{detail}" if detail else "")) from e
        self._client = client
        self._reader = asyncio.create_task(self._read())

    async def send(self, text: str, entry: dict) -> None:
        """Start a turn with this user message; `entry` is the chat entry it will fill."""
        if self.busy:
            raise RuntimeError("The assistant is still working.")
        await self.connect()
        self.entry = entry
        self._tools = {}
        self._ended = []
        try:
            await self._client.query(text)
        except Exception:
            self.entry = None
            raise

    async def interject(self, text: str) -> None:
        """A message for the assistant while it works: the CLI hands it over with its next tool
        result, or in a turn of its own straight after (which wakes an entry if this one has ended)."""
        if self._client is None:
            raise RuntimeError("The assistant has stopped.")
        await self._client.query(text)

    async def interrupt(self) -> None:
        if self._client is not None and self.busy:
            await self._client.interrupt()

    async def close(self) -> None:
        client, self._client = self._client, None
        self.tasks = {}
        if self._reader:
            self._reader.cancel()
            self._reader = None
        if client is not None:
            try:
                await asyncio.wait_for(client.disconnect(), 10)
            except Exception:  # noqa: BLE001 - closing anyway
                pass
        if self.entry is not None:
            self._finish(error="the assistant was stopped")

    @staticmethod
    def _text(entry: dict, text: str) -> None:
        last = entry["parts"][-1] if entry["parts"] else None
        if last and last["t"] == "text":
            last["text"] = (last["text"] + "\n\n" + text).strip()
        else:
            entry["parts"].append({"t": "text", "text": text})

    @staticmethod
    def _thinking(entry: dict, text: str) -> None:
        last = entry["parts"][-1] if entry["parts"] else None
        if last and last["t"] == "thinking":
            last["text"] = (last["text"] + "\n\n" + text).strip()
        else:
            entry["parts"].append({"t": "thinking", "text": text})

    @staticmethod
    def _step(entry: dict, rec: dict) -> None:
        last = entry["parts"][-1] if entry["parts"] else None
        if last and last["t"] == "steps":
            last["items"].append(rec)
        else:
            entry["parts"].append({"t": "steps", "items": [rec]})

    async def _read(self) -> None:
        from claude_agent_sdk import (TERMINAL_TASK_STATUSES, AssistantMessage, ResultMessage, StreamEvent,
                                      SystemMessage, TextBlock, ThinkingBlock, ToolResultBlock, ToolUseBlock, UserMessage)
        try:
            async for msg in self._client.receive_messages():
                entry = self.entry
                if isinstance(msg, SystemMessage):
                    data = msg.data if isinstance(msg.data, dict) else {}
                    sid = data.get("session_id")
                    if msg.subtype == "init" and sid and sid != self.session_id:
                        self.session_id = sid
                        self._on_session(sid)
                    elif msg.subtype == "session_state_changed":
                        self._state = data.get("state")
                        if self._state == "running" and entry is None and self._on_wake:
                            # e.g. a build it left running in the background has finished
                            self.entry, self._tools, self._ended = self._on_wake(), {}, []
                        elif self._state == "idle" and self._ended and entry is not None:
                            await self._settle()
                    elif msg.subtype == "task_started" and data.get("task_id"):
                        rec = self._tools.get(data.get("tool_use_id") or "")
                        self.tasks[str(data["task_id"])] = {
                            "description": str(data.get("description") or (rec or {}).get("summary") or "")[:200],
                            "since": time.time(),
                            "background": bool((rec or {}).get("background")) or data.get("task_type") == "local_agent"}
                    elif msg.subtype in ("task_notification", "task_updated"):
                        status = data.get("status") or (data.get("patch") or {}).get("status")
                        if status in TERMINAL_TASK_STATUSES:
                            self.tasks.pop(str(data.get("task_id")), None)
                    elif msg.subtype == "api_retry" and entry is not None:
                        # the CLI is retrying a failed model request (it tries ten times, for minutes)
                        entry["retry"] = {"attempt": data.get("attempt"), "max": data.get("max_retries"),
                                          "status": data.get("error_status"), "error": data.get("error")}
                        self._on_change(entry)
                    continue
                if entry is None and self._state == "running" and self._on_wake \
                        and isinstance(msg, (AssistantMessage, StreamEvent)) and not msg.parent_tool_use_id:
                    # it went on by itself without saying "running" again (e.g. after the user stopped it)
                    entry = self.entry = self._on_wake()
                    self._tools, self._ended = {}, []
                if entry is None:
                    continue                        # nothing of ours is in progress
                if isinstance(msg, StreamEvent):
                    ev = msg.event or {}
                    delta = ev.get("delta") or {}
                    if msg.parent_tool_use_id:
                        continue                    # a subagent's stream: its steps show instead
                    if ev.get("type") == "content_block_delta" and delta.get("type") == "text_delta":
                        self._emit("delta", kind="text", text=delta.get("text", ""))
                    elif ev.get("type") == "content_block_delta" and delta.get("type") == "thinking_delta":
                        self._emit("delta", kind="thinking", text="")
                    continue
                if isinstance(msg, AssistantMessage):
                    entry.pop("retry", None)
                    if msg.error:
                        entry.setdefault("errors", []).append(str(msg.error))
                    for block in msg.content:
                        if isinstance(block, TextBlock) and not msg.parent_tool_use_id and block.text.strip():
                            self._text(entry, block.text)
                        elif isinstance(block, ThinkingBlock) and not msg.parent_tool_use_id and block.thinking.strip():
                            self._thinking(entry, block.thinking)
                        elif isinstance(block, ToolUseBlock) and block.name not in CARD_TOOLS:
                            rec = {"id": block.id, "tool": block.name, "summary": summarize_tool(block.name, block.input or {}),
                                   "status": "running", "at": time.time(), **({"sub": True} if msg.parent_tool_use_id else {}),
                                   **({"background": True} if (block.input or {}).get("run_in_background") else {})}
                            self._tools[block.id] = rec
                            self._step(entry, rec)
                    entry["model"] = msg.model or entry.get("model", "")
                    self._on_change(entry)
                elif isinstance(msg, UserMessage) and isinstance(msg.content, list):
                    changed = False
                    for block in msg.content:
                        if isinstance(block, ToolResultBlock) and block.tool_use_id in self._tools:
                            rec = self._tools[block.tool_use_id]
                            rec["status"] = "error" if block.is_error else "done"
                            rec["output"] = _result_text(block.content)[-1500:]
                            changed = True
                    if changed:
                        self._on_change(entry)
                elif isinstance(msg, ResultMessage):
                    if msg.session_id and msg.session_id != self.session_id:
                        self.session_id = msg.session_id
                        self._on_session(msg.session_id)
                    # not msg.total_cost_usd: Claude Code prices every model as Claude, and its figure adds
                    # up over the session; the gateway counts the tokens instead (Engine.spend)
                    entry["usage"] = msg.usage
                    error = None
                    if msg.terminal_reason in ("aborted_streaming", "aborted_tools"):
                        error = "stopped"
                    elif msg.is_error:
                        error = "; ".join(msg.errors or []) or (msg.result or "") or msg.subtype
                    self._ended = [error]
                    # more to come while it's running (the user stopping it is the end, whatever runs on)
                    if self._state in (None, "idle") or error == "stopped":
                        await self._settle()
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 - the CLI went away; say so and let the next send reconnect
            detail = "\n".join(self.stderr_tail[-6:])
            self._client, self.tasks = None, {}
            if self.entry is not None:
                self._finish(error=f"the assistant stopped unexpectedly: {e}" + (f"\n{detail}" if detail else ""))

    async def _settle(self) -> None:
        """The CLI is done: end the entry, or first ask for the message or question card it lacks."""
        entry, (error,) = self.entry, self._ended
        self._ended = []
        if error is None and not told_user(entry) and not entry.get("nudged"):
            since, done = turn_summary(entry)
            entry["nudged"] = True
            self._emit("nudged", kind="no_message", since=since, done=done)
            await self._client.query(NO_MESSAGE_NUDGE.format(since=since, done=done))
            return                          # the same entry goes on, for its message
        # twice an entry at most, and never twice for the same message
        if error is None and asks_in_text(entry) and len(entry.setdefault("carded", [])) < 2 \
                and len(entry["parts"]) not in entry["carded"]:
            entry["carded"].append(len(entry["parts"]))
            self._emit("nudged", kind="question_in_text")
            await self._client.query(QUESTION_NUDGE)
            return                          # ... or for its question card
        self._finish(error=error)

    def _finish(self, error: str | None) -> None:
        entry, self.entry = self.entry, None
        if entry is None:
            return
        for part in entry["parts"]:
            for rec in part.get("items", []):
                if rec["status"] == "running":
                    rec["status"] = "stopped" if error else "done"
        if error:
            entry["error"] = error
        self._on_turn_end(entry)
