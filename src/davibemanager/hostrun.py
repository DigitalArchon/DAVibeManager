"""Commands the AI asks to run on this computer.

Nothing here runs by itself: a HostRequest is shown to the user, who may edit it, get a second
opinion, run it or refuse. Running it is non-interactive (no stdin), bounded in time and output,
and in the user's own environment; root goes through pkexec, so the desktop asks for the
password and the app never sees it. What the command printed is then shown to the user,
redacted, and (by default) goes to the AI only when they send it.
"""

from __future__ import annotations

import asyncio
import os
import signal
import time
from dataclasses import asdict, dataclass, field, fields

from .hostenv import host_env
from .safety import hidden, risk
from .safety.sensitive import sensitive

MAX_OUTPUT = 2 * 1024 * 1024        # bytes read from a command; the rest is dropped
DEFAULT_TIMEOUT, MAX_TIMEOUT = 120, 1800
# seconds a stopped command may take to end: root's side of it (after its pipe is closed), then after signals
STOP_GRACE, STOP_WAIT = 5, 10
# pending -> running -> done -> sent | withheld; pending -> declined; anything open -> cancelled
STATUSES = ("pending", "running", "done", "sent", "withheld", "declined", "cancelled", "failed")
OPEN = ("pending", "running", "done")


@dataclass
class HostRequest:
    id: int
    command: str
    purpose: str
    model_risk: str
    risk: str = "modifying"
    risk_reasons: list[str] = field(default_factory=list)
    rollback: str = ""
    as_root: bool = False
    timeout: int = DEFAULT_TIMEOUT
    original_command: str = ""
    sensitive: list[str] = field(default_factory=list)   # local rules: may expose secrets or private data
    hidden: list[str] = field(default_factory=list)      # invisible characters taken out of the command
    status: str = "pending"
    created: float = field(default_factory=time.time)
    ran_at: float | None = None
    exit_code: int | None = None
    timed_out: bool = False
    still_running: bool = False   # it didn't end when stopped (an administrator's may go on)
    seconds: float | None = None
    output: str = ""        # what the command printed (kept on this computer)
    preview: str = ""       # the same, redacted and cut: what the AI would get
    redactions: int = 0
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)    # text in the output that looks aimed at an AI
    sent_text: str = ""     # what was actually sent
    note: str = ""          # the user's words with their decision
    review: dict = field(default_factory=dict)
    detached: bool = False  # the AI stopped waiting; the answer goes as a message instead

    @classmethod
    def create(cls, num: int, raw: dict) -> "HostRequest":
        command, removed = hidden.clean(str(raw.get("command", "")))
        command = command.strip()
        if not command:
            raise ValueError("no command given")
        if command.startswith(("sudo ", "sudo\t")) or command in ("sudo",):
            raise ValueError("don't use sudo: set as_root instead (the desktop asks for the password)")
        r = cls(id=num, command=command, purpose=str(raw.get("purpose", "")).strip()[:500],
                model_risk=str(raw.get("risk", "modifying")), rollback=str(raw.get("rollback", "") or "").strip()[:1000],
                as_root=bool(raw.get("as_root")), original_command=command, hidden=removed,
                timeout=_timeout(raw.get("timeout")))
        r.classify()
        return r

    @classmethod
    def from_dict(cls, d: dict) -> "HostRequest":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known})

    def classify(self) -> None:
        self.risk, self.risk_reasons = risk.effective(self.model_risk, self.command)
        if self.as_root and self.risk == "read_only":
            self.risk_reasons = self.risk_reasons + ["runs as administrator"]
        self.sensitive = sensitive(self.command)

    def edit(self, command: str) -> None:
        if self.status != "pending":
            raise ValueError("only a command that hasn't run can be changed")
        command, removed = hidden.clean(command)
        if not command.strip():
            raise ValueError("the command is empty")
        self.command = command.strip()
        if removed:
            self.hidden = removed
        self.review = {}
        self.classify()

    @property
    def edited(self) -> bool:
        return self.command != self.original_command

    @property
    def unconfirmed(self) -> bool:
        """The AI called it read-only and nothing in the local rules says otherwise, but they don't
        know it as a command that only reads (risk.UNKNOWN): it is shown as a change, and what the
        card says of it is that, not that a change came without a way to undo it."""
        return self.model_risk == "read_only" and self.risk_reasons == [risk.UNKNOWN]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["edited"] = self.edited
        d["unconfirmed"] = self.unconfirmed
        if len(d["output"]) > 200_000:
            d["output"] = d["output"][:100_000] + "\n…\n" + d["output"][-100_000:]
        return d


def _timeout(value) -> int:
    try:
        return max(5, min(MAX_TIMEOUT, int(value)))
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT


@dataclass
class RunResult:
    exit_code: int | None
    output: str
    timed_out: bool
    seconds: float
    still_running: bool = False     # it didn't end when stopped (and may go on)


# How a command runs as administrator. pkexec turns into the program it runs, as root, so this app
# can't signal it (or anything it starts) any more: stopping it, or its time limit, would do nothing.
# So root's side stops it itself: the command runs in a process group of its own, and a watcher
# ends that group when this app closes its end of a pipe (the wrapper's stdin), which it does to
# stop it, and which also happens if this app ends. Once it runs as root (the password given), it says
# so (ROOT_RUNNING): the command's time limit starts there, not while the password is asked for. And
# if this app gave up meanwhile (stopped, or out of time: its pipe is closed), nothing is started.
ROOT_RUNNING = b"@@dvm-root-running\n"
ROOT_WRAPPER = r"""
exec 3<&0 </dev/null
if read -t 0 -u 3; then exit 125; fi
printf '@@dvm-root-running\n'
setsid /bin/bash -c "$1" 3<&- &
pid=$!
( read -r _ <&3; kill -s TERM -- "-$pid" 2>/dev/null; sleep 3; kill -s KILL -- "-$pid" 2>/dev/null ) >/dev/null 2>&1 &
watcher=$!
exec 3<&-
wait "$pid"
rc=$?
kill "$watcher" 2>/dev/null
exit "$rc"
"""


PROMPT_TIMEOUT = 10 * 60            # how long the password may take, before the command's own time limit
# Something a command starts in the background (`app &`) keeps its output open after it ends: that
# isn't the command still running. Its output is read for a moment longer, then the result is in;
# what's left running goes on (what it prints is still read, and dropped, so it isn't stopped by that).
LEFT_OPEN = 2
LEFT_NOTE = ("\n[It left something running in the background that still has this output open: "
             "what that prints from here on isn't shown.]")
_left: set[asyncio.Task] = set()     # those readers, until what they read from ends


def argv_for(command: str, as_root: bool) -> list[str]:
    return ["pkexec", "/bin/bash", "-c", ROOT_WRAPPER, "sh", command] if as_root else ["/bin/bash", "-c", command]


async def run(command: str, *, as_root: bool = False, timeout: float = DEFAULT_TIMEOUT,
              cancel: asyncio.Event | None = None, argv: list[str] | None = None) -> RunResult:
    """Run one command without a terminal; stops it (its whole process group) on timeout or cancel.
    `argv`: how it is started (tests), else argv_for."""
    started = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *(argv or argv_for(command, as_root)),
        stdin=asyncio.subprocess.PIPE if as_root else asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT, env=host_env(), cwd=os.path.expanduser("~"), start_new_session=True)
    chunks: list[bytes] = []
    size = 0
    running = asyncio.Event()           # as root: the password was given, the command runs
    if not as_root:
        running.set()

    left_open = False

    def keep(chunk: bytes) -> None:
        nonlocal size
        if left_open:
            return
        if size < MAX_OUTPUT:
            chunks.append(chunk[:MAX_OUTPUT - size])
        size += len(chunk)

    async def drain():
        pending = b""                   # before root's side says it runs: pkexec's own words, or that
        while chunk := await proc.stdout.read(65536):
            if not running.is_set():
                pending += chunk
                if ROOT_RUNNING not in pending:
                    continue
                before, _, chunk = pending.partition(ROOT_RUNNING)
                pending = b""
                keep(before)
                running.set()
            keep(chunk)
        keep(pending)

    async def read():
        # to the end of its output, or until a moment after the command itself ended (LEFT_OPEN)
        nonlocal left_open
        draining = asyncio.ensure_future(drain())
        try:
            while not draining.done() and proc.returncode is None:
                await asyncio.wait([draining], timeout=0.25)
            if not draining.done():
                await asyncio.wait([draining], timeout=LEFT_OPEN)
        except BaseException:
            draining.cancel()
            raise
        if not draining.done():
            left_open = True
            _left.add(draining)
            draining.add_done_callback(lambda t: (_left.discard(t), t.cancelled() or t.exception()))
            return
        draining.result()
        await proc.wait()

    reader = asyncio.ensure_future(read())
    waits = [reader] + ([asyncio.ensure_future(cancel.wait())] if cancel else [])
    timed_out = still_running = False
    try:
        if not running.is_set():
            # the password is asked for first: that time isn't the command's
            asked = asyncio.ensure_future(running.wait())
            first, _ = await asyncio.wait([asked, *waits], timeout=PROMPT_TIMEOUT, return_when=asyncio.FIRST_COMPLETED)
            asked.cancel()
            # ended there (refused, the dialog closed), stopped, or nobody gave the password in time: as below
            done = None if asked in first and reader not in first else first - {asked}
        else:
            done = None
        if done is None:
            done, _ = await asyncio.wait(waits, timeout=min(max(timeout, 1), MAX_TIMEOUT), return_when=asyncio.FIRST_COMPLETED)
        if reader not in done:
            timed_out = cancel is None or not cancel.is_set()
            still_running = not await _stop(proc, reader)
    finally:
        for w in waits[1:]:
            w.cancel()
        if proc.returncode is None:
            _close(proc)
            _signal(proc)
        if not reader.done():
            reader.cancel()
    text = b"".join(chunks).decode("utf-8", errors="replace")
    if size > MAX_OUTPUT:
        text += f"\n[… {size - MAX_OUTPUT} more bytes not kept]"
    if left_open:
        text += LEFT_NOTE
    return RunResult(None if timed_out or still_running else proc.returncode, text, timed_out,
                     round(time.monotonic() - started, 2), still_running)


async def _stop(proc, reader: asyncio.Future) -> bool:
    """Stop a command; whether it ended. An administrator's is stopped by root's side of it, when
    its pipe is closed (ROOT_WRAPPER); this app signals only what is its own: all of an ordinary
    command, or pkexec while it still asks for the password."""
    async def ended(seconds: float) -> bool:
        try:
            await asyncio.wait_for(asyncio.shield(reader), seconds)
            return True
        except asyncio.TimeoutError:
            return False
    if proc.stdin is not None:
        _close(proc)
        if await ended(STOP_GRACE):
            return True
    _signal(proc)
    return await ended(STOP_WAIT)


def _close(proc) -> None:
    if proc.stdin is not None and not proc.stdin.is_closing():
        proc.stdin.close()


def _signal(proc) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
