"""The app's own tor: run only while sync needs it, and gone with the app.

Tor runs with a data folder of its own ($XDG_STATE_HOME/davibemanager/tor), its own torrc and an
empty defaults file, so the system's /etc/tor/torrc is never read and a system tor, if there is
one, is never touched. Its control port and SOCKS port are unix sockets in the app's runtime
folder (0700). The SOCKS port only goes to onion services (OnionTrafficOnly: it's no proxy for
anything else) and says why one can't be reached (ExtendedErrors). It exits when the app does:
__OwningControllerProcess, and TAKEOWNERSHIP once the app is logged in. Its onion services
aren't detached, so none outlives the control connection either.

The tor run is the AppImage's own (the Tor Expert Bundle's, in usr/lib/tor: AppRun sets DVM_TOR),
else one on PATH. It's given its own folder as its library path and nothing else of the app's
environment.

The control protocol, as much of it as sync speaks (tor's control-spec.txt), after SealedLore's:
PROTOCOLINFO, AUTHCHALLENGE SAFECOOKIE and AUTHENTICATE (the cookie is never sent, and tor proves
it read it), TAKEOWNERSHIP, SETEVENTS, GETINFO status/bootstrap-phase, ADD_ONION and DEL_ONION,
ONION_CLIENT_AUTH_ADD and ONION_CLIENT_AUTH_REMOVE.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import re
import secrets
import shutil
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import onion as onion_mod
from . import wire

SERVER_TO_CONTROLLER = b"Tor safe cookie authentication server-to-controller hash"
CONTROLLER_TO_SERVER = b"Tor safe cookie authentication controller-to-server hash"
SOCKET_PATH_MOST = 100              # under the 107 bytes a unix socket's path may have
CONTROL_WAIT = 30                   # seconds tor has to open its control socket
BOOTSTRAP_WAIT = 300                # and to reach the network
BUNDLED_LIBRARIES = ("libevent-2.1.so.7", "libssl.so.3", "libcrypto.so.3")
_SERVICE_ID = re.compile(r"[a-z2-7]{56}")
_UNSAFE = set(' \t\n"\\')


class TorError(Exception):
    """Tor couldn't be run, or said no: in words for the window."""


# ---------------------------------------------------------------- the control protocol (pure)

@dataclass
class Reply:
    """One reply: its status, its lines (without the code and separator), and the data blocks a
    `250+` line carried. An event is status 650."""

    status: int
    lines: list[str] = field(default_factory=list)
    data: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == 250

    @property
    def event(self) -> bool:
        return self.status == 650

    def text(self) -> str:
        return " ".join(self.lines)


class ReplyReader:
    """Bytes in as they come; whole replies out, in order."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._lines: list[str] = []
        self._data: dict[str, str] = {}
        self._block: tuple[str, list[str]] | None = None

    def feed(self, data: bytes) -> list[Reply]:
        self._buffer += data
        replies = []
        while (end := self._buffer.find(b"\r\n")) != -1:
            raw = self._buffer[:end].decode("utf-8", "replace")
            del self._buffer[:end + 2]
            if (reply := self._line(raw)) is not None:
                replies.append(reply)
        if len(self._buffer) > 1_000_000:
            raise TorError("tor sent a control reply line with no end")
        return replies

    def _line(self, raw: str) -> Reply | None:
        if self._block is not None:
            key, lines = self._block
            if raw == ".":
                self._data[key] = "\n".join(lines)
                self._block = None
            else:
                lines.append(raw[1:] if raw.startswith("..") else raw)
            return None
        if len(raw) < 4 or not raw[:3].isdigit() or raw[3] not in " -+":
            raise TorError(f"tor sent a control reply that can't be read: {raw[:80]!r}")
        status, kind, rest = int(raw[:3]), raw[3], raw[4:]
        if kind == "+":
            key, _, first = rest.partition("=")
            self._lines.append(key)
            self._block = (key, [first] if first else [])
            return None
        self._lines.append(rest)
        if kind == "-":
            return None
        reply = Reply(status, self._lines, self._data)
        self._lines, self._data = [], {}
        return reply


def fields(text: str) -> dict[str, str]:
    """KEY=value and KEY="quoted value" pairs, anywhere in a line."""
    out = {}
    for m in re.finditer(r'([A-Za-z_]+)=("(?:[^"\\]|\\.)*"|\S*)', text):
        value = m.group(2)
        if value.startswith('"'):
            value = re.sub(r"\\(.)", r"\1", value[1:-1])
        out[m.group(1)] = value
    return out


def quoted(value: str) -> str:
    """A QuotedString, as the control protocol (and torrc) reads one."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def cookie_file(protocolinfo: Reply) -> str:
    """Where tor keeps the cookie, from PROTOCOLINFO; SAFECOOKIE must be offered."""
    for line in protocolinfo.lines:
        if line.startswith("AUTH "):
            f = fields(line[5:])
            if "SAFECOOKIE" not in f.get("METHODS", "").split(","):
                raise TorError(f"tor offers no SAFECOOKIE login ({f.get('METHODS')})")
            if f.get("COOKIEFILE"):
                return f["COOKIEFILE"]
    raise TorError("tor didn't say where its cookie is")


def safecookie(cookie: bytes, client_nonce: bytes, server_nonce: bytes) -> tuple[bytes, bytes]:
    """(the hash tor must have sent, the hash sent back)."""
    message = cookie + client_nonce + server_nonce
    return (hmac.new(SERVER_TO_CONTROLLER, message, hashlib.sha256).digest(),
            hmac.new(CONTROLLER_TO_SERVER, message, hashlib.sha256).digest())


def authenticate(cookie: bytes, client_nonce: bytes, challenge: Reply) -> str:
    """AUTHENTICATE, for tor's AUTHCHALLENGE answer, once tor has shown it read the same cookie: a
    server hash that doesn't match means something else answered on the socket."""
    if not challenge.ok:
        raise TorError(f"tor refused the login: {challenge.text()}")
    f = fields(challenge.text())
    try:
        server_hash, server_nonce = bytes.fromhex(f["SERVERHASH"]), bytes.fromhex(f["SERVERNONCE"])
    except (KeyError, ValueError):
        raise TorError("tor's login challenge has no hash and nonce") from None
    expected, client_hash = safecookie(cookie, client_nonce, server_nonce)
    if not hmac.compare_digest(expected, server_hash):
        raise TorError("the control socket didn't prove it is tor")
    return f"AUTHENTICATE {client_hash.hex()}"


@dataclass(frozen=True)
class Bootstrap:
    progress: int
    summary: str


def bootstrap_of(text: str) -> Bootstrap | None:
    """From GETINFO status/bootstrap-phase's answer, or a STATUS_CLIENT event."""
    if "BOOTSTRAP" not in text:
        return None
    f = fields(text)
    try:
        progress = int(f.get("PROGRESS", ""))
    except ValueError:
        return None
    return Bootstrap(max(0, min(100, progress)), f.get("SUMMARY", ""))


def add_onion(key: onion_mod.OnionKey, port: int, target: str, clients: list[str] = ()) -> str:
    """An onion service on `port` to `target` ("unix:/path"), with the key given. With `clients`
    (their public keys), only they can find it. Not detached: it lives as long as the control
    connection, so it can't outlive the app."""
    flags = ["MaxStreamsCloseCircuit"] + (["V3Auth"] if clients else [])
    return (f"ADD_ONION {key.tor_blob} Flags={','.join(flags)} MaxStreams=32 PoWDefensesEnabled=1 "
            f"Port={port},{target}" + "".join(f" ClientAuthV3={c}" for c in clients))


def service_of(reply: Reply) -> str:
    if not reply.ok:
        raise TorError(f"tor refused the onion service: {reply.text()}")
    for line in reply.lines:
        name, _, value = line.partition("=")
        if name == "ServiceID" and _SERVICE_ID.fullmatch(value):
            return value
    raise TorError("tor gave no onion address")


def descriptor_uploaded(event: Reply, service_id: str) -> bool:
    words = event.text().split()
    return event.event and len(words) >= 3 and words[:2] == ["HS_DESC", "UPLOADED"] and words[2] == service_id


# ---------------------------------------------------------------- where it runs

def socket_safe(path: Path) -> bool:
    text = str(path)
    return len(text.encode()) <= SOCKET_PATH_MOST and not (set(text) & _UNSAFE)


@dataclass(frozen=True)
class TorPaths:
    data: Path                      # tor's DataDirectory (kept: its guards, its cached consensus)
    sockets: Path                   # 0700, in the runtime folder: control.sock, socks.sock, the services'
    torrc: Path
    defaults: Path

    @property
    def control(self) -> Path:
        return self.sockets / "control.sock"

    @property
    def socks(self) -> Path:
        return self.sockets / "socks.sock"


def paths_for(state: Path, runtime: Path) -> TorPaths:
    sockets = runtime / "tor"
    if not socket_safe(sockets / "control.sock"):
        raise TorError(f"The app's runtime folder can't hold tor's sockets: {sockets}")
    return TorPaths(data=state / "tor", sockets=sockets, torrc=state / "torrc", defaults=state / "torrc-defaults")


def render_torrc(p: TorPaths, owner_pid: int) -> str:
    return "\n".join([
        f"DataDirectory {quoted(str(p.data))}",
        f"SocksPort unix:{quoted(str(p.socks))} OnionTrafficOnly ExtendedErrors",
        f"ControlPort unix:{quoted(str(p.control))}",
        "CookieAuthentication 1",
        f"__OwningControllerProcess {owner_pid}",
        "Log notice stdout",
        "AvoidDiskWrites 1",
    ]) + "\n"


def find_tor(environ: dict | None = None) -> Path | None:
    """The tor to run: the AppImage's own (AppRun sets DVM_TOR), else one on PATH."""
    env = os.environ if environ is None else environ
    given = env.get("DVM_TOR")
    if given and os.access(given, os.X_OK):
        return Path(given)
    found = shutil.which("tor", path=env.get("PATH"))
    return Path(found) if found else None


def tor_environment(tor: Path, environ: dict | None = None) -> dict:
    """A clean environment for tor: nothing of the app's own, and the bundle's folder as its library
    path when the bundle's libraries are beside it."""
    env = os.environ if environ is None else environ
    out = {k: env[k] for k in ("HOME", "LANG", "PATH") if k in env}
    out.setdefault("PATH", "/usr/bin:/bin")
    if all((tor.parent / name).exists() for name in BUNDLED_LIBRARIES):
        out["LD_LIBRARY_PATH"] = str(tor.parent)
    return out


def _private_file(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


# ---------------------------------------------------------------- the process and its control connection

class Tor:
    """One tor, started on demand. `on_change` hears its state ({"step", "progress", "words"})."""

    def __init__(self, paths: TorPaths, binary: Path | None = None, on_change: Callable[[dict], None] | None = None):
        self.paths, self.binary = paths, binary
        self.on_change = on_change or (lambda state: None)
        self.state = {"step": "stopped", "progress": 0, "words": ""}
        self.log: deque[str] = deque(maxlen=40)
        self._proc: asyncio.subprocess.Process | None = None
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._waiting: deque[asyncio.Future] = deque()
        self._events: list[Callable[[Reply], None]] = []
        self._tasks: list[asyncio.Task] = []
        self._lock = asyncio.Lock()
        self._started: asyncio.Future | None = None
        self._stopping = False              # stopped on purpose: its exit is no failure
        self._uploaded: set[str] = set()    # the onions whose descriptor reached a directory
        self._upload = asyncio.Event()

    def _set(self, step: str, words: str, progress: int | None = None) -> None:
        self.state = {"step": step, "progress": self.state["progress"] if progress is None else progress, "words": words}
        self.on_change(dict(self.state))

    @property
    def running(self) -> bool:
        return self.state["step"] == "ready"

    async def start(self) -> None:
        """Run tor and wait until it has reached the network (or say why it couldn't)."""
        async with self._lock:
            if self.running:
                return
            try:
                await self._start()
            except TorError as e:
                await self._kill()
                self._set("failed", str(e))
                raise
            except BaseException:
                await self._kill()
                self._set("stopped", "")
                raise

    async def _start(self) -> None:
        self._stopping = False
        tor = self.binary or find_tor()
        if tor is None:
            raise TorError("Tor isn't here: this build of DA Vibe Manager can't sync. Install tor, or use the AppImage.")
        for folder in (self.paths.data, self.paths.sockets):
            folder.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(folder, 0o700)
        self.paths.control.unlink(missing_ok=True)      # what a tor that died left
        self.paths.socks.unlink(missing_ok=True)
        _private_file(self.paths.torrc, render_torrc(self.paths, os.getpid()))
        _private_file(self.paths.defaults, "")
        self._set("starting", "Starting Tor…", 0)
        try:
            self._proc = await asyncio.create_subprocess_exec(
                str(tor), "-f", str(self.paths.torrc), "--defaults-torrc", str(self.paths.defaults),
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                env=tor_environment(tor), start_new_session=True)
        except OSError as e:
            raise TorError(f"Tor couldn't be started: {e}") from None
        self._tasks.append(asyncio.ensure_future(self._read_log()))
        for _ in range(int(CONTROL_WAIT / 0.1)):
            if self.paths.control.exists() or self._proc.returncode is not None:
                break
            await asyncio.sleep(0.1)
        if not self.paths.control.exists():
            raise TorError("Tor didn't start: " + (self._last_log() or "it opened no control socket."))
        self._reader, self._writer = await asyncio.open_unix_connection(str(self.paths.control))
        self._tasks.append(asyncio.ensure_future(self._read_control()))
        info = await self.command("PROTOCOLINFO 1")
        cookie = Path(cookie_file(info)).read_bytes()
        nonce = secrets.token_bytes(32)
        challenge = await self.command(f"AUTHCHALLENGE SAFECOOKIE {nonce.hex()}", check=False)
        await self.command(authenticate(cookie, nonce, challenge))
        await self.command("TAKEOWNERSHIP")
        self._events.append(self._on_status)
        await self.command("SETEVENTS STATUS_CLIENT HS_DESC")
        self._set("connecting", "Connecting to the Tor network…", 0)
        self._started = asyncio.get_running_loop().create_future()
        phase = bootstrap_of((await self.command("GETINFO status/bootstrap-phase")).text())
        if phase:
            self._bootstrapped(phase)
        try:
            await asyncio.wait_for(asyncio.shield(self._started), BOOTSTRAP_WAIT)
        except asyncio.TimeoutError:
            raise TorError("Tor couldn't reach the Tor network in five minutes: this network may block it.") from None

    def _bootstrapped(self, phase: Bootstrap) -> None:
        if phase.progress >= 100:
            self._set("ready", "Connected to Tor", 100)
            if self._started and not self._started.done():
                self._started.set_result(True)
        elif self.state["step"] in ("connecting", "starting"):
            self._set("connecting", f"Connecting to the Tor network… {phase.progress}%", phase.progress)

    def _on_status(self, event: Reply) -> None:
        words = event.text().split()
        if words[:2] == ["HS_DESC", "UPLOADED"] and len(words) >= 3:
            self._uploaded.add(words[2])
            self._upload.set()
        phase = bootstrap_of(event.text())
        if phase:
            self._bootstrapped(phase)

    def _last_log(self) -> str:
        for line in reversed(self.log):
            if "[err]" in line or "[warn]" in line:
                return line.split("] ", 1)[-1][:300]
        return ""

    async def _read_log(self) -> None:
        proc = self._proc
        while proc and (line := await proc.stdout.readline()):
            self.log.append(line.decode("utf-8", "replace").rstrip())
        if proc:
            await proc.wait()
            if not self._stopping and self.state["step"] not in ("stopped", "failed"):
                self._set("failed", "Tor stopped: " + (self._last_log() or f"it ended with code {proc.returncode}."))
                self._fail_waiting(TorError("Tor stopped."))

    async def _read_control(self) -> None:
        reader = ReplyReader()
        try:
            while chunk := await self._reader.read(65536):
                for reply in reader.feed(chunk):
                    if reply.event:
                        for listener in list(self._events):
                            listener(reply)
                    elif self._waiting:
                        fut = self._waiting.popleft()
                        if not fut.done():
                            fut.set_result(reply)
        except (OSError, TorError):
            pass
        self._fail_waiting(TorError("Tor's control connection closed."))

    def _fail_waiting(self, error: Exception) -> None:
        while self._waiting:
            fut = self._waiting.popleft()
            if not fut.done():
                fut.set_exception(error)
        if self._started and not self._started.done():
            self._started.set_exception(error)

    async def command(self, line: str, check: bool = True) -> Reply:
        if self._writer is None:
            raise TorError("Tor isn't running.")
        fut = asyncio.get_running_loop().create_future()
        self._waiting.append(fut)
        self._writer.write(line.encode() + b"\r\n")
        await self._writer.drain()
        reply = await asyncio.wait_for(fut, 60)
        if check and not reply.ok:
            raise TorError(f"Tor said no ({line.split()[0]}): {reply.text()[:200]}")
        return reply

    # ---------------------------------------------------------------- what sync asks of it

    async def add_onion(self, key: onion_mod.OnionKey, port: int, target: Path, clients: list[str] = ()) -> str:
        if not socket_safe(target):
            raise TorError(f"An onion service's socket path can't be given to tor: {target}")
        service = service_of(await self.command(add_onion(key, port, f"unix:{target}", list(clients)), check=False))
        if service != key.address:
            raise TorError("Tor published another address than the key's.")
        return service

    async def remove_onion(self, service_id: str) -> None:
        self._uploaded.discard(service_id)
        await self.command(f"DEL_ONION {service_id}", check=False)

    async def wait_published(self, service_id: str, wait: float = 120) -> bool:
        """Whether its descriptor reached a directory in time: until then, nobody can find it."""
        end = asyncio.get_running_loop().time() + wait
        while service_id not in self._uploaded:
            left = end - asyncio.get_running_loop().time()
            if left <= 0:
                return False
            self._upload.clear()
            try:
                await asyncio.wait_for(self._upload.wait(), left)
            except asyncio.TimeoutError:
                return False
        return True

    async def allow_client(self, address: str, key: onion_mod.ClientKey) -> None:
        """Give tor the key this computer reads `address`'s descriptor with."""
        reply = await self.command(f"ONION_CLIENT_AUTH_ADD {address} {key.tor_private}", check=False)
        if reply.status not in (250, 251, 252):
            raise TorError(f"Tor didn't take a client key: {reply.text()[:200]}")

    async def forget_client(self, address: str) -> None:
        await self.command(f"ONION_CLIENT_AUTH_REMOVE {address}", check=False)

    async def forget_lookups(self) -> None:
        """Forget what tor found out of the onions it looked for: one it couldn't find (it wasn't up yet)
        is looked for again at once, rather than a quarter of an hour later, when tor asks the same
        directories again. Tor forgets the client keys it was given with it (allow_client them again)."""
        await self.command("SIGNAL NEWNYM")

    @property
    def socks(self) -> Path:
        return self.paths.socks

    async def open(self, address: str, port: int, wait: float = 120):
        """A stream to an onion service through this tor: (reader, writer). Raises wire.Unreachable."""
        return await wire.socks_connect(self.paths.socks, f"{address}.onion", port, wait)

    async def stop(self) -> None:
        async with self._lock:
            await self._kill()
            self._set("stopped", "", 0)

    async def _kill(self) -> None:
        self._stopping = True
        if self._writer is not None:
            self._writer.close()                # TAKEOWNERSHIP: tor exits now
            self._writer = None
        proc, self._proc = self._proc, None
        if proc and proc.returncode is None:
            try:
                await asyncio.wait_for(proc.wait(), 5)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()
        self._fail_waiting(TorError("Tor stopped."))
        self._events.clear()
