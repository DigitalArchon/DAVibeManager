"""The workspace's only way out: two Unix sockets in a directory bind-mounted into the container.

- **model.sock**: the builder's Anthropic Messages endpoint. Requests must carry this run's
  random token (the container never holds the API key); the gateway checks the model against
  the ones this project may use, adds the provider's real key from the keyring and streams the
  request to the provider over HTTPS. Each request is logged (model, sizes, status, timing, and the
  tokens it used, which is what this chat's cost is worked out from). A TEE model's enclave is
  attested before anything is sent to it, and each reply it sends is checked against the record
  the attested key signed once the reply has gone on (llm/tee.py check_reply): never holding up or
  changing what Claude Code gets, but said in the log, and a reply that fails has its model
  attested again before its next request.
- **proxy.sock**: an HTTPS proxy. It accepts only `CONNECT host:443`, resolves the name here
  and refuses unless every address is globally routable (no LAN, loopback, link-local, CGNAT
  or ULA), then connects to the address it checked, so a DNS answer can't change under it.
  Plain http requests are refused with an explanation. Every connection is logged and shown.

Inside the container, socat exposes them on 127.0.0.1:8080 and :3128 (workspace/image/dvm-entry).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import secrets
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse
from typing import Awaitable, Callable

import httpx

from .llm import anthropic_bridge as bridge
from .llm.errors import error_words, said as one_line, shown_error
from .llm import routes
from .llm import privacy
from .llm.client import capped_lines
from .llm.secure_http import ACCEPT_ENCODING, ProviderError, is_local, loads, local_http_options
from .llm.params import effort_unsupported, efforts_named, fit_claude, nearest_effort, with_effort
from . import netpolicy
from .netpolicy import InsecureURL, check_url, is_global_ip, is_secure, key_problem, own_networks, scrubbed, shown

PROXY_PORTS = frozenset({443})
# what of the provider's API the assistant may use with the user's key: what Claude Code needs (its
# messages, counting their tokens, the models), not the provider's other paid endpoints
MODEL_PATHS = frozenset({("POST", "/v1/messages"), ("POST", "/v1/messages/count_tokens"), ("GET", "/v1/models")})
OWN_NETWORKS_EVERY = 60
PUBLIC_ADDRESS_EVERY = 15 * 60       # the router asked again for its public address
# what a TLS connection starts with, the client's handshake record: 0x16 and a version, 03 01 to 03 04
TLS_START = (b"\x16\x03\x01", b"\x16\x03\x02", b"\x16\x03\x03", b"\x16\x03\x04")
MAX_HEADER = 16 * 1024
CONNECT_TIMEOUT = 20
# request headers passed through to the provider; everything else (auth, host, cookies, the
# container's own idea of where it is) stays behind
PASS_HEADERS = ("content-type", "accept", "anthropic-version", "anthropic-beta", "user-agent", "x-stainless-retry-count",
                "x-app")
# response headers passed back
RETURN_HEADERS = ("content-type", "request-id", "x-request-id", "retry-after", "x-should-retry",
                  "anthropic-ratelimit-requests-remaining", "anthropic-ratelimit-tokens-remaining")


class Refused(Exception):
    """A request the gateway won't send, or one the provider refused, and the reason Claude Code
    shows for it. Unless `retry`, asking again won't help, and Claude Code is told so (it would
    otherwise ask up to ten times, for minutes, calling it a temporary server-side issue)."""

    def __init__(self, status: int, message: str, kind: str = "permission_error", retry: bool = False):
        super().__init__(message)
        self.status = status
        self.kind = kind
        self.retry = retry


def _may_pass(e: BaseException | None) -> bool:
    """Whether a failure may well pass if asked again: the network, or the provider's server error,
    also as what caused the error that says so; not a check that was made and didn't hold (a TEE
    model's attestation), nor a key or a request the provider refused."""
    from .llm.secure_http import ProviderError
    from .llm.tee import TeeRefused
    try:
        from openai import APIConnectionError
    except ImportError:  # pragma: no cover - openai is a dependency
        APIConnectionError = ()                                      # noqa: N806
    for _ in range(8):
        if e is None:
            return False
        if isinstance(e, (httpx.TransportError, asyncio.TimeoutError)) or (APIConnectionError and isinstance(e, APIConnectionError)):
            return True
        if isinstance(e, ProviderError) and not isinstance(e, TeeRefused) and (e.status_code is None or e.status_code >= 500):
            return True
        e = e.__cause__
    return False


def _their_words(e: BaseException) -> str:
    """The provider's own message alone ("Invalid session"), one line and cut short; "" where it gave none."""
    body = getattr(e, "body", None)
    message = body.get("message") if isinstance(body, dict) else body if isinstance(body, str) else None
    return one_line(message) if isinstance(message, str) else ""


def upstream_refusal(model: str, e: BaseException, provider: str, answering: bool = False) -> Refused:
    """What Claude Code is told of a request for `model` that failed on its way to the provider (or,
    `answering`, while it answered), by the provider's HTTP status. NanoGPT answers an empty balance
    with 402 ("Insufficient balance": it reserves max_tokens at the model's price, so this comes a little
    before the balance is quite zero). Asked again only when that may help: a busy or failing provider,
    the network."""
    from .llm.private_mode import ModelRetired
    status = getattr(e, "status_code", None)
    status = status if isinstance(status, int) and not isinstance(status, bool) else None
    name = provider or "the provider"
    words = shown_error(e)              # the provider's own words labelled, on one line, cut short
    said = f"{model}: {words}"
    if isinstance(e, ModelRetired):
        return Refused(400, said, "invalid_request_error")
    if status == 402:
        return Refused(402, f"{model}: your {name} balance is too low for this request, so it wasn't run. Top it up, "
                            f"then try again. ({name} said: {words})", "billing_error")
    if status in (401, 403):
        # never a 401 to Claude Code: it would take its own login for the one refused. In words, not statuses: the
        # user read "API Error: 403 … refused the request (HTTP 401): Error code: 401 - Invalid session"
        theirs = _their_words(e) or words
        if status == 401:
            return Refused(403, f"{name} didn't accept the API key, so {model} wasn't asked anything. Check the API "
                                f"key in Settings. ({name} said: {theirs})")
        return Refused(403, f"{name} wouldn't run {model} for this API key. ({name} said: {theirs})")
    if status == 429:
        return Refused(429, said, "rate_limit_error", retry=True)
    if status is not None and 400 <= status < 500:
        return Refused(400, said, "invalid_request_error")
    return Refused(502, said, "api_error", retry=_may_pass(e) or (status or 0) >= 500 or (answering and status is None))


async def answered(events):
    """`events` once the provider has answered (its first event, or "open" when its reply began), so a
    request it refuses (an empty balance, its key, too long) is told Claude Code by its status, before
    any reply has started; the "open" markers aren't passed on. Raises what the provider's refusal raised."""
    it = aiter(events)
    try:
        first = await anext(it)
    except StopAsyncIteration:
        first = None

    async def rest():
        try:
            if first is not None and first[0] != "open":
                yield first
            if first is not None:
                async for event in it:
                    if event[0] != "open":
                        yield event
        finally:
            close = getattr(it, "aclose", None)
            if close is not None:
                await close()
    return rest()


def is_anthropic(model: str) -> bool:
    """Claude models: sent to the provider's Anthropic endpoint as they are."""
    m = (model or "").lower()
    return m.startswith(("anthropic/", "claude-", "claude/"))


def on_nanogpt(url: str) -> bool:
    """Whether an address is NanoGPT's (nano-gpt.com, or a host under it)."""
    host = (urlparse(url or "").hostname or "").lower().rstrip(".")
    return host == "nano-gpt.com" or host.endswith(".nano-gpt.com")


def upstream_url(base: str, path: str, query: str = "") -> str:
    """The provider's URL for a request path. Claude Code appends /v1/messages to its base URL;
    a base that already ends in /v1 (NanoGPT documents https://nano-gpt.com/api/v1) would give
    .../v1/v1/messages, which NanoGPT answers with a redirect, so the /v1 isn't doubled."""
    base = base.rstrip("/")
    if base.endswith("/v1") and path.startswith("/v1/"):
        path = path[3:]
    return base + path + (f"?{query}" if query else "")


def anthropic_usage(u) -> dict:
    """An Anthropic usage block as tokens by kind (input here excludes the cache's)."""
    u = u if isinstance(u, dict) else {}

    def n(key: str) -> int:
        v = u.get(key)
        return v if isinstance(v, int) and v > 0 else 0
    return {"input": n("input_tokens"), "output": n("output_tokens"), "cache_read": n("cache_read_input_tokens"),
            "cache_write": n("cache_creation_input_tokens")}


def openai_usage(u) -> dict:
    """A chat completions usage block as tokens by kind (its prompt_tokens include the cached ones)."""
    u = u if isinstance(u, dict) else {}

    def n(v) -> int:
        return v if isinstance(v, int) and v > 0 else 0
    cached = n((u.get("prompt_tokens_details") or {}).get("cached_tokens"))
    out = {"input": max(n(u.get("prompt_tokens")) - cached, 0), "output": n(u.get("completion_tokens")),
           "cache_read": cached, "cache_write": 0}
    cost = u.get("cost")
    if isinstance(cost, (int, float)) and not isinstance(cost, bool) and cost >= 0:
        out["cost"] = float(cost)       # what NanoGPT billed for it, when it says (USD)
    return out


class UsageReader:
    """Picks the usage out of an Anthropic event stream as it passes: message_start has the input
    side, message_delta the output so far."""

    def __init__(self) -> None:
        self._buf = b""
        self.usage: dict | None = None

    def feed(self, chunk: bytes) -> None:
        *lines, self._buf = (self._buf + chunk).split(b"\n")
        if len(self._buf) > 1 << 20:
            self._buf = b""                     # a line this long is no usage line
        for line in lines:
            if line.startswith(b"data:") and b'"usage"' in line:
                try:
                    data = loads(line[5:])
                except ValueError:
                    continue
                if not isinstance(data, dict):
                    continue
                if data.get("type") == "message_start":
                    self.usage = anthropic_usage((data.get("message") or {}).get("usage"))
                elif data.get("type") == "message_delta" and isinstance(data.get("usage"), dict):
                    later = anthropic_usage(data["usage"])
                    self.usage = {k: later[k] or v for k, v in (self.usage or later).items()}


def _route_held(rec: dict) -> dict:
    """A routed reply NanoGPT billed nothing for went on its own routing (the subscription's), not
    the route: the host may be down, or not serve the model now. NanoGPT names no host in a reply,
    so the bill is the evidence (SealedLore, engine/routing.py)."""
    cost = (rec.get("usage") or {}).get("cost")
    if rec.get("route") and cost is not None and rec.get("status") == 200:
        rec["route_held"] = cost > 0
    return rec


def as_sent(rec: dict, ended: dict) -> dict:
    """A TEE request's event as it went. One whose whole reply never came (refused, stopped, cut short) has no check
    coming (`_check_later` checks only a reply its stream carried to the end), so it names none: it was "checking"
    for ever, and Sandbox activity marked it so (DA Private Coder's proxy.as_sent, 6c26aa6)."""
    if rec.get("tee") == "checking" and ended.get("reply") is None:
        return {k: v for k, v in rec.items() if k not in ("id", "tee")}
    return rec


def refusal_response(e: Refused):
    """A refusal as Anthropic's API says one, telling Claude Code not to ask again unless it may help."""
    from starlette.responses import JSONResponse
    return JSONResponse({"type": "error", "error": {"type": e.kind, "message": str(e)}}, status_code=e.status,
                        headers={} if e.retry else {"x-should-retry": "false"})


def broke_off(name: str, e: BaseException) -> str:
    """Why a reply passed on as it came stopped coming (a reset, a timeout, an answer past what is read), for the log
    and for Claude Code: the provider's words without a password in an address."""
    return f"{name}'s reply broke off before it was finished: {scrubbed(str(e)) or type(e).__name__}"


def stream_error(said: str) -> bytes:
    """An error as Anthropic tells one mid-stream: Claude Code says so, and may ask again."""
    return ("event: error\ndata: " + json.dumps({"type": "error", "error": {
        "type": "api_error", "message": f"{said}. Asking again may work."}}) + "\n\n").encode()


def _error_text(raw: bytes) -> str:
    try:
        data = loads(raw)
        err = data.get("error", data) if isinstance(data, dict) else data
        msg = err.get("message") if isinstance(err, dict) else err
        return str(msg or data)[:500]
    except ValueError:
        return raw.decode("utf-8", errors="replace")[:500]


@dataclass
class Upstream:
    """Where the builder's model requests go, and what it may ask for."""
    base_url: str                 # e.g. https://nano-gpt.com/api/v1 (paths like /v1/messages are appended); "" for none
    auth: str                     # "bearer" or "x-api-key"
    key: Callable[[], str | None]  # read from the keyring per request: a key changed in Settings applies at once
    models: tuple[str, ...]        # allowed model ids: (main, small); a request for any other gets the small one
    provider: str = ""
    tier: str = "standard"
    # models other than Anthropic's: model id -> a chat-completions client (llm/client.LLMClient, or
    # for private/ models one that seals each request to an attested enclave, llm/private_mode.py).
    # Their requests are translated here rather than forwarded, so the app sets their reasoning
    # effort and describes images for them
    chat: Callable[[str], object] | None = None
    # checks a model before anything is sent to it (a TEE model's attestation); raises to refuse
    guard: Callable[[str], Awaitable[object]] | None = None
    # for a TEE model just attested (`guard` gave its attestation): the check of a reply from it, against
    # that attestation: (the reply's TurnResult) -> {"tee": "verified" | "signed" | "failed" |
    # "unchecked", "detail"?} (models.Models.reply_check); None when there is none to make
    reply_check: Callable[[str], Callable[[object], Awaitable[dict]] | None] | None = None
    # the vision helper for models that can't see: (data URL, context) -> description
    describe: bridge.Describe | None = None
    vision_model: str = ""
    # whether a translated model reads images itself (then it gets them, not descriptions)
    # (None: not known now, the provider's model list unread: the request is refused, to be asked again)
    sees: Callable[[str], Awaitable[bool | None]] | None = None
    # how hard the assistant thinks (config.BUILDER_EFFORTS): a translated model's reasoning effort, a
    # Claude model's own effort and thinking, each the nearest it takes (never "none": see config)
    reasoning: str = "low"
    # the efforts a translated model takes (None: not known, sent as asked); the nearest goes (llm/params.py)
    efforts: Callable[[str], Awaitable[tuple[str, ...] | None]] | None = None
    # which of NanoGPT's hosts runs a translated model: model id -> its route, or None for
    # NanoGPT's own choice (llm/routes.py)
    route: Callable[[str], dict | None] = lambda model: None
    # how private a model is on this provider (llm/privacy.py Privacy: kind, service, level); by its id alone when not
    # given (tests)
    privacy: Callable[[str], object] | None = None
    # how private the chat these requests are of was made (Engine._chat_privacy), when it ran on a more private model
    # than the assistant's is now: nothing of it goes to a model less private than that either (None: no more than
    # the assistant's model is)
    floor: object | None = None

    def privacy_of(self, model: str):
        return self.privacy(model) if self.privacy is not None else privacy.privacy_at(model)



# With SELinux, the sandbox (a confined container: container_t) may connect only to a socket of a container's
# type, and Fedora's policy refuses one of the user's own session without logging it (Permission denied): every
# model request failed. So its sockets are made with that type (the container stays confined; the socket file
# is relabelled for it by the mount's :z). /proc/thread-self/attr/sockcreate sets it for the sockets this
# thread makes next.
CONTAINER_SOCKET = "system_u:system_r:container_t:s0"
SOCKCREATE = "/proc/thread-self/attr/sockcreate"
SELINUX = "/sys/fs/selinux/enforce"


def _sockcreate(context: str) -> bool:
    try:
        with open(SOCKCREATE, "wb", buffering=0) as f:
            f.write(context.encode() or b"\n")     # an empty line puts the default back
        return True
    except OSError:
        return False


def unix_listener(path: Path) -> socket.socket:
    """A listening unix socket at `path`, that the sandbox can connect to."""
    labelled = os.path.exists(SELINUX) and _sockcreate(CONTAINER_SOCKET)
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    finally:
        if labelled:
            _sockcreate("")
    try:
        sock.bind(str(path))
        sock.listen(128)
        sock.setblocking(False)
    except OSError:
        sock.close()
        raise
    return sock


@dataclass
class Gateway:
    """One project's gateway. `upstream()` is asked per request, so changes in Settings (or the
    project's sensitivity) apply without restarting anything; it raises to refuse."""
    dir: Path
    upstream: Callable[[], Upstream]
    on_event: Callable[[dict], None] = lambda e: None     # network and model events, for the UI and the logs
    on_progress: Callable[[dict], None] = lambda p: None  # a private model still thinking: how long, how much
    resolver: Callable[[str, int], Awaitable[list[str]]] | None = None   # tests
    connector: Callable[[str, int], Awaitable[tuple]] | None = None       # tests
    http: httpx.AsyncClient | None = None                                  # tests
    own_networks: Callable[[], tuple] = own_networks                        # this computer's (tests: theirs)
    # why a host name may not be connected to ("" if it may): it carries something from this computer
    refuse_host: Callable[[str], str] = lambda host: ""
    _own: tuple | None = None
    # this network's public IPv4 address, as its router says (netpolicy.router_public_addresses; tests: theirs),
    # asked aside now and then: (when, its networks), and the look under way
    public_addresses: Callable[[], list[str]] | None = None
    _public: tuple = (float("-inf"), ())
    _asking: asyncio.Task | None = None
    token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    _servers: list[asyncio.AbstractServer] = field(default_factory=list)
    _uvicorn: object | None = None
    _uvicorn_task: asyncio.Task | None = None
    _own_http: bool = False
    _local_http: httpx.AsyncClient | None = None     # for a provider on this computer or its network
    _images: bridge.ImageDescriber | None = None
    # what models said when they refused an effort: model -> the efforts it takes (() for none at all)
    _efforts: dict = field(default_factory=dict)
    # where reasoning handed back (reasoning_content) was refused: not sent there again
    _no_reasoning_back: set = field(default_factory=set)
    # TEE replies being checked against their signed records, after they went on (_check_later)
    _checks: set = field(default_factory=set)

    @property
    def model_socket(self) -> Path:
        return self.dir / "model.sock"

    @property
    def proxy_socket(self) -> Path:
        return self.dir / "proxy.sock"

    async def start(self) -> None:
        # 0711: the container's agent (another uid) can reach the sockets but not list the directory
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o711)
        os.chmod(self.dir, 0o711)
        for sock in (self.model_socket, self.proxy_socket):
            sock.unlink(missing_ok=True)
        self._ask_router()                  # before the sandbox's first connection, if the router answers quickly
        proxy = await asyncio.start_unix_server(self._proxy_client, sock=unix_listener(self.proxy_socket))
        self._servers.append(proxy)
        await self._start_model_server()
        for sock in (self.model_socket, self.proxy_socket):
            os.chmod(sock, 0o666)

    async def _start_model_server(self) -> None:
        import uvicorn
        config = uvicorn.Config(self.model_app(), log_level="warning", lifespan="off", access_log=False,
                                timeout_keep_alive=75)
        server = uvicorn.Server(config)
        server.install_signal_handlers = lambda: None   # the app's own server handles signals
        self._uvicorn = server
        self._uvicorn_task = asyncio.create_task(server.serve(sockets=[unix_listener(self.model_socket)]))
        for _ in range(200):
            if server.started:
                return
            if self._uvicorn_task.done():
                self._uvicorn_task.result()
            await asyncio.sleep(0.01)

    async def stop(self) -> None:
        for s in self._servers:
            s.close()
        self._servers.clear()
        for task in list(self._checks):
            task.cancel()
        if self._uvicorn is not None:
            self._uvicorn.should_exit = True
            try:
                await asyncio.wait_for(self._uvicorn_task, 5)
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):  # noqa: BLE001 - shutting down
                self._uvicorn_task.cancel()
            self._uvicorn = None
        if self._own_http and self.http is not None:
            await self.http.aclose()
            self.http, self._own_http = None, False
        if self._local_http is not None:
            await self._local_http.aclose()
            self._local_http = None
        for sock in (self.model_socket, self.proxy_socket):
            sock.unlink(missing_ok=True)

    # ---------------------------------------------------------------- the model endpoint

    def model_app(self):
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse, Response, StreamingResponse
        from starlette.routing import Route

        def fail(path: str, status: int, message: str, kind: str = "permission_error", retry: bool = False,
                 **extra) -> JSONResponse:
            """Refuse, and say so in the activity log: the CLI only retries, and the user would see nothing."""
            self.on_event({"kind": "model", "path": path, "status": status, "error": message, **extra})
            return refusal_response(Refused(status, message, kind, retry))

        async def forward(request: Request):
            path = request.url.path
            supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip() \
                or request.headers.get("x-api-key", "").strip()
            if not secrets.compare_digest(supplied.encode(), self.token.encode()):
                return fail(path, 401, "This sandbox's gateway token doesn't match.", "authentication_error")
            if (request.method, path) not in MODEL_PATHS:
                return fail(path, 404, f"The gateway only passes on the assistant's messages (POST /v1/messages), not "
                            f"{request.method} {path}.", "not_found_error")
            try:
                up = self.upstream()
                # none for a provider with only a chat address: every request translated (below), none passed on
                base = check_url(up.base_url, "The assistant's endpoint").rstrip("/") if up.base_url else ""
            except InsecureURL as e:
                return fail(path, 403, str(e))
            except Exception as e:  # noqa: BLE001 - the reason is the user's to see (no provider, no key)
                return fail(path, 403, f"DA Vibe Manager refused this request: {e}")
            try:
                key = up.key()
            except Exception as e:  # noqa: BLE001 - entered for another address (models.key_problem_for): said
                return fail(path, 403, f"DA Vibe Manager refused this request: {e}")
            if not key:
                # a 403, not a 401: Claude Code would take a 401 for its own login refused
                return fail(path, 403, f"No API key is stored for {up.provider}; add it in Settings.")
            if problem := key_problem(key, up.provider):
                # no header can carry it: h11's refusal would quote it whole, in the log and to Claude Code
                return fail(path, 403, problem)
            body = await request.body()
            model, sent_model, data = "", "", {}
            kept = up.privacy_of(up.models[0]) if up.models else privacy.NONE    # how private the assistant's model is
            if up.floor is not None:
                kept = privacy.more_private(kept, up.floor)      # ... or its chat was made, whichever is higher
            if body and request.method == "POST":
                try:
                    data = loads(body)            # nested no deeper than 200 levels (secure_http.loads)
                except ValueError:
                    return fail(path, 400, "The request body isn't JSON.", "invalid_request_error")
                if not isinstance(data, dict):
                    return fail(path, 400, "The request body isn't a JSON object.", "invalid_request_error")
                model = sent_model = str(data.get("model") or "")
                if model not in up.models:
                    # Claude Code asks for its own defaults now and then; only the chosen models are used, and never
                    # one less private than what was asked of (a chat begun on private GLM, then the models changed:
                    # its Claude Code still asks for it, with all that was said)
                    asked = up.privacy_of(model)
                    sent_model = next((m for m in reversed(up.models)
                                       if privacy.rank(up.privacy_of(m)) >= privacy.rank(asked)), "")
                    if not sent_model:
                        return fail(path, 403, f"{model} is a private model ({privacy.level_phrase(asked)}), and the "
                                    "assistant's models aren't that private now: what was asked of it isn't sent to "
                                    "another in the clear, nor with less privacy. Start a new chat.", "permission_error", model=model)
                    data["model"] = sent_model
                    body = json.dumps(data).encode()
            found = up.privacy_of(sent_model)
            if privacy.rank(found) < privacy.rank(kept):
                # the assistant's model is private: everything of its chat goes at its level or higher, or not at all
                return fail(path, 403, f"The assistant's model is private ({privacy.level_phrase(kept)}), so "
                            f"{sent_model or 'a request without a model'} ({privacy.level_phrase(found)}) can't be "
                            "used for its chat in the clear, nor with less privacy. "
                            "Choose private models for quick tasks too (Settings), or leave them empty to use the "
                            "same one.", "permission_error", model=sent_model)
            if found.sealed:
                # sealed by its own client (NanoGPT's Private Mode, Tinfoil's, Chutes'), translated, whatever its id
                # says: never passed on as it is
                if up.chat is None:
                    return fail(path, 403, f"{sent_model} is end-to-end encrypted and is sent only through its own "
                                "client, which this provider has no chat address for: nothing was sent.",
                                "permission_error", model=sent_model)
                return await self._translated(path, data, up, sent_model, model, len(body))
            if up.chat is not None and not is_anthropic(sent_model):
                return await self._translated(path, data, up, sent_model, model, len(body))
            if not base:
                what = sent_model or "this request"
                return fail(path, 403, f"{up.provider} has no address for Anthropic's Messages API, so {what} can't be "
                            "passed on there. Add one in Settings → AI providers, or choose another model.",
                            model=sent_model)
            if up.guard is not None:
                # forwarded as it is, but through the guard every translated request takes: a model the provider's
                # settings mark TEE (tier_overrides) is attested before anything goes to it, or nothing does
                # (llm/client.detect_tier relies on it; SealedLore's 0721878: every call to a TEE model, guarded)
                try:
                    await up.guard(sent_model)
                except Exception as e:  # noqa: BLE001 - the reason goes to the CLI and the log
                    return fail(path, 502, f"Couldn't prepare the request for {sent_model}: {e}", "api_error",
                                retry=_may_pass(e), model=sent_model)
            if bridge.drop_our_thinking(data):
                # another model's reasoning, signed as ours: Anthropic's API refuses a signature it didn't make
                body = json.dumps(data).encode()
            # how hard it thinks, as chosen in Settings and as near as the model goes: Claude Code was started
            # at it, but reads NanoGPT's names wrongly, and a change since reaches it only at its next start
            before = (json.dumps(data.get("thinking")), json.dumps(data.get("output_config")))
            fitted = fit_claude(data, sent_model, up.reasoning or "low") if data else {}
            if data and not is_anthropic(sent_model) and on_nanogpt(base):
                # Claude Code's thinking setting is Claude's: NanoGPT runs a model given one as its ":thinking" variant,
                # which reasons at length whatever the effort (DA Private Coder, measured Nov 2026: GLM-5.3 asked for
                # low gave replies of 16K to 32K tokens, where its chat completions, never sent it, gave none), and it
                # refuses Claude Code's display "updates". The effort decides, as on chat completions
                data.pop("thinking", None)
            if (json.dumps(data.get("thinking")), json.dumps(data.get("output_config"))) != before:
                body = json.dumps(data).encode()
            headers = {k: v for k, v in request.headers.items() if k.lower() in PASS_HEADERS}
            # Chutes' proxy of the Messages API takes the key only as a bearer token (privacy.anthropic_bearer: an
            # x-api-key reached its backend as nothing, SealedLore live, Nov 15 2026)
            if up.auth == "x-api-key" and not privacy.anthropic_bearer(base):
                headers["x-api-key"] = key
            else:
                headers["authorization"] = f"Bearer {key}"
            url = upstream_url(base, path, request.url.query)
            client = self._client(url)
            started = time.monotonic()
            req = client.build_request(request.method, url, content=body, headers=headers)
            try:
                resp = await client.send(req, stream=True)
            except (httpx.HTTPError, ProviderError) as e:     # or an answer refused unread (capped_lines)
                return fail(path, 502, f"Could not reach {up.provider}: {scrubbed(e)}", "api_error", retry=True,
                            model=sent_model)
            if resp.is_redirect:
                # never followed: the key would go wherever the provider points (one points at 0.0.0.0)
                where = shown(resp.headers.get("location", ""))[:200]
                await resp.aclose()
                return fail(path, 502, f"{up.provider} redirected the request to {where}; refusing to follow.",
                            "api_error", model=sent_model, url=shown(url))
            rec = {"kind": "model", "path": path, "model": sent_model,
                   "asked_for": model if model != sent_model else "", "status": resp.status_code,
                   "provider": up.provider, "tier": up.tier, "bytes_out": len(body)}
            if "effort" in fitted:
                rec.update(effort=fitted["effort"], **({"effort_asked": up.reasoning}
                                                       if fitted["effort"] != up.reasoning else {}),
                           **({"thinking_budget": fitted["budget"]} if "budget" in fitted else {}))
            if resp.status_code >= 400:
                # the provider's own explanation (wrong key, unknown model, no credit), for the log and the CLI
                raw = (await resp.aread())[:8000]
                await resp.aclose()
                self.on_event({**rec, "error": _error_text(raw), "seconds": round(time.monotonic() - started, 2)})
                return Response(raw, status_code=resp.status_code,
                                headers={k: v for k, v in resp.headers.items() if k.lower() in RETURN_HEADERS})

            async def stream():
                n = 0
                usage = UsageReader()
                whole = b"" if "json" in resp.headers.get("content-type", "") else None
                broken = ""
                try:
                    try:
                        async for chunk in resp.aiter_bytes():     # decoded here: the CLI gets plain bytes
                            n += len(chunk)
                            if whole is None:
                                usage.feed(chunk)
                            elif len(whole) < 8 << 20:
                                whole += chunk
                            yield chunk
                    except (httpx.HTTPError, ProviderError) as e:
                        # the provider's reply broke off (a reset, a timeout): until Nov 2026 its error went up
                        # through the server, a traceback in its error output, Claude Code's connection dropped
                        # without its end, and the request logged as answered
                        broken = broke_off(up.provider, e)
                        if "event-stream" in resp.headers.get("content-type", ""):
                            yield stream_error(broken)
                finally:
                    await resp.aclose()
                    if whole and not broken:
                        try:
                            usage.usage = anthropic_usage(loads(whole).get("usage"))
                        except (ValueError, AttributeError):
                            pass
                    self.on_event({**rec, "bytes_in": n, "seconds": round(time.monotonic() - started, 2),
                                   **({"status": 502, "error": broken[:300]} if broken else {}),
                                   **({"usage": usage.usage} if usage.usage else {})})

            out_headers = {k: v for k, v in resp.headers.items() if k.lower() in RETURN_HEADERS}
            if request.method == "HEAD":
                await resp.aclose()
                return Response(status_code=resp.status_code, headers=out_headers)
            return StreamingResponse(stream(), status_code=resp.status_code, headers=out_headers)

        return Starlette(routes=[Route("/{path:path}", forward, methods=["GET", "POST", "HEAD"])])

    async def _translated(self, path: str, data: dict, up: Upstream, model: str, asked: str, size: int):
        """A request for a non-Anthropic model: Anthropic in, chat completions out (sealed, for a
        private model), Anthropic back."""
        from starlette.responses import JSONResponse, StreamingResponse
        found = up.privacy_of(model)
        private = found.sealed           # sealed on this computer by its own client
        rec = {"kind": "model", "path": path, "model": model, "asked_for": asked if asked != model else "",
               "provider": up.provider, "tier": "e2ee" if private else up.tier, "private": private,
               "level": found.level, **({"service": found.service} if found.service else {}), "bytes_out": size}
        started = time.monotonic()
        ended: dict = {}                            # the provider's whole reply, once its stream has ended

        def err(e: Refused):
            # refused, before or while it answered: no whole reply, so no check is coming (as_sent)
            self.on_event({**as_sent(rec, ended), "status": e.status, "error": str(e),
                           "seconds": round(time.monotonic() - started, 2)})
            return refusal_response(e)
        if path == "/v1/messages/count_tokens":
            return JSONResponse({"input_tokens": bridge.estimate_tokens(data)})
        if path != "/v1/messages":
            # GET /v1/models, which names no model: it read "/v1/models isn't available for ." until Nov 2026
            return err(Refused(404, f"{path} isn't available" + (f" for {model}." if model else ": the assistant's "
                                                                 "models are the ones chosen in Settings."), "not_found_error"))
        if self._images is None or self._images.model != up.vision_model:
            self._images = bridge.ImageDescriber(up.describe, up.vision_model)
        wanted = up.reasoning or "low"
        try:
            native = False
            if up.sees is not None and bridge.has_images(data):
                native = await up.sees(model)
                if native is None:
                    raise Refused(503, f"{up.provider}'s list of models couldn't be read, so it isn't known whether "
                                       f"{model} sees images: nothing was sent. It's asked for again.", "api_error",
                                  retry=True)
            try:
                messages, tools, params = await bridge.to_openai(data, self._images, native=native)
            except Exception as e:  # noqa: BLE001 - a request that isn't the Messages API's, said in words (a 400)
                raise Refused(400, bridge.not_messages(model), "invalid_request_error") from e
            effort = await self._effort(up, model, wanted)
            params = with_effort(params, effort)
            route = None if found.private else up.route(model)
            params.update(routes.body(route))      # which of NanoGPT's hosts runs it, if the user chose
            attested = None
            if up.guard is not None:
                attested = await up.guard(model)   # e.g. a TEE model's enclave attested; raises to refuse
            # a TEE model's reply is checked against the record its attested key signs, once it has gone on
            check = up.reply_check(model) if attested is not None and up.reply_check is not None else None
            client = up.chat(model)
        except Refused as e:
            return err(e)
        except Exception as e:  # noqa: BLE001 - the reason goes to the CLI and the log
            return err(Refused(502, f"Couldn't prepare the request for {model}: {e}", "api_error", retry=_may_pass(e)))
        estimate = bridge.estimate_tokens(data)
        # the model's reasoning is shown as Claude Code shows Claude's, unless its thinking is off
        show = not (isinstance(data.get("thinking"), dict) and data["thinking"].get("type") == "disabled")
        rec.update(status=200, effort=effort, **({"effort_asked": wanted} if effort != wanted else {}),
                   **({"route": routes.describe(route)} if route else {}), **({"sees": True} if native else {}))
        if check is not None:
            # its reply's check comes later, as an event of its own naming this one (the log marks the request)
            rec.update(id=secrets.token_hex(6), tee="checking")
        where = f"{up.provider}:{'e2ee' if private else 'plain'}"
        if where in self._no_reasoning_back and bridge.handed_back(messages):
            messages = bridge.without_reasoning(messages)
            rec["reasoning_back"] = False
        try:
            # the provider's answer first: a request it refuses is told by its status, not as a reply cut short
            events = await answered(self._stream(client, model, messages, tools, params, rec, where,
                                                 exact=check is not None, ended=ended))
        except Exception as e:  # noqa: BLE001
            return err(upstream_refusal(model, e, up.provider))
        if not data.get("stream"):
            stats: dict = {}
            try:
                reply = await bridge.message(events, model, estimate, stats=stats, thinking=show)
            except Exception as e:  # noqa: BLE001
                return err(upstream_refusal(model, e, up.provider, answering=True))
            # the provider's own count (cached tokens, the bill), as for a streamed reply; none if it gave none
            # (the reply's own figures would be the gateway's estimate)
            self.on_event(_route_held({**as_sent(rec, ended), "seconds": round(time.monotonic() - started, 2),
                                       **({"usage": openai_usage(stats["usage"])} if stats.get("usage") else {})}))
            self._check_later(check, ended, rec)
            return JSONResponse(reply)

        async def body():
            n = 0
            stats: dict = {}
            try:
                async for chunk in bridge.sse(events, model, estimate, stats=stats, thinking=show,
                                              progress=lambda st: self.on_progress({"model": model, **st})):
                    n += len(chunk)
                    if chunk.startswith(b"event: error"):
                        rec.update(status=502, error=chunk.decode(errors="replace")[:300])
                    yield chunk
            finally:
                if "usage" in stats:
                    stats["usage"] = openai_usage(stats["usage"])
                # stopped or cut short, no whole reply: no check is coming, and the event names none (as_sent)
                self.on_event(_route_held({**as_sent(rec, ended), **stats, "bytes_in": n,
                                           "seconds": round(time.monotonic() - started, 2)}))
                self._check_later(check, ended, rec)
        return StreamingResponse(body(), media_type="text/event-stream")

    def _check_later(self, check, ended: dict, rec: dict) -> None:
        """A TEE model's reply, which has gone on to Claude Code as it came, checked against the record its
        attested key signed (llm/tee.py check_reply), aside: said afterwards as an event naming the request
        (rec["id"]). Only a reply its stream carried to the end is checked; one stopped or cut short has no
        record to match."""
        reply = ended.get("reply")
        if check is None or reply is None:
            return

        async def run():
            try:
                found = await check(reply)
            except Exception as e:  # noqa: BLE001 - a check that couldn't be made is "unchecked", never a failure
                found = {"tee": "unchecked", "detail": str(e)[:300]}
            self.on_event({"kind": "tee_reply", "of": rec.get("id"), "model": rec.get("model"), **found})
        task = asyncio.get_running_loop().create_task(run())
        self._checks.add(task)
        task.add_done_callback(self._checks.discard)

    async def _effort(self, up: Upstream, model: str, asked: str) -> str:
        """The effort `model` is sent for `asked`: the nearest it takes, as it said when it refused one,
        else as listed ("": none, a model that takes none)."""
        takes = self._efforts.get(model)
        if takes is None and up.efforts is not None:
            try:
                takes = await up.efforts(model)
            except Exception:  # noqa: BLE001 - not known: sent as asked
                takes = None
        return "" if takes == () else nearest_effort(asked, takes)

    def _learned(self, model: str, error: BaseException, sent: str | None) -> str | None:
        """When `model` refused the effort it was sent and said which it takes (or that it takes none):
        remember them, and the one to send instead ("": none; None: not that kind of refusal)."""
        if not sent:
            return None
        words = error_words(error)         # the body too: openai 3.38 and later leave it out of str(error)
        takes = efforts_named(words, sent)
        if takes:
            self._efforts[model] = takes
            return nearest_effort(sent, takes)
        if effort_unsupported(words):
            self._efforts[model] = ()
            return ""
        return None

    def _stream(self, client, model: str, messages: list[dict], tools, params: dict, rec: dict, where: str,
                exact: bool = False, ended: dict | None = None):
        """The model's events. Refused before it answers, it is asked again (twice at most): without the
        reasoning handed back, if `where` won't take that field (nor from then on); with an effort it
        takes, if it named those (rec["effort"] says which went). With `exact` (a TEE model's reply, to be
        checked), its stream's every byte is hashed as it passes (LLMClient.stream); the whole reply, once
        the stream has ended, goes in `ended`["reply"]."""
        async def events():
            msgs, prm = messages, params
            for attempt in range(3):
                sent = prm.get("reasoning_effort")
                begun = False
                try:
                    async for event in client.stream(model, msgs, tools, prm, **({"exact": True} if exact else {})):
                        begun = True
                        if event[0] == "done" and ended is not None:
                            ended["reply"] = event[1]
                        yield event
                    return
                except Exception as e:
                    if begun or attempt == 2:
                        raise
                    # the body too: openai 3.38 and later leave it out of str(e), so a provider that named the field
                    # beside its message, or in a body that isn't JSON, wasn't asked again (as _learned reads it)
                    if "reasoning_content" in error_words(e).lower() and bridge.handed_back(msgs):
                        self._no_reasoning_back.add(where)
                        msgs = bridge.without_reasoning(msgs)
                        rec["reasoning_back"] = False          # in the log: the provider wouldn't take it
                        continue
                    instead = self._learned(model, e, sent)
                    if instead is None or instead == sent:
                        raise
                    rec.setdefault("effort_asked", sent)
                    rec["effort"] = instead
                    prm = with_effort(prm, instead)
        return events()

    def _client(self, url: str = "") -> httpx.AsyncClient:
        """The client for a request to `url`: one of the gateway's own, or the one it was given (tests). A
        provider on this computer or its network gets one that never goes through a proxy the environment
        names (secure_http.local_http_options): the key and the conversation went to it."""
        async def refuse_insecure(response: httpx.Response) -> None:
            loc = response.headers.get("location")
            if response.is_redirect and loc and not is_secure(str(response.url.join(loc))):
                raise httpx.HTTPError(f"redirect to insecure {loc[:100]!r} refused")

        def make(**options) -> httpx.AsyncClient:
            # only gzip and deflate asked for (httpx asks for br too, brotli being installed), and the
            # provider's answer read only so far as it passes (llm/client.py capped_lines): an error's
            # to 64 KB, a reply not streamed to 32 MB, a stream's line to 32 MB
            return httpx.AsyncClient(timeout=httpx.Timeout(600, connect=30), follow_redirects=False,
                                     headers={"Accept-Encoding": ACCEPT_ENCODING},
                                     event_hooks={"response": [refuse_insecure, capped_lines]}, **options)
        if self.http is not None and not self._own_http:
            return self.http
        if url and is_local(url):
            if self._local_http is None:
                self._local_http = make(**local_http_options(url))
            return self._local_http
        if self.http is None:
            self._own_http = True
            self.http = make()
        return self.http

    # ---------------------------------------------------------------- the HTTPS proxy

    def _own_networks(self) -> tuple:
        """This computer's addresses and networks, looked at again every minute (a laptop moves), and
        the public address of the network it's on, which its router is asked for aside (never waited on)."""
        now = time.monotonic()
        if self._own is None or now - self._own[0] > OWN_NETWORKS_EVERY:
            self._own = (now, self.own_networks())
        if now - self._public[0] > PUBLIC_ADDRESS_EVERY and (self._asking is None or self._asking.done()):
            self._ask_router()
        return self._own[1] + self._public[1]

    def _ask_router(self) -> None:
        ask = self.public_addresses or netpolicy.router_public_addresses
        started = time.monotonic()

        async def go():
            try:
                found = await asyncio.to_thread(ask)
            except Exception:  # noqa: BLE001 - only a look; asked again later
                found = []
            self._public = (started, tuple(ipaddress.ip_network(f"{ip}/32") for ip in found))
        self._asking = asyncio.get_running_loop().create_task(go())

    async def _resolve(self, host: str, port: int) -> list[str]:
        if self.resolver:
            return await self.resolver(host, port)
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return list(dict.fromkeys(info[4][0] for info in infos))

    async def _connect(self, ip: str, port: int):
        if self.connector:
            return await self.connector(ip, port)
        return await asyncio.wait_for(asyncio.open_connection(ip, port), CONNECT_TIMEOUT)

    async def _proxy_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        started = time.monotonic()
        rec: dict = {"kind": "connect"}
        up_writer = None
        try:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
                return
            if len(head) > MAX_HEADER:
                return await self._refuse(writer, 431, "Request header too large", rec)
            line = head.split(b"\r\n", 1)[0].decode("latin-1")
            parts = line.split()
            if len(parts) != 3:
                return await self._refuse(writer, 400, "Bad request", rec)
            method, target, _ = parts
            if method.upper() != "CONNECT":
                rec.update(kind="http", target=target[:200])
                return await self._refuse(writer, 403, (
                    "Plain http is refused: DA Vibe Manager only lets the workspace use HTTPS. Use the https:// "
                    "form of this URL."), rec)
            host, _, port_s = target.rpartition(":")
            host = host.strip("[]").lower()
            rec.update(host=host, port=port_s)
            if not host or not port_s.isdigit():
                return await self._refuse(writer, 400, "CONNECT needs host:port", rec)
            port = int(port_s)
            if port not in PROXY_PORTS:
                return await self._refuse(writer, 403, (
                    f"Port {port} is refused: the workspace may only make HTTPS connections (port 443). For git, "
                    "use the https:// URL rather than ssh."), rec)
            why = self.refuse_host(host)
            if why:
                return await self._refuse(writer, 403, why, rec)
            try:
                ips = await asyncio.wait_for(self._resolve(host, port), CONNECT_TIMEOUT)
            except (OSError, asyncio.TimeoutError) as e:
                return await self._refuse(writer, 502, f"Could not resolve {host}: {e}", rec)
            if not ips:
                return await self._refuse(writer, 502, f"{host} has no address", rec)
            local = [ip for ip in ips if not is_global_ip(ip, self._own_networks())]
            if local:
                rec["ips"] = ips
                return await self._refuse(writer, 403, (
                    f"{host} resolves to {local[0]}, which is on this computer or a private network. The workspace "
                    "may only reach public internet addresses."), rec)
            ip = ips[0]
            rec["ip"] = ip
            try:
                up_reader, up_writer = await self._connect(ip, port)
            except (OSError, asyncio.TimeoutError) as e:
                return await self._refuse(writer, 502, f"Could not connect to {host}: {e}", rec)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            # what goes through is TLS, and nothing else: port 443 alone lets plain http or anything else in
            # the clear out (curl --proxytunnel http://host:443/?data). The client speaks first in TLS.
            try:
                first = await asyncio.wait_for(reader.readexactly(3), 30)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                rec.update(status=200, error="nothing was sent through")
                return
            if first not in TLS_START:
                rec.update(status=403, refused="Only TLS (HTTPS) goes through, nothing in the clear: this wasn't TLS.")
                return
            up_writer.write(first)
            rec["status"] = 200
            sent, received = await asyncio.gather(self._pipe(reader, up_writer), self._pipe(up_reader, writer))
            rec.update(bytes_out=sent + len(first), bytes_in=received)
        except Exception as e:  # noqa: BLE001 - one connection's failure never stops the gateway
            rec.setdefault("error", str(e))
        finally:
            rec["seconds"] = round(time.monotonic() - started, 2)
            if "host" in rec or rec["kind"] == "http":
                self.on_event(rec)
            writer.close()
            if up_writer is not None:
                up_writer.close()           # half-closed by the pipes; closed for good here

    async def _refuse(self, writer: asyncio.StreamWriter, status: int, message: str, rec: dict) -> None:
        rec.update(status=status, refused=message)
        body = message.encode() + b"\n"
        reason = {400: "Bad Request", 403: "Forbidden", 431: "Request Header Fields Too Large",
                  502: "Bad Gateway"}.get(status, "Error")
        writer.write(f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
                     f"Connection: close\r\n\r\n".encode() + body)
        try:
            await writer.drain()
        except ConnectionError:
            pass

    @staticmethod
    async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> int:
        n = 0
        try:
            while chunk := await src.read(65536):
                n += len(chunk)
                dst.write(chunk)
                await dst.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                dst.write_eof()
            except (OSError, RuntimeError):
                dst.close()
        return n
