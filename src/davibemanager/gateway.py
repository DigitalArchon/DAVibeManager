"""The workspace's only way out: two Unix sockets in a directory bind-mounted into the container.

- **model.sock**: the builder's Anthropic Messages endpoint. Requests must carry this run's
  random token (the container never holds the API key); the gateway checks the model against
  the ones this project may use, adds the provider's real key from the keyring and streams the
  request to the provider over HTTPS. Each request is logged (model, sizes, status, timing, and the
  tokens it used, which is what this chat's cost is worked out from).
- **proxy.sock**: an HTTPS proxy. It accepts only `CONNECT host:443`, resolves the name here
  and refuses unless every address is globally routable (no LAN, loopback, link-local, CGNAT
  or ULA), then connects to the address it checked, so a DNS answer can't change under it.
  Plain http requests are refused with an explanation. Every connection is logged and shown.

Inside the container, socat exposes them on 127.0.0.1:8080 and :3128 (workspace/image/dvm-entry).
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

import httpx

from .llm import anthropic_bridge as bridge
from .llm import routes
from .llm.client import is_private_mode
from .netpolicy import InsecureURL, check_url, is_global_ip, is_secure, own_networks

PROXY_PORTS = frozenset({443})
# what of the provider's API the assistant may use with the user's key: what Claude Code needs (its
# messages, counting their tokens, the models), not the provider's other paid endpoints
MODEL_PATHS = frozenset({("POST", "/v1/messages"), ("POST", "/v1/messages/count_tokens"), ("GET", "/v1/models")})
OWN_NETWORKS_EVERY = 60
MAX_HEADER = 16 * 1024
CONNECT_TIMEOUT = 20
# request headers passed through to the provider; everything else (auth, host, cookies, the
# container's own idea of where it is) stays behind
PASS_HEADERS = ("content-type", "accept", "anthropic-version", "anthropic-beta", "user-agent", "x-stainless-retry-count",
                "x-app")
# response headers passed back
RETURN_HEADERS = ("content-type", "request-id", "x-request-id", "retry-after", "anthropic-ratelimit-requests-remaining",
                  "anthropic-ratelimit-tokens-remaining")


def is_anthropic(model: str) -> bool:
    """Claude models: sent to the provider's Anthropic endpoint as they are."""
    m = (model or "").lower()
    return m.startswith(("anthropic/", "claude-", "claude/"))


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
                    data = json.loads(line[5:])
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


def _error_text(raw: bytes) -> str:
    try:
        data = json.loads(raw)
        err = data.get("error", data) if isinstance(data, dict) else data
        msg = err.get("message") if isinstance(err, dict) else err
        return str(msg or data)[:500]
    except ValueError:
        return raw.decode("utf-8", errors="replace")[:500]


@dataclass
class Upstream:
    """Where the builder's model requests go, and what it may ask for."""
    base_url: str                 # e.g. https://nano-gpt.com/api/v1 (paths like /v1/messages are appended)
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
    # the vision helper for models that can't see: (data URL, context) -> description
    describe: bridge.Describe | None = None
    vision_model: str = ""
    reasoning: str = "low"           # reasoning effort for translated models (never "none": see config)
    # which of NanoGPT's hosts runs a translated model: model id -> its route, or None for
    # NanoGPT's own choice (llm/routes.py)
    route: Callable[[str], dict | None] = lambda model: None


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
    token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    _servers: list[asyncio.AbstractServer] = field(default_factory=list)
    _uvicorn: object | None = None
    _uvicorn_task: asyncio.Task | None = None
    _own_http: bool = False
    _images: bridge.ImageDescriber | None = None

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
        proxy = await asyncio.start_unix_server(self._proxy_client, path=str(self.proxy_socket))
        self._servers.append(proxy)
        await self._start_model_server()
        for sock in (self.model_socket, self.proxy_socket):
            os.chmod(sock, 0o666)

    async def _start_model_server(self) -> None:
        import uvicorn
        config = uvicorn.Config(self.model_app(), uds=str(self.model_socket), log_level="warning",
                                lifespan="off", access_log=False, timeout_keep_alive=75)
        server = uvicorn.Server(config)
        server.install_signal_handlers = lambda: None   # the app's own server handles signals
        self._uvicorn = server
        self._uvicorn_task = asyncio.create_task(server.serve())
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
        for sock in (self.model_socket, self.proxy_socket):
            sock.unlink(missing_ok=True)

    # ---------------------------------------------------------------- the model endpoint

    def model_app(self):
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse, Response, StreamingResponse
        from starlette.routing import Route

        def error(status: int, message: str, kind: str = "permission_error") -> JSONResponse:
            return JSONResponse({"type": "error", "error": {"type": kind, "message": message}}, status_code=status)

        def fail(path: str, status: int, message: str, kind: str = "permission_error", **extra) -> JSONResponse:
            """Refuse, and say so in the activity log: the CLI only retries, and the user would see nothing."""
            self.on_event({"kind": "model", "path": path, "status": status, "error": message, **extra})
            return error(status, message, kind)

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
                base = check_url(up.base_url, "The assistant's endpoint").rstrip("/")
            except InsecureURL as e:
                return fail(path, 403, str(e))
            except Exception as e:  # noqa: BLE001 - the reason is the user's to see (no provider, no key)
                return fail(path, 403, f"DA Vibe Manager refused this request: {e}")
            key = up.key()
            if not key:
                return fail(path, 401, f"No API key is stored for {up.provider}; add it in Settings.", "authentication_error")
            body = await request.body()
            model, sent_model = "", ""
            if body and request.method == "POST":
                try:
                    data = json.loads(body)
                except ValueError:
                    return fail(path, 400, "The request body isn't JSON.", "invalid_request_error")
                if isinstance(data, dict) and "model" in data:
                    model = sent_model = str(data["model"])
                    if model not in up.models:
                        # Claude Code asks for its own defaults now and then; only the chosen models are used
                        sent_model = data["model"] = up.models[-1]
                        body = json.dumps(data).encode()
            if up.chat is not None and not is_anthropic(sent_model):
                return await self._translated(path, data if body else {}, up, sent_model, model, len(body))
            headers = {k: v for k, v in request.headers.items() if k.lower() in PASS_HEADERS}
            if up.auth == "x-api-key":
                headers["x-api-key"] = key
            else:
                headers["authorization"] = f"Bearer {key}"
            url = upstream_url(base, path, request.url.query)
            client = self._client()
            started = time.monotonic()
            req = client.build_request(request.method, url, content=body, headers=headers)
            try:
                resp = await client.send(req, stream=True)
            except httpx.HTTPError as e:
                return fail(path, 502, f"Could not reach {up.provider}: {e}", "api_error", model=sent_model)
            if resp.is_redirect:
                # never followed: the key would go wherever the provider points (one points at 0.0.0.0)
                where = resp.headers.get("location", "")[:200]
                await resp.aclose()
                return fail(path, 502, f"{up.provider} redirected the request to {where}; refusing to follow.",
                            "api_error", model=sent_model, url=url)
            rec = {"kind": "model", "path": path, "model": sent_model,
                   "asked_for": model if model != sent_model else "", "status": resp.status_code,
                   "provider": up.provider, "tier": up.tier, "bytes_out": len(body)}
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
                try:
                    async for chunk in resp.aiter_bytes():     # decoded here: the CLI gets plain bytes
                        n += len(chunk)
                        if whole is None:
                            usage.feed(chunk)
                        elif len(whole) < 8 << 20:
                            whole += chunk
                        yield chunk
                finally:
                    await resp.aclose()
                    if whole:
                        try:
                            usage.usage = anthropic_usage(json.loads(whole).get("usage"))
                        except (ValueError, AttributeError):
                            pass
                    self.on_event({**rec, "bytes_in": n, "seconds": round(time.monotonic() - started, 2),
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
        private = is_private_mode(model)

        def err(status: int, message: str):
            self.on_event({"kind": "model", "path": path, "model": model, "status": status, "error": message,
                           "private": private})
            return JSONResponse({"type": "error", "error": {"type": "api_error", "message": message}}, status_code=status)
        if path == "/v1/messages/count_tokens":
            return JSONResponse({"input_tokens": bridge.estimate_tokens(data)})
        if path != "/v1/messages":
            return err(404, f"{path} isn't available for {model}.")
        if self._images is None or self._images.model != up.vision_model:
            self._images = bridge.ImageDescriber(up.describe, up.vision_model)
        started = time.monotonic()
        try:
            messages, tools, params = await bridge.to_openai(data, self._images)
            params["reasoning_effort"] = up.reasoning or "low"
            route = None if private else up.route(model)
            params.update(routes.body(route))      # which of NanoGPT's hosts runs it, if the user chose
            if up.guard is not None:
                await up.guard(model)              # e.g. a TEE model's enclave attested; raises to refuse
            client = up.chat(model)
        except Exception as e:  # noqa: BLE001 - the CLI retries; the reason goes to the log
            return err(502, f"Couldn't prepare the request for {model}: {e}")
        estimate = bridge.estimate_tokens(data)
        rec = {"kind": "model", "path": path, "model": model, "asked_for": asked if asked != model else "",
               "status": 200, "provider": up.provider, "tier": "e2ee" if private else up.tier, "private": private,
               "bytes_out": size, **({"route": routes.describe(route)} if route else {})}
        events = client.stream(model, messages, tools, params)
        if not data.get("stream"):
            try:
                reply = await bridge.message(events, model, estimate)
            except Exception as e:  # noqa: BLE001
                return err(502, f"{model}: {e}")
            self.on_event({**rec, "seconds": round(time.monotonic() - started, 2), "usage": anthropic_usage(reply.get("usage"))})
            return JSONResponse(reply)

        async def body():
            n = 0
            stats: dict = {}
            try:
                async for chunk in bridge.sse(events, model, estimate, stats=stats,
                                              progress=lambda st: self.on_progress({"model": model, **st})):
                    n += len(chunk)
                    if chunk.startswith(b"event: error"):
                        rec.update(status=502, error=chunk.decode(errors="replace")[:300])
                    yield chunk
            finally:
                if "usage" in stats:
                    stats["usage"] = openai_usage(stats["usage"])
                self.on_event(_route_held({**rec, **stats, "bytes_in": n, "seconds": round(time.monotonic() - started, 2)}))
        return StreamingResponse(body(), media_type="text/event-stream")

    def _client(self) -> httpx.AsyncClient:
        if self.http is None:
            self._own_http = True

            async def refuse_insecure(response: httpx.Response) -> None:
                loc = response.headers.get("location")
                if response.is_redirect and loc and not is_secure(str(response.url.join(loc))):
                    raise httpx.HTTPError(f"redirect to insecure {loc[:100]!r} refused")

            self.http = httpx.AsyncClient(timeout=httpx.Timeout(600, connect=30), follow_redirects=False,
                                          event_hooks={"response": [refuse_insecure]})
        return self.http

    # ---------------------------------------------------------------- the HTTPS proxy

    def _own_networks(self) -> tuple:
        """This computer's addresses and networks, looked at again every minute (a laptop moves)."""
        now = time.monotonic()
        if self._own is None or now - self._own[0] > OWN_NETWORKS_EVERY:
            self._own = (now, self.own_networks())
        return self._own[1]

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
            rec["status"] = 200
            sent, received = await asyncio.gather(self._pipe(reader, up_writer), self._pipe(up_reader, writer))
            rec.update(bytes_out=sent, bytes_in=received)
        except Exception as e:  # noqa: BLE001 - one connection's failure never stops the gateway
            rec.setdefault("error", str(e))
        finally:
            rec["seconds"] = round(time.monotonic() - started, 2)
            if "host" in rec or rec["kind"] == "http":
                self.on_event(rec)
            writer.close()

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
