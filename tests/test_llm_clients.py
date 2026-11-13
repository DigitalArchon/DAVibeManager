"""The model clients on the wire (llm/client.py, and the smaller clients built from a provider's
address): what reaches a proxy the environment names, and what doesn't (DA Toolkit's c6de017).

A stub proxy and a stub provider listen on loopback; nothing here leaves the machine."""

import asyncio
import json

import httpx
import pytest

from davibemanager.gateway import Gateway, Upstream
from davibemanager.llm import capabilities, routes, websearch
from davibemanager.llm.client import LLMClient
from davibemanager.llm.secure_http import local_http_options, make_client

USER = [{"role": "user", "content": "the database password is hunter2"}]
CHUNK = {"id": "c1", "object": "chat.completion.chunk", "created": 0, "model": "m",
         "choices": [{"index": 0, "delta": {"content": "fine"}, "finish_reason": "stop"}]}


class Stub:
    """An HTTP server on loopback that keeps what it was sent. As a provider it answers every
    path with what `answers` holds for it; as a proxy it answers 502 to everything."""

    def __init__(self, answers: dict | None = None):
        self.answers = answers
        self.seen: list[bytes] = []
        self.server = None

    async def __aenter__(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        self.server.close()
        await self.server.wait_closed()

    def paths(self) -> list[str]:
        return [raw.split(b" ")[1].decode() for raw in self.seen]

    async def _handle(self, reader, writer):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            length = next((int(line.split(b":")[1]) for line in head.split(b"\r\n")
                           if line.lower().startswith(b"content-length:")), 0)
            body = await reader.readexactly(length) if length else b""
            self.seen.append(head + body)
            path = head.split(b" ")[1].decode().split("?")[0]
            found = (self.answers or {}).get(path) if self.answers is not None else None
            if found is None:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            else:
                kind, content = found
                writer.write(f"HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {len(content)}\r\n"
                             "Connection: close\r\n\r\n".encode() + content)
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()


@pytest.fixture
async def proxy(monkeypatch):
    """A proxy on loopback that every proxy variable names, and nothing exempted from it."""
    async with Stub() as stub:
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            monkeypatch.setenv(name, f"http://127.0.0.1:{stub.port}")
            monkeypatch.setenv(name.lower(), f"http://127.0.0.1:{stub.port}")
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        yield stub


MODELS = json.dumps({"object": "list", "data": [{"id": "m", "object": "model"}]}).encode()
PROVIDER = {"/v1/chat/completions": ("text/event-stream", f"data: {json.dumps(CHUNK)}\n\ndata: [DONE]\n\n".encode()),
            "/v1/models": ("application/json", MODELS),
            "/v1/messages": ("application/json", b'{"type": "message", "content": []}'),
            "/api/web": ("application/json", b'{"data": []}'),
            "/api/models/m/providers": ("application/json", b'{"providers": []}'),
            "/attest": ("application/json", b"{}")}


async def test_a_local_provider_is_reached_directly_whatever_proxy_the_environment_names(proxy, tmp_path):
    """Until Nov 2026 only loopback was kept off the proxy here: a provider at 192.168.x or a .local
    name sent its key and the conversation to HTTP_PROXY / ALL_PROXY like any other. The stub is on
    loopback, which local_http_options counts with the rest of the local network."""
    async with Stub(PROVIDER) as provider:
        base = f"http://127.0.0.1:{provider.port}"
        client = LLMClient(base + "/v1", "sk-local-SECRET")
        events = [e async for e in client.stream("m", USER)]
        assert events[-1][0] == "done" and events[-1][1].content == "fine"
        assert await client.list_models() == ["m"]
        await capabilities.fetch_nanogpt(base + "/v1", "sk-local-SECRET")
        await websearch.web_search(base + "/api/v1", "sk-local-SECRET", "a query")
        await routes.fetch_hosts(base + "/api/v1", "m")
        def attest() -> int:                                  # the TEE verifier's client (sync: off the loop)
            with make_client(base) as c:
                return c.get(base + "/attest").status_code
        assert await asyncio.to_thread(attest) == 200
        # the gateway's forwarder (an Anthropic-compatible provider, passed through as it is)
        g = Gateway(tmp_path / "gw", lambda: Upstream(base + "/v1", "x-api-key", lambda: "sk-local-SECRET", ("m",)))
        try:
            assert g._client(base + "/v1/messages").trust_env is False
            assert g._client("https://api.anthropic.com/v1/messages").trust_env is True
            r = await g._client(base + "/v1/messages").post(base + "/v1/messages", content=json.dumps(USER))
            assert r.status_code == 200
        finally:
            await g.stop()
        assert proxy.seen == [], "nothing for a local address reaches the proxy"
        assert set(provider.paths()) >= {"/v1/chat/completions", "/v1/models", "/v1/models?detailed=true",
                                         "/api/web", "/api/models/m/providers", "/attest", "/v1/messages"}


async def test_any_other_address_keeps_the_environments_proxy(proxy):
    client = LLMClient("https://models.example.invalid/v1", "sk-x")
    client._client = client._client.with_options(max_retries=0)
    with pytest.raises(Exception):                                    # noqa: B017 - the stub proxy answers 502
        [e async for e in client.stream("m", USER)]
    assert len(proxy.seen) == 1 and proxy.seen[0].startswith(b"CONNECT models.example.invalid:443")


def test_which_addresses_stay_off_the_proxy():
    for local in ("http://localhost:11434/v1", "http://127.0.0.1:8080/v1", "http://[::1]:1234/v1", "http://10.0.0.5/v1",
                  "http://172.16.0.1/v1", "http://192.168.1.50:11434/v1", "http://169.254.10.10/v1", "http://[fe80::1]/v1",
                  "http://[fd12:3456:789a::1]/v1", "http://ollama.local:11434/v1", "https://ollama.local/v1",
                  "https://192.168.1.50/v1"):
        assert local_http_options(local)["trust_env"] is False, local
        assert LLMClient(local, "k")._client._client.trust_env is False, local
        with make_client(local) as c:
            assert c.trust_env is False, local
    for other in ("https://nano-gpt.com/api/v1", "https://api.anthropic.com", "https://192.0.2.7/v1",
                  "https://127.0.0.1.evil.example/v1", "https://lan/v1", "https://[2001:db8::1]/v1"):
        assert local_http_options(other) == {}, other
        assert LLMClient(other, "k")._client._client.trust_env is True, other
        with make_client(other) as c:
            assert c.trust_env is True, other


def test_a_local_https_server_is_still_checked_against_the_environments_certificates(tmp_path, monkeypatch):
    """`trust_env=False` alone would also stop SSL_CERT_FILE being read, which the AppImage sets to
    the system's bundle so that a company's own CA stands for a server on its network."""
    import certifi

    bundle = tmp_path / "company-ca.pem"
    bundle.write_text(open(certifi.where()).read().split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n")
    monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
    context = local_http_options("https://192.168.1.50/v1")["verify"]
    assert len(context.get_ca_certs()) == 1                              # the one certificate of that file
    assert context.verify_mode.name == "CERT_REQUIRED" and context.check_hostname
    assert isinstance(httpx.AsyncClient(**local_http_options("https://192.168.1.50/v1")), httpx.AsyncClient)


# ---------------------------------------------------------------- the SDK's own environment variables (DA Toolkit's 624a4be)

async def test_the_sdks_environment_adds_no_header_to_a_provider(monkeypatch):
    """OPENAI_ORG_ID, OPENAI_PROJECT_ID and OPENAI_CUSTOM_HEADERS are for OpenAI's own service: whatever
    another tool or the shell set there went, as headers, to every provider. A provider is sent its own
    key and nothing else."""
    import httpx2                                       # the SDK's own HTTP library
    from openai import DefaultAsyncHttpxClient

    for name, value in {"OPENAI_ORG_ID": "org-ENV", "OPENAI_PROJECT_ID": "proj-ENV", "OPENAI_API_KEY": "ENV-OPENAI-KEY",
                        "OPENAI_ADMIN_KEY": "ENV-ADMIN-KEY", "OPENAI_BASE_URL": "https://env-base.invalid/v1",
                        "OPENAI_CUSTOM_HEADERS": "X-Env: 1\nAuthorization: Bearer ENV-HEADER-KEY\nOpenAI-Beta: env"}.items():
        monkeypatch.setenv(name, value)
    got: list[tuple[str, dict]] = []

    def handler(request):
        got.append((str(request.url), {k.lower(): v for k, v in request.headers.items()}))
        if request.url.path.endswith("/models"):
            return httpx2.Response(200, json={"object": "list", "data": []})
        if not json.loads(request.content).get("stream"):
            return httpx2.Response(200, json={"id": "c", "object": "chat.completion", "created": 0, "model": "m", "choices": [
                {"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "fine"}}]})
        return httpx2.Response(200, headers={"content-type": "text/event-stream"},
                              content=f"data: {json.dumps(CHUNK)}\n\ndata: [DONE]\n\n".encode())

    for base, key in (("https://models.example/api/v1", "PROVIDER-KEY"), ("http://localhost:11434/v1", None)):
        client = LLMClient(base, key, http_client=DefaultAsyncHttpxClient(transport=httpx2.MockTransport(handler)))
        client._client = client._client.with_options(max_retries=0)       # a copy the SDK makes is cleared too
        await client.list_models()
        [e async for e in client.stream("m", USER)]
        assert await client.complete("m", USER) == "fine"
    assert len(got) == 6
    for url, headers in got:
        assert not url.startswith("https://env-base.invalid"), url
        assert headers["authorization"] in ("Bearer PROVIDER-KEY", "Bearer not-needed"), url
        for name in ("openai-organization", "openai-project", "x-env", "openai-beta"):
            assert name not in headers, (url, name)
        assert "ENV" not in json.dumps(headers), url


# ---------------------------------------------------------------- a server that isn't there (DA Toolkit's 2d1aa54)

def test_connecting_has_a_timeout_of_its_own_beside_the_long_wait_for_a_reply():
    from davibemanager.llm.client import CONNECT_TIMEOUT

    assert CONNECT_TIMEOUT <= 15
    timeout = LLMClient("http://192.168.1.50:11434/v1", None)._client.timeout
    assert timeout.connect == CONNECT_TIMEOUT and timeout.read == 300


async def test_a_model_server_that_never_answers_the_connection_fails_soon(monkeypatch):
    """A machine that is switched off takes no connection and refuses none. Here: a listening socket
    that accepts nothing, its queue filled, so the next connection waits for ever."""
    import socket

    from davibemanager.llm import client as client_module

    monkeypatch.setattr(client_module, "CONNECT_TIMEOUT", 0.3)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(0)
    port = listener.getsockname()[1]
    held = []
    try:
        for _ in range(4):                       # more than the queue holds: these are never accepted
            s = socket.socket()
            s.setblocking(False)
            s.connect_ex(("127.0.0.1", port))
            held.append(s)
        client = LLMClient(f"http://127.0.0.1:{port}/v1", None)
        client._client = client._client.with_options(max_retries=0)
        with pytest.raises(Exception, match="(?i)timed out|timeout"):
            await asyncio.wait_for(client.complete("m", USER), 5)       # 300 s without the connect timeout
    finally:
        for s in held + [listener]:
            s.close()
