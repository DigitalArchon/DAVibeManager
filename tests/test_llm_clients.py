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


# --- a stream's lines: split at line ends alone, in time and memory its length takes (SealedLore's read_lines) -

def _pieces(data: bytes, size: int, taken: list | None = None):
    async def gen():
        for i in range(0, len(data), size):
            if taken is not None:
                taken.append(i)
            yield data[i:i + size]
    return gen()


@pytest.mark.parametrize("size", [1, 2, 3, 7, 1000])
async def test_a_streams_lines_read_in_any_pieces_are_split_at_line_ends_alone(size):
    """CRLF, CR or LF, a CRLF split between two pieces, a character split between two: and never at U+2028 or U+0085,
    which a JSON string may hold unescaped."""
    import re

    from davibemanager.llm.client import read_lines

    text = "data: one\r\ndata: two\rdata: thrée\n\ndata: f o\x85ur\r\n\r\nlast"
    got = [line async for line in read_lines(_pieces(text.encode(), size))]
    assert got == re.split(r"\r\n|\r|\n", text) and got[-1] == "last"
    assert [line async for line in read_lines(_pieces(b"a\r\n", size))] == ["a"]


async def test_a_long_line_costs_its_length_not_its_length_squared():
    """Every piece was added to the line so far and the whole of it split again: a megabyte-long line in small pieces
    took time growing with its square."""
    import time

    from davibemanager.llm.client import read_lines

    data = b"data: " + b"x" * (1024 * 1024) + b"\n"
    started = time.monotonic()
    (line,) = [line async for line in read_lines(_pieces(data, 32))]
    assert len(line) == len(data) - 1
    assert time.monotonic() - started < 5.0


async def test_a_line_that_never_ends_is_refused_before_it_fills_memory(monkeypatch):
    """A provider (or whatever answers at its address) that sends one line for ever was read for ever, all of it
    held. Now it is refused at MAX_LINE_CHARS, nothing more read: through the client the gateway and the app's own
    requests use, and a private model's sealed stream alike."""
    from davibemanager.llm import client as client_mod
    from davibemanager.llm.secure_http import ProviderError

    monkeypatch.setattr(client_mod, "MAX_LINE_CHARS", 10_000)
    taken: list = []
    body = _pieces(b"data: " + b"x" * 10_000_000, 1000, taken)
    http = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})))
    with pytest.raises(ProviderError, match="a line of more than"):
        async for _ in LLMClient("https://nano-gpt.com/api/v1", "k", http).stream("m", USER):
            pass
    assert len(taken) < 20, "read no further than the limit"

    from test_private_mode import Relay, collect
    relay = Relay(replies=[(200, "data: " + "x" * 20_000)])
    with pytest.raises(ProviderError, match="a line of more than"):
        await collect(relay.client())


async def test_a_private_models_reply_keeps_a_character_httpx_would_have_split_a_line_at():
    """httpx's aiter_lines splits as str.splitlines does, at U+0085 and U+2028 too, which a JSON string may hold
    unescaped: the chunk's two halves weren't JSON, and were dropped without a word."""
    from test_private_mode import Relay, chunk, collect

    reply = (chunk({"role": "assistant", "content": "a\x85b c"}).replace("\\u0085", "\x85").replace("\\u2028", " ")
             + chunk({}, "stop") + "data: [DONE]\n\n")
    assert "\x85" in reply
    events = await collect(Relay(replies=[(200, reply)]).client())
    assert "".join(v for k, v in events if k == "text") == "a\x85b c"


async def test_an_overflow_is_recognised_however_the_openai_library_words_its_error():
    """openai 3.38 and later write only the body's "message" into an error's text, and nothing of a body that isn't
    JSON: the code (context_length_exceeded) and a plain-text answer are in its .body alone (DA Toolkit's test: a
    source install there took 3.51 and saw no overflow as one)."""
    import openai

    def answer(request):
        if b"plain" in request.content:
            return httpx.Response(400, text="prompt is too long: 210345 tokens > 200000 maximum")
        return httpx.Response(400, json={"error": {"message": "This request is too long for the model's context window.",
                                                   "code": "context_length_exceeded"}})

    client = LLMClient("https://fake.example/v1", "sk-test", httpx.AsyncClient(transport=httpx.MockTransport(answer)))
    errors = []
    for asked in ("json", "plain"):
        with pytest.raises(openai.APIStatusError) as caught:
            await client.complete("m", [{"role": "user", "content": asked}])
        errors.append(caught.value)
    for error, limit in zip(errors, (None, 200000)):
        message = error.body.get("message") if isinstance(error.body, dict) else None
        # as the openai installed wrote it, and as 3.38 and later write it
        later = type(error)("Error code: 400" + (f" - {message}" if message else ""), response=error.response,
                            body=error.body)
        assert capabilities.overflow(error) == capabilities.overflow(later) == (True, limit), str(error)
    assert capabilities.overflow("Error code: 400") == (False, None)


async def _provider_errors(*answers):
    """The errors the real client raises for each of `answers` (httpx.Response), as the openai installed words
    them, each with its twin as openai 3.38 and later word it: only the body's message in the text."""
    import openai

    out = []
    for answer in answers:
        client = LLMClient("https://fake.example/v1", "sk-test",
                           httpx.AsyncClient(transport=httpx.MockTransport(lambda r, a=answer: a)))
        with pytest.raises(openai.APIStatusError) as caught:
            await client.complete("m", [{"role": "user", "content": "hi"}])
        error = caught.value
        message = error.body.get("message") if isinstance(error.body, dict) else None
        later = type(error)(f"Error code: {error.status_code}" + (f" - {message}" if message else ""),
                            response=error.response, body=error.body)
        out.append((error, later))
    return out


async def test_a_key_the_provider_refuses_is_told_in_words_never_as_statuses():
    """A key NanoGPT refuses read in the turn as "API Error: 403 glm: NanoGPT refused the request (HTTP 401): Error
    code: 401 - Invalid session (the provider said: ...)": two statuses, neither the user's to read. Now what happened
    and what to do, with the provider's own message; still a 403 to Claude Code (a 401 it takes for its own login)."""
    from davibemanager.gateway import upstream_refusal

    (key, key_later), (barred, barred_later) = await _provider_errors(
        httpx.Response(401, json={"error": {"message": "Invalid session", "type": "invalid_api_key",
                                            "code": "invalid_api_key", "status": 401}}),
        httpx.Response(403, json={"error": {"message": "This model isn't available on your plan"}}))
    for error in (key, key_later):
        told = upstream_refusal("z-ai/glm-5.3", error, "NanoGPT")
        assert told.status == 403
        assert str(told) == ("NanoGPT didn't accept the API key, so z-ai/glm-5.3 wasn't asked anything. Check the "
                             "API key in Settings. (NanoGPT said: Invalid session)")
    for error in (barred, barred_later):
        told = upstream_refusal("z-ai/glm-5.3", error, "NanoGPT")
        assert told.status == 403
        assert str(told) == ("NanoGPT wouldn't run z-ai/glm-5.3 for this API key. (NanoGPT said: This model isn't "
                             "available on your plan)")
    plain = (await _provider_errors(httpx.Response(401, text="no")))[0][0]
    assert str(upstream_refusal("glm", plain, "NanoGPT")).endswith("(NanoGPT said: no)")


async def test_a_providers_words_are_read_whole_and_told_labelled_short_whichever_openai_wrote_them():
    """llm/errors.py (DA Toolkit's): what Claude Code is told of a refusal, and Sandbox activity shows, is the status,
    the provider's message and the rest of its answer labelled as its own, on one line and cut short, on either
    openai; the settings and efforts a route refuses are found in the body too. 3.37 put the whole body in the
    text, uncut; 3.38 and later nothing of one that isn't JSON."""
    from types import SimpleNamespace

    from davibemanager.config import Config
    from davibemanager.gateway import Gateway, upstream_refusal
    from davibemanager.llm.errors import SHOWN_WORDS, shown_error
    from davibemanager.models import Models

    (plain, plain_later), (coded, coded_later), (long, long_later), (setting, setting_later), (effort, effort_later) = \
        await _provider_errors(
            httpx.Response(400, text="the upstream said no:\nquota exceeded for this key"),
            httpx.Response(400, json={"error": {"message": "This request is too long.", "code": "context_length_exceeded"}}),
            httpx.Response(400, text="x" * 70_000),
            httpx.Response(400, text="moonshotai/kimi-k3 does not support temperature on the selected route"),
            httpx.Response(400, text="reasoning_effort must be one of low, high, max"))
    assert shown_error(plain) == shown_error(plain_later) == \
        "Error code: 400 (the provider said: the upstream said no: quota exceeded for this key)"
    assert shown_error(coded) == shown_error(coded_later) == \
        'Error code: 400 - This request is too long. (the provider said: {"code": "context_length_exceeded"})'
    assert shown_error(long) == shown_error(long_later) == f"Error code: 400 (the provider said: {'x' * SHOWN_WORDS})"
    for error in (plain, plain_later):
        told = upstream_refusal("glm", error, "NanoGPT")
        assert str(told) == "glm: Error code: 400 (the provider said: the upstream said no: quota exceeded for this key)"
    assert len(str(upstream_refusal("glm", long_later, "NanoGPT"))) < 400
    models = Models(Config(), save_config=lambda c: None, emit=lambda *a, **k: None, log=lambda *a, **k: None)
    prov = SimpleNamespace(name="NanoGPT")
    for error in (setting, setting_later):
        assert models.learn_unsupported(prov, "kimi", {"temperature": 0.3}, error) == "temperature"
    for error in (effort, effort_later):
        gateway = SimpleNamespace(_efforts={})
        assert Gateway._learned(gateway, "kimi", error, "medium") == "high" and gateway._efforts["kimi"] == ("low", "high", "max")


async def test_an_entry_that_is_no_model_doesnt_take_the_model_list_down():
    """One entry without an id, or that isn't an object at all, lost the whole list to Python's own error
    ("KeyError: 'id'", "'<' not supported between instances of 'NoneType' and 'str'"), and a size given as text
    failed later, where a request's max_tokens is held to it (until Nov 2026; DA Private Coder skipped them)."""
    listed = [{"id": "good", "object": "model", "context_length": "128k", "max_output_tokens": "8k",
               "capabilities": ["vision"], "reasoning_efforts": "high", "subscription": "yes"},
              {"object": "model"}, {"id": 5}, "junk", None, {"id": ""}]
    caps = capabilities.parse(listed)
    assert list(caps) == ["good"] and caps["good"]["context"] is None and caps["good"]["max_output"] is None
    assert caps["good"]["vision"] is False and caps["good"]["efforts"] == []
    assert capabilities.parse(None) == {} and capabilities.parse("junk") == {}
    answer = json.dumps({"object": "list", "data": listed}).encode()
    async with Stub({"/v1/models": ("application/json", answer)}) as provider:
        assert await LLMClient(f"http://127.0.0.1:{provider.port}/v1", "sk-local-1").list_models() == ["good"]
