"""What is read from outside is read only so far, as every DA app reads it (the cross-app standard, Nov
2026; DA Toolkit's tests/test_untrusted_bodies.py): only gzip and deflate asked for and any other coding
refused unread, an error's body read to 64 KB, a whole body to 32 MB (both counted decoded), and JSON
nested no deeper than 200 levels, wherever it comes from: a provider, NanoGPT's relay, the gateway's
caller, another computer in a sync group, a backup, the window's own API."""

import gzip
import json
import unittest.mock

import httpx
import httpx2
import pytest

from davibemanager import backup
from davibemanager.config import Config
from davibemanager.engine import Engine
from davibemanager.llm import client as client_mod
from davibemanager.llm import private_mode, secure_http, tee
from davibemanager.llm.client import LLMClient, capped_lines, reading_options
from davibemanager.llm.secure_http import MAX_NESTING, ProviderError, TooDeep, loads, make_client, nests_deeper
from davibemanager.server.app import create_app
from davibemanager.sync import wire

from test_private_mode import BASE, RELAY, Relay


def nested(depth: int) -> str:
    return "[" * depth + "]" * depth


def pieces(data: bytes, size: int = 4096):
    """A body as a connection hands it over, a piece at a time (bytes given whole are read at once)."""
    return iter([data[i:i + size] for i in range(0, len(data), size)])


async def apieces(data: bytes, size: int = 4096):
    for i in range(0, len(data), size):
        yield data[i:i + size]


@pytest.fixture(autouse=True)
def no_proxies(monkeypatch):
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)


def test_json_from_outside_is_refused_past_two_hundred_levels():
    assert loads(nested(MAX_NESTING)) is not None
    assert not nests_deeper(json.loads(nested(MAX_NESTING)))
    with pytest.raises(TooDeep):
        loads(nested(MAX_NESTING + 1))
    with pytest.raises(TooDeep):
        loads(nested(100_000))                  # past what Python's parser takes: no RecursionError


# ------------------------------------------------------------------- the sync client (TEE, Intel, NVIDIA)

def sync_client(handler) -> httpx.Client:
    client = make_client("https://x.test")
    client._transport = httpx.MockTransport(handler)
    return client


def test_the_attestation_client_asks_for_gzip_and_deflate_alone_and_refuses_another_coding():
    seen = {}

    def handler(request):
        seen.update(request.headers)
        return httpx.Response(200, json={})
    sync_client(handler).get("https://x.test/")
    assert seen["accept-encoding"] == "gzip, deflate"
    with pytest.raises(ProviderError, match="compressed as 'br'"):
        sync_client(lambda r: httpx.Response(200, content=b"x", headers={"content-encoding": "br"})).get(
            "https://x.test/")


def test_the_attestation_client_reads_an_error_to_64_kb_and_a_body_to_32_mb(monkeypatch):
    big = b"e" * (secure_http.MAX_ERROR_BYTES * 10)
    assert len(sync_client(lambda r: httpx.Response(500, content=pieces(big))).get("https://x.test/").content) \
        == secure_http.MAX_ERROR_BYTES
    monkeypatch.setattr(secure_http, "MAX_BODY_BYTES", 100_000)
    packed = gzip.compress(b"0" * 1_000_000)
    with pytest.raises(ProviderError, match="sent more than"):
        sync_client(lambda r: httpx.Response(200, content=pieces(packed), headers={"content-encoding": "gzip"})).get(
            "https://x.test/")


def test_a_session_record_nested_past_reading_is_a_note_never_a_crash():
    client = sync_client(lambda r: httpx.Response(200, content=nested(50_000).encode()))
    with pytest.raises(ProviderError, match="couldn't be read"):
        tee._session_record(client, "ab" * 32)


# ------------------------------------------------------------------- the async clients

async def read_through_hook(response: httpx.Response) -> bytes:
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: response),
                                 event_hooks={"response": [capped_lines]}) as client:
        return (await client.get("https://x.test/")).content


async def test_an_error_body_is_read_to_64_kb_and_a_whole_body_to_32_mb(monkeypatch):
    body = await read_through_hook(httpx.Response(400, content=apieces(b"e" * (secure_http.MAX_ERROR_BYTES * 4))))
    assert len(body) == secure_http.MAX_ERROR_BYTES
    monkeypatch.setattr(client_mod, "MAX_BODY_BYTES", 50_000)
    with pytest.raises(ProviderError, match="sent more than"):
        await read_through_hook(httpx.Response(200, content=apieces(b"line\n" * 20_000),
                                               headers={"content-type": "application/json"}))
    streamed = await read_through_hook(httpx.Response(200, content=apieces(b"data: x\n\n" * 20_000),
                                                      headers={"content-type": "text/event-stream"}))
    assert len(streamed) == 9 * 20_000           # an event stream is held to its lines, not its length
    with pytest.raises(ProviderError, match="compressed as 'zstd'"):
        await read_through_hook(httpx.Response(200, content=b"x", headers={"content-encoding": "zstd"}))


async def test_a_reply_asked_for_whole_is_held_to_32_mb_whatever_its_content_type(monkeypatch):
    monkeypatch.setattr(client_mod, "MAX_BODY_BYTES", 50_000)
    client = LLMClient("https://x.test/v1", "k")
    client._client._client._transport = httpx2.MockTransport(lambda request: httpx2.Response(
        200, content=apieces(b"data: x\n\n" * 20_000), headers={"content-type": "text/event-stream"}))
    with pytest.raises(ProviderError, match="sent more than"):
        await client.complete("m", [{"role": "user", "content": "hi"}])


def test_every_client_reading_a_provider_asks_for_gzip_and_deflate_alone():
    """httpx (and httpx2, the SDK's) ask for br too whenever brotli is installed, and it is."""
    assert dict(LLMClient("https://x.test/v1", "k")._client._client.headers)["accept-encoding"] == "gzip, deflate"
    options = reading_options("https://x.test")
    assert options["headers"]["Accept-Encoding"] == "gzip, deflate"
    assert capped_lines in options["event_hooks"]["response"]


async def test_the_gateways_own_clients_ask_for_gzip_and_deflate_and_read_only_so_far(tmp_path):
    from davibemanager.gateway import Gateway
    g = Gateway(tmp_path / "gw", lambda: None, on_event=lambda e: None)
    for url in ("https://upstream.example/v1/messages", "http://192.168.1.5:8080/v1/messages"):
        client = g._client(url)
        assert client.headers["accept-encoding"] == "gzip, deflate"
        assert capped_lines in client.event_hooks["response"]
        await client.aclose()


# ------------------------------------------------------------------- Private Mode

async def test_private_modes_requests_ask_for_gzip_and_deflate_alone():
    relay = Relay()
    seen, plain_seen = [], []
    factory = relay.transport

    def watching(key, proxy=None):
        inner = factory(key, proxy)

        def handle(request):
            seen.append(request.headers.get("accept-encoding"))
            return inner.handle_request(request)
        return httpx.MockTransport(handle)
    client = private_mode.PrivateModeClient(BASE, "sk-test", private_mode.Enclave(RELAY, verifier=relay.verifier),
                                            transport_factory=watching)

    async def plain(request):
        plain_seen.append(request.headers.get("accept-encoding"))
        return relay.preflight(request)
    original = httpx.AsyncClient

    def built(**kwargs):
        kwargs.setdefault("transport", httpx.MockTransport(plain))
        return original(**kwargs)
    with unittest.mock.patch.object(private_mode.httpx, "AsyncClient", built):
        [event async for event in client.stream("private/glm-5-3", [{"role": "user", "content": "x"}])]
    assert seen == ["gzip, deflate"] and plain_seen and set(plain_seen) == {"gzip, deflate"}


async def test_the_relays_error_body_is_read_to_64_kb_and_a_nested_preflight_refused():
    relay = Relay()
    client = relay.client()
    client._transport_factory = lambda key, proxy=None: httpx.MockTransport(lambda request: httpx.Response(
        500, content=apieces(b"x" * (secure_http.MAX_ERROR_BYTES * 3))))
    with pytest.raises(private_mode.PrivateModeError) as raised:
        [event async for event in client.stream("private/glm-5-3", [{"role": "user", "content": "x"}])]
    assert len(raised.value.body) == secure_http.MAX_ERROR_BYTES
    client = Relay().client()
    client._plain = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: relay.preflight(r) if r.url.path.endswith("/models") else httpx.Response(200, text=nested(50_000))))
    with pytest.raises(private_mode.PrivateModeError, match="wasn't JSON"):
        [event async for event in client.stream("private/glm-5-3", [{"role": "user", "content": "x"}])]


# ------------------------------------------------------------------- what this app is sent otherwise

async def test_a_sync_message_nested_past_reading_is_refused_in_words(monkeypatch):
    for depth in (300, 60_000):
        reader = __import__("asyncio").StreamReader()
        data = nested(depth).encode()
        reader.feed_data(b"J" + len(data).to_bytes(4, "big") + data)
        reader.feed_eof()
        with pytest.raises(wire.WireError, match="can't be read"):
            await wire.recv(reader)


def test_a_backup_whose_json_is_nested_past_reading_is_damaged_not_a_crash(tmp_path):
    import io
    header = nested(30_000).encode()
    with pytest.raises(backup.BackupError, match="damaged"):
        backup.read_header(io.BytesIO(backup.MAGIC + len(header).to_bytes(4, "big") + header))
    unpacked = tmp_path / "unpacked"
    state = unpacked / "data" / "conversations" / "c1" / "state.json"
    state.parent.mkdir(parents=True)
    state.write_text('{"chat": ' + nested(300) + "}")
    with pytest.raises(backup.BackupError, match="damaged"):
        backup.settle(unpacked, Config())


async def test_the_gateways_callers_body_is_read_nested_no_deeper_than_200_levels(tmp_path):
    from test_gateway import _model_client
    from davibemanager.gateway import Gateway, Upstream
    sent = []
    g = Gateway(tmp_path / "gw", lambda: Upstream("https://upstream.example/api/v1", "bearer", lambda: "sk-real",
                                                  ("big-model",), provider="Up"),
                on_event=lambda e: None,
                http=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(
                    200, text='event: message_stop\ndata: {"ok": true}\n\n',
                    headers={"content-type": "text/event-stream"}))))
    await g.start()
    try:
        async with _model_client(g) as c:
            body = '{"model": "big-model", "metadata": {"x": ' + nested(300) + "}}"
            r = await c.post("/v1/messages", headers={"authorization": f"Bearer {g.token}",
                                                      "content-type": "application/json"}, content=body)
        assert r.status_code == 400 and "isn't JSON" in r.text and not sent
    finally:
        await g.stop()


async def test_the_windows_api_reads_a_body_nested_no_deeper_than_200_levels(tmp_path):
    def make(emit):
        e = Engine(Config(), emit, tmp_path, save_config=lambda c: None)
        e.start_workspace = lambda: None
        return e
    app = create_app("secret", make)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
                                     headers={"x-token": "secret", "content-type": "application/json"}) as c:
            for depth, status in ((150, 200), (300, 400), (5000, 400)):
                r = await c.post("/api/settings", content='{"theme": "light", "x": ' + nested(depth) + "}")
                assert r.status_code == status, (depth, r.status_code, r.text[:200])
