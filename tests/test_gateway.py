"""The workspace's gateway: the HTTPS-only, public-only proxy and the model forwarder that holds the key."""

import asyncio
import ipaddress
import json

import httpx
import pytest

from davibemanager.gateway import Gateway, Upstream


@pytest.fixture
async def gw(tmp_path):
    events, upstream_reqs = [], []
    state = {"refuse": None, "base": "https://upstream.example/api/v1"}

    def upstream():
        if state["refuse"]:
            raise RuntimeError(state["refuse"])
        return Upstream(state["base"], "bearer", lambda: "sk-real", ("big-model", "small-model"), provider="Up")

    def handler(request: httpx.Request) -> httpx.Response:
        upstream_reqs.append(request)
        return httpx.Response(200, text='event: message_stop\ndata: {"ok": true}\n\n',
                              headers={"content-type": "text/event-stream", "request-id": "r1", "set-cookie": "x=y"})

    async def resolver(host, port):
        return {"github.com": ["140.82.112.3"], "evil.example": ["140.82.112.4", "192.168.1.1"],
                "rebind.example": ["10.0.2.2"]}.get(host, [])

    echo = await asyncio.start_server(_echo, "127.0.0.1", 0)
    echo_port = echo.sockets[0].getsockname()[1]

    async def connector(ip, port):
        assert ip == "140.82.112.3" and port == 443          # the checked address, never the name
        return await asyncio.open_connection("127.0.0.1", echo_port)

    g = Gateway(tmp_path / "gw", upstream, on_event=events.append, resolver=resolver, connector=connector,
                http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    await g.start()
    yield g, events, upstream_reqs, state
    await g.stop()
    echo.close()


async def _echo(reader, writer):
    while data := await reader.read(1024):
        writer.write(data.upper())
        await writer.drain()
    writer.close()


async def _proxy(g, head: bytes) -> tuple[bytes, asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_unix_connection(str(g.proxy_socket))
    writer.write(head)
    await writer.drain()
    reply = await reader.readuntil(b"\r\n\r\n")
    return reply, reader, writer


async def test_connect_to_a_public_address_is_relayed_and_logged(gw):
    g, events, _, _ = gw
    reply, reader, writer = await _proxy(g, b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n")
    assert reply.startswith(b"HTTP/1.1 200")
    writer.write(b"hello")
    await writer.drain()
    assert await reader.readexactly(5) == b"HELLO"
    writer.close()
    for _ in range(100):
        if events:
            break
        await asyncio.sleep(0.01)
    assert events[-1]["host"] == "github.com" and events[-1]["status"] == 200 and events[-1]["bytes_out"] == 5


@pytest.mark.parametrize("target,why", [
    ("evil.example:443", b"private network"),         # one private address among public ones is enough
    ("rebind.example:443", b"private network"),
    ("192.168.1.1:443", b"private network"),
    ("[::ffff:127.0.0.1]:443", b"private network"),     # loopback, however it's written
    ("[64:ff9b::a00:202]:443", b"private network"),     # 10.0.2.2 through NAT64
    ("[2002:c0a8:101::1]:443", b"private network"),     # 192.168.1.1 through 6to4
    ("mine.example:443", b"private network"),          # this computer's own global IPv6 address
    ("printer.example:443", b"private network"),       # another device on its network
    ("github.com:22", b"Port 22 is refused"),
    ("github.com:80", b"Port 80 is refused"),
])
async def test_connect_to_anything_but_public_https_is_refused(gw, target, why):
    g, events, _, _ = gw

    async def resolver(host, port):
        return {"evil.example": ["140.82.112.4", "192.168.1.1"], "rebind.example": ["10.0.2.2"],
                "github.com": ["140.82.112.3"], "mine.example": ["2a02:8108:1:2::10"],
                "printer.example": ["2a02:8108:1:2::99"]}.get(host, [host])
    g.resolver = resolver
    g.own_networks = lambda: (ipaddress.ip_network("2a02:8108:1:2::/64"), ipaddress.ip_network("2a02:8108:1:2::10/128"))
    reply, reader, writer = await _proxy(g, f"CONNECT {target} HTTP/1.1\r\n\r\n".encode())
    body = await reader.read()
    assert reply.startswith(b"HTTP/1.1 403") and why in body
    writer.close()


async def test_a_host_name_carrying_something_from_this_computer_is_refused(gw):
    """The name is all of an HTTPS connection the gateway sees: data put in it is refused."""
    g, events, _, _ = gw
    asked = []

    def refuse_host(host):
        asked.append(host)
        return "Refused: the host name holds something from this computer" if host.startswith("sam-laptop.") else ""
    g.refuse_host = refuse_host
    reply, reader, writer = await _proxy(g, b"CONNECT sam-laptop.collect.example:443 HTTP/1.1\r\n\r\n")
    assert reply.startswith(b"HTTP/1.1 403") and b"from this computer" in await reader.read()
    writer.close()
    reply, _, writer = await _proxy(g, b"CONNECT github.com:443 HTTP/1.1\r\n\r\n")
    assert reply.startswith(b"HTTP/1.1 200") and asked == ["sam-laptop.collect.example", "github.com"]
    writer.close()


def test_only_the_labels_before_a_sites_own_name_are_checked(tmp_path):
    from davibemanager.safety.outside import OutsideData
    o = OutsideData(tmp_path / "outside.json", names=["sam-laptop"])
    o.add("Linux sam-laptop 6.8.0-45-generic x86_64 github.com/gnome")
    assert o.check_host("sam-laptop.collect.example") and o.check_host("6.8.0-45-generic.x.example")
    assert not o.check_host("github.com") and not o.check_host("api.github.com") and not o.check_host("objects.githubusercontent.com")


async def test_plain_http_is_refused_with_an_explanation(gw):
    g, events, _, _ = gw
    reply, reader, writer = await _proxy(g, b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
    body = await reader.read()
    assert reply.startswith(b"HTTP/1.1 403") and b"Plain http is refused" in body
    writer.close()
    await asyncio.sleep(0.05)
    assert events[-1]["kind"] == "http" and events[-1]["target"] == "http://example.com/"


def _model_client(g):
    return httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(g.model_socket)), base_url="http://gw")


async def test_only_the_assistants_messages_are_passed_on_with_the_users_key(gw):
    """Not the provider's other paid endpoints (image generation, chat completions...)."""
    g, _, upstream_reqs, _ = gw
    async with _model_client(g) as c:
        for method, path in (("POST", "/v1/images/generations"), ("POST", "/v1/chat/completions"), ("GET", "/v1/messages"),
                             ("DELETE", "/v1/models"), ("POST", "/v1/messages/../balance")):
            r = await c.request(method, path, headers={"authorization": f"Bearer {g.token}"}, json={"model": "big-model"})
            assert r.status_code in (404, 405) and not upstream_reqs, (method, path)
        r = await c.post("/v1/messages", headers={"authorization": f"Bearer {g.token}"}, json={"model": "big-model"})
    assert r.status_code == 200 and len(upstream_reqs) == 1


async def test_model_requests_need_the_workspace_token(gw):
    g, _, upstream_reqs, _ = gw
    async with _model_client(g) as c:
        r = await c.post("/v1/messages", headers={"authorization": "Bearer wrong"}, json={"model": "big-model"})
    assert r.status_code == 401 and not upstream_reqs


async def test_the_real_key_is_added_on_the_way_out_and_the_token_never_leaves(gw):
    g, events, upstream_reqs, _ = gw
    async with _model_client(g) as c:
        r = await c.post("/v1/messages?beta=true", headers={"authorization": f"Bearer {g.token}", "anthropic-version": "2023-06-01",
                                                            "cookie": "session=1", "x-forwarded-for": "10.0.0.5"},
                         json={"model": "big-model", "messages": []})
    assert r.status_code == 200 and "message_stop" in r.text
    assert "set-cookie" not in r.headers and r.headers["request-id"] == "r1"
    [req] = upstream_reqs
    assert str(req.url) == "https://upstream.example/api/v1/messages?beta=true"   # /v1 not doubled
    assert req.headers["authorization"] == "Bearer sk-real"
    assert g.token not in json.dumps(dict(req.headers))
    assert "cookie" not in req.headers and "x-forwarded-for" not in req.headers
    assert req.headers["anthropic-version"] == "2023-06-01"
    await asyncio.sleep(0.05)
    assert events[-1]["kind"] == "model" and events[-1]["model"] == "big-model"


async def test_a_model_the_project_did_not_choose_is_replaced_by_the_small_one(gw):
    g, events, upstream_reqs, _ = gw
    async with _model_client(g) as c:
        await c.post("/v1/messages", headers={"x-api-key": g.token}, json={"model": "claude-haiku-whatever"})
    assert json.loads(upstream_reqs[-1].content)["model"] == "small-model"
    await asyncio.sleep(0.05)
    assert events[-1]["asked_for"] == "claude-haiku-whatever"


async def test_the_gateway_refuses_when_the_project_may_not_use_the_builder(gw):
    g, _, upstream_reqs, state = gw
    state["refuse"] = "This project is CONFIDENTIAL"
    async with _model_client(g) as c:
        r = await c.post("/v1/messages", headers={"authorization": f"Bearer {g.token}"}, json={"model": "big-model"})
    assert r.status_code == 403 and "CONFIDENTIAL" in r.json()["error"]["message"] and not upstream_reqs


async def test_a_plain_http_upstream_is_never_used(gw):
    g, _, upstream_reqs, state = gw
    state["base"] = "http://upstream.example/api/v1"
    async with _model_client(g) as c:
        r = await c.post("/v1/messages", headers={"authorization": f"Bearer {g.token}"}, json={"model": "big-model"})
    assert r.status_code == 403 and "plain http" in r.json()["error"]["message"] and not upstream_reqs


async def test_the_sockets_are_reachable_by_the_containers_user_but_the_directory_is_not_listable(gw):
    g, _, _, _ = gw
    assert oct(g.dir.stat().st_mode & 0o777) == "0o711"
    assert oct(g.model_socket.stat().st_mode & 0o777) == "0o666"


def test_a_base_ending_in_v1_does_not_double_it():
    from davibemanager.gateway import upstream_url
    assert upstream_url("https://nano-gpt.com/api/v1", "/v1/messages", "beta=true") == "https://nano-gpt.com/api/v1/messages?beta=true"
    assert upstream_url("https://nano-gpt.com/api/v1/", "/v1/messages") == "https://nano-gpt.com/api/v1/messages"
    assert upstream_url("https://api.anthropic.com", "/v1/messages") == "https://api.anthropic.com/v1/messages"


async def test_redirects_and_provider_errors_are_logged_with_their_reason(gw):
    g, events, upstream_reqs, _ = gw
    replies = iter([httpx.Response(307, headers={"location": "https://0.0.0.0:3000/api/v1/messages"}),
                    httpx.Response(404, json={"error": {"message": "Model anthropic/claude-nope not found"}})])
    g.http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: next(replies)))
    async with _model_client(g) as c:
        r = await c.post("/v1/messages", headers={"authorization": f"Bearer {g.token}"}, json={"model": "big-model"})
        assert r.status_code == 502 and "0.0.0.0:3000" in r.json()["error"]["message"]
        r = await c.post("/v1/messages", headers={"authorization": f"Bearer {g.token}"}, json={"model": "big-model"})
        assert r.status_code == 404 and "not found" in r.text           # the provider's answer reaches the CLI
    await asyncio.sleep(0.05)
    assert "refusing to follow" in events[-2]["error"] and "not found" in events[-1]["error"]


async def test_a_refused_token_is_logged(gw):
    g, events, _, _ = gw
    async with _model_client(g) as c:
        await c.post("/v1/messages", headers={"authorization": "Bearer nope"}, json={})
    assert events[-1]["status"] == 401 and "token" in events[-1]["error"]


async def test_the_tokens_a_claude_request_used_are_counted_from_its_stream(gw):
    g, events, _, _ = gw
    stream = (b'event: message_start\ndata: {"type": "message_start", "message": {"usage": {"input_tokens": 12, '
              b'"cache_creation_input_tokens": 300, "cache_read_input_tokens": 9000, "output_tokens": 1}}}\n\n'
              b'event: content_block_delta\ndata: {"type": "content_block_delta", "delta": {"text": "\\"usage\\" hi"}}\n\n'
              b'event: message_delta\ndata: {"type": "message_delta", "usage": {"output_tokens": 345}}\n\n'
              b'event: message_stop\ndata: {"type": "message_stop"}\n\n')
    chunks = [stream[i:i + 17] for i in range(0, len(stream), 17)]       # lines split across chunks

    async def body():
        for c in chunks:
            yield c
    g.http = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, content=body(), headers={"content-type": "text/event-stream"})))
    async with _model_client(g) as c:
        r = await c.post("/v1/messages", headers={"authorization": f"Bearer {g.token}"}, json={"model": "big-model", "stream": True})
    assert r.content == stream
    await asyncio.sleep(0.05)
    assert events[-1]["usage"] == {"input": 12, "output": 345, "cache_read": 9000, "cache_write": 300}


async def test_the_tokens_of_a_reply_that_does_not_stream_are_counted(gw):
    g, events, _, _ = gw
    g.http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(
        200, json={"type": "message", "content": [], "usage": {"input_tokens": 50, "output_tokens": 5}})))
    async with _model_client(g) as c:
        await c.post("/v1/messages", headers={"authorization": f"Bearer {g.token}"}, json={"model": "big-model"})
    await asyncio.sleep(0.05)
    assert events[-1]["usage"] == {"input": 50, "output": 5, "cache_read": 0, "cache_write": 0}


def test_chat_completions_usage_separates_the_cached_input():
    from davibemanager.gateway import openai_usage
    assert openai_usage({"prompt_tokens": 1000, "completion_tokens": 20, "prompt_tokens_details": {"cached_tokens": 800}}) == {
        "input": 200, "output": 20, "cache_read": 800, "cache_write": 0}
    assert openai_usage(None) == {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
