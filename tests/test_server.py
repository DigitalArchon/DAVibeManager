"""The local server: everything needs the per-launch token."""

import os

import httpx

from davibemanager.config import Config
from davibemanager.engine import Engine
from davibemanager.server.app import create_app


async def test_the_api_needs_the_token(tmp_path):
    def make(emit):
        e = Engine(Config(), emit, tmp_path, save_config=lambda c: None)
        e.start_workspace = lambda: None
        return e
    app = create_app("secret", make)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            assert (await c.get("/api/state")).status_code == 403
            assert (await c.get("/api/state", headers={"x-token": "wrong"})).status_code == 403
            r = await c.get("/api/state", headers={"x-token": "secret"})
            assert r.status_code == 200 and r.json()["ready"] is False and r.json()["conversation"]
            r = await c.post("/api/send", headers={"x-token": "secret"}, json={"message": "hi"})
            assert r.status_code == 400 and "NanoGPT key" in r.json()["error"]
            r = await c.post("/api/requests/1/run", headers={"x-token": "secret"}, json={})
            assert r.status_code == 400
            assert (await c.get("/")).status_code == 200      # the page itself holds no secrets


async def test_the_colours_are_dark_unless_the_user_picks_others(tmp_path):
    saved = []

    def make(emit):
        e = Engine(Config(), emit, tmp_path, save_config=saved.append)
        e.start_workspace = lambda: None
        return e
    app = create_app("secret", make)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
                                     headers={"x-token": "secret"}) as c:
            assert (await c.get("/api/state")).json()["config"]["settings"]["theme"] == "dark"
            assert (await c.post("/api/settings", json={"theme": "light"})).status_code == 200
            assert saved[-1].settings.theme == "light"
            assert (await c.post("/api/settings", json={"theme": "pink"})).status_code == 400
            assert saved[-1].settings.theme == "light"


async def test_files_are_attached_as_raw_bytes_with_a_size_limit(tmp_path, monkeypatch):
    from davibemanager.server import app as app_mod

    def make(emit):
        e = Engine(Config(), emit, tmp_path, save_config=lambda c: None)
        e.start_workspace = lambda: None
        return e
    monkeypatch.setattr(app_mod, "MAX_ATTACHMENT", 1000)
    app = create_app("secret", make)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
                                     headers={"x-token": "secret"}) as c:
            r = await c.post("/api/attachments", content=b"step one\n", headers={"x-filename": "my%20notes.txt"})
            f = r.json()
            assert r.status_code == 200 and f["name"] == "my-notes.txt" and f["kind"] == "file" and "local" not in f
            assert (await c.get(f"/api/attachments/{f['id']}")).content == b"step one\n"
            r = await c.post("/api/attachments", content=b"x" * 1001, headers={"x-filename": "big.bin"})
            assert r.status_code == 400 and "too big" in r.json()["error"]
            assert (await c.delete(f"/api/attachments/{f['id']}")).status_code == 200
            assert (await c.get(f"/api/attachments/{f['id']}")).status_code == 400
            assert (await c.get("/api/attachments/../../state.json")).status_code in (400, 404)
            r = await c.post("/api/attachments", content=b"hi", headers={"x-filename": "a.txt", "x-token": "nope"})
            assert r.status_code == 403


async def test_a_backup_uploaded_to_restore_is_bounded_and_not_kept_when_refused(tmp_path, monkeypatch):
    from davibemanager import backup
    from davibemanager.server import app as app_mod

    def make(emit):
        e = Engine(Config(), emit, tmp_path, save_config=lambda c: None)
        e.start_workspace = lambda: None
        return e
    monkeypatch.setattr(backup, "MAX_UPLOAD", 1000)
    monkeypatch.setattr(app_mod, "upload_dir", lambda: tmp_path / "uploads")
    app = create_app("secret", make)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
                                     headers={"x-token": "secret"}) as c:
            r = await c.post("/api/restore/upload", content=b"x" * 500)
            assert r.status_code == 200 and (tmp_path / "uploads" / f"restore-{r.json()['file']}.dvmbackup").is_file()

            async def stream():                     # no Content-Length: only counting stops it
                for _ in range(5):
                    yield b"x" * 400
            r = await c.post("/api/restore/upload", content=stream())
            assert r.status_code == 400 and "too big" in r.json()["error"]
            assert len(list((tmp_path / "uploads").iterdir())) == 1
            monkeypatch.setattr(backup, "MAX_UPLOAD", 1 << 40)
            monkeypatch.setattr(backup, "KEEP_FREE", 1 << 62)        # more than any disk has free
            r = await c.post("/api/restore/upload", content=b"x" * 500)
            assert r.status_code == 400 and "free space" in r.json()["error"]
            assert len(list((tmp_path / "uploads").iterdir())) == 1


def test_an_event_is_sent_as_it_was_when_it_happened(tmp_path):
    """A state's chat is the conversation's own list: written out only when the window's socket got to it,
    it held a message added after it too, which that message's own event then added again (an update's
    request showed twice when the assistant was asked to make it)."""
    from starlette.testclient import TestClient
    got = {}

    def make(emit):
        got["emit"] = emit
        e = Engine(Config(), emit, tmp_path, save_config=lambda c: None)
        e.start_workspace = lambda: None
        return e
    app = create_app("secret", make)
    with TestClient(app) as client, client.websocket_connect("/ws/events?t=secret") as ws:
        ws.receive_json()                                   # the state on connecting
        chat = []

        def as_the_engine_does():                           # one go on the loop, nothing awaited between
            got["emit"]({"type": "state", "state": {"chat": chat}})
            entry = {"kind": "user", "text": "Please update my htop"}
            chat.append(entry)
            got["emit"]({"type": "chat", "entry": entry})
        client.portal.call(as_the_engine_does)
        assert ws.receive_json() == {"type": "state", "state": {"chat": []}}
        assert ws.receive_json()["type"] == "chat"


async def _gate_call(headers, path="/api/send"):
    """WindowGate on one POST: (status, response headers, app reached, body read)."""
    from davibemanager.server.app import WindowGate

    seen = {"app": False, "read": False, "start": None}

    async def inner(scope, receive, send):
        seen["app"] = True

    async def receive():
        seen["read"] = True
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        if msg["type"] == "http.response.start":
            seen["start"] = msg
    scope = {"type": "http", "method": "POST", "path": path, "query_string": b"",
             "headers": [(k.encode(), v.encode() if isinstance(v, str) else v) for k, v in headers.items()]}
    await WindowGate(inner, lambda t: t == "secret")(scope, receive, send)
    start = seen["start"]
    return (start["status"] if start else None, dict(start["headers"]) if start else {}, seen["app"], seen["read"])


async def test_the_gate_refuses_on_headers_before_any_body_is_read():
    """FastAPI read and parsed a JSON body before the token was checked, with no limit on its size
    (DA Toolkit's CompanionGate, ported)."""
    from davibemanager.server.app import MAX_BODY

    big = str(MAX_BODY + 1)
    for headers, status in (({"content-length": big}, 403),                              # no token
                            ({"x-token": "wrong", "content-length": "10"}, 403),
                            ({"x-token": "secret", "content-length": big}, 413),
                            ({"x-token": "secret", "transfer-encoding": "chunked"}, 411),
                            ({"x-token": "secret", "content-length": "lots"}, 400)):
        got, resp_headers, reached, read = await _gate_call(headers)
        assert (got, reached, read) == (status, False, False), headers
        assert resp_headers[b"connection"] == b"close"                 # not kept open for the rest
    assert (await _gate_call({"x-token": "secret", "content-length": "100"}))[2]
    # an upload is read as it comes and limited as it is (each route's own limit): only the token, here
    for path in ("/api/attachments", "/api/restore/upload", "/api/share/upload"):
        assert (await _gate_call({"x-token": "secret", "transfer-encoding": "chunked"}, path))[2]
        assert (await _gate_call({"transfer-encoding": "chunked"}, path))[0] == 403


async def test_a_token_with_letters_outside_ascii_is_refused_not_a_server_error(tmp_path):
    def make(emit):
        e = Engine(Config(), emit, tmp_path, save_config=lambda c: None)
        e.start_workspace = lambda: None
        return e
    app = create_app("secret", make)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            for token in (b"s\xc3\xa9cret", b"\xff\xfe"):
                assert (await c.get("/api/state", headers={"x-token": token})).status_code == 403
            assert (await c.get("/api/state", headers={"x-token": "secret"})).status_code == 200


async def test_an_unauthenticated_upload_is_cut_off_over_the_socket(tmp_path):
    """Anyone on this computer, without the token, announcing a huge body gets a 403 at once and the
    connection closes: the server never reads or buffers it."""
    import asyncio
    import socket

    import uvicorn

    def make(emit):
        e = Engine(Config(), emit, tmp_path, save_config=lambda c: None)
        e.start_workspace = lambda: None
        return e
    app = create_app("secret", make)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning", loop="asyncio"))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        for _ in range(200):
            if server.started:
                break
            await asyncio.sleep(0.01)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"POST /api/send HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                     b"Content-Length: 2000000000\r\n\r\n" + b"[" * 65536)
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(), 5)            # read() to EOF: the server hangs up
        assert reply.startswith(b"HTTP/1.1 403")
        writer.close()
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 10)


def test_the_browser_is_opened_on_a_one_time_code_never_the_token(monkeypatch):
    """A browser's command line shows every user of this computer what it was opened with: it was the token
    (?t=…), which gave them the app for as long as it ran."""
    import webbrowser

    from davibemanager.app import browser_opener
    from davibemanager.server.app import Launches

    opened, launches = [], Launches()
    monkeypatch.setattr(webbrowser, "open", opened.append)
    browser_opener(8123, launches)()
    browser_opener(8123, launches)()                     # a second launch: a code of its own
    assert all(u.startswith("http://127.0.0.1:8123/#c=") and "t=" not in u for u in opened)
    first, second = (u.split("#c=")[1] for u in opened)
    assert first != second and launches.take(second) and launches.take(first)
    assert not launches.take(first)                       # once


def test_a_launch_code_is_good_once_briefly_and_only_to_this_user(monkeypatch):
    from davibemanager.server import app as app_mod

    launches = app_mod.Launches()
    code = launches.new()
    assert not launches.take("guessed") and not launches.take(code + "x")
    monkeypatch.setattr(app_mod, "peer_uid", lambda peer, server: os.getuid() + 1)
    assert not launches.take(code, ("127.0.0.1", 40000), ("127.0.0.1", 8123))     # another user's process
    monkeypatch.setattr(app_mod, "peer_uid", lambda peer, server: os.getuid())
    assert launches.take(code, ("127.0.0.1", 40001), ("127.0.0.1", 8123))         # still this user's to use
    late = launches.new()
    monkeypatch.setattr(app_mod.time, "monotonic", lambda real=app_mod.time.monotonic: real() + app_mod.LAUNCH_SECONDS + 1)
    assert not launches.take(late)


def test_the_peer_of_a_loopback_connection_is_known_by_its_user():
    import socket

    from davibemanager.server.app import peer_uid

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    client = socket.create_connection(server.getsockname())
    try:
        assert peer_uid(client.getsockname(), server.getsockname()) == os.getuid()
        assert peer_uid(("127.0.0.1", 1), server.getsockname()) is None
    finally:
        client.close()
        server.close()


async def test_the_page_exchanges_its_code_for_the_token_and_nothing_else_does(tmp_path):
    from davibemanager.server.app import Launches

    def make(emit):
        e = Engine(Config(), emit, tmp_path, save_config=lambda c: None)
        e.start_workspace = lambda: None
        return e
    launches = Launches()
    app = create_app("secret", make, launches=launches)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            code = launches.new()
            r = await c.post("/api/launch", json={"code": code})
            assert r.status_code == 200 and r.json() == {"token": "secret"}
            r = await c.post("/api/launch", json={"code": code})
            assert r.status_code == 403 and "used already" in r.json()["error"]
            assert (await c.post("/api/launch", json={"code": "nope"})).status_code == 403
            assert (await c.post("/api/launch", content=b"x" * 2000)).status_code == 413     # nothing big read
            assert (await c.post("/api/launch", content=b"{")).status_code == 403
