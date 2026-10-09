"""The local server: everything needs the per-launch token."""

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
