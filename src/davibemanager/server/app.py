"""Local HTTP/WebSocket server for the window, bound to 127.0.0.1 and gated by a per-launch token."""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import re
import secrets
import shutil
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable
from urllib.parse import unquote

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse

from fastapi.staticfiles import StaticFiles

from .. import backup as backup_mod
from .. import delivery as delivery_mod
from .. import share as share_mod
from ..engine import MAX_ATTACHMENT, Engine, UserError
from ..hostenv import host_env
from ..workspace.podman import PodmanError

WEB_DIR = Path(__file__).resolve().parents[1] / "web"


def upload_dir() -> Path:
    """Where a backup the user uploads to restore waits (outside the data folder a restore replaces)."""
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return Path(base) / "davibemanager"


def create_app(token: str, make_engine: Callable[[Callable[[dict], None]], Engine],
               desktop=None, on_quit: Callable[[], None] | None = None) -> FastAPI:
    """The window's app, for 127.0.0.1 only. `desktop` (app.Desktop, only in the app window)
    serves the clipboard and hides the window. `on_quit` ends the process (POST /api/quit)."""
    listeners: set[asyncio.Queue] = set()

    def emit(event: dict) -> None:
        for q in list(listeners):
            q.put_nowait(event)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # backups uploaded to restore and never restored: possibly GBs each, kept a day
        for old in upload_dir().glob(f"restore-*{backup_mod.SUFFIX}") if upload_dir().is_dir() else []:
            if time.time() - old.stat().st_mtime > 86400:
                old.unlink(missing_ok=True)
        app.state.engine = make_engine(emit)
        await app.state.engine.start()
        try:
            yield
        finally:
            await app.state.engine.stop()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    def check(t: str | None) -> bool:
        return t is not None and hmac.compare_digest(t, token)

    def auth(request: Request) -> Engine:
        if not check(request.headers.get("x-token")):
            raise HTTPException(403, "bad token")
        return request.app.state.engine

    async def user_error(_: Request, exc: Exception):
        return JSONResponse({"error": str(exc)}, status_code=400)

    async def key_error(_: Request, exc: KeyError):
        return JSONResponse({"error": f"Not found: {exc.args[0] if exc.args else exc}"}, status_code=400)

    app.add_exception_handler(UserError, user_error)
    app.add_exception_handler(PodmanError, user_error)
    app.add_exception_handler(KeyError, key_error)

    @app.get("/")
    async def index():
        return FileResponse(WEB_DIR / "index.html", headers={"Cache-Control": "no-store"})

    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    # ------------------------------------------------------------ the window

    if desktop is not None:
        @app.get("/api/desktop/clipboard")
        async def desktop_clip_get(e: Engine = Depends(auth)):
            return {"text": await asyncio.to_thread(desktop.clipboard_get)}

        @app.post("/api/desktop/clipboard")
        async def desktop_clip_set(body: dict, e: Engine = Depends(auth)):
            await asyncio.to_thread(desktop.clipboard_set, str(body.get("text", "")))
            return {"ok": True}

        @app.post("/api/desktop/hide")
        async def desktop_hide(e: Engine = Depends(auth)):
            desktop.hide()
            return {"ok": True}

    if on_quit is not None:
        @app.post("/api/quit")
        async def quit_app(e: Engine = Depends(auth)):
            asyncio.get_running_loop().call_later(0.3, on_quit)  # let this reply reach the page first
            return {"ok": True}

    # ------------------------------------------------------------ setup and settings

    @app.get("/api/state")
    async def state(e: Engine = Depends(auth)):
        return e.snapshot()

    @app.post("/api/keyring/retry")
    async def keyring_retry(e: Engine = Depends(auth)):
        e.retry_keyring()
        return {"ok": True}

    @app.post("/api/setup")
    async def setup(body: dict, e: Engine = Depends(auth)):
        await e.quick_setup(str(body.get("api_key", "")))
        return {"ok": True}

    @app.post("/api/providers")
    async def save_provider(body: dict, e: Engine = Depends(auth)):
        e.save_provider(body.get("provider", {}), body.get("api_key") or None, body.get("original_name"))
        return {"ok": True}

    @app.delete("/api/providers/{name}")
    async def delete_provider(name: str, e: Engine = Depends(auth)):
        e.delete_provider(name)
        return {"ok": True}

    @app.get("/api/models")
    async def models(provider: str, refresh: bool = False, e: Engine = Depends(auth)):
        return {"models": await e.list_models(provider, refresh)}

    @app.get("/api/models/hosts")
    async def model_hosts(model: str, refresh: bool = False, e: Engine = Depends(auth)):
        """The hosts NanoGPT runs a model on, with its figures for each (Settings → Which host)."""
        return await e.model_hosts(model, refresh)

    @app.post("/api/models/route")
    async def model_route(body: dict, e: Engine = Depends(auth)):
        return {"route": await e.set_model_route(str(body.get("model") or ""), body.get("route") or {})}

    @app.get("/api/about-computer")
    async def about_computer(parts: str = "", e: Engine = Depends(auth)):
        """What the assistant would be told with these parts on (Settings shows it)."""
        return {"text": await asyncio.to_thread(e.about_computer, [p for p in parts.split(",") if p])}

    @app.post("/api/settings")
    async def save_settings(body: dict, e: Engine = Depends(auth)):
        e.save_settings(body)
        if any(k in body for k in ("container_memory", "container_cpus", "container_pids")):
            return {"ok": True, "limits": await e.apply_limits()}     # "now", or "next start"
        return {"ok": True}

    # ------------------------------------------------------------ the conversation

    @app.post("/api/send")
    async def send(body: dict, e: Engine = Depends(auth)):
        ids = body.get("attachments") or []
        await e.send_with_files(str(body.get("message", "")), [str(i) for i in ids] if isinstance(ids, list) else [])
        return {"ok": True}

    @app.post("/api/attachments")
    async def attach(request: Request, e: Engine = Depends(auth)):
        """A file the user attached: the raw bytes, its name in X-Filename (URI-encoded)."""
        name = unquote(request.headers.get("x-filename", ""))[:200]
        if int(request.headers.get("content-length") or 0) > MAX_ATTACHMENT:
            raise UserError(f"{name or 'That file'} is over {MAX_ATTACHMENT >> 20} MB: too big to attach.")
        data = bytearray()
        async for chunk in request.stream():
            data += chunk
            if len(data) > MAX_ATTACHMENT:
                raise UserError(f"{name or 'That file'} is over {MAX_ATTACHMENT >> 20} MB: too big to attach.")
        return await e.attach(name, bytes(data))

    @app.delete("/api/attachments/{aid}")
    async def unattach(aid: str, e: Engine = Depends(auth)):
        e.unattach(aid)
        return {"ok": True}

    @app.get("/api/attachments/{aid}")
    async def attachment(aid: str, e: Engine = Depends(auth)):
        return FileResponse(e.attachment_file(aid), headers={"Cache-Control": "no-store"})

    @app.post("/api/stop")
    async def stop(e: Engine = Depends(auth)):
        e.stop_turn()
        return {"ok": True}

    @app.get("/api/chats")
    async def chats(e: Engine = Depends(auth)):
        return {"chats": e.list_chats()}

    @app.post("/api/chats/new")
    async def new_chat(body: dict | None = None, e: Engine = Depends(auth)):
        body = body or {}
        await e.new_chat(str(body.get("mode") or ""), str(body.get("app") or ""), str(body.get("app_name") or ""),
                         remake=bool(body.get("remake")))
        return {"ok": True}

    @app.post("/api/chats/open")
    async def open_chat(body: dict, e: Engine = Depends(auth)):
        await e.open_chat(str(body.get("id", "")))
        return {"ok": True}

    @app.post("/api/chats/delete")
    async def delete_chats(body: dict, e: Engine = Depends(auth)):
        return e.delete_chats([str(i) for i in body.get("ids", [])])

    @app.post("/api/requests/{rid}/{action}")
    async def request_action(rid: int, action: str, body: dict | None = None, e: Engine = Depends(auth)):
        body = body or {}
        note = str(body.get("note", ""))
        if action == "edit":
            e.edit_request(rid, str(body.get("command", "")))
        elif action == "run":
            e.run_request(rid)
        elif action == "stop":
            e.stop_request(rid)
        elif action == "send":
            e.send_request(rid, body.get("text"), note)
        elif action == "withhold":
            e.withhold_request(rid, note)
        elif action == "decline":
            e.decline_request(rid, note)
        elif action == "review":
            return await e.review_request(rid)
        else:
            raise HTTPException(404)
        return {"ok": True}

    @app.post("/api/questions/{qid}")
    async def answer(qid: int, body: dict, e: Engine = Depends(auth)):
        e.answer_question(qid, [str(a) for a in body.get("answers", [])])
        return {"ok": True}

    @app.get("/api/screens/{name}")
    async def screen(name: str, e: Engine = Depends(auth)):
        return FileResponse(e.screen_file(name), headers={"Cache-Control": "no-store"})

    # ------------------------------------------------------------ the sandbox and its deliveries

    @app.post("/api/workspace/{action}")
    async def workspace(action: str, e: Engine = Depends(auth)):
        if action == "start":
            e.start_workspace()
        elif action == "reset":
            await e.reset_workspace()
        else:
            raise HTTPException(404)
        return {"ok": True}

    @app.post("/api/podman/install")
    async def podman_install(e: Engine = Depends(auth)):
        """Install Podman with the app's own command for this distribution (podmansetup.py), as
        administrator: the desktop asks for the password. It runs on; the window follows its state."""
        e.install_podman()
        return {"ok": True}

    @app.get("/api/deliveries/{did}")
    async def delivery(did: str, e: Engine = Depends(auth)):
        return e.delivery_detail(did)

    @app.get("/api/deliveries/{did}/shots/{name}")
    async def delivery_shot(did: str, name: str, e: Engine = Depends(auth)):
        return FileResponse(e.delivery_file(did, name), headers={"Cache-Control": "no-store"})

    @app.post("/api/deliveries/{did}/{action}")
    async def delivery_action(did: str, action: str, e: Engine = Depends(auth)):
        if action == "install":
            return e.install_delivery(did)
        if action == "reject":
            e.reject_delivery(did)
        elif action == "open":
            e.open_app(did)
        elif action == "try":
            e.try_delivery(did)
        elif action == "works":
            return e.app_manager.works_here(did)
        else:
            raise HTTPException(404)
        return {"ok": True}

    @app.get("/api/apps/{app_id}/changelog")
    async def app_changelog(app_id: str, e: Engine = Depends(auth)):
        return e.app_manager.read_changelog(app_id) or await e.app_manager.changelog(app_id)

    @app.get("/api/apps/{app_id}/changes/{change_id}")
    async def app_change(app_id: str, change_id: str, e: Engine = Depends(auth)):
        return e.app_manager.change_detail(app_id, change_id)

    @app.post("/api/apps/{app_id}/{action}")
    async def app_action(app_id: str, action: str, body: dict | None = None, e: Engine = Depends(auth)):
        m = e.app_manager
        if action == "check":
            return await m.check(app_id)
        if action == "summarize":
            return await m.summarize(app_id)
        if action == "skip":
            m.skip(app_id)
        elif action == "watch":
            m.set_watch(app_id, bool((body or {}).get("on", True)))
        elif action == "schedule":
            body = body or {}
            m.set_schedule(app_id, check_every=body.get("check_every"), build_when=body.get("build_when"))
        elif action == "rebuild":
            e._spawn(m.rebuild(app_id, by_user=True))
        elif action == "build":
            # an app imported, or changes added from a shared app: built on the app's own release
            e._spawn(m.rebuild(app_id, by_user=True, tag=m.app(app_id).get("base_ref", "")))
        elif action == "share-preview":
            return e.sharing.preview(app_id)
        elif action == "export":
            # the notes as the user corrected them on the preview, if they did
            notes = (body or {}).get("notes")
            if notes:
                try:
                    await m.set_notes(app_id, notes)
                except delivery_mod.DeliveryError as err:
                    raise UserError(str(err)) from None
            return e.sharing.export(app_id)
        elif action == "export-appimage":
            return m.export_appimage(app_id)
        elif action == "reshare-later":
            m.reshare_later(app_id)
        elif action == "assistant":
            await m.ask_assistant(app_id, None)
        elif action == "rollback":
            return m.rollback(app_id)
        elif action == "remove":
            return m.remove(app_id, keep_installed=bool((body or {}).get("keep_installed")))
        else:
            raise HTTPException(404)
        return {"ok": True}

    # ------------------------------------------------------------ one app, shared (share.py)

    @app.post("/api/share/upload")
    async def share_upload(request: Request, e: Engine = Depends(auth)):
        """A .vibe file someone gave the user: read (strictly) and reviewed, then deleted."""
        d = upload_dir()
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = d / f"share-{secrets.token_hex(16)}{share_mod.SUFFIX}"
        try:
            size = 0
            with open(path, "wb") as f:
                os.fchmod(f.fileno(), 0o600)
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > share_mod.MAX_FILE:
                        raise UserError("That file is too big to be a shared app.")
                    f.write(chunk)
            return e.sharing.peek(path)
        finally:
            path.unlink(missing_ok=True)

    @app.get("/api/share/{token}")
    async def share_view(token: str, e: Engine = Depends(auth)):
        return e.sharing.view(token)

    @app.post("/api/share/{token}/import")
    async def share_import(token: str, body: dict, e: Engine = Depends(auth)):
        return e.sharing.accept(token, into=str(body.get("into") or ""), name=str(body.get("name") or ""),
                                update=str(body.get("update") or ""))

    # ------------------------------------------------------------ backups

    def backup_file(e: Engine, body: dict) -> Path:
        """The backup a request means: one in the backup folder (by name), or one the user uploaded."""
        name, file = str(body.get("name") or ""), str(body.get("file") or "")
        if name:
            if not backup_mod.NAME.fullmatch(name):
                raise UserError("That isn't one of your backups.")
            path = e.backups.folder() / name
        elif re.fullmatch(r"[0-9a-f]{32}", file):
            path = upload_dir() / f"restore-{file}{backup_mod.SUFFIX}"
        else:
            raise UserError("Which backup?")
        if not path.is_file():
            raise UserError("That backup isn't there any more.")
        return path

    @app.get("/api/backups")
    async def backups(e: Engine = Depends(auth)):
        return e.backups.view()

    @app.post("/api/backups")
    async def backup_now(body: dict | None = None, e: Engine = Depends(auth)):
        body = body or {}
        password = str(body.get("password") or "") or None
        if password and body.get("save_password"):
            e.backups.set_password(password)
        out = await e.backups.backup(password)
        return {k: v for k, v in out.items() if k != "manifest"}

    @app.post("/api/backups/password")
    async def backup_password(body: dict, e: Engine = Depends(auth)):
        e.backups.set_password(str(body.get("password") or "") or None)
        return {"ok": True}

    @app.post("/api/backups/open-folder")
    async def backups_folder(e: Engine = Depends(auth)):
        folder = e.backups.folder()
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        await asyncio.create_subprocess_exec("xdg-open", str(folder), env=host_env())
        return {"ok": True}

    @app.post("/api/restore/upload")
    async def restore_upload(request: Request, e: Engine = Depends(auth)):
        """A backup file from elsewhere (another computer's): kept in the cache until it's restored."""
        token = secrets.token_hex(16)
        d = upload_dir()
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        for old in d.glob(f"restore-*{backup_mod.SUFFIX}"):
            if time.time() - old.stat().st_mtime > 86400:
                old.unlink(missing_ok=True)
        path = d / f"restore-{token}{backup_mod.SUFFIX}"
        if int(request.headers.get("content-length") or 0) > backup_mod.MAX_UPLOAD:
            raise UserError("That file is too big to be a backup.")
        try:
            size, look_at = 0, 0                    # the free space is looked at every 64 MB
            with open(path, "wb") as f:
                os.fchmod(f.fileno(), 0o600)
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > backup_mod.MAX_UPLOAD:
                        raise UserError("That file is too big to be a backup.")
                    if size >= look_at:
                        if shutil.disk_usage(d).free < backup_mod.KEEP_FREE + len(chunk):
                            raise UserError("There isn't enough free space on this computer to take in that backup.")
                        look_at = size + (64 << 20)
                    f.write(chunk)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return {"file": token}

    @app.post("/api/restore/peek")
    async def restore_peek(body: dict, e: Engine = Depends(auth)):
        return await asyncio.to_thread(e.backups.peek, backup_file(e, body), str(body.get("password") or ""))

    @app.post("/api/restore")
    async def restore(body: dict, e: Engine = Depends(auth)):
        path = backup_file(e, body)
        out = await e.backups.restore(path, str(body.get("password") or ""))
        if path.parent == upload_dir():
            path.unlink(missing_ok=True)
        return out

    @app.post("/api/open-folder")
    async def open_folder(body: dict, e: Engine = Depends(auth)):
        target = e.conv.dir if e.conv else None
        if body.get("export"):
            # a .vibe file or an AppImage just saved, shown in its folder
            p = Path(str(body["export"]))
            if p.suffix not in (share_mod.SUFFIX, ".AppImage") or p.parent != e.sharing.folder() or not p.is_file():
                raise UserError("That isn't an app you exported.")
            await asyncio.create_subprocess_exec("xdg-open", str(p.parent), env=host_env())
            return {"ok": True}
        if body.get("delivery"):
            installed = e.delivery_detail(str(body["delivery"])).get("installed_to")
            target = Path(installed) if installed else target
            target = target if target and target.is_dir() else (target.parent if target else None)
        if target:
            await asyncio.create_subprocess_exec("xdg-open", str(target), env=host_env())
        return {"ok": True}

    # ------------------------------------------------------------ events

    @app.websocket("/ws/events")
    async def ws_events(ws: WebSocket):
        if not check(ws.query_params.get("t")):
            await ws.close(code=4403)
            return
        await ws.accept()
        q: asyncio.Queue = asyncio.Queue()
        listeners.add(q)
        try:
            await ws.send_text(json.dumps({"type": "state", "state": app.state.engine.snapshot()}, default=str))
            receiver = asyncio.create_task(ws.receive_text())
            while True:
                getter = asyncio.create_task(q.get())
                done, _ = await asyncio.wait({getter, receiver}, return_when=asyncio.FIRST_COMPLETED)
                if receiver in done:
                    getter.cancel()
                    receiver.result()  # raises on disconnect
                    receiver = asyncio.create_task(ws.receive_text())
                    continue
                await ws.send_text(json.dumps(getter.result(), default=str))
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            listeners.discard(q)

    return app


def runtime_dir() -> Path:
    base = Path(os.environ.get("XDG_RUNTIME_DIR") or "/tmp")
    # sweep leftovers from instances that were killed before they could clean up
    for d in base.glob("davibemanager-*"):
        pid = d.name.removeprefix("davibemanager-")
        if pid.isdigit() and not Path(f"/proc/{pid}").exists() and d.owner() == os.environ.get("USER", d.owner()):
            shutil.rmtree(d, ignore_errors=True)
    return base / f"davibemanager-{os.getpid()}"
