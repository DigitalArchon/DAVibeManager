"""Backups of everything the user has here, to restore on this computer or another, and go on
having and looking after their apps there.

What the app keeps is enough to make every app again without the AI (apps.py: each app's
official source, release, changes and build script), so a backup is small but for the apps
themselves. It holds:
- the settings (config.toml) and the API keys (from the keyring);
- each app's record, and its installed build (else its newest), to install without building;
- the chats, their screenshots, and what came from this computer (outside.json: still never in
  a web search after a restore);
- Claude Code's session files from the sandbox, so old chats go on where they were;
- the pinned AppImage runtime (installing checks a build against it).
Not the sandbox itself: an app's source is made again from its official repository.

The file is encrypted with the user's password: scrypt, then AES-256-GCM in chunks of 1 MiB, each
sealed with the file's header, its number and whether it is the last one, so nothing can be cut
off, reordered or changed unnoticed. Inside is a tar of the above, its manifest first.

Restoring moves what is here aside first (a folder, nothing deleted), keeps this computer's own
settings (where apps are installed, the sandbox's size), and marks the apps as not installed
here: their builds are ready to install.
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
import os
import re
import secrets
import shutil
import tarfile
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import tomli_w

from . import __version__, apps, config, creds
from . import delivery as delivery_mod
from .conversation import Conversation
from .models import UserError
from .workspace import podman

if TYPE_CHECKING:
    from .engine import Engine

MAGIC = b"DVMBACKUP\x00\x01"
FORMAT = 1
CHUNK = 1 << 20
SCRYPT = {"n": 1 << 17, "r": 8, "p": 1}
MIN_PASSWORD = 10
SUFFIX = ".dvmbackup"
NAME = re.compile(r"DAVibeManager-(backup|auto)-\d{8}-\d{6}(-\d{1,3})?\.dvmbackup")
EVERY = {"day": 20 * 3600, "week": 6.5 * 86400}
AUTO = ("off", "day", "week", "change")
SESSIONS = "/home/agent/.claude/projects"
# a backup uploaded to restore: at most this big, and never filling the disk to its last GB
MAX_UPLOAD = 64 << 30
KEEP_FREE = 1 << 30
# this computer's own settings: kept when a backup from another one is restored
OWN_SETTINGS = ("install_dir", "app_home", "container_memory", "container_cpus", "container_pids", "ui_mode",
                "backup_dir", "backup_auto", "backup_keep")
# what of the data folder goes in (besides each app's kept builds)
DATA = ("apps", "conversations", "screens", "outside.json", "runtime-x86_64")


class BackupError(UserError):
    pass


# ---------------------------------------------------------------- the encrypted file


def _key(password: str, salt: bytes, kdf: dict) -> bytes:
    return Scrypt(salt=salt, length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(password.encode())


def _aad(header: bytes, n: int, last: bool) -> bytes:
    return header + n.to_bytes(8, "big") + (b"\x01" if last else b"\x00")


class Sealed(io.RawIOBase):
    """Writes the backup file: what is written to it is encrypted, chunk by chunk."""

    def __init__(self, f: BinaryIO, password: str, info: dict):
        self.f, self.salt, self.prefix = f, secrets.token_bytes(16), secrets.token_bytes(4)
        self.header = json.dumps({"format": FORMAT, "kdf": "scrypt", **SCRYPT,
                                  "salt": base64.b64encode(self.salt).decode(), "nonce": base64.b64encode(self.prefix).decode(),
                                  "chunk": CHUNK, **info}, sort_keys=True).encode()
        self.aes = AESGCM(_key(password, self.salt, SCRYPT))
        self.buf, self.n, self.done = bytearray(), 0, False
        f.write(MAGIC + len(self.header).to_bytes(4, "big") + self.header)

    def writable(self) -> bool:
        return True

    def write(self, b) -> int:
        self.buf += b
        while len(self.buf) > CHUNK:            # one is always held back: the last is sealed as the last
            self._seal(bytes(self.buf[:CHUNK]), False)
            del self.buf[:CHUNK]
        return len(b)

    def _seal(self, data: bytes, last: bool) -> None:
        ct = self.aes.encrypt(self.prefix + self.n.to_bytes(8, "big"), data, _aad(self.header, self.n, last))
        self.f.write(len(ct).to_bytes(4, "big") + ct)
        self.n += 1

    def close(self) -> None:
        if not self.done:
            self.done = True
            self._seal(bytes(self.buf), True)
            self.buf.clear()
        super().close()


def read_header(f: BinaryIO) -> tuple[bytes, dict]:
    if f.read(len(MAGIC)) != MAGIC:
        raise BackupError("That isn't a DA Vibe Manager backup.")
    size = int.from_bytes(f.read(4), "big")
    if not 0 < size < 65536:
        raise BackupError("That backup is damaged.")
    header = f.read(size)
    try:
        info = json.loads(header)
    except ValueError:
        raise BackupError("That backup is damaged.") from None
    if not isinstance(info, dict) or info.get("format") != FORMAT or info.get("kdf") != "scrypt":
        raise BackupError("That backup was made by a newer DA Vibe Manager: update this one first.")
    # the key's cost is the file's to say, so it is bounded: a made-up file must not take all the
    # memory (128·n·r bytes) or hours; ours is n 2^17, r 8, p 1
    n, r, p = info.get("n"), info.get("r"), info.get("p")
    if not all(isinstance(x, int) and not isinstance(x, bool) for x in (n, r, p)) \
            or not (2 <= n <= 1 << 20 and n & (n - 1) == 0 and 1 <= r <= 16 and 1 <= p <= 4 and n * r * 128 <= 1 << 30):
        raise BackupError("That backup is damaged.")
    try:
        salt, nonce = base64.b64decode(info.get("salt", ""), validate=True), base64.b64decode(info.get("nonce", ""), validate=True)
    except (ValueError, TypeError):
        raise BackupError("That backup is damaged.") from None
    if len(salt) < 16 or len(nonce) != 4:
        raise BackupError("That backup is damaged.")
    return header, info


class Opened(io.RawIOBase):
    """Reads the backup file: decrypts it chunk by chunk, checking each, and that none is missing."""

    def __init__(self, f: BinaryIO, password: str):
        self.f = f
        self.header, self.info = read_header(f)
        self.aes = AESGCM(_key(password, base64.b64decode(self.info["salt"]), self.info))
        self.prefix = base64.b64decode(self.info["nonce"])
        self.n, self.buf, self.pos, self.ended = 0, b"", 0, False
        self.next = self._read_chunk()
        try:
            self._fill()
        except BackupError:
            raise BackupError("That password doesn't open this backup.") from None

    def _read_chunk(self) -> bytes | None:
        size = self.f.read(4)
        if not size:
            return None
        n = int.from_bytes(size, "big")
        if n > CHUNK + 64:
            raise BackupError("That backup is damaged.")
        data = self.f.read(n)
        if len(data) != n:
            raise BackupError("That backup is cut short.")
        return data

    def _fill(self) -> None:
        if self.ended:
            return
        if self.next is None:
            raise BackupError("That backup is cut short.")
        ct, self.next = self.next, self._read_chunk()
        last = self.next is None
        try:
            self.buf = self.buf[self.pos:] + self.aes.decrypt(self.prefix + self.n.to_bytes(8, "big"), ct,
                                                              _aad(self.header, self.n, last))
            self.pos = 0
        except InvalidTag:
            raise BackupError("That backup is damaged, or was changed.") from None
        self.n += 1
        self.ended = last

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        while self.pos >= len(self.buf) and not self.ended:
            self._fill()
        n = min(len(b), len(self.buf) - self.pos)
        b[:n] = self.buf[self.pos:self.pos + n]
        self.pos += n
        return n


# ---------------------------------------------------------------- what goes in, and where it goes back


def kept_builds(all_apps: list[dict]) -> list[str]:
    """Each app's build to keep: the installed one, else its newest."""
    out = []
    for a in all_apps:
        did = (a.get("installed") or {}).get("build") or (a.get("builds") or [""])[-1]
        if did and (delivery_mod.root_dir() / did / "delivery.json").is_file():
            out.append(did)
    return out


def _add_tree(tar: tarfile.TarFile, src: Path, arc: str) -> None:
    if src.is_symlink() or not src.exists():
        return
    if src.is_file():
        tar.add(src, arc, recursive=False)
        return
    tar.add(src, arc, recursive=False)
    for p in sorted(src.iterdir()):
        _add_tree(tar, p, f"{arc}/{p.name}")


def write_backup(dest: Path, password: str, cfg: config.Config, sessions: Path | None) -> dict:
    """The backup file at dest (written whole, then put in place). Returns its manifest."""
    data = config.data_dir()
    all_apps = apps.list_all()
    builds = kept_builds(all_apps)
    keys = {}
    for p in cfg.providers:
        try:
            if (key := creds.get_secret("provider", p.name)):
                keys[p.name] = key
        except creds.KeyringUnavailable as e:
            raise BackupError(f"Your keyring is locked, so the API key can't go in the backup: {e}") from None
    manifest = {"format": FORMAT, "app_version": __version__, "created": time.time(),
                "apps": [{"id": a["id"], "name": a["name"], "version": (a.get("installed") or {}).get("version", ""),
                          "changes": [c["title"] for c in a.get("changes", [])]} for a in all_apps],
                "builds": builds, "chats": len(Conversation.list_all()), "keys": sorted(keys),
                "sessions": bool(sessions)}
    part = dest.with_name(dest.name + ".part")
    try:
        with open(part, "wb") as f:
            os.fchmod(f.fileno(), 0o600)
            sealed = Sealed(f, password, {"created": manifest["created"], "app_version": __version__})
            with tarfile.open(fileobj=sealed, mode="w|", format=tarfile.PAX_FORMAT) as tar:
                def blob(name: str, text: bytes) -> None:
                    ti = tarfile.TarInfo(name)
                    ti.size, ti.mtime, ti.mode = len(text), int(time.time()), 0o600
                    tar.addfile(ti, io.BytesIO(text))
                blob("manifest.json", json.dumps(manifest, indent=1).encode())
                blob("secrets.json", json.dumps({"providers": keys}).encode())
                blob("config/config.toml", tomli_w.dumps(cfg.to_dict()).encode())      # the settings as they are now
                for name in DATA:
                    _add_tree(tar, data / name, f"data/{name}")
                for did in builds:
                    _add_tree(tar, delivery_mod.root_dir() / did, f"data/deliveries/{did}")
                if sessions:
                    _add_tree(tar, sessions, "sessions")
            sealed.close()
        part.replace(dest)
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    return manifest


def _safe(member: tarfile.TarInfo) -> str | None:
    """Where a member of the backup goes, or None for anything that isn't a plain file or folder
    inside the backup's own layout."""
    p = PurePosixPath(member.name)
    if p.is_absolute() or ".." in p.parts or not p.parts or not (member.isfile() or member.isdir()):
        return None
    if p.parts[0] not in ("manifest.json", "secrets.json", "config", "data", "sessions"):
        return None
    return str(p)


def read_backup(path: Path, password: str, into: Path | None = None) -> dict:
    """The backup's manifest (checked with the password); with `into`, everything in it unpacked
    there, plainly: only files and folders, only where the backup's layout has them."""
    with open(path, "rb") as f:
        opened = Opened(f, password)
        with tarfile.open(fileobj=opened, mode="r|") as tar:
            manifest = None
            for m in tar:
                where = _safe(m)
                if where is None:
                    continue
                if where == "manifest.json":
                    manifest = json.loads(tar.extractfile(m).read())
                    if into is None:
                        return manifest
                    continue
                if into is None:
                    continue
                target = into / where
                if m.isdir():
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with open(target, "wb") as out:
                    shutil.copyfileobj(tar.extractfile(m), out)
                os.chmod(target, (m.mode & 0o755) | 0o600)
            if manifest is None:
                raise BackupError("That backup has no manifest: it is damaged.")
            return manifest


def settle(unpacked: Path, current: config.Config) -> tuple[config.Config, dict]:
    """The unpacked backup made right for this computer: settings with this computer's own kept,
    apps not installed here (their kept builds ready to install), chats without sessions that
    didn't come along. Returns (the settings, the keys)."""
    data = unpacked / "data"
    cfg = config.load(unpacked / "config" / "config.toml") if (unpacked / "config" / "config.toml").is_file() else config.Config()
    for key in OWN_SETTINGS:
        setattr(cfg.settings, key, getattr(current.settings, key))
    for meta_path in (data / "deliveries").glob("D*/delivery.json"):
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("status") in ("installed", "replaced"):
            meta["status"] = "new"
        for k in ("installed_to", "installed_via", "installed_at", "installed_files", "backups", "removed", "tried"):
            meta.pop(k, None)
        meta_path.write_text(json.dumps(meta, indent=1, ensure_ascii=False), encoding="utf-8")
    for app_path in (data / "apps").glob("*/app.json"):
        a = json.loads(app_path.read_text(encoding="utf-8"))
        was = a.get("installed") or {}
        a.update(installed=None, previous=None, restored={"version": was.get("version", ""), "at": time.time()})
        app_path.write_text(json.dumps(a, indent=1, ensure_ascii=False), encoding="utf-8")
    have = {p.stem for p in (unpacked / "sessions").rglob("*.jsonl")} if (unpacked / "sessions").is_dir() else set()
    for state in (data / "conversations").glob("*/state.json"):
        s = json.loads(state.read_text(encoding="utf-8"))
        if s.get("session") and s["session"] not in have:
            s["session"] = ""                   # the assistant starts it afresh; the chat is all there
            state.write_text(json.dumps(s, ensure_ascii=False), encoding="utf-8")
    keys = json.loads((unpacked / "secrets.json").read_text(encoding="utf-8")) if (unpacked / "secrets.json").is_file() else {}
    return cfg, keys.get("providers") or {}


# ---------------------------------------------------------------- the app's side of it


class Backups:
    def __init__(self, engine: "Engine"):
        self.e = engine
        self.running: dict | None = None        # {"what": "backup" | "restore", "since"}
        self._lock = asyncio.Lock()
        self._placing = asyncio.Lock()          # sessions put back into the sandbox, once at a time

    @staticmethod
    def state_path() -> Path:
        return config.data_dir() / "backups.json"

    def state(self) -> dict:
        try:
            return json.loads(self.state_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save_state(self, **changes) -> None:
        st = {**self.state(), **changes}
        p = self.state_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(st), encoding="utf-8")

    def folder(self) -> Path:
        return Path(os.path.expanduser(self.e.cfg.settings.backup_dir or "~/DA Vibe Manager backups"))

    def has_password(self) -> bool:
        try:
            return bool(creds.get_secret("backup", "password"))
        except creds.KeyringUnavailable:
            return False

    def set_password(self, password: str | None) -> None:
        if password:
            check_password(password)
            creds.set_secret("backup", "password", password)
        else:
            creds.delete_secret("backup", "password")
        self.changed()

    def found(self) -> list[dict]:
        """The backups in the backup folder, newest first."""
        try:
            files = [p for p in self.folder().iterdir() if NAME.fullmatch(p.name) and p.is_file()]
        except OSError:
            return []
        files.sort(key=lambda p: (p.stat().st_mtime, p.name), reverse=True)
        return [{"name": p.name, "size": p.stat().st_size, "at": p.stat().st_mtime, "auto": "-auto-" in p.name}
                for p in files[:30]]

    def view(self) -> dict:
        s = self.e.cfg.settings
        return {"folder": str(self.folder()), "auto": s.backup_auto, "keep": s.backup_keep, "has_password": self.has_password(),
                "running": self.running, **{k: v for k, v in self.state().items() if k in ("last", "error")},
                "found": self.found()}

    def changed(self) -> None:
        self.e.emit("backups", backups=self.view())

    async def _sessions(self, into: Path) -> Path | None:
        """The chats' Claude Code sessions, copied out of the sandbox (if it runs)."""
        if self.e.workspace.get("state") != "running":
            return None
        ids = sorted({c.session for c in map(_load, Conversation.list_all()) if c and c.session})
        if not ids:
            return None
        rc, out = await podman.exec_agent(self.e.sandbox, ["sh", "-c", 'cd "$0" 2>/dev/null && for s in "$@"; do '
                                                            'find . -maxdepth 2 -name "$s.jsonl" -type f; done', SESSIONS, *ids],
                                          timeout=60)
        rels = [r[2:] for r in out.split() if rc == 0 and re.fullmatch(r"\./[\w.-]+/[\w-]+\.jsonl", r)]
        for rel in rels:
            (into / rel).parent.mkdir(parents=True, exist_ok=True)
            try:
                await podman.copy_out(self.e.sandbox, f"{SESSIONS}/{rel}", into / rel)
            except podman.PodmanError:
                pass
        return into if rels else None

    async def backup(self, password: str | None = None, auto: bool = False) -> dict:
        """A backup in the backup folder, with the password given (or saved). Returns what's in it."""
        if password is None:
            try:
                password = creds.get_secret("backup", "password") or ""
            except creds.KeyringUnavailable as e:
                raise BackupError(f"Your keyring is locked, so the backup's password can't be read: {e}") from None
            if not password:
                raise BackupError("Choose a password for your backups first.")
        check_password(password)
        if self._lock.locked():
            raise BackupError("A backup or a restore is under way already.")
        async with self._lock:
            self.running = {"what": "backup", "since": time.time()}
            self.changed()
            try:
                folder = self.folder()
                if not folder.is_dir():
                    if auto:
                        raise BackupError(f"The backup folder {folder} isn't there (a drive that isn't plugged in?).")
                    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
                stem = f"DAVibeManager-{'auto' if auto else 'backup'}-{time.strftime('%Y%m%d-%H%M%S')}"
                dest, n = folder / f"{stem}{SUFFIX}", 2
                while dest.exists() and n < 1000:       # two in the same second
                    dest, n = folder / f"{stem}-{n}{SUFFIX}", n + 1
                with tempfile.TemporaryDirectory(prefix="dvm-sessions-") as tmp:
                    sessions = await self._sessions(Path(tmp))
                    manifest = await asyncio.to_thread(write_backup, dest, password, self.e.cfg, sessions)
                if auto:
                    self._prune(folder)
                last = {"at": time.time(), "path": str(dest), "size": dest.stat().st_size, "auto": auto,
                        "apps": len(manifest["apps"]), "marker": self.marker()}
                self._save_state(last=last, error=None)
                self.e.log("backup", path=str(dest), size=last["size"], apps=last["apps"], auto=auto)
                return {**last, "manifest": manifest}
            except Exception as e:
                was = self.state().get("error") or {}
                self._save_state(error={"at": time.time(), "text": str(e)[-400:], "auto": auto,
                                        **({"told": True} if was.get("told") and was.get("text") == str(e)[-400:] else {})})
                raise
            finally:
                self.running = None
                self.changed()

    def _prune(self, folder: Path) -> None:
        keep = max(1, int(self.e.cfg.settings.backup_keep or 5))
        autos = sorted((p for p in folder.iterdir() if NAME.fullmatch(p.name) and "-auto-" in p.name),
                       key=lambda p: (p.stat().st_mtime, p.name))
        for p in autos[:-keep]:
            p.unlink(missing_ok=True)

    @staticmethod
    def marker() -> float:
        """When the user's apps last changed (a new app, change or build)."""
        return max((a.get("updated", 0) for a in apps.list_all()), default=0)

    def due(self, now: float) -> bool:
        s = self.e.cfg.settings
        if s.backup_auto not in EVERY and s.backup_auto != "change":
            return False
        last = (self.state().get("last") or {})
        if s.backup_auto == "change":
            return self.marker() > last.get("marker", 0) and now - last.get("at", 0) > 600
        return now - last.get("at", 0) > EVERY[s.backup_auto]

    async def tick(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        if not self.due(now) or self._lock.locked() or self.e.app_manager.building or self.e.busy:
            return
        if not self.has_password():
            return
        try:
            await self.backup(auto=True)
        except BackupError as e:
            err = self.state().get("error") or {}
            if not err.get("told"):
                self.e.notify("Your apps weren't backed up", str(e))
                self._save_state(error={**err, "told": True})

    async def watch(self) -> None:
        await asyncio.sleep(180)
        while True:
            try:
                await self.tick()
            except Exception as e:  # noqa: BLE001 - tried again at the next tick
                self.e.log("backup_tick_failed", error=str(e))
            await asyncio.sleep(600)

    # ---------------------------------------------------------------- restoring

    def peek(self, path: Path, password: str) -> dict:
        """What a backup holds, checked with its password, without changing anything."""
        return read_backup(path, password)

    async def restore(self, path: Path, password: str) -> dict:
        """Everything in the backup, in place of what is here (which is moved aside, not deleted)."""
        e = self.e
        if e.busy:
            raise BackupError("Wait for the assistant to finish (or stop it) first.")
        if e.app_manager.building:
            raise BackupError("Wait for the app that's being built to finish first.")
        if self._lock.locked():
            raise BackupError("A backup or a restore is under way already.")
        async with self._lock:
            self.running = {"what": "restore", "since": time.time()}
            self.changed()
            data = config.data_dir()
            work = data.with_name(f"{data.name}.restoring-{secrets.token_hex(4)}")
            aside = ""
            try:
                manifest = await asyncio.to_thread(read_backup, path, password, work)
                cfg, keys = await asyncio.to_thread(settle, work, e.cfg)
                await e._close_builder()
                e._persist()
                e.conv = None                    # nothing of the chat open now is written after this
                if data.exists():
                    aside = str(data.with_name(f"{data.name}.before-restore-{time.strftime('%Y%m%d-%H%M%S')}"))
                    data.rename(aside)
                try:
                    (work / "data").rename(data)
                except OSError:
                    if aside:
                        Path(aside).rename(data)     # what was here, back as it was
                    aside = ""
                    raise
                if aside and (config.config_dir() / "config.toml").is_file():
                    shutil.copy2(config.config_dir() / "config.toml", Path(aside) / "config.toml")
                if (work / "sessions").is_dir():
                    shutil.move(str(work / "sessions"), str(data / "restored-sessions"))
                for name, key in keys.items():
                    creds.set_secret("provider", name, key)
                e.cfg.providers, e.cfg.settings = cfg.providers, cfg.settings     # in place: the app holds e.cfg
                e._save_config(e.cfg)
            finally:
                shutil.rmtree(work, ignore_errors=True)
                self.running = None
                if e.conv is None:
                    chats = Conversation.list_all()
                    e._open(Conversation.load(chats[0]["id"]) if chats else Conversation.create())
                    e._load_outside()
                self.changed()
            await self.place_sessions()
            e.log("restored", path=str(path), apps=len(manifest.get("apps", [])), aside=aside)
            e._changed()
            e.app_manager.changed()
            if e.ready and e.workspace.get("state") != "running":
                e.start_workspace()
            return {"apps": manifest.get("apps", []), "chats": manifest.get("chats", 0), "aside": aside,
                    "created": manifest.get("created"), "sessions": manifest.get("sessions", False)}

    async def place_sessions(self) -> None:
        """Chats' Claude Code sessions kept outside the sandbox (from a backup restored, or across a reset
        of the sandbox) put back into it: when it runs, else when it starts."""
        async with self._placing:
            src = config.data_dir() / "restored-sessions"
            if not src.is_dir() or self.e.workspace.get("state") != "running":
                return
            for f in sorted(src.rglob("*.jsonl")):
                await podman.put_file(self.e.sandbox, f"{SESSIONS}/{f.relative_to(src).as_posix()}", f.read_bytes())
            shutil.rmtree(src, ignore_errors=True)
        await self.e.app_manager.sync()

    async def keep_sessions(self) -> set[str]:
        """The chats' sessions copied out of the running sandbox, to be put back (place_sessions) once it
        starts again: the ids kept."""
        keep = config.data_dir() / "restored-sessions"
        keep.mkdir(parents=True, exist_ok=True, mode=0o700)
        await self._sessions(keep)
        return {p.stem for p in keep.rglob("*.jsonl")}


def check_password(password: str) -> None:
    if len(password or "") < MIN_PASSWORD:
        raise BackupError(f"The password needs at least {MIN_PASSWORD} characters. A few words you'll remember are best.")


def _load(c: dict) -> Conversation | None:
    try:
        return Conversation.load(c["id"])
    except FileNotFoundError:
        return None
