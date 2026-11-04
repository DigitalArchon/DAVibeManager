"""Sync, for the engine: tor when it's needed, pairing, and the apps kept the same on each computer.

Tor runs only while this computer is paired with another, or pairing. Then this computer's onion
service (its key in store.identity) is up, listing as its clients only the computers paired with
it, and this computer has given its tor the key to each of theirs.

A sync is one computer pulling from another: it asks for the other's apps (their summaries), and
takes what plan() says to, bundle by bundle, each checked against its digest and read as strictly
as a shared file (share.read). It pulls from each computer it's paired with when it starts, every
few minutes, when the other says it changed something (a poke), and right after pairing. Each
computer pulls for itself, so what changed on one reaches the other when the other pulls.

Nothing arrives while the app it would change is being built, its chat is working on it, or a
backup is being restored: it's taken next time.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .. import apps, share
from ..models import UserError
from . import library, pairing, store, tor as tor_mod, wire

if TYPE_CHECKING:
    from ..engine import Engine

SYNC_PORT = 7301                    # the virtual port of each computer's onion service
PULL_EVERY = 300                    # seconds between pulls from each computer
RETRY = 60                          # after tor itself failed
ANNOUNCE_AFTER = 5                  # a local change is told to the others this long after the last one
FIND_FOR = 180                      # seconds a joining computer looks for the pairing onion (it may be publishing)
FIND_AGAIN = 5                      # and how long it waits between tries
MAX_APPS = 500
SHARE_ID = re.compile(r"[0-9a-f]{32}")
DIGEST = re.compile(r"[0-9a-f]{64}")
ENDED = ("done", "failed", "cancelled", "expired")


class SyncError(UserError):
    pass


def _checked_list(apps_said) -> dict:
    """The other computer's summaries, checked: anything that isn't one is left out."""
    out = {}
    if not isinstance(apps_said, dict):
        return out
    for sid, s in list(apps_said.items())[:MAX_APPS]:
        if not (isinstance(s, dict) and SHARE_ID.fullmatch(str(sid)) and s.get("share") == sid
                and DIGEST.fullmatch(str(s.get("digest") or "")) and isinstance(s.get("changes"), dict)):
            continue
        out[sid] = {"share": sid, "name": str(s.get("name") or "")[:80], "digest": s["digest"],
                    "base_ref": str(s.get("base_ref") or "")[:100], "build": str(s.get("build") or "")[:12],
                    "changes": {str(k)[:48]: str(v)[:12] for k, v in list(s["changes"].items())[:apps.MAX_CHANGES * 2]}}
    return out


class SyncService:
    def __init__(self, engine: "Engine", make_tor: Callable | None = None):
        self.e = engine
        self.make_tor = make_tor
        self.available = make_tor is not None or tor_mod.find_tor() is not None
        self.tor = None
        self.pairing: dict | None = None
        self._decision: asyncio.Future | None = None
        self._pair_task: asyncio.Task | None = None
        self._pair_busy = False
        self._servers: dict[str, asyncio.AbstractServer] = {}
        self._onions: dict[str, str] = {}
        self._wake = asyncio.Event()
        self._runner: asyncio.Task | None = None
        self._pull_lock = asyncio.Lock()
        self._publish_lock = asyncio.Lock()
        self._announce: asyncio.TimerHandle | None = None
        self._announced: dict[str, str] = {}
        self._status: dict[str, dict] = {}         # peer id -> {"syncing": bool, "online": bool}
        self._me: store.Identity | None = None
        self._published: set[str] = set()          # the computers this computer's onion lists now

    # ---------------------------------------------------------------- for the window

    def me(self) -> store.Identity:
        if self._me is None:
            self._me = store.identity()
        return self._me

    def view(self) -> dict:
        peers = store.peers()
        return {"available": self.available, "name": self.me().name if peers or self.pairing else store.default_name(),
                "tor": dict(self.tor.state) if self.tor else {"step": "stopped", "progress": 0, "words": ""},
                "peers": [{**p.view(), **self._status.get(p.id, {})} for p in peers],
                "pairing": dict(self.pairing) if self.pairing else None}

    def _changed(self) -> None:
        self.e.emit("sync", sync=self.view())

    def _log(self, event: str, **data) -> None:
        from ..engine import app_log
        app_log(f"sync_{event}", **data)

    # ---------------------------------------------------------------- start and stop

    async def start(self) -> None:
        if store.peers():
            self._run_soon()

    def _run_soon(self) -> None:
        if self._runner is None or self._runner.done():
            self._runner = asyncio.ensure_future(self._run())
        self._wake.set()

    async def stop(self) -> None:
        for task in (self._runner, self._pair_task):
            if task and not task.done():
                task.cancel()
        if self._announce:
            self._announce.cancel()
        for server in self._servers.values():
            server.close()
        self._servers.clear()
        self._onions.clear()
        if self.tor:
            await self.tor.stop()

    async def _ensure_tor(self) -> None:
        if self.tor is None:
            def changed(state: dict) -> None:
                self._changed()
            self.tor = (self.make_tor or self._real_tor)(changed)
        if not self.tor.running:
            self._onions.clear()                # a tor that stopped took its onions with it
            await self.tor.start()

    def _real_tor(self, on_change):
        return tor_mod.Tor(tor_mod.paths_for(store.state_dir(), self.e.runtime_dir), on_change=on_change)

    def _socket(self, name: str) -> Path:
        d = self.e.runtime_dir / "tor"
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        return d / f"{name}.sock"

    async def _listen(self, name: str, handler) -> Path:
        path = self._socket(name)
        if name not in self._servers:
            path.unlink(missing_ok=True)
            self._servers[name] = await asyncio.start_unix_server(handler, path=str(path))
            path.chmod(0o600)
        return path

    async def _stop_tor_if_idle(self) -> None:
        if not store.peers() and not (self.pairing and self.pairing.get("step") not in ENDED) and self.tor:
            for server in self._servers.values():
                server.close()
            self._servers.clear()
            self._onions.clear()
            await self.tor.stop()

    # ---------------------------------------------------------------- this computer's onion service

    async def _publish(self) -> None:
        """This computer's onion, listing every computer paired with it; and its tor told the key to each
        of theirs."""
        async with self._publish_lock:
            await self._ensure_tor()
            me, peers = self.me(), store.peers()
            for p in peers:
                await self.tor.allow_client(p.onion, me.client_key)
            if "sync" in self._onions:
                await self.tor.remove_onion(self._onions.pop("sync"))
            self._published = set()
            if peers:
                path = await self._listen("sync", self._serve)
                self._onions["sync"] = await self.tor.add_onion(me.onion_key, SYNC_PORT, path, [p.client for p in peers])
                self._published = {p.id for p in peers}

    async def _run(self) -> None:
        """While this computer is paired: its onion up, and a pull from each other computer now and then."""
        while store.peers():
            try:
                if self._published != {p.id for p in store.peers()} or "sync" not in self._onions or not self.tor.running:
                    await self._publish()
            except (tor_mod.TorError, OSError) as e:
                self._log("tor_failed", error=str(e))
                self._changed()
                await asyncio.sleep(RETRY)
                continue
            self._wake.clear()
            for p in store.peers():
                await self.pull(p.id)
            try:
                await asyncio.wait_for(self._wake.wait(), PULL_EVERY)
            except asyncio.TimeoutError:
                pass
        await self._stop_tor_if_idle()
        self._changed()

    # ---------------------------------------------------------------- pairing

    def _pair_step(self, step: str, **more) -> None:
        self.pairing = {**(self.pairing or {}), "step": step, **more}
        self._changed()

    def _pairing_free(self) -> None:
        if not self.available:
            raise SyncError("This build of DA Vibe Manager has no Tor, so it can't sync: use the AppImage.")
        if self.pairing and self.pairing.get("step") not in ENDED:
            raise SyncError("A pairing is under way already: finish it, or cancel it.")

    def pair_show(self) -> dict:
        """Show a code for another computer to type (the code comes at once; tor starts meanwhile)."""
        self._pairing_free()
        code = pairing.new_code()
        self.pairing = {"role": "show", "code": pairing.shown(code), "step": "starting", "digits": "", "with": "",
                        "error": "", "until": time.time() + pairing.WAIT}
        self._changed()
        self._pair_task = asyncio.ensure_future(self._show(code))
        return dict(self.pairing)

    def pair_join(self, text: str) -> dict:
        """The code another computer shows, typed here."""
        self._pairing_free()
        try:
            code = pairing.read_code(text)
        except pairing.PairingError as e:
            raise SyncError(str(e)) from None
        self.pairing = {"role": "join", "code": "", "step": "starting", "digits": "", "with": "", "error": "",
                        "until": time.time() + FIND_FOR}
        self._changed()
        self._pair_task = asyncio.ensure_future(self._join(code))
        return dict(self.pairing)

    def pair_decide(self, same: bool) -> None:
        """The user's answer to "do both screens show these digits?"."""
        if not (self.pairing and self.pairing.get("step") == "check" and self._decision and not self._decision.done()):
            raise SyncError("There's nothing to check just now.")
        self._decision.set_result(bool(same))
        self._pair_step("deciding")

    async def pair_cancel(self) -> None:
        if self._pair_task and not self._pair_task.done():
            self._pair_task.cancel()
            try:
                await self._pair_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001 - it's being cancelled
                pass
        if self.pairing and self.pairing.get("step") not in ENDED:
            self._pair_step("cancelled")
        await self._stop_tor_if_idle()

    async def _show(self, code: str) -> None:
        paired = asyncio.get_running_loop().create_future()
        try:
            waiting = await asyncio.to_thread(pairing.Waiting, code, self.me().info())
            await self._ensure_tor()
            self._pair_step("publishing")

            async def on_pair(reader, writer):
                await self._pairing_with(waiting, reader, writer, paired)
            path = await self._listen("pair", on_pair)
            self._onions["pair"] = await self.tor.add_onion(pairing.pairing_onion(waiting.secret), pairing.VIRTUAL_PORT, path)
            # until its descriptor is on a directory, the other computer can't find it (it keeps trying meanwhile)
            await self.tor.wait_published(self._onions["pair"], 90)
            self._pair_step("waiting")
            left = self.pairing["until"] - time.time()
            await asyncio.wait_for(paired, max(1, left))
        except asyncio.TimeoutError:
            self._pair_step("expired", error="The code stopped working: show a new one.")
        except (tor_mod.TorError, pairing.PairingError, wire.WireError, OSError) as e:
            self._pair_step("failed", error=str(e))
        finally:
            if "pair" in self._onions and self.tor:
                try:
                    await self.tor.remove_onion(self._onions.pop("pair"))
                except tor_mod.TorError:
                    pass
            if "pair" in self._servers:
                self._servers.pop("pair").close()
            await self._stop_tor_if_idle()

    async def _pairing_with(self, waiting: pairing.Waiting, reader, writer, paired: asyncio.Future) -> None:
        """The other computer found the code's onion (one at a time)."""
        if self._pair_busy or paired.done():
            writer.close()
            return
        self._pair_busy = True
        try:
            await wire.send(writer, waiting.opened(await wire.recv(reader)))
            waiting.revealed(await wire.recv(reader))
            await self._agree(waiting.them, waiting.digits, waiting.secret_for_them, reader, writer)
            if not paired.done():
                paired.set_result(True)
        except (pairing.PairingError, wire.WireError, tor_mod.TorError) as e:
            self._pair_step("failed", error=str(e))
            if not paired.done():
                paired.set_result(False)
        finally:
            self._pair_busy = False
            writer.close()

    async def _join(self, code: str) -> None:
        try:
            joining = await asyncio.to_thread(pairing.Joining, code, self.me().info())
            await self._ensure_tor()
            self._pair_step("finding")
            address = pairing.pairing_onion(joining.secret).address
            while True:
                try:
                    reader, writer = await self.tor.open(address, pairing.VIRTUAL_PORT)
                    break
                except wire.Unreachable as e:
                    if time.time() > self.pairing["until"] or e.code in (0xF4, 0xF5, 0xF6):
                        raise pairing.PairingError("No computer is waiting with that code: check it, and that the "
                                                   "other computer still shows it.") from None
                    await asyncio.sleep(FIND_AGAIN)  # its onion may still be on its way to the directories
            try:
                await wire.send(writer, joining.opening())
                await wire.send(writer, joining.answered(await wire.recv(reader)))
                await self._agree(joining.them, joining.digits, joining.secret_for_them, reader, writer)
            finally:
                writer.close()
        except (tor_mod.TorError, pairing.PairingError, wire.WireError, OSError) as e:
            self._pair_step("failed", error=str(e))
        finally:
            await self._stop_tor_if_idle()

    async def _agree(self, them: dict, digits: str, secret: bytes, reader, writer) -> None:
        """Both screens show the digits; each user says whether they match, and each computer tells the
        other. Paired only when both said yes."""
        self._decision = asyncio.get_running_loop().create_future()
        self._pair_step("check", digits=digits, **{"with": them["name"]})
        remote = asyncio.ensure_future(wire.recv(reader, pairing.WAIT))
        try:
            done, _ = await asyncio.wait({self._decision, remote}, timeout=pairing.WAIT, return_when=asyncio.FIRST_COMPLETED)
            if not done:
                raise pairing.PairingError("Nobody answered in time: nothing was paired.")
            if self._decision in done:
                mine = self._decision.result()
                await wire.send(writer, {"t": "decided", "same": mine})
                if not mine:
                    raise pairing.PairingError("The numbers didn't match, so nothing was paired.")
                msg = await remote
            else:
                msg = remote.result()
                if not (msg.get("t") == "decided" and msg.get("same") is True):
                    raise pairing.PairingError("The other computer said the numbers didn't match: nothing was paired.")
                mine = await asyncio.wait_for(asyncio.shield(self._decision), pairing.WAIT)
                await wire.send(writer, {"t": "decided", "same": mine})
                if not mine:
                    raise pairing.PairingError("The numbers didn't match, so nothing was paired.")
            if not (msg.get("t") == "decided" and msg.get("same") is True):
                raise pairing.PairingError("The other computer said the numbers didn't match: nothing was paired.")
        finally:
            remote.cancel()
        peers = [p for p in store.peers() if p.id != them["id"]]
        peers.append(store.Peer(them["id"], them["name"], them["onion"], them["client"], base64.b64encode(secret).decode()))
        store.save_peers(peers)
        self._log("paired", peer=them["id"], name=them["name"])
        self._pair_step("done", error="")
        try:
            await self._publish()
        except (tor_mod.TorError, OSError) as e:   # paired all the same: the runner publishes it again
            self._log("publish_failed", error=str(e))
        self._run_soon()

    # ---------------------------------------------------------------- the computers paired with this one

    def rename(self, name: str) -> None:
        me = self.me()
        me.name = pairing.clean_name(name)
        store.save_identity(me)
        self._changed()

    async def unpair(self, peer_id: str) -> None:
        peer = next((p for p in store.peers() if p.id == peer_id), None)
        if peer is None:
            raise SyncError("That computer isn't paired with this one.")
        try:                                    # it's told, if it can be reached: it forgets this one too
            reader, writer = await asyncio.wait_for(self._connect(peer), 60)
            try:
                await wire.send(writer, {"t": "unpair"})
            finally:
                writer.close()
        except (wire.WireError, tor_mod.TorError, OSError, asyncio.TimeoutError):
            pass
        await self._forget(peer)

    async def _forget(self, peer: store.Peer) -> None:
        store.forget(peer.id)
        self._status.pop(peer.id, None)
        self._log("unpaired", peer=peer.id)
        if self.tor and self.tor.running:
            try:
                await self.tor.forget_client(peer.onion)
                await self._publish()
            except tor_mod.TorError:
                pass
        self._wake.set()
        self._changed()

    async def _connect(self, peer: store.Peer):
        await self._ensure_tor()
        reader, writer = await self.tor.open(peer.onion, SYNC_PORT)
        try:
            await wire.hello_as_client(reader, writer, self.me().id, peer.id, peer.secret_bytes)
        except BaseException:
            writer.close()
            raise
        return reader, writer

    def sync_now(self) -> None:
        if not store.peers():
            raise SyncError("This computer isn't paired with another yet.")
        self._run_soon()

    # ---------------------------------------------------------------- what's asked of this computer

    async def _serve(self, reader, writer) -> None:
        """Another computer, paired with this one, connected to its onion."""
        me = self.me()
        try:
            def secret_of(pid):
                p = next((p for p in store.peers() if p.id == pid), None)
                return p.secret_bytes if p else None
            who = await wire.hello_as_server(reader, writer, me.id, secret_of)
            self._seen(who)
            while True:
                msg = await wire.recv(reader)
                t = msg.get("t")
                if t == "list":
                    self._renamed(who, msg.get("name"))
                    here = library.local()
                    await wire.send(writer, {"t": "apps", "name": me.name, "apps": {sid: s for sid, (a, s, d) in here.items()}})
                elif t == "bundle":
                    entry = library.local().get(str(msg.get("share") or ""))
                    if entry is None:
                        await wire.send(writer, {"t": "missing"})
                    else:
                        await wire.send(writer, {"t": "bundle", "share": entry[1]["share"], "digest": entry[1]["digest"]})
                        await wire.send_bytes(writer, entry[2])
                elif t == "poke":
                    self._wake.set()            # it changed something: pull from it
                elif t == "unpair":
                    peer = next((p for p in store.peers() if p.id == who), None)
                    if peer:
                        await self._forget(peer)
                    return
                else:
                    return
        except wire.WireError:
            pass
        finally:
            writer.close()

    def _seen(self, pid: str, error: str = "") -> None:
        items = store.peers()
        for p in items:
            if p.id == pid:
                p.seen = time.time() if not error else p.seen
                p.error = error
        store.save_peers(items)
        self._status[pid] = {**self._status.get(pid, {}), "online": not error}
        self._changed()

    def _renamed(self, pid: str, name) -> None:
        if not name:
            return
        items = store.peers()
        for p in items:
            if p.id == pid and p.name != pairing.clean_name(name):
                p.name = pairing.clean_name(name)
                store.save_peers(items)

    # ---------------------------------------------------------------- pulling

    def _busy_with(self, app_id: str) -> bool:
        e = self.e
        conv = getattr(e, "conv", None)
        return (app_id in e.app_manager.building or bool(getattr(e.backups, "running", None))
                or (e.busy and conv is not None and conv.app == app_id))

    async def pull(self, peer_id: str) -> dict:
        """Take what the other computer changed. Returns what came: {"apps": [...], "error": ""}."""
        peer = next((p for p in store.peers() if p.id == peer_id), None)
        if peer is None:
            return {"apps": [], "error": "not paired"}
        async with self._pull_lock:
            self._status[peer.id] = {**self._status.get(peer.id, {}), "syncing": True}
            self._changed()
            came: list[str] = []
            try:
                reader, writer = await self._connect(peer)
                try:
                    came = await self._pull_from(peer, reader, writer)
                    await wire.send(writer, {"t": "bye"})
                finally:
                    writer.close()
                items = store.peers()
                for p in items:
                    if p.id == peer.id:
                        p.synced = p.seen = time.time()
                        p.error = ""
                store.save_peers(items)
                self._status[peer.id] = {"syncing": False, "online": True}
                if came:
                    self._log("pulled", peer=peer.id, apps=came)
                    self.e.app_manager.changed()
                return {"apps": came, "error": ""}
            except (wire.WireError, tor_mod.TorError, share.ShareError, OSError) as e:
                why = e.why if isinstance(e, wire.Unreachable) else str(e)
                self._status[peer.id] = {"syncing": False, "online": False}
                self._seen(peer.id, error=why[:300])
                return {"apps": came, "error": why}
            finally:
                self._status[peer.id] = {**self._status.get(peer.id, {}), "syncing": False}
                self._changed()

    async def _pull_from(self, peer: store.Peer, reader, writer) -> list[str]:
        await wire.send(writer, {"t": "list", "name": self.me().name})
        msg = await wire.recv(reader)
        if msg.get("t") != "apps":
            raise wire.WireError("the other computer didn't list its apps")
        self._renamed(peer.id, msg.get("name"))
        theirs = _checked_list(msg.get("apps"))
        here = library.local()
        base = store.base_of(peer.id)
        new_base, came = {}, []
        for sid in sorted(set(here) | set(theirs)):
            mine, t, b = here.get(sid), theirs.get(sid), base.get(sid)
            how = library.plan(mine and mine[1], t, b)
            if how in ("same", "keep"):
                new_base[sid] = t
            elif how in ("gone_here", "gone_there"):
                new_base[sid] = b
                if how == "gone_there":
                    self._removed_there(mine[0], peer)
            elif how in ("take", "merge", "new", "back"):
                if mine and self._busy_with(mine[0]["id"]) or getattr(self.e.backups, "running", None):
                    if b:
                        new_base[sid] = b           # next time
                    continue
                got = await self._bundle(reader, writer, sid, t["digest"])
                if got is None:
                    if b:
                        new_base[sid] = b
                    continue
                if how in ("new", "back"):
                    a = library.create(got, peer.id, peer.name)
                else:
                    a, _ = library.combine(mine[0], got, b, peer.id, peer.name)
                came.append(a["id"])
                new_base[sid] = t
        store.save_base(peer.id, new_base)
        return came

    async def _bundle(self, reader, writer, sid: str, digest: str) -> dict | None:
        await wire.send(writer, {"t": "bundle", "share": sid})
        head = await wire.recv(reader)
        if head.get("t") != "bundle":
            return None                         # it changed meanwhile: next time
        data = await wire.recv_bytes(reader)
        if hashlib.sha256(data).hexdigest() != head.get("digest") or head.get("share") != sid:
            raise wire.WireError("an app's bundle didn't match what was said of it")
        got = share.read(data)
        if got["app"]["share"]["id"] != sid:
            raise wire.WireError("an app's bundle is of another app")
        return got

    def _removed_there(self, a: dict, peer: store.Peer) -> None:
        synced = dict(a.get("synced") or {})
        if (synced.get("removed_on") or {}).get("peer") == peer.id:
            return
        synced["removed_on"] = {"peer": peer.id, "name": peer.name, "at": time.time()}
        apps.save({**a, "synced": synced})
        self.e.app_manager.changed()

    def keep_here(self, app_id: str) -> None:
        """The user keeps an app another computer removed: it's this computer's own from now on."""
        a = apps.load(app_id)
        if not a or not (a.get("synced") or {}).get("removed_on"):
            raise SyncError("There's nothing to keep.")
        synced = dict(a["synced"])
        gone = synced.pop("removed_on")
        base = store.base_of(gone["peer"])
        base.pop((a.get("share") or {}).get("id", ""), None)
        if gone["peer"] in {p.id for p in store.peers()}:
            store.save_base(gone["peer"], base)
        apps.save({**a, "synced": synced})
        self.e.app_manager.changed()

    def resolve(self, app_id: str, item: str, keep: str) -> None:
        library.resolve(apps.check_id(app_id), str(item), str(keep))
        self.e.app_manager.changed()

    # ---------------------------------------------------------------- telling the others

    def local_changed(self) -> None:
        """An app changed here (AppManager.changed): the others are told, a moment after the last change."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:                    # from a worker thread: onto the loop
            if getattr(self.e, "loop", None):
                self.e.loop.call_soon_threadsafe(self.local_changed)
            return
        if not store.peers():
            return
        if self._announce:
            self._announce.cancel()
        self._announce = loop.call_later(ANNOUNCE_AFTER, lambda: asyncio.ensure_future(self._tell()))

    async def _tell(self) -> None:
        now = {sid: s for sid, (a, s, d) in library.local().items()}
        if {k: v["digest"] for k, v in now.items()} == {k: v["digest"] for k, v in self._announced.items()}:
            return
        self._announced = now
        for p in store.peers():
            try:
                reader, writer = await asyncio.wait_for(self._connect(p), 60)
                try:
                    await wire.send(writer, {"t": "poke"})
                finally:
                    writer.close()
            except (wire.WireError, tor_mod.TorError, OSError, asyncio.TimeoutError):
                continue                        # offline: it pulls when it's next on
