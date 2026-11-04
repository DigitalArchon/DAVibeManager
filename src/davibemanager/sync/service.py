"""Sync, for the engine: the user's group of computers, tor when it's needed, and the apps the same on each.

The group is every computer of the user's that was added to it (pairing.py), all alike: any of them
can add another, or remove one. Each computer runs an onion service (its key in store.identity) that
lists as its clients only the group's other members, and its tor has the key to each of theirs.
Whenever two members talk they first exchange their lists of members (store.merge_members), so a
computer added by one, or removed by one, is soon known to all, however many there are; and each
syncs with every other directly. Tor runs only while this computer is in a group with another, or a
code is being shown or looked for.

A code works until it's used, or cancelled. It's kept (store.pending_pairing) and taken up again
after a restart, and the computer it was typed on looks for the other until it finds it: nobody
needs to be at the computer showing it.

A computer that was in a group of its own joins another with all of it: it brings its members
along, and keeps its old group's key a while. A member of the old group that hasn't heard yet is
told by the first computer it talks to that knows both ("move"), and changes over.

A sync is one computer pulling from another: it asks for the other's apps (their summaries), and
takes what library.plan() says to, bundle by bundle, each checked against its digest and read as
strictly as a shared file (share.read). Then the other pulls from it in turn, on the same
connection: one that can reach the other syncs both ways (Tor may find one computer's onion well
before the other's). Each pulls from each member when it starts, every few minutes, and soon after
it couldn't reach it, a few at a time; and a change is taken to the others as it's made. Nothing arrives while the app it would change is being built, its chat is working on
it, or a backup is being restored: it's taken next time.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import time
import weakref
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .. import apps, share
from ..models import UserError
from . import library, pairing, store, tor as tor_mod, wire

if TYPE_CHECKING:
    from ..engine import Engine

SYNC_PORT = 7301                    # the virtual port of each computer's onion service
PULL_EVERY = 300                    # seconds between pulls from each member
RETRY = 60                          # after tor itself failed
# after a member couldn't be reached, tried again this soon, then twice as long each time up to
# PULL_EVERY: right after a computer is added, its onion (and the others' lists) take a while
RETRY_FIRST = 20
FIRST_AFTER = 45                    # a computer just added is first pulled from this long after (its onion is on its way)
NEW_FOR = 900                       # and counts as just added this long
ANNOUNCE_AFTER = 5                  # a local change is told to the others this long after the last one
FIND_AGAIN, FIND_MOST = 5, 60       # a code's onion looked for again after this, doubling up to this
CHECK_EVERY = 60                    # how often a code shown checks that its onion is still up
FRESH_EVERY = 120                   # tor's memory of onions it couldn't find, forgotten at most this often
AT_ONCE = 4                         # members pulled from, and told something, at the same time
TELL_FOR = 7 * 86400                # a computer removed while it was off is told when it's next on, for a week
HOLD_MOST = 60                      # a new list of members waits at most this long for connections to this onion to end
MAX_APPS = 500
SHARE_ID = re.compile(r"[0-9a-f]{32}")
DIGEST = re.compile(r"[0-9a-f]{64}")
ENDED = ("done", "failed", "cancelled")
TAKES = ("take", "merge", "new", "back")


class SyncError(UserError):
    pass


class Gone(Exception):
    """This computer isn't in the group any more (it was removed, or left) since the sync began."""


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


def _group_msg(g: store.Group) -> dict:
    return {"id": g.id, "key": base64.b64encode(g.key).decode()}


def _group_of(msg) -> tuple[str, bytes] | None:
    """A group (its id and key) as another computer sent it, checked."""
    try:
        gid, key = str(msg.get("id") or ""), base64.b64decode(str(msg.get("key") or ""), validate=True)
    except (AttributeError, ValueError):
        return None
    return (gid, key) if store.GROUP_ID.fullmatch(gid) and len(key) == 32 else None


class SyncService:
    def __init__(self, engine: "Engine", make_tor: Callable | None = None):
        self.e = engine
        self.make_tor = make_tor
        self.available = make_tor is not None or tor_mod.find_tor() is not None
        self.tor = None
        self.pairing: dict | None = None            # a code shown or typed, for the window
        self._pair_task: asyncio.Task | None = None
        self._pair_busy = False
        self._spent: asyncio.Future | None = None   # the code shown is used up
        self._joiner = ""                           # the computer it added, until that one's in for sure
        self._servers: dict[str, asyncio.AbstractServer] = {}
        self._onions: dict[str, str] = {}
        self._allowed: set[str] = set()             # the onions this computer's tor has its client key for
        self._published: list[str] | None = None    # the client keys this computer's onion lists
        self._held_since = 0.0                      # a new list of them waiting for connections to end, since
        self._serving = 0                           # connections to this computer's onion, now
        self._outgoing = 0                          # a removed computer being told, now
        self._fresh_at = 0.0
        self._wake = asyncio.Event()
        self._runner: asyncio.Task | None = None
        self._pulling: dict[str, asyncio.Task] = {}
        self._again: set[str] = set()               # poked while being pulled from: pulled again right after
        self._next: dict[str, float] = {}           # member id -> when to pull from it next
        self._delay: dict[str, float] = {}          # member id -> how long to wait after its next miss
        self._publish_lock = asyncio.Lock()
        self._slots = asyncio.Semaphore(AT_ONCE)
        self._tell_slots = asyncio.Semaphore(AT_ONCE)
        self._tasks: set[asyncio.Task] = set()
        self._streams = weakref.WeakSet()           # the connections open, to cut when sync stops
        self._announce: asyncio.TimerHandle | None = None
        self._announced: dict[str, str] = {}
        self._live: dict[str, dict] = {}            # member id -> {"syncing", "online"} (not kept)
        self._me: store.Identity | None = None
        self._leaving = False
        self._stopped = False
        self._notice: dict | None = None            # this computer was removed from the group: by whom, when

    # ---------------------------------------------------------------- for the window

    def me(self) -> store.Identity:
        if self._me is None:
            self._me = store.identity()
        return self._me

    def _roster(self) -> dict[str, dict]:
        """The group's members (none when this computer isn't in one)."""
        return store.members() if store.group() else {}

    def _others(self) -> list[dict]:
        """The group's other members, not removed."""
        roster = self._roster()
        return store.live(roster, but=self.me().id) if roster else []

    def view(self) -> dict:
        me = self._me or store.identity(make=False)
        self._me = me
        roster = self._roster() if me else {}
        mine = roster.get(me.id) if me else None
        st, now = (store.status() if roster else {}), time.time()
        members = []
        for e in store.live(roster, but=me.id if me else ""):
            s = st.get(e["id"], {})
            members.append({"id": e["id"], "name": e["name"], "synced": s.get("synced", 0), "seen": s.get("seen", 0),
                            "error": s.get("error", ""), "syncing": False,
                            "new": now - max(s.get("since", 0), (mine or {}).get("added", 0)) < NEW_FOR,
                            **self._live.get(e["id"], {})})
        return {"available": self.available, "name": me.name if me else store.default_name(),
                "tor": dict(self.tor.state) if self.tor else {"step": "stopped", "progress": 0, "words": ""},
                "members": sorted(members, key=lambda m: m["name"].lower()),
                "pairing": dict(self.pairing) if self.pairing else None, "removed": self._notice}

    def _changed(self) -> None:
        self.e.emit("sync", sync=self.view())

    def _log(self, event: str, **data) -> None:
        from ..engine import app_log
        app_log(f"sync_{event}", **data)

    def _name_of(self, member_id: str) -> str:
        if member_id == self.me().id:
            return self.me().name
        return (store.members().get(member_id) or {}).get("name") or "Another of your computers"

    def _notify(self, title: str, body: str) -> None:
        notify = getattr(self.e, "notify", None)
        if callable(notify):
            try:
                notify(title, body)
            except Exception:  # noqa: BLE001 - a desktop that can't show one
                pass

    def _spawn(self, coro) -> asyncio.Task:
        task = asyncio.ensure_future(coro)
        self._keep(task)
        return task

    def _keep(self, task: asyncio.Task | None) -> None:
        """A task stopped with the rest when sync stops (one serving a connection to this computer's onions, say)."""
        if task:
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    # ---------------------------------------------------------------- start and stop

    async def start(self) -> None:
        me = store.identity(make=False)
        if me and store.group() and (store.members().get(me.id) or {}).get("removed"):
            store.leave_all()                   # it left, or heard it was removed, and stopped before it was done
        pending = store.pending_pairing()
        if pending and self.available:          # a code shown or typed before a restart: it still works
            self._begin(pending)
        if self._others():
            self._run_soon()

    def _run_soon(self) -> None:
        if self._runner is None or self._runner.done():
            self._runner = asyncio.ensure_future(self._run())
        self._wake.set()

    async def stop(self) -> None:
        """Everything stopped, tor too. A task told to stop runs on until it next waits, so nothing may
        start tor again meanwhile (_ensure_tor), and each is waited for."""
        self._stopped = True
        tasks = [t for t in (self._runner, self._pair_task, *self._pulling.values(), *self._tasks)
                 if t and not t.done() and t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        if self._announce:
            self._announce.cancel()
        self._close_all()
        for writer in list(self._streams):
            writer.transport.abort()
        if self.tor:
            await self.tor.stop()
        if tasks:
            await asyncio.wait(tasks, timeout=5)

    def _close_all(self) -> None:
        for server in self._servers.values():
            server.close()
        self._servers.clear()
        self._onions.clear()
        self._allowed.clear()
        self._published = None

    async def _ensure_tor(self) -> None:
        if self._stopped:
            raise tor_mod.TorError("Sync has stopped.")
        if self.tor is None:
            self.tor = (self.make_tor or self._real_tor)(lambda state: self._changed())
        if not self.tor.running:
            self._onions.clear()                # a tor that stopped took its onions and keys with it
            self._allowed.clear()
            self._published = None
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

    async def _open(self, address: str, port: int):
        reader, writer = await self.tor.open(address, port)
        self._streams.add(writer)
        return reader, writer

    def _pairing_under_way(self) -> bool:
        return bool(self.pairing and self.pairing.get("step") not in ENDED)

    async def _stop_tor_if_idle(self) -> None:
        if self.tor and not self._others() and not self._pairing_under_way() and not self._outgoing:
            self._close_all()
            await self.tor.stop()

    async def _fresh_lookups(self) -> None:
        """Tor's memory of the onions it couldn't find forgotten (at most every FRESH_EVERY), so one that's
        up now is found now, not a quarter of an hour later; the keys it forgets with it, given again."""
        if time.time() - self._fresh_at < FRESH_EVERY or not (self.tor and self.tor.running):
            return
        self._fresh_at = time.time()
        try:
            async with self._publish_lock:
                await self.tor.forget_lookups()
                self._allowed.clear()
                await self._allow_all()
        except (tor_mod.TorError, OSError) as e:
            self._log("tor_failed", error=str(e))

    # ---------------------------------------------------------------- this computer's onion service

    async def _publish(self) -> bool:
        """This computer's onion, listing the group's other members as its clients, and its tor given the
        key to each of theirs. False when a new list had to wait: listing them anew cuts off whoever is
        connected to it just then, so it waits for them to finish (HOLD_MOST at most)."""
        async with self._publish_lock:
            await self._ensure_tor()
            await self._allow_all()
            clients = sorted(e["client"] for e in self._others())
            if clients == self._published and ("sync" in self._onions) == bool(clients):
                self._held_since = 0
                return True
            if self._serving and "sync" in self._onions:
                self._held_since = self._held_since or time.time()
                if time.time() - self._held_since < HOLD_MOST:
                    return False
            self._held_since = 0
            if "sync" in self._onions:
                await self.tor.remove_onion(self._onions.pop("sync"))
            if clients:
                path = await self._listen("sync", self._serve)
                self._onions["sync"] = await self.tor.add_onion(self.me().onion_key, SYNC_PORT, path, clients)
            self._published = clients
            return True

    async def _allow_all(self) -> None:
        """Tor given this computer's client key for each member's onion (and for any computer removed that
        it's still to tell), and made to forget it for the rest. With _publish_lock held."""
        reach = {e["onion"] for e in self._others() + self._to_tell()}
        for address in sorted(reach - self._allowed):
            await self.tor.allow_client(address, self.me().client_key)
            self._allowed.add(address)
        for address in sorted(self._allowed - reach):
            await self.tor.forget_client(address)
            self._allowed.discard(address)

    def _to_tell(self) -> list[dict]:
        """The computers this one removed from the group while they were off: told when they're next on
        (for TELL_FOR)."""
        roster = self._roster()
        if not roster:
            return []
        me, st, now = self.me().id, store.status(), time.time()
        return [e for e in roster.values() if e["removed"] and e["by"] == me and e["id"] != me
                and now - e["removed"] < TELL_FOR and not st.get(e["id"], {}).get("told")]

    async def _run(self) -> None:
        """While this computer is in a group with others: its onion up, and each member pulled from now
        and then (a few at a time, each on its own time)."""
        while self._others() and not self._leaving:
            try:
                held = not await self._publish()
            except (tor_mod.TorError, OSError) as e:
                self._log("tor_failed", error=str(e))
                self._changed()
                await asyncio.sleep(RETRY)
                continue
            self._wake.clear()
            now = time.time()
            due = self._others() + self._to_tell()
            for e in due:
                if self._next.get(e["id"], 0) <= now and e["id"] not in self._pulling:
                    self._pulling[e["id"]] = asyncio.ensure_future(self._pull_slot(e))
            later = [self._next[e["id"]] - now for e in due if e["id"] not in self._pulling and e["id"] in self._next]
            try:
                await asyncio.wait_for(self._wake.wait(), max(0.05, min([PULL_EVERY, *later, *([5] if held else [])])))
            except asyncio.TimeoutError:
                pass
        await self._stop_tor_if_idle()
        self._changed()

    async def _pull_slot(self, e: dict) -> None:
        mid = e["id"]
        try:
            async with self._slots:
                ok = await self._tell_removed(e) if e["removed"] else not (await self.pull(mid))["error"]
            if ok:
                self._next[mid], self._delay[mid] = time.time() + PULL_EVERY, RETRY_FIRST
            else:
                delay = self._delay.get(mid, RETRY_FIRST)
                self._next[mid], self._delay[mid] = time.time() + delay, min(delay * 2, PULL_EVERY)
                if self._is_new(mid):
                    await self._fresh_lookups()
            if mid in self._again:
                self._next[mid] = 0
        finally:
            self._again.discard(mid)
            self._pulling.pop(mid, None)
            self._wake.set()

    def _soon(self, member_id: str, after: float = 0) -> None:
        """A pull from that member now (or `after` seconds from now)."""
        self._next[member_id] = time.time() + after if after else 0
        if member_id in self._pulling and not after:
            self._again.add(member_id)
        self._wake.set()

    def _is_new(self, member_id: str) -> bool:
        """Whether that member, or this computer, was added lately: its onion, or this one's place in the
        others' lists, may still be on its way."""
        since = store.status().get(member_id, {}).get("since", 0)
        added = (self._roster().get(self.me().id) or {}).get("added", 0)
        return time.time() - max(since, added) < NEW_FOR

    def sync_now(self) -> None:
        if not self._others():
            raise SyncError("This computer isn't in a group with another yet.")
        for e in self._others():
            self._soon(e["id"])
        self._run_soon()

    # ---------------------------------------------------------------- adding a computer

    def _pair_step(self, step: str, **more) -> None:
        self.pairing = {**(self.pairing or {}), "step": step, **more}
        self._changed()

    def _need_tor(self) -> None:
        if not self.available:
            raise SyncError("This copy of DA Vibe Manager has no Tor, so it can't sync: use the AppImage.")

    def pair_show(self) -> dict:
        """A code for another computer to type, whenever it's ready: it works until it's used once, or
        cancelled (while it waits, the same code is shown again)."""
        self._need_tor()
        if self._pairing_under_way():
            if self.pairing["role"] == "show":
                return dict(self.pairing)
            raise SyncError("This computer is looking for another with a code: cancel that first.")
        if len(self._others()) + 1 >= store.MAX_MEMBERS:
            raise SyncError(f"A group can have up to {store.MAX_MEMBERS} computers: remove one first.")
        pending = {"role": "show", "code": pairing.new_code(), "since": time.time()}
        store.save_pending_pairing(pending)
        self._begin(pending)
        return dict(self.pairing)

    def pair_join(self, text: str) -> dict:
        """The code another computer shows, typed here: that computer is looked for until it's found (it
        may be off just now), or the user cancels."""
        self._need_tor()
        if self._pairing_under_way():
            raise SyncError("A pairing is under way already: cancel it first.")
        try:
            code = pairing.read_code(text)
        except pairing.PairingError as e:
            raise SyncError(str(e)) from None
        pending = {"role": "join", "code": code, "since": time.time()}
        store.save_pending_pairing(pending)
        self._begin(pending)
        return dict(self.pairing)

    def _begin(self, pending: dict) -> None:
        role, code = pending["role"], pending["code"]
        self._joiner = str(pending.get("joiner") or "") if role == "show" else ""
        self.pairing = {"role": role, "code": pairing.shown(code) if role == "show" else "", "step": "starting",
                        "digits": "", "with": self._name_of(self._joiner) if self._joiner else "", "error": "",
                        "since": pending.get("since") or time.time()}
        self._changed()
        self._pair_task = asyncio.ensure_future(self._show(code) if role == "show" else self._join(code))

    async def pair_cancel(self) -> None:
        task = self._pair_task
        if task and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001 - it's being cancelled
                pass
        store.save_pending_pairing(None)
        self._joiner = ""
        if self._pairing_under_way():
            self._pair_step("cancelled")
        await self._stop_tor_if_idle()

    def dismiss(self) -> None:
        """The window showed how a pairing ended, or that this computer was removed: it's put away."""
        self._notice = None
        if self.pairing and self.pairing.get("step") in ENDED:
            self.pairing = None
        self._changed()

    async def _tor_however_long(self) -> None:
        """Tor started, tried again every minute while it can't be (no network, say): a code has no time limit."""
        while True:
            try:
                await self._ensure_tor()
                return
            except (tor_mod.TorError, OSError) as e:
                self._pair_step(self.pairing["step"], error=f"{e} Trying again in a minute.")
                await asyncio.sleep(RETRY)

    async def _show(self, code: str) -> None:
        spent = self._spent = asyncio.get_running_loop().create_future()
        name = ""
        try:
            secret = await asyncio.to_thread(pairing.code_secret, code)
            key = pairing.pairing_onion(secret)
            name = f"pair-{key.address[:12]}"   # its own: the code shown before may still be going away

            async def on_pair(reader, writer):
                await self._adding(code, secret, spent, reader, writer)
            while not spent.done():
                if name not in self._onions or not self.tor.running:
                    try:
                        await self._tor_however_long()
                        self._pair_step("adding" if self._joiner else "publishing", error="")
                        path = await self._listen(name, on_pair)
                        self._onions[name] = await self.tor.add_onion(key, pairing.VIRTUAL_PORT, path)
                        # until its descriptor is on a directory nobody can find it (the other keeps looking)
                        await self.tor.wait_published(self._onions[name], 120)
                        if self.pairing["step"] == "publishing":
                            self._pair_step("waiting")
                    except (tor_mod.TorError, OSError) as e:
                        self._pair_step(self.pairing["step"], error=f"{e} Trying again in a minute.")
                        await asyncio.sleep(RETRY)
                        continue
                try:
                    await asyncio.wait_for(asyncio.shield(spent), CHECK_EVERY)
                except asyncio.TimeoutError:
                    pass                        # no time limit: its onion checked, and waited on again
        finally:
            if self._spent is spent:
                self._spent = None
            onion = self._onions.pop(name, None)
            if onion and self.tor and self.tor.running:
                try:
                    await self.tor.remove_onion(onion)
                except tor_mod.TorError:
                    pass
            if name in self._servers:
                self._servers.pop(name).close()
            await self._stop_tor_if_idle()

    async def _adding(self, code: str, secret: bytes, spent: asyncio.Future, reader, writer) -> None:
        """A computer found the code's onion (one at a time): it's added to the group, with any computers
        it was in a group with."""
        if self._pair_busy or spent.done() or self._stopped:
            writer.close()
            return
        self._keep(asyncio.current_task())
        self._streams.add(writer)
        self._pair_busy = True
        me = self.me()
        waiting = pairing.Waiting(code, me.info(), secret)
        try:
            answer = waiting.opened(await wire.recv(reader))
            them = waiting.them
            if self._joiner and them["id"] != self._joiner:
                await wire.send(writer, {"t": "used"})
                raise pairing.PairingError("another computer tried the code after it was used")
            await wire.send(writer, answer)
            waiting.revealed(await wire.recv(reader))
            g = store.group() or store.new_group()
            roster = self._roster()
            roster[me.id] = store.entry_of(me, roster.get(me.id))
            await wire.send(writer, {"t": "welcome", "group": _group_msg(g), "members": list(roster.values())})
            msg = await wire.recv(reader)
            if msg.get("t") != "joined":
                raise pairing.PairingError("it stopped before it was added")
            said = msg.get("members") if isinstance(msg.get("members"), list) else []
            brought = [e for e in map(store.checked_member, said[:store.MAX_ENTRIES]) if e]
            it = next((e for e in brought if e["id"] == them["id"]), None)
            if it is None or (it["onion"], it["client"]) != (them["onion"], them["client"]):
                raise pairing.PairingError("it didn't say which computer it is")
            before = {e["id"] for e in store.live(roster, but=me.id)}
            roster, _ = store.merge_members(roster, [e for e in brought if e["id"] not in (me.id, them["id"])], me.id)
            now = time.time()
            roster[them["id"]] = {**it, "name": them["name"], "updated": max(now, it["updated"]),
                                  "added": max(now, it["added"]), "removed": 0, "by": me.id}
            if len(store.live(roster)) > store.MAX_MEMBERS:
                raise pairing.PairingError(f"together they'd be more than {store.MAX_MEMBERS} computers")
            if self._spent is not spent or spent.done():
                raise pairing.PairingError("the code was cancelled meanwhile")
            store.save_group(g)
            store.save_members(roster)
            self._joiner = them["id"]
            store.save_pending_pairing({"role": "show", "code": code, "since": time.time(),
                                        **(store.pending_pairing() or {}), "joiner": them["id"]})
            await wire.send(writer, {"t": "added"})
            new = [e["id"] for e in store.live(roster, but=me.id) if e["id"] not in before or e["id"] == them["id"]]
            self._log("added", member=them["id"], name=them["name"], with_it=len(new) - 1)
            if self._spent is spent and self._pairing_under_way():
                self._pair_step("adding", digits=waiting.digits, error="", **{"with": them["name"]})
            self._members_changed(new)
            self._spawn(self._tell_all(but=set(new)))      # the others hear of it now
            try:                                # its last word: it's in, so the code is used up
                if (await wire.recv(reader, 60)).get("t") == "done":
                    self._spend(them["id"])
            except wire.WireError:
                pass                            # else when it first connects as a member
        except (pairing.PairingError, wire.WireError, tor_mod.TorError, OSError) as e:
            # only a computer with the code gets this far: it may try again (the code still works)
            self._log("adding_failed", error=str(e))
            if self._spent is spent and self._pairing_under_way() and self.pairing.get("step") != "adding":
                self._pair_step(self.pairing["step"], error=f"A computer tried the code but didn't finish ({e}): it can try again.")
        finally:
            self._pair_busy = False
            writer.close()

    def _spend(self, member_id: str) -> None:
        """The computer the code shown added is in for sure (it said so, or connected as a member): the
        code stops working."""
        if not member_id or member_id != self._joiner:
            return
        self._joiner = ""
        store.save_pending_pairing(None)
        name = self._name_of(member_id)
        if self.pairing and self.pairing.get("role") == "show" and self.pairing.get("step") not in ENDED:
            self._pair_step("done", error="", **{"with": name})
        self._log("code_used", member=member_id)
        self._notify(f"{name} was added to your computers", "Your apps sync between them whenever both are on.")
        if self._spent and not self._spent.done():
            self._spent.set_result(True)

    async def _join(self, code: str) -> None:
        try:
            secret = await asyncio.to_thread(pairing.code_secret, code)
            address = pairing.pairing_onion(secret).address
            delay = FIND_AGAIN
            while True:
                await self._tor_however_long()
                if self.pairing["step"] != "finding":
                    self._pair_step("finding")
                try:
                    reader, writer = await self._open(address, pairing.VIRTUAL_PORT)
                except wire.Unreachable:
                    # not on yet, or its onion not found yet: looked for again, as long as it takes
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, FIND_MOST)
                    await self._fresh_lookups()
                    continue
                except (wire.WireError, OSError) as e:
                    self._pair_step("finding", error=f"Tor: {e}. Trying again in a minute.")
                    await asyncio.sleep(RETRY)
                    continue
                delay = FIND_AGAIN
                try:
                    if await self._joined(pairing.Joining(code, self.me().info(), secret), reader, writer):
                        return
                except wire.WireError as e:     # the connection broke, or the other was busy: tried again
                    self._log("joining_interrupted", error=str(e))
                finally:
                    writer.close()
                await asyncio.sleep(FIND_AGAIN)
        except pairing.PairingError as e:
            store.save_pending_pairing(None)
            self._pair_step("failed", error=str(e))
        finally:
            await self._stop_tor_if_idle()

    async def _joined(self, joining: pairing.Joining, reader, writer) -> bool:
        """The code's computer found: this one is added to its group, with any this one was in a group with."""
        await wire.send(writer, joining.opening())
        msg = await wire.recv(reader)
        if msg.get("t") == "used":
            raise pairing.PairingError("That code added another computer already: show a new one on the other computer.")
        await wire.send(writer, joining.answered(msg))
        welcome = await wire.recv(reader)
        got = _group_of(welcome.get("group")) if welcome.get("t") == "welcome" else None
        if got is None:
            raise wire.WireError("the other computer didn't send its group")
        me, old = self.me(), store.group()
        mine = self._roster()
        now = time.time()
        mine[me.id] = store.entry_of(me, mine.get(me.id), updated=now, added=now)
        await wire.send(writer, {"t": "joined", "members": list(mine.values())})
        if (await wire.recv(reader)).get("t") != "added":
            raise wire.WireError("the other computer didn't say this one was added")
        gid, key = got
        olds = [*old.old, {"id": old.id, "key": old.key}] if old and old.id != gid else (old.old if old else [])
        store.save_group(store.Group(gid, key, olds))
        roster, _ = store.merge_members(mine, welcome.get("members"), me.id)
        store.save_members(roster)
        store.save_pending_pairing(None)
        try:
            await wire.send(writer, {"t": "done"})
        except wire.WireError:
            pass                                # it hears when this one first connects
        others = store.live(roster, but=me.id)
        self._log("joined", group=gid, by=joining.them["id"], members=len(others))
        self._pair_step("done", error="", digits=joining.digits, **{"with": joining.them["name"]})
        self._members_changed([e["id"] for e in others])
        return True

    # ---------------------------------------------------------------- the group's members

    def _members_changed(self, new: list[str] = ()) -> None:
        """Computers added, or removed, or this one added to a group: the new ones pulled from soon (once
        their onion is up), this computer's onion listing who's in now, and the window told."""
        if new:
            st, now = store.status(), time.time()
            for mid in new:
                st[mid] = {**st.get(mid, {}), "since": now}
                self._soon(mid, after=FIRST_AFTER)
            store.save_status(st)
        if self._others():
            self._run_soon()
        self._wake.set()
        self._changed()

    def rename(self, name: str) -> None:
        me = self.me()
        me.name = pairing.clean_name(name)
        store.save_identity(me)
        roster = self._roster()
        if me.id in roster:
            roster[me.id] = store.entry_of(me, roster[me.id], updated=time.time())
            store.save_members(roster)
            if self._others():
                self._spawn(self._tell_all())
        self._changed()

    def remove(self, member_id: str) -> None:
        """Another computer, removed from the group: by every member as it hears (straight away, those
        that are on), and told itself when it's next on. It keeps its apps."""
        me, roster = self.me(), self._roster()
        e = roster.get(member_id)
        if e is None or e["removed"] or member_id == me.id:
            raise SyncError("That computer isn't one of this group's any more.")
        now = time.time()
        gone = {**e, "removed": now, "updated": now, "by": me.id}
        roster[member_id] = gone
        store.save_members(roster)
        store.forget_base(member_id)
        self._live.pop(member_id, None)
        self._log("removed", member=member_id)
        if self._others():
            self._soon(member_id)               # told by the runner (_to_tell), its key off this onion
            self._run_soon()
            self._spawn(self._tell_all())
        else:
            self._spawn(self._tell_then_stop(gone))
        self._changed()

    async def _tell_then_stop(self, e: dict) -> None:
        await self._tell_removed(e)
        await self._stop_tor_if_idle()

    async def _tell_removed(self, e: dict) -> bool:
        """A computer this one removed, told (it leaves the group, keeping its apps). Whether it heard."""
        self._outgoing += 1
        try:
            reader, writer = await asyncio.wait_for(self._connect(e, tell=[e]), 120)
            writer.close()
        except wire.Refused:
            pass                                # it knew already, or is in another group now
        except (Gone, wire.WireError, tor_mod.TorError, OSError, asyncio.TimeoutError):
            return False
        finally:
            self._outgoing -= 1
        if store.group():
            st = store.status()
            st[e["id"]] = {**st.get(e["id"], {}), "told": time.time()}
            store.save_status(st)
        self._log("told_removed", member=e["id"])
        self._wake.set()                        # its client key forgotten
        return True

    async def leave(self) -> dict:
        """This computer leaves the group: the others that are on are told now (the rest hear from them),
        and it keeps its apps. Returns {"told": how many heard}."""
        me, roster = self.me(), self._roster()
        if me.id not in roster:
            raise SyncError("This computer isn't in a group of yours.")
        now = time.time()
        roster[me.id] = {**roster[me.id], "removed": now, "updated": now, "by": me.id}
        store.save_members(roster)
        self._leaving = True
        told = 0
        try:
            for task in (self._runner, *self._pulling.values()):
                if task and not task.done():
                    task.cancel()
            try:
                told = await asyncio.wait_for(self._tell_all(), 90)
            except asyncio.TimeoutError:
                pass
        finally:
            self._leaving = False
        self._log("left", told=told)
        self._gone()
        return {"told": told}

    def _gone(self, notice: dict | None = None) -> None:
        """Out of the group (this computer left, or was removed): what it knew of the group forgotten, its
        apps kept, its onion taken down, and tor stopped unless a code is being shown or looked for."""
        store.leave_all()
        self._notice = notice
        for d in (self._live, self._next, self._delay):
            d.clear()
        self._again.clear()
        if self._runner and not self._runner.done() and self._runner is not asyncio.current_task():
            self._runner.cancel()
        if self._announce:
            self._announce.cancel()
        self._spawn(self._wind_down())
        self._changed()

    async def _wind_down(self) -> None:
        try:
            if self.tor and self.tor.running:
                await self._publish()           # lists nobody: the onion comes down
        except (tor_mod.TorError, OSError):
            pass
        await self._stop_tor_if_idle()

    def _removed(self, info: dict) -> None:
        by = str((info or {}).get("by") or "Another of your computers")[:60]
        self._log("removed_from_group", by=by)
        self._notify("This computer was removed from your computers", f"{by} removed it. Its apps stay on it, but don't sync any more.")
        try:
            at = float((info or {}).get("at") or 0) or time.time()
        except (TypeError, ValueError):
            at = time.time()
        self._gone({"by": by, "at": at})

    def _refused_as_removed(self, r: wire.Refused) -> bool:
        """A member refused this computer as removed from the group: so it is, unless that was before this
        one was last added (that member hasn't heard yet)."""
        if r.code != "removed" or self._leaving:
            return False
        mine = self._roster().get(self.me().id)
        try:
            at = float(r.removed.get("at") or 0)
        except (AttributeError, TypeError, ValueError):
            return False
        if mine is None or not at or at < mine["added"]:
            return False
        self._removed(r.removed)
        return True

    # ---------------------------------------------------------------- talking to a member

    def _merge_roster(self, theirs) -> set[str] | None:
        """Another member's list of members merged into this one's, and saved. Returns who was in before,
        for _after_roster, when anything changed; None when nothing did."""
        before = {e["id"] for e in self._others()}
        roster, changed = store.merge_members(store.members(), theirs, self.me().id)
        if not changed:
            return None
        store.save_members(roster)
        return before

    def _after_roster(self, before: set[str]) -> None:
        """The members changed: this computer may have been removed, others added or removed."""
        me, roster = self.me().id, self._roster()
        mine = roster.get(me)
        if mine and mine["removed"]:
            if self._leaving:
                return
            if mine["by"] == me:
                self._gone()                    # it left before, and stopped before it was done
            else:
                self._removed({"by": self._name_of(mine["by"]), "at": mine["removed"]})
            return
        for e in roster.values():
            if e["removed"] and e["id"] in before:
                store.forget_base(e["id"])
                self._live.pop(e["id"], None)
        self._members_changed([e["id"] for e in store.live(roster, but=me) if e["id"] not in before])

    async def _connect(self, e: dict, tell: list | None = None):
        """A session with a member: connected, each proved to the other, a member still on a group this one
        moved from told to move too, and their lists of members exchanged (merged into this one's, but for
        `tell`: what's sent to a computer that was removed, which isn't listened to). Returns (reader,
        writer); raises Gone when this computer turns out to be out of the group."""
        await self._ensure_tor()
        me, g = self.me(), store.group()
        if g is None:
            raise Gone()
        refused = None
        for gid, key in [(g.id, g.key), *((o["id"], o["key"]) for o in reversed(g.old))]:
            reader, writer = await self._open(e["onion"], SYNC_PORT)
            try:
                await wire.hello_as_client(reader, writer, me.id, e["id"], gid, store.pair_key(key, me.id, e["id"]))
                if gid != g.id:                 # it's still in a group this one moved from: it moves too
                    await wire.send(writer, {"t": "move", "group": _group_msg(g)})
                    if (await wire.recv(reader)).get("t") != "moved":
                        raise wire.WireError("the other computer didn't move to this group")
                await wire.send(writer, {"t": "roster", "members": tell if tell is not None else list(store.members().values())})
                msg = await wire.recv(reader)
                if msg.get("t") != "roster":
                    raise wire.WireError("the other computer didn't say who's in the group")
            except wire.Refused as r:
                writer.close()
                if r.code != "group":
                    raise
                refused = r                     # not with this group's key: maybe with one it was in before
                continue
            except BaseException:
                writer.close()
                raise
            if tell is None:
                if isinstance(msg.get("move"), dict):
                    self._adopt(msg["move"])
                before = self._merge_roster(msg.get("members"))
                if before is not None:
                    self._after_roster(before)
                if not store.group():
                    writer.close()
                    raise Gone()
            return reader, writer
        raise refused or wire.WireError("no group to connect with")

    def _adopt(self, group_msg) -> None:
        """Told by a member that moved: the group this computer is in became part of another (one of its
        members joined that, bringing the rest). It moves too, keeping the old group's key a while for the
        members that haven't moved yet."""
        got, g = _group_of(group_msg), store.group()
        if got is None or g is None or got[0] == g.id or any(o["id"] == got[0] for o in g.old):
            return
        store.save_group(store.Group(got[0], got[1], [*g.old, {"id": g.id, "key": g.key}]))
        self._log("moved", group=got[0])

    def _lookup(self, who: str, gid: str):
        """For wire.hello_as_server: the secret this computer and `who` prove which they are with, or why
        it isn't let in."""
        me, roster = self.me().id, self._roster()
        e = roster.get(who)
        if e is None or who == me:
            return ("member", None)
        if e["removed"]:
            return ("removed", {"by": self._name_of(e["by"]), "at": e["removed"]})
        key = store.group().key_of(gid)
        return store.pair_key(key, me, who) if key else ("group", None)

    async def _serve(self, reader, writer) -> None:
        """A member connected to this computer's onion."""
        if self._stopped:
            writer.close()
            return
        self._keep(asyncio.current_task())
        self._streams.add(writer)
        self._serving += 1
        try:
            who, gid = await wire.hello_as_server(reader, writer, self.me().id, self._lookup)
            self._seen(who)
            self._spend(who)                    # the computer a code shown added: in for sure
            here = None
            while True:
                msg = await wire.recv(reader)
                t = msg.get("t")
                if t == "move":
                    self._adopt(msg.get("group"))
                    gid = store.group().id if store.group() else gid
                    await wire.send(writer, {"t": "moved"})
                elif t == "roster":
                    before = self._merge_roster(msg.get("members"))
                    g = store.group()
                    await wire.send(writer, {"t": "roster", "members": list(store.members().values()),
                                             **({"move": _group_msg(g)} if g and gid != g.id else {})})
                    if before is not None:
                        self._after_roster(before)
                        if not store.group():
                            return
                elif t in ("list", "bundle"):
                    here = await self._give(writer, msg, here)
                elif t == "turn":               # its apps, offered in turn: pulled from it on this connection
                    await self._take_turn(who, reader, writer)
                    return
                else:
                    return
        except wire.WireError:
            pass
        except Exception as e:  # noqa: BLE001 - one connection's trouble isn't the app's
            self._log("serve_failed", error=repr(e)[:300])
        finally:
            self._serving -= 1
            writer.close()
            if not self._serving and self._held_since:
                self._wake.set()                # a new list of members was waiting for this to end

    async def _give(self, writer, msg: dict, here: dict | None) -> dict:
        """A member's request for this computer's apps: their list, or one's bundle (as listed). Returns the
        apps as listed, for the bundles asked for next."""
        if msg.get("t") == "list" or here is None:
            here = library.local()
        if msg.get("t") == "list":
            await wire.send(writer, {"t": "apps", "apps": {sid: s for sid, (a, s, d) in here.items()}})
            return here
        entry = here.get(str(msg.get("share") or ""))
        if entry is None:
            await wire.send(writer, {"t": "missing"})
        else:
            await wire.send(writer, {"t": "bundle", "share": entry[1]["share"], "digest": entry[1]["digest"]})
            await wire.send_bytes(writer, entry[2])
        return here

    async def _answer(self, reader, writer) -> None:
        """The member this one is connected to pulls from it, on the same connection, until it's done."""
        here = None
        while (msg := await wire.recv(reader)).get("t") in ("list", "bundle"):
            here = await self._give(writer, msg, here)

    async def _take_turn(self, who: str, reader, writer) -> None:
        """A member that pulled from this computer (or changed something) offers its own apps in turn: pulled
        from on its connection, unless this one is pulling from it just now. It may not be reachable on its
        own onion yet (just added; or Tor, which looks for an onion it couldn't find only every quarter of
        an hour, hasn't looked again since it came back on)."""
        e = self._roster().get(who)
        if e is None or e["removed"] or who in self._pulling:
            await wire.send(writer, {"t": "bye"})
            return
        self._pulling[who] = asyncio.current_task()
        try:
            came = await self._pull_from(e, reader, writer)
            await wire.send(writer, {"t": "bye"})
            self._next[who], self._delay[who] = time.time() + PULL_EVERY, RETRY_FIRST
            self._pulled(who, came)
        finally:
            if self._pulling.get(who) is asyncio.current_task():
                self._pulling.pop(who, None)
            self._wake.set()

    def _pulled(self, member_id: str, came: list[str]) -> None:
        self._seen(member_id, synced=True)
        self._spend(member_id)
        if came:
            self._log("pulled", member=member_id, apps=came)
            self.e.app_manager.changed()

    def _seen(self, member_id: str, error: str = "", synced: bool = False) -> None:
        if not store.group():
            return
        st, now = store.status(), time.time()
        rec = dict(st.get(member_id, {}))
        if error:
            rec["error"] = error[:300]
        else:
            rec.update({"seen": now, "error": "", **({"synced": now} if synced else {})})
        st[member_id] = rec
        store.save_status(st)
        self._live[member_id] = {**self._live.get(member_id, {}), "online": not error}
        self._changed()

    # ---------------------------------------------------------------- pulling

    def _busy_with(self, app_id: str) -> bool:
        e = self.e
        conv = getattr(e, "conv", None)
        return (app_id in e.app_manager.building or bool(getattr(e.backups, "running", None))
                or (e.busy and conv is not None and conv.app == app_id))

    def _held(self, mine) -> bool:
        """Whether what would arrive for an app waits for next time: it's being built or worked on in its
        chat, or a backup is being restored."""
        return bool(getattr(self.e.backups, "running", None)) or bool(mine and self._busy_with(mine[0]["id"]))

    async def pull(self, member_id: str) -> dict:
        """Take what another member changed. Returns {"apps": [the apps that changed here], "error": ""}."""
        e = self._roster().get(member_id)
        if e is None or e["removed"]:
            return {"apps": [], "error": "not one of this group's computers"}
        self._live[member_id] = {**self._live.get(member_id, {}), "syncing": True}
        self._changed()
        try:
            reader, writer = await self._connect(e)
            try:
                came = await self._pull_from(e, reader, writer)
                try:                            # and it pulls from this one in turn, the same way round
                    await wire.send(writer, {"t": "turn"})
                    await self._answer(reader, writer)
                except wire.WireError:
                    pass
            finally:
                writer.close()
        except Gone:
            return {"apps": [], "error": "This computer isn't in the group any more."}
        except wire.Refused as r:
            if not self._refused_as_removed(r):
                self._seen(member_id, error=r.why)
            return {"apps": [], "error": r.why}
        except (wire.WireError, tor_mod.TorError, share.ShareError, OSError) as x:
            why = x.why if isinstance(x, wire.Unreachable) else str(x)
            self._seen(member_id, error=why)
            return {"apps": [], "error": why}
        finally:
            self._live[member_id] = {**self._live.get(member_id, {}), "syncing": False}
            self._changed()
        self._pulled(member_id, came)
        return {"apps": came, "error": ""}

    async def _pull_from(self, member: dict, reader, writer) -> list[str]:
        await wire.send(writer, {"t": "list"})
        msg = await wire.recv(reader)
        if msg.get("t") != "apps":
            raise wire.WireError("the other computer didn't list its apps")
        theirs = _checked_list(msg.get("apps"))
        here, base = library.local(), store.base_of(member["id"])
        got = {}
        for sid in sorted(theirs):
            mine = here.get(sid)
            if library.plan(mine and mine[1], theirs[sid], base.get(sid)) in TAKES and not self._held(mine):
                bundle = await self._bundle(reader, writer, sid)
                if bundle is not None:
                    got[sid] = bundle
        return self._apply(member, theirs, got)

    def _apply(self, member: dict, theirs: dict, got: dict) -> list[str]:
        """What a member has, taken in against this computer's apps as they are now (other pulls may have
        changed them while the bundles came): all at once, nothing else running in between. Returns the
        apps that changed here."""
        if not store.group():
            raise Gone()
        e = store.members().get(member["id"])
        if e is None or e["removed"]:
            return []                           # removed meanwhile: nothing taken from it
        here, base = library.local(), store.base_of(e["id"])
        new_base, came = {}, []
        for sid in sorted(set(here) | set(theirs)):
            mine, t, b = here.get(sid), theirs.get(sid), base.get(sid)
            how = library.plan(mine and mine[1], t, b)
            if how in ("same", "keep"):
                new_base[sid] = t
            elif how in ("gone_here", "gone_there"):
                new_base[sid] = b
                if how == "gone_there":
                    self._removed_there(mine[0], e)
            elif how in TAKES:
                if sid not in got or self._held(mine):
                    if b:
                        new_base[sid] = b       # next time
                    continue
                if how in ("new", "back"):
                    a = library.create(got[sid], e["id"], e["name"])
                else:
                    a, _ = library.combine(mine[0], got[sid], b, e["id"], e["name"])
                came.append(a["id"])
                new_base[sid] = t
        store.save_base(e["id"], new_base)
        return came

    async def _bundle(self, reader, writer, sid: str) -> dict | None:
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

    def _removed_there(self, a: dict, member: dict) -> None:
        synced = dict(a.get("synced") or {})
        if (synced.get("removed_on") or {}).get("peer") == member["id"]:
            return
        synced["removed_on"] = {"peer": member["id"], "name": member["name"], "at": time.time()}
        apps.save({**a, "synced": synced})
        self.e.app_manager.changed()

    def keep_here(self, app_id: str) -> None:
        """The user keeps an app another computer removed: it isn't asked about again for that one."""
        a = apps.load(app_id)
        if not a or not (a.get("synced") or {}).get("removed_on"):
            raise SyncError("There's nothing to keep.")
        synced = dict(a["synced"])
        gone = synced.pop("removed_on")
        base = store.base_of(gone["peer"])
        if base.pop((a.get("share") or {}).get("id", ""), None) is not None:
            store.save_base(gone["peer"], base)
        apps.save({**a, "synced": synced})
        self.e.app_manager.changed()

    def resolve(self, app_id: str, item: str, keep: str) -> None:
        """The user's choice where a change was edited on more than one computer: `keep` "mine", or the
        id of the computer whose version to take."""
        library.resolve(apps.check_id(app_id), str(item), str(keep))
        self.e.app_manager.changed()

    def compare(self, app_id: str, item: str) -> dict:
        """The versions of a change (or the build script) edited on more than one computer."""
        return library.versions(apps.check_id(app_id), str(item))

    # ---------------------------------------------------------------- telling the others

    def local_changed(self) -> None:
        """An app changed here (AppManager.changed): the others are told, a moment after the last change."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:                    # from a worker thread: onto the loop
            if getattr(self.e, "loop", None):
                self.e.loop.call_soon_threadsafe(self.local_changed)
            return
        if not self._others():
            return
        if self._announce:
            self._announce.cancel()
        self._announce = loop.call_later(ANNOUNCE_AFTER, lambda: self._spawn(self._tell()))

    async def _tell(self) -> None:
        now = {sid: s["digest"] for sid, (a, s, d) in library.local().items()}
        if now == self._announced:
            return
        self._announced = now
        await self._tell_all(poke=True)

    async def _tell_all(self, poke: bool = False, but: set[str] = frozenset()) -> int:
        """Each other member (but `but`) told this computer's list of members, and with `poke` that its
        apps changed: it pulls from this one there and then, on the same connection. Returns how many
        heard."""
        async def one(e) -> bool:
            async with self._tell_slots:
                try:
                    reader, writer = await asyncio.wait_for(self._connect(e), 120)
                except wire.Refused as r:
                    if self._leaving:
                        return r.code == "removed"      # it heard already, from another
                    self._refused_as_removed(r)
                    return False
                except (Gone, wire.WireError, tor_mod.TorError, OSError, asyncio.TimeoutError):
                    return False                # off: it hears when it's next on
                try:
                    if poke:
                        await wire.send(writer, {"t": "turn"})
                        await self._answer(reader, writer)
                    else:
                        await wire.send(writer, {"t": "bye"})
                except wire.WireError:
                    pass
                finally:
                    writer.close()
                return True
        return sum(await asyncio.gather(*(one(e) for e in self._others() if e["id"] not in but)))
