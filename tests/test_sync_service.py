"""Two computers pairing and syncing, in one process: each with its own folders (config.ROOTS),
over a stand-in for Tor that keeps to what matters (an onion with clients lets only them in)."""

import asyncio
import contextvars
import os
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from davibemanager import apps, config, share
from davibemanager.sync import library, pairing, service, store, wire
from test_sync import commit_patch, make_app


@pytest.fixture(autouse=True)
def quick(monkeypatch):
    monkeypatch.setattr(pairing, "SCRYPT", {"n": 2 ** 10, "r": 8, "p": 1})
    monkeypatch.setattr(service, "ANNOUNCE_AFTER", 0.05)
    monkeypatch.setattr(service, "FIND_FOR", 0.5)
    monkeypatch.setattr(service, "FIND_AGAIN", 0.05)


class FakeNet:
    """The onion services up, and who may reach each."""

    def __init__(self):
        self.services: dict[str, dict] = {}


class FakeTor:
    def __init__(self, net: FakeNet, on_change):
        self.net, self.on_change = net, on_change
        self.state = {"step": "stopped", "progress": 0, "words": ""}
        self.keys: dict[str, str] = {}              # onion -> this computer's client key for it (public half)
        self.started = 0

    @property
    def running(self):
        return self.state["step"] == "ready"

    async def start(self):
        self.started += 1
        self.state = {"step": "ready", "progress": 100, "words": "Connected to Tor"}
        self.on_change(self.state)

    async def stop(self):
        self.state = {"step": "stopped", "progress": 0, "words": ""}
        for sid in [s for s, v in self.net.services.items() if v["tor"] is self]:
            self.net.services.pop(sid)

    async def add_onion(self, key, port, target, clients=()):
        self.net.services[key.address] = {"port": port, "target": target, "clients": set(clients), "tor": self}
        return key.address

    async def remove_onion(self, sid):
        self.net.services.pop(sid, None)

    async def wait_published(self, sid, wait=120):
        return sid in self.net.services

    async def allow_client(self, address, key):
        self.keys[address] = key.public

    async def forget_client(self, address):
        self.keys.pop(address, None)

    async def open(self, address, port, wait=120):
        s = self.net.services.get(address)
        if s is None or s["port"] != port:
            raise wire.Unreachable(0xF0, "it isn't online, or DA Vibe Manager isn't running on it")
        if s["clients"] and self.keys.get(address) not in s["clients"]:
            raise wire.Unreachable(0xF4, "it doesn't let this computer in: it isn't paired with this one any more")
        return await asyncio.open_unix_connection(str(s["target"]))


class Computer:
    """One computer: its folders, its engine as sync sees it, its sync."""

    def __init__(self, root: Path, net: FakeNet, name: str):
        self.ctx = contextvars.copy_context()
        self.ctx.run(config.ROOTS.set, (root / "config", root / "data"))
        runtime = Path(tempfile.mkdtemp(prefix="dvm-", dir="/tmp"))       # short: unix sockets' paths
        self.events = []
        self.engine = SimpleNamespace(runtime_dir=runtime, busy=False, conv=None, loop=None,
                                      backups=SimpleNamespace(running=None),
                                      app_manager=SimpleNamespace(building={}, changed=self.changed),
                                      emit=lambda kind, **data: self.events.append((kind, data)))
        self.sync = self.run(lambda: service.SyncService(self.engine, make_tor=lambda on_change: FakeTor(net, on_change)))
        self.run(lambda: self.sync.rename(name))

    def changed(self):
        self.sync.local_changed()

    def run(self, fn, *args):
        """fn(*args) as this computer (and any task it starts)."""
        return self.ctx.run(fn, *args)

    async def wait(self, coro):
        return await asyncio.create_task(coro, context=self.ctx)

    def view(self):
        return self.run(self.sync.view)

    async def until(self, cond, what, limit=10):
        end = time.monotonic() + limit
        while time.monotonic() < end:
            v = self.view()
            if cond(v):
                return v
            await asyncio.sleep(0.02)
        raise AssertionError(f"timed out waiting for {what}: {self.view()}")


async def pair(a: Computer, b: Computer, b_says=True):
    shown = a.run(a.sync.pair_show)
    await a.until(lambda v: v["pairing"]["step"] == "waiting", "the code's onion")
    b.run(b.sync.pair_join, shown["code"])
    va = await a.until(lambda v: v["pairing"]["step"] == "check", "the digits on the first")
    vb = await b.until(lambda v: v["pairing"]["step"] == "check", "the digits on the second")
    assert va["pairing"]["digits"] == vb["pairing"]["digits"] and va["pairing"]["with"] == "Laptop"
    a.run(a.sync.pair_decide, True)
    b.run(b.sync.pair_decide, b_says)
    ends = ("done", "failed")
    return (await a.until(lambda v: v["pairing"]["step"] in ends, "the first's end"),
            await b.until(lambda v: v["pairing"]["step"] in ends, "the second's end"))


async def test_two_computers_pair_with_a_code_and_the_same_digits_and_then_sync(tmp_path):
    net = FakeNet()
    desktop, laptop = Computer(tmp_path / "A", net, "Desktop"), Computer(tmp_path / "B", net, "Laptop")
    desktop.run(make_app)
    va, vb = await pair(desktop, laptop)
    assert va["pairing"]["step"] == vb["pairing"]["step"] == "done"
    assert [p["name"] for p in va["peers"]] == ["Laptop"] and [p["name"] for p in vb["peers"]] == ["Desktop"]
    # each one's onion lets in only the other, and the code's onion is gone
    d_me, l_me = desktop.run(store.identity), laptop.run(store.identity)
    assert net.services[d_me.onion_key.address]["clients"] == {l_me.client_key.public}
    assert set(net.services) == {d_me.onion_key.address, l_me.onion_key.address}
    # right after pairing, the laptop has the desktop's app, to build when its user says so
    arrived = await laptop.until(lambda v: laptop.run(apps.list_all), "the app")
    a = laptop.run(apps.list_all)[0]
    assert a["name"] == "gThumb" and a["synced"]["from"] == "Desktop" and a["synced"]["built"] is False
    # a change on the desktop is told to the laptop, which pulls it
    def edited():
        a = apps.list_all()[0]
        apps.write_file(a["id"], "changes/zoom.patch", commit_patch("b" * 40, "zoom", "+a better zoom", "zoom"))
        apps.save({**a, "changes": [{**c, "rev": share.new_rev(c["rev"])} for c in a["changes"]]})
        desktop.changed()
    desktop.run(edited)
    await laptop.until(lambda v: "better zoom" in laptop.run(lambda: apps.read_file(apps.list_all()[0]["id"], "changes/zoom.patch")),
                       "the change, pulled")
    await desktop.wait(desktop.sync.stop())
    await laptop.wait(laptop.sync.stop())


async def test_digits_one_computer_says_dont_match_pair_nothing(tmp_path):
    net = FakeNet()
    desktop, laptop = Computer(tmp_path / "A", net, "Desktop"), Computer(tmp_path / "B", net, "Laptop")
    va, vb = await pair(desktop, laptop, b_says=False)
    assert va["pairing"]["step"] == vb["pairing"]["step"] == "failed"
    assert "didn't match" in va["pairing"]["error"] and "didn't match" in vb["pairing"]["error"]
    assert va["peers"] == vb["peers"] == [] and net.services == {}        # tor stops: nothing to sync


async def test_a_code_nobody_is_waiting_with_is_said_so(tmp_path):
    laptop = Computer(tmp_path / "B", FakeNet(), "Laptop")
    with pytest.raises(service.SyncError, match="mistyped"):
        laptop.run(laptop.sync.pair_join, "1234 5678 9012")
    laptop.run(laptop.sync.pair_join, pairing.new_code())
    v = await laptop.until(lambda v: v["pairing"]["step"] == "failed", "giving up", limit=15)
    assert "No computer is waiting with that code" in v["pairing"]["error"]


async def test_unpairing_on_one_computer_unpairs_both_and_shuts_the_other_out(tmp_path):
    net = FakeNet()
    desktop, laptop = Computer(tmp_path / "A", net, "Desktop"), Computer(tmp_path / "B", net, "Laptop")
    await pair(desktop, laptop)
    peer = laptop.view()["peers"][0]
    await laptop.wait(laptop.sync.unpair(peer["id"]))
    assert laptop.view()["peers"] == []
    await desktop.until(lambda v: v["peers"] == [], "the desktop forgetting it too")
    with pytest.raises(service.SyncError, match="isn't paired"):
        await laptop.wait(laptop.sync.unpair(peer["id"]))
    await desktop.wait(desktop.sync.stop())
    await laptop.wait(laptop.sync.stop())


async def test_the_window_pairs_through_the_api_and_hears_why_when_it_cant(tmp_path):
    import httpx

    from davibemanager.config import Config
    from davibemanager.engine import Engine
    from davibemanager.server.app import create_app

    net = FakeNet()

    def make(emit):
        e = Engine(Config(), emit, Path(tempfile.mkdtemp(prefix="dvm-", dir="/tmp")), save_config=lambda c: None)
        e.start_workspace = lambda: None
        return e
    app = create_app("secret", make)
    async with app.router.lifespan_context(app):
        e = app.state.engine
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
                                     headers={"x-token": "secret"}) as c:
            e.sync.available = False
            r = await c.post("/api/sync/pair")
            assert r.status_code == 400 and "has no Tor" in r.json()["error"]
            e.sync.available, e.sync.make_tor = True, lambda on_change: FakeTor(net, on_change)
            r = await c.post("/api/sync/join", json={"code": "1234 5678 9012"})
            assert r.status_code == 400 and "mistyped" in r.json()["error"]
            r = await c.post("/api/sync/decide", json={"same": True})
            assert r.status_code == 400 and "nothing to check" in r.json()["error"]
            r = await c.post("/api/sync/pair")
            assert r.status_code == 200 and len(r.json()["code"].replace(" ", "")) == 12
            assert (await c.get("/api/state")).json()["sync"]["pairing"]["role"] == "show"
            r = await c.post("/api/sync/pair")
            assert r.status_code == 400 and "under way already" in r.json()["error"]
            assert (await c.post("/api/sync/cancel")).status_code == 200
            assert (await c.get("/api/state")).json()["sync"]["pairing"]["step"] == "cancelled"
            r = await c.post("/api/sync/now")
            assert r.status_code == 400 and "isn't paired" in r.json()["error"]
