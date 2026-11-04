"""Computers of one user's group adding each other and syncing, in one process: each with its own
folders (config.ROOTS), over a stand-in for Tor that keeps to what matters (an onion with clients lets
only them in, and one that isn't up can't be reached)."""

import asyncio
import contextvars
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from davibemanager import apps, config, share
from davibemanager.sync import library, pairing, service, store, tor as tor_mod, wire
from test_sync import commit_patch, make_app


@pytest.fixture(autouse=True)
def quick(monkeypatch):
    monkeypatch.setattr(pairing, "SCRYPT", {"n": 2 ** 10, "r": 8, "p": 1})
    for name, value in (("ANNOUNCE_AFTER", 0.05), ("FIND_AGAIN", 0.02), ("FIND_MOST", 0.1), ("FIRST_AFTER", 0.05),
                        ("RETRY_FIRST", 0.05), ("PULL_EVERY", 1.5), ("CHECK_EVERY", 0.2), ("FRESH_EVERY", 0.2),
                        ("HOLD_MOST", 0.5)):
        monkeypatch.setattr(service, name, value)


class FakeNet:
    """The onion services up, and who may reach each."""

    def __init__(self):
        self.services: dict[str, dict] = {}


class FakeTor:
    def __init__(self, net: FakeNet, on_change):
        self.net, self.on_change = net, on_change
        self.state = {"step": "stopped", "progress": 0, "words": ""}
        self.keys: dict[str, str] = {}              # onion -> this computer's client key for it (public half)
        self.forgot = 0

    @property
    def running(self):
        return self.state["step"] == "ready"

    async def start(self):
        self.state = {"step": "ready", "progress": 100, "words": "Connected to Tor"}
        self.on_change(self.state)

    async def stop(self):
        self.state = {"step": "stopped", "progress": 0, "words": ""}
        self.keys.clear()
        for sid in [s for s, v in self.net.services.items() if v["tor"] is self]:
            self.net.services.pop(sid)

    async def add_onion(self, key, port, target, clients=()):
        if (self.net.services.get(key.address) or {}).get("tor") is self:
            raise tor_mod.TorError("Tor said no (ADD_ONION): 550 Onion address collision")
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

    async def forget_lookups(self):
        self.forgot += 1
        self.keys.clear()                           # as tor's NEWNYM does: the client keys go with it

    async def open(self, address, port, wait=120):
        s = self.net.services.get(address)
        if s is None or s["port"] != port:
            raise wire.Unreachable(0xF0, "it isn't online, or DA Vibe Manager isn't running on it")
        if s["clients"] and self.keys.get(address) not in s["clients"]:
            raise wire.Unreachable(0xF4, "it doesn't let this computer in")
        return await asyncio.open_unix_connection(str(s["target"]))


class Computer:
    """One computer: its folders, its engine as sync sees it, its sync."""

    def __init__(self, root: Path, net: FakeNet, name: str):
        self.net, self.name = net, name
        self.ctx = contextvars.copy_context()
        self.ctx.run(config.ROOTS.set, (root / "config", root / "data"))
        runtime = Path(tempfile.mkdtemp(prefix="dvm-", dir="/tmp"))       # short: unix sockets' paths
        self.notes = []
        self.engine = SimpleNamespace(runtime_dir=runtime, busy=False, conv=None, loop=None,
                                      backups=SimpleNamespace(running=None),
                                      app_manager=SimpleNamespace(building={}, changed=self.changed),
                                      emit=lambda kind, **data: None, notify=lambda title, body: self.notes.append(title))
        self.sync = self.new_sync()
        self.run(lambda: self.sync.rename(name))

    def new_sync(self):
        return self.run(lambda: service.SyncService(self.engine, make_tor=lambda on_change: FakeTor(self.net, on_change)))

    def changed(self):
        self.sync.local_changed()

    def run(self, fn, *args):
        """fn(*args) as this computer (and any task it starts)."""
        return self.ctx.run(fn, *args)

    async def wait(self, coro):
        return await asyncio.create_task(coro, context=self.ctx)

    async def off(self):
        await self.wait(self.sync.stop())

    async def on(self):
        self.sync = self.new_sync()
        await self.wait(self.sync.start())

    def view(self):
        return self.run(self.sync.view)

    def me(self):
        return self.run(store.identity)

    def make_app(self, name="gThumb"):
        a = self.run(make_app, (("zoom", "A zoom box"),), name)
        self.run(self.changed)
        return a

    def apps(self):
        return self.run(apps.list_all)

    async def until(self, cond, what, limit=10):
        end = time.monotonic() + limit
        while time.monotonic() < end:
            v = self.view()
            if cond(v):
                return v
            await asyncio.sleep(0.02)
        raise AssertionError(f"timed out waiting for {what}: {self.view()}")


def names(v):
    return [m["name"] for m in v["members"]]


def step(v):
    return (v["pairing"] or {}).get("step")


async def add(shower: Computer, joiner: Computer):
    """`joiner` added to `shower`'s group with a code `shower` shows."""
    shown = shower.run(shower.sync.pair_show)
    joiner.run(joiner.sync.pair_join, shown["code"])
    va = await shower.until(lambda v: step(v) == "done", f"{shower.name}'s code used")
    vb = await joiner.until(lambda v: step(v) == "done", f"{joiner.name} added")
    assert va["pairing"]["digits"] == vb["pairing"]["digits"]
    assert va["pairing"]["with"] == joiner.name and vb["pairing"]["with"] == shower.name
    shower.run(shower.sync.dismiss)
    joiner.run(joiner.sync.dismiss)
    return va, vb


async def all_know(computers, limit=20):
    for c in computers:
        others = sorted(o.name for o in computers if o is not c)
        await c.until(lambda v: sorted(names(v)) == others, f"{c.name} knowing the others", limit)


async def onions_list_each_other(computers, limit=10):
    for c in computers:
        address = c.me().onion_key.address
        others = {o.me().client_key.public for o in computers if o is not c}
        await c.until(lambda v: (c.net.services.get(address) or {}).get("clients") == others,
                      f"{c.name}'s onion listing the others", limit)


async def stop_all(*computers):
    await asyncio.gather(*(c.off() for c in computers))
    await asyncio.sleep(0.1)                    # connections taken as they stopped: each sees it and closes


async def test_a_code_works_whenever_the_other_computer_is_ready_even_after_a_restart(tmp_path):
    net = FakeNet()
    desktop, laptop = Computer(tmp_path / "A", net, "Desktop"), Computer(tmp_path / "B", net, "Laptop")
    desktop.make_app()
    shown = desktop.run(desktop.sync.pair_show)
    assert len(shown["code"].replace(" ", "")) == 16
    await desktop.until(lambda v: step(v) == "waiting", "the code's onion")
    assert desktop.run(desktop.sync.pair_show)["code"] == shown["code"]      # asked again: the same code
    await desktop.off()
    await desktop.on()                          # restarted (hours later, say): still waiting, with the same code
    v = await desktop.until(lambda v: step(v) == "waiting", "waiting again")
    assert v["pairing"]["code"] == shown["code"]
    va, vb = await add_with(desktop, laptop, shown["code"])
    assert names(va) == ["Laptop"] and names(vb) == ["Desktop"]
    assert desktop.notes == ["Laptop was added to your computers"]
    # the code is used up: its onion is gone, and it isn't kept; each one's onion lets in only the other
    d_me, l_me = desktop.me(), laptop.me()
    await desktop.until(lambda v: set(net.services) == {d_me.onion_key.address, l_me.onion_key.address}, "the code's onion gone")
    assert desktop.run(store.pending_pairing) is None and laptop.run(store.pending_pairing) is None
    await onions_list_each_other([desktop, laptop])
    # the laptop gets the desktop's app, to build when its user says so
    await laptop.until(lambda v: laptop.apps(), "the app")
    a = laptop.apps()[0]
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
    await stop_all(desktop, laptop)


async def add_with(shower, joiner, code):
    joiner.run(joiner.sync.pair_join, code)
    va = await shower.until(lambda v: step(v) == "done", "the code used")
    vb = await joiner.until(lambda v: step(v) == "done", "added")
    assert va["pairing"]["digits"] == vb["pairing"]["digits"] and len(va["pairing"]["digits"].replace(" ", "")) == 6
    assert va["pairing"]["with"] == joiner.name and vb["pairing"]["with"] == shower.name
    return va, vb


async def test_the_computer_a_code_is_typed_on_keeps_looking_until_the_other_is_on(tmp_path):
    net = FakeNet()
    desktop, laptop = Computer(tmp_path / "A", net, "Desktop"), Computer(tmp_path / "B", net, "Laptop")
    shown = desktop.run(desktop.sync.pair_show)
    await desktop.until(lambda v: step(v) == "waiting", "the code's onion")
    await desktop.off()                          # off before the other computer is ready
    laptop.run(laptop.sync.pair_join, shown["code"])
    await laptop.until(lambda v: step(v) == "finding", "looking for it")
    await asyncio.sleep(0.6)                     # tried again and again: it keeps looking
    assert step(laptop.view()) == "finding" and laptop.sync.tor.forgot      # tor told to forget it couldn't find it
    await laptop.off()
    await laptop.on()                            # and after a restart, too
    await laptop.until(lambda v: step(v) == "finding", "looking again")
    await desktop.on()                           # the desktop is on again
    await desktop.until(lambda v: step(v) == "done", "the code used")
    await laptop.until(lambda v: step(v) == "done", "added")
    await all_know([desktop, laptop])
    await stop_all(desktop, laptop)


async def check_both(desktop, laptop, *, shower_asks=True):
    """A code shown on the desktop, typed on the laptop, with the numbers to be checked on both screens
    (asked for on the desktop, or on the laptop): both at the check."""
    shown = desktop.run(desktop.sync.pair_show)
    if shower_asks:
        desktop.run(desktop.sync.pair_check, True)
    laptop.run(lambda: laptop.sync.pair_join(shown["code"], check=not shower_asks))
    va = await desktop.until(lambda v: step(v) == "check", "the numbers on the desktop")
    vb = await laptop.until(lambda v: step(v) == "check", "the numbers on the laptop")
    assert va["pairing"]["digits"] == vb["pairing"]["digits"] and va["pairing"]["with"] == "Laptop"
    return shown


@pytest.mark.parametrize("shower_asks", [True, False])
async def test_with_both_screens_in_view_the_numbers_are_checked_on_both_before_its_added(tmp_path, shower_asks):
    net = FakeNet()
    desktop, laptop = Computer(tmp_path / "A", net, "Desktop"), Computer(tmp_path / "B", net, "Laptop")
    await check_both(desktop, laptop, shower_asks=shower_asks)
    desktop.run(desktop.sync.pair_decide, True)
    await desktop.until(lambda v: step(v) == "deciding", "the desktop waiting for the laptop")
    await laptop.until(lambda v: v["pairing"]["other"] == "same", "the laptop hearing the desktop says they match")
    await asyncio.sleep(0.2)
    assert desktop.run(store.group) is None and names(desktop.view()) == []     # nothing until both said so
    laptop.run(laptop.sync.pair_decide, True)
    va = await desktop.until(lambda v: step(v) == "done", "the code used")
    vb = await laptop.until(lambda v: step(v) == "done", "added")
    assert va["pairing"]["checked"] and vb["pairing"]["checked"]
    await all_know([desktop, laptop])
    await stop_all(desktop, laptop)


async def test_numbers_one_computer_says_dont_match_add_nothing_and_the_code_stops_working(tmp_path):
    net = FakeNet()
    desktop, laptop = Computer(tmp_path / "A", net, "Desktop"), Computer(tmp_path / "B", net, "Laptop")
    await check_both(desktop, laptop)
    desktop.run(desktop.sync.pair_decide, True)
    laptop.run(laptop.sync.pair_decide, False)
    va = await desktop.until(lambda v: step(v) == "failed", "the desktop refusing it")
    vb = await laptop.until(lambda v: step(v) == "failed", "the laptop refusing it")
    assert "Laptop said the numbers didn't match" in va["pairing"]["error"] and "doesn't work any more" in va["pairing"]["error"]
    assert "didn't match" in vb["pairing"]["error"]
    assert desktop.run(store.pending_pairing) is None and laptop.run(store.pending_pairing) is None
    assert desktop.run(store.group) is None and laptop.run(store.group) is None
    await desktop.until(lambda v: v["tor"]["step"] == "stopped", "the desktop's tor stopped")
    with pytest.raises(service.SyncError, match="nothing to check"):
        desktop.run(desktop.sync.pair_decide, True)
    await stop_all(desktop, laptop)


async def test_cancelling_while_the_numbers_are_checked_says_so_on_the_other(tmp_path):
    net = FakeNet()
    desktop, laptop = Computer(tmp_path / "A", net, "Desktop"), Computer(tmp_path / "B", net, "Laptop")
    await check_both(desktop, laptop)
    await laptop.wait(laptop.sync.pair_cancel())             # the laptop's user changes their mind
    assert step(laptop.view()) == "cancelled"
    va = await desktop.until(lambda v: step(v) == "waiting" and v["pairing"]["error"], "the desktop waiting again")
    assert "Laptop cancelled" in va["pairing"]["error"] and desktop.run(store.pending_pairing)   # the code still works
    await desktop.wait(desktop.sync.pair_cancel())
    assert step(desktop.view()) == "cancelled" and desktop.run(store.pending_pairing) is None
    await stop_all(desktop, laptop)


async def test_a_code_can_be_cancelled_and_a_wrong_one_is_said_so(tmp_path):
    net = FakeNet()
    laptop = Computer(tmp_path / "B", net, "Laptop")
    code = pairing.new_code()
    with pytest.raises(service.SyncError, match="mistyped"):
        laptop.run(laptop.sync.pair_join, code[:-1] + str((int(code[-1]) + 1) % 10))
    laptop.run(laptop.sync.pair_join, code)
    await laptop.until(lambda v: step(v) == "finding", "looking for it")
    with pytest.raises(service.SyncError, match="under way already"):
        laptop.run(laptop.sync.pair_join, code)
    await laptop.wait(laptop.sync.pair_cancel())
    v = laptop.view()
    assert step(v) == "cancelled" and v["tor"]["step"] == "stopped" and laptop.run(store.pending_pairing) is None
    laptop.run(laptop.sync.dismiss)
    assert laptop.view()["pairing"] is None


async def test_three_computers_each_sync_with_each_other_directly(tmp_path):
    net = FakeNet()
    desktop, laptop, server = (Computer(tmp_path / d, net, n) for d, n in (("A", "Desktop"), ("B", "Laptop"), ("C", "Server")))
    await add(desktop, laptop)
    await add(desktop, server)                  # the laptop hears of it from the desktop
    trio = [desktop, laptop, server]
    await all_know(trio)
    await onions_list_each_other(trio)
    # an app made on the server reaches the laptop straight from it, the desktop being off
    await desktop.off()
    server.make_app()
    await laptop.until(lambda v: laptop.apps(), "the server's app")
    assert laptop.apps()[0]["synced"]["from"] == "Server"
    await desktop.on()                          # and the desktop gets it when it's on again
    await desktop.until(lambda v: desktop.apps(), "the server's app, later")
    await stop_all(*trio)


async def test_ten_computers_each_added_by_the_one_before_all_know_and_sync_with_each_other(tmp_path):
    net = FakeNet()
    pcs = [Computer(tmp_path / f"pc{i}", net, f"PC {i}") for i in range(10)]
    for a, b in zip(pcs, pcs[1:]):
        await add(a, b)
    await all_know(pcs, limit=60)
    await onions_list_each_other(pcs, limit=30)
    pcs[-1].make_app()
    for c in pcs[:-1]:
        await c.until(lambda v, c=c: c.apps(), f"the app on {c.name}", limit=30)
    await stop_all(*pcs)


async def test_a_computer_removed_is_shut_out_by_all_and_told_when_its_next_on(tmp_path):
    net = FakeNet()
    desktop, laptop, old = (Computer(tmp_path / d, net, n) for d, n in (("A", "Desktop"), ("B", "Laptop"), ("C", "Old laptop")))
    await add(desktop, laptop)
    await add(laptop, old)
    await all_know([desktop, laptop, old])
    old.make_app()
    await desktop.until(lambda v: desktop.apps(), "the old laptop's app")
    await old.off()                             # it's off when it's removed
    gone = old.me().id
    desktop.run(desktop.sync.remove, gone)
    with pytest.raises(service.SyncError, match="isn't one of this group's"):
        desktop.run(desktop.sync.remove, gone)
    assert names(desktop.view()) == ["Laptop"]
    await laptop.until(lambda v: names(v) == ["Desktop"], "the laptop hearing of it")
    await onions_list_each_other([desktop, laptop])
    assert desktop.apps() and laptop.apps()     # what it made stays
    # on again: it's told it was removed (by the desktop), and leaves the group, keeping its apps
    await old.on()
    v = await old.until(lambda v: v["removed"], "being told")
    assert v["removed"]["by"] == "Desktop" and v["members"] == [] and old.run(store.group) is None
    assert old.apps() and "This computer was removed from your computers" in old.notes
    await old.until(lambda v: v["tor"]["step"] == "stopped", "its tor stopped")
    await desktop.until(lambda v: desktop.run(store.status).get(gone, {}).get("told"), "the desktop knowing it heard")
    old.run(old.sync.dismiss)
    assert old.view()["removed"] is None
    await stop_all(desktop, laptop, old)


async def test_leaving_tells_the_others_and_keeps_the_apps(tmp_path):
    net = FakeNet()
    desktop, laptop, server = (Computer(tmp_path / d, net, n) for d, n in (("A", "Desktop"), ("B", "Laptop"), ("C", "Server")))
    await add(desktop, laptop)
    await add(desktop, server)
    await all_know([desktop, laptop, server])
    desktop.make_app()
    await laptop.until(lambda v: laptop.apps(), "the desktop's app")
    out = await laptop.wait(laptop.sync.leave())
    assert 1 <= out["told"] <= 2                # (the second may have heard it from the first)
    v = laptop.view()
    assert v["members"] == [] and v["removed"] is None and laptop.run(store.group) is None and laptop.apps()
    for c, other in ((desktop, "Server"), (server, "Desktop")):
        await c.until(lambda v, other=other: names(v) == [other], f"{c.name} hearing it left")
    await laptop.until(lambda v: v["tor"]["step"] == "stopped", "its tor stopped")
    with pytest.raises(service.SyncError, match="isn't in a group"):
        await laptop.wait(laptop.sync.leave())
    await stop_all(desktop, laptop, server)


async def test_a_computer_removed_and_added_again_is_back_on_every_computer(tmp_path):
    """Added again by another while the one that removed it was off: when that one's on again, the
    newer word (it's back) wins, not the removal it had."""
    net = FakeNet()
    desktop, laptop, server = (Computer(tmp_path / d, net, n) for d, n in (("A", "Desktop"), ("B", "Laptop"), ("C", "Server")))
    await add(desktop, laptop)
    await add(desktop, server)
    await all_know([desktop, laptop, server])
    desktop.run(desktop.sync.remove, laptop.me().id)
    await laptop.until(lambda v: v["removed"], "the laptop told")
    laptop.run(laptop.sync.dismiss)
    await server.until(lambda v: names(v) == ["Desktop"], "the server hearing of it")
    await desktop.off()
    await add(server, laptop)
    await desktop.on()
    await all_know([desktop, laptop, server])
    await onions_list_each_other([desktop, laptop, server])
    assert laptop.view()["removed"] is None
    await stop_all(desktop, laptop, server)


async def test_two_groups_become_one_when_a_computer_of_one_joins_the_other(tmp_path):
    net = FakeNet()
    desktop, laptop, work, server = (Computer(tmp_path / d, net, n) for d, n in (
        ("A", "Desktop"), ("B", "Laptop"), ("C", "Work PC"), ("D", "Server")))
    await add(desktop, laptop)
    await add(work, server)
    server.make_app("Server tool")
    await work.until(lambda v: work.apps(), "the server's app at work")
    await add(desktop, work)                     # the work PC joins the home group, bringing the server along
    everyone = [desktop, laptop, work, server]
    await all_know(everyone, limit=30)
    home = desktop.run(store.group).id
    for c in everyone:
        await c.until(lambda v, c=c: c.run(store.group).id == home, f"{c.name} in the one group")
    await onions_list_each_other(everyone)
    await laptop.until(lambda v: laptop.apps(), "the server's app at home")
    await stop_all(*everyone)


async def test_a_computer_not_found_at_first_is_tried_again_soon_not_minutes_later(tmp_path, monkeypatch):
    """Right after a computer is added, its onion takes a while to be found on Tor: a pull that missed
    it is tried again in seconds, then less often, rather than in five minutes."""
    monkeypatch.setattr(service, "PULL_EVERY", 60)
    net = FakeNet()
    desktop, laptop = Computer(tmp_path / "A", net, "Desktop"), Computer(tmp_path / "B", net, "Laptop")
    await add(desktop, laptop)
    await laptop.until(lambda v: v["members"][0]["synced"], "a first sync")
    d_onion = desktop.me().onion_key.address
    gone = net.services.pop(d_onion)                     # the desktop's onion can't be found, for a while
    desktop.make_app()
    laptop.run(laptop.sync.sync_now)
    await laptop.until(lambda v: v["members"][0]["error"], "a pull that missed it")
    net.services[d_onion] = gone                         # now it is
    await laptop.until(lambda v: laptop.apps(), "the app, pulled soon after", limit=3)
    await stop_all(desktop, laptop)


async def test_a_computer_the_others_cant_reach_still_syncs_both_ways_on_its_own_connections(tmp_path, monkeypatch):
    """Tor may find one computer's onion long before the other's (one just added, or back on): each
    session syncs both ways, so one that can reach the other is enough."""
    monkeypatch.setattr(service, "PULL_EVERY", 60)
    net = FakeNet()
    desktop, laptop = Computer(tmp_path / "A", net, "Desktop"), Computer(tmp_path / "B", net, "Laptop")
    await add(desktop, laptop)
    await laptop.until(lambda v: v["members"][0]["synced"], "a first sync")
    d_onion = desktop.me().onion_key.address
    hidden = net.services.pop(d_onion)                   # nobody can reach the desktop just now
    desktop.make_app()                                   # its change reaches the laptop on the desktop's connection
    await laptop.until(lambda v: laptop.apps(), "the desktop's app", limit=5)
    laptop.make_app("Laptop tool")                       # the laptop can't take it to the desktop...
    await asyncio.sleep(0.3)
    assert len(desktop.apps()) == 1
    desktop.run(desktop.sync.sync_now)                   # ...but the desktop gets it when it next pulls
    await desktop.until(lambda v: len(desktop.apps()) == 2, "the laptop's app", limit=5)
    net.services[d_onion] = hidden
    await stop_all(desktop, laptop)


async def test_the_window_adds_computers_through_the_api_and_hears_why_when_it_cant(tmp_path):
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
            code = pairing.new_code()
            r = await c.post("/api/sync/join", json={"code": code[:-1] + str((int(code[-1]) + 1) % 10)})
            assert r.status_code == 400 and "mistyped" in r.json()["error"]
            r = await c.post("/api/sync/pair")
            assert r.status_code == 200 and len(r.json()["code"].replace(" ", "")) == 16
            assert (await c.post("/api/sync/pair")).json()["code"] == r.json()["code"]
            assert (await c.get("/api/state")).json()["sync"]["pairing"]["role"] == "show"
            r = await c.post("/api/sync/join", json={"code": code})
            assert r.status_code == 400 and "looking for another" not in r.json()["error"] and "under way" in r.json()["error"]
            assert (await c.post("/api/sync/cancel")).status_code == 200
            assert (await c.get("/api/state")).json()["sync"]["pairing"]["step"] == "cancelled"
            assert (await c.post("/api/sync/dismiss")).status_code == 200
            assert (await c.get("/api/state")).json()["sync"]["pairing"] is None
            for path, said in (("/api/sync/now", "isn't in a group"), ("/api/sync/leave", "isn't in a group"),
                               (f"/api/sync/members/{'e' * 32}/remove", "isn't one of this group's"),
                               ("/api/sync/decide", "nothing to check"), ("/api/sync/check", "no code being shown")):
                r = await c.post(path, json={})
                assert r.status_code == 400 and said in r.json()["error"], path


def test_a_member_saying_this_computer_was_removed_is_believed_only_if_that_was_after_it_was_added(tmp_path):
    from test_sync import computer, member
    with computer(tmp_path):
        sync = service.SyncService(SimpleNamespace(emit=lambda kind, **data: None), make_tor=lambda c: None)
        me = sync.me()
        g = store.new_group()
        store.save_group(g)
        mine = store.entry_of(me)
        other = member("Desktop")
        store.save_members({me.id: mine, other["id"]: other})
        stale = wire.Refused("removed", "it was removed", {"by": "Desktop", "at": mine["added"] - 60})
        assert not sync._refused_as_removed(stale) and store.group()
        sync._spawn = lambda coro: coro.close()          # (no tor to take down)
        news = wire.Refused("removed", "it was removed", {"by": "Desktop", "at": mine["added"] + 60})
        assert sync._refused_as_removed(news) and store.group() is None
        assert sync.view()["removed"]["by"] == "Desktop"


def test_the_versions_of_a_change_edited_on_two_computers_can_be_compared(tmp_path):
    from test_sync import computer, edit, mine, pull
    desktop, laptop = tmp_path / "A", tmp_path / "B"
    with computer(desktop):
        make_app()
    _, got = pull(desktop)
    with computer(laptop):
        library.create(got, "f" * 32, "Desktop")
        _, base = mine()
        edit(mine()[0], "zoom", "+zoom, the laptop's way")
    with computer(desktop):
        edit(mine()[0], "zoom", "+zoom, the desktop's way")
    _, got = pull(desktop)
    with computer(laptop):
        b, _ = library.combine(mine()[0], got, base, "f" * 32, "Desktop")
        sync = service.SyncService(SimpleNamespace(app_manager=SimpleNamespace(changed=lambda: None)), make_tor=lambda c: None)
        x = sync.compare(b["id"], "zoom")
        assert "laptop's way" in x["mine"]["text"] and x["mine"]["notes"].startswith("# A zoom box")
        assert [(t["from"], t["peer"]) for t in x["theirs"]] == [("Desktop", "f" * 32)] and "desktop's way" in x["theirs"][0]["text"]
        with pytest.raises(share.ShareError, match="no such choice"):
            sync.compare(b["id"], "nothing")
        sync.resolve(b["id"], "zoom", "f" * 32)
        assert "desktop's way" in apps.read_file(b["id"], "changes/zoom.patch")
