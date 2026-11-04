"""Sync between the user's computers, its parts one by one: the onion keys, pairing, the wire,
tor's control protocol, what's kept, and how an app changed on two computers comes together."""

import asyncio
import base64
import hashlib
import os
import time
from contextlib import contextmanager

import pytest
from fakesandbox import commit_patch

from davibemanager import apps, config, share
from davibemanager.sync import library, onion, pairing, store, tor, wire

DDG = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad"    # a published onion address


@pytest.fixture(autouse=True)
def quick_scrypt(monkeypatch):
    monkeypatch.setattr(pairing, "SCRYPT", {"n": 2 ** 10, "r": 8, "p": 1})


@contextmanager
def computer(root):
    """What follows runs as another computer: its own config and data folders."""
    token = config.ROOTS.set((root / "config", root / "data"))
    try:
        yield
    finally:
        config.ROOTS.reset(token)


# ---------------------------------------------------------------- onion keys

def test_an_onion_address_is_its_key_with_a_checksum():
    assert onion.valid_address(DDG) and onion.valid_address(DDG + ".onion")
    assert not onion.valid_address(DDG[:-1] + "b") and not onion.valid_address(DDG.upper())
    assert onion.address_of(base64.b32decode(DDG.upper())[:32]) == DDG


def test_an_onion_key_gives_tor_its_expanded_secret_and_says_its_address():
    key = onion.OnionKey(bytes(range(32)))
    kind, _, blob = key.tor_blob.partition(":")
    raw = base64.b64decode(blob)
    assert kind == "ED25519-V3" and len(raw) == 64
    assert raw[0] & 7 == 0 and raw[31] & 0x80 == 0 and raw[31] & 0x40      # the scalar clamped, as tor's is
    assert raw[32:] == hashlib.sha512(key.seed).digest()[32:]
    assert onion.valid_address(key.address) and key.address == onion.OnionKey(bytes(range(32))).address


def test_a_client_key_is_listed_by_its_public_half_and_given_to_tor_whole():
    key = onion.ClientKey.new()
    assert onion.CLIENT_PUBLIC.fullmatch(key.public)
    assert key.tor_private.startswith("x25519:") and len(base64.b64decode(key.tor_private[7:])) == 32


# ---------------------------------------------------------------- pairing

def test_a_code_is_twelve_digits_whose_last_catches_a_typo_or_a_swap():
    code = pairing.new_code()
    assert len(code) == 12 and pairing.read_code(pairing.shown(code)) == code
    assert pairing.read_code(f" {code[:4]}-{code[4:8]} {code[8:]} ") == code
    for i in range(12):
        wrong = code[:i] + str((int(code[i]) + 1) % 10) + code[i + 1:]
        with pytest.raises(pairing.PairingError, match="mistyped"):
            pairing.read_code(wrong)
    for i in range(11):
        if code[i] != code[i + 1]:
            with pytest.raises(pairing.PairingError):
                pairing.read_code(code[:i] + code[i + 1] + code[i] + code[i + 2:])
    with pytest.raises(pairing.PairingError, match="12 digits"):
        pairing.read_code("1234")


def info(name):
    return {"id": os.urandom(16).hex(), "name": name, "onion": onion.OnionKey.new().address, "client": onion.ClientKey.new().public}


def test_both_computers_work_out_the_same_onion_digits_and_secret():
    code = pairing.new_code()
    a, b = pairing.Waiting(code, info("Desktop")), pairing.Joining(code, info("Laptop"))
    assert pairing.pairing_onion(a.secret).address == pairing.pairing_onion(b.secret).address
    a.revealed(b.answered(a.opened(b.opening())))
    assert a.them["name"] == "Laptop" and b.them["name"] == "Desktop"
    assert a.digits == b.digits and len(a.digits.replace(" ", "")) == 6
    assert a.secret_for_them == b.secret_for_them
    other = pairing.Waiting(pairing.new_code(), info("Elsewhere"))
    assert pairing.pairing_onion(other.secret).address != pairing.pairing_onion(a.secret).address


def test_a_reveal_that_isnt_what_was_committed_to_pairs_nothing():
    code = pairing.new_code()
    a, b = pairing.Waiting(code, info("Desktop")), pairing.Joining(code, info("Laptop"))
    reveal = b.answered(a.opened(b.opening()))
    with pytest.raises(pairing.PairingError, match="didn't match"):
        a.revealed({**reveal, "nonce": os.urandom(32).hex()})


def test_someone_in_the_middle_with_the_code_gets_other_digits_on_each_screen():
    """They'd have to pair with each computer separately: the second committed to its part before it
    saw theirs, so they can't make the two screens' digits match (one in a million by chance)."""
    code = pairing.new_code()
    desktop, laptop = pairing.Waiting(code, info("Desktop")), pairing.Joining(code, info("Laptop"))
    middle_as_laptop, middle_as_desktop = pairing.Joining(code, info("Laptop")), pairing.Waiting(code, info("Desktop"))
    desktop.revealed(middle_as_laptop.answered(desktop.opened(middle_as_laptop.opening())))
    middle_as_desktop.revealed(laptop.answered(middle_as_desktop.opened(laptop.opening())))
    assert desktop.digits != laptop.digits


def test_what_a_computer_says_of_itself_is_checked():
    good = info("Laptop")
    assert pairing.checked_info({**good, "name": "Lap\x00top" + "x" * 99})["name"] == "Laptop" + "x" * 54
    for bad in ({**good, "onion": DDG[:-1] + "b"}, {**good, "client": "abc"}, {**good, "id": "1"}, "text"):
        with pytest.raises(pairing.PairingError):
            pairing.checked_info(bad)
    code = pairing.new_code()
    me = info("Desktop")
    a, b = pairing.Waiting(code, me), pairing.Joining(code, me)
    with pytest.raises(pairing.PairingError, match="own code"):
        a.opened(b.opening())


# ---------------------------------------------------------------- the wire

async def pipe():
    """Two ends of a connection: (reader, writer) for each."""
    got = asyncio.get_running_loop().create_future()

    async def accepted(r, w):
        got.set_result((r, w))
    server = await asyncio.start_server(accepted, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    client = await asyncio.open_connection("127.0.0.1", port)
    return client, await got, server


async def test_messages_and_bytes_go_in_frames_with_limits():
    (cr, cw), (sr, sw), server = await pipe()
    await wire.send(cw, {"t": "list", "x": "é"})
    await wire.send_bytes(cw, b"\x00" * 1000)
    assert await wire.recv(sr) == {"t": "list", "x": "é"} and await wire.recv_bytes(sr) == b"\x00" * 1000
    cw.write(b"J" + (wire.MAX_JSON + 1).to_bytes(4, "big"))
    with pytest.raises(wire.WireError, match="isn't one"):
        await wire.recv(sr)
    cw.close()
    with pytest.raises(wire.WireError, match="closed"):
        await wire.recv(sr, 2)
    server.close()


async def test_paired_computers_prove_which_they_are_and_others_are_refused():
    secret, me, them = os.urandom(32), os.urandom(16).hex(), os.urandom(16).hex()
    for client_secret, server_knows, said in ((secret, them, None), (os.urandom(32), them, "couldn't prove"),
                                              (secret, "", "isn't paired")):
        (cr, cw), (sr, sw), server = await pipe()
        serving = asyncio.ensure_future(wire.hello_as_server(sr, sw, me, lambda who: secret if who == server_knows else None))
        if said is None:
            await wire.hello_as_client(cr, cw, them, me, client_secret)
            assert await serving == them
        else:
            with pytest.raises(wire.WireError, match=said):
                await wire.hello_as_client(cr, cw, them, me, client_secret)
            cw.close()                          # as the app does with a connection it gave up on
            with pytest.raises(wire.WireError):
                await serving
        cw.close()
        server.close()


async def test_tor_saying_an_onion_cant_be_reached_is_put_in_words(tmp_path):
    path = tmp_path / "socks.sock"
    answers = {}

    async def socks(r, w):
        await r.readexactly(3)
        w.write(b"\x05\x00")
        head = await r.readexactly(5)
        host = (await r.readexactly(head[4])).decode()
        await r.readexactly(2)
        w.write(bytes([5, answers[host], 0, 1, 0, 0, 0, 0, 0, 0]))
        await w.drain()
    server = await asyncio.start_unix_server(socks, path=str(path))
    answers.update({"a.onion": 0, "b.onion": 0xF0, "c.onion": 0xF4})
    r, w = await wire.socks_connect(path, "a.onion", 7301)
    w.close()
    with pytest.raises(wire.Unreachable, match="isn't online"):
        await wire.socks_connect(path, "b.onion", 7301)
    with pytest.raises(wire.Unreachable, match="isn't paired with this one any more") as e:
        await wire.socks_connect(path, "c.onion", 7301)
    assert e.value.code == 0xF4
    server.close()


# ---------------------------------------------------------------- tor's control protocol

def test_control_replies_are_read_whole_with_their_data_blocks():
    r = tor.ReplyReader()
    assert r.feed(b"250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/x/control_auth_cookie\"\r\n") == []
    (info,) = r.feed(b"250 OK\r\n")
    assert info.ok and tor.cookie_file(info) == "/x/control_auth_cookie"
    (block,) = r.feed(b"250+onions/current=\r\nabc\r\n..dotted\r\n.\r\n250 OK\r\n")
    assert block.data["onions/current"] == "abc\n.dotted"
    (event,) = r.feed(b"650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=45 TAG=loading_descriptors SUMMARY=\"Loading relay descriptors\"\r\n")
    assert event.event and tor.bootstrap_of(event.text()) == tor.Bootstrap(45, "Loading relay descriptors")
    with pytest.raises(tor.TorError):
        r.feed(b"nonsense\r\n")


def test_the_login_needs_tor_to_prove_it_read_the_same_cookie():
    cookie, nonce, server_nonce = os.urandom(32), os.urandom(32), os.urandom(32)
    server_hash, client_hash = tor.safecookie(cookie, nonce, server_nonce)
    good = tor.Reply(250, [f"AUTHCHALLENGE SERVERHASH={server_hash.hex()} SERVERNONCE={server_nonce.hex()}"])
    assert tor.authenticate(cookie, nonce, good) == f"AUTHENTICATE {client_hash.hex()}"
    with pytest.raises(tor.TorError, match="didn't prove"):
        tor.authenticate(os.urandom(32), nonce, good)


def test_an_onion_with_clients_lets_only_them_find_it_and_dies_with_the_app():
    key, clients = onion.OnionKey.new(), [onion.ClientKey.new().public for _ in range(2)]
    line = tor.add_onion(key, 7301, "unix:/run/x/sync.sock", clients)
    assert line.startswith(f"ADD_ONION {key.tor_blob} Flags=MaxStreamsCloseCircuit,V3Auth ")
    assert "Detach" not in line and f"ClientAuthV3={clients[0]} ClientAuthV3={clients[1]}" in line
    assert "Port=7301,unix:/run/x/sync.sock" in line and "V3Auth" not in tor.add_onion(key, 1, "unix:/s")
    assert tor.service_of(tor.Reply(250, [f"ServiceID={key.address}", "OK"])) == key.address
    with pytest.raises(tor.TorError, match="refused"):
        tor.service_of(tor.Reply(512, ["Bad arguments"]))


def test_tor_runs_for_onions_only_owned_by_the_app(tmp_path):
    p = tor.paths_for(tmp_path / "state", tmp_path / "run")
    text = tor.render_torrc(p, 4242)
    assert f'SocksPort unix:"{p.socks}" OnionTrafficOnly ExtendedErrors' in text
    assert "__OwningControllerProcess 4242" in text and "CookieAuthentication 1" in text
    with pytest.raises(tor.TorError):
        tor.paths_for(tmp_path, tmp_path / ("x" * 120))


# ---------------------------------------------------------------- what's kept

def test_this_computers_identity_is_made_once_and_kept_private():
    me = store.identity()
    assert store.identity().onion_key.address == me.onion_key.address
    assert oct(os.stat(store.folder() / "identity.json").st_mode & 0o777) == "0o600"
    assert oct(os.stat(store.folder()).st_mode & 0o777) == "0o700"
    peer = store.Peer(os.urandom(16).hex(), "Laptop", onion.OnionKey.new().address, onion.ClientKey.new().public,
                      base64.b64encode(os.urandom(32)).decode())
    store.save_peers([peer, store.Peer("bad", "x", "y", "z", "w")])
    assert [p.id for p in store.peers()] == [peer.id] and "secret" not in store.peers()[0].view()
    store.save_base(peer.id, {"s": {"digest": "d"}})
    assert store.base_of(peer.id) == {"s": {"digest": "d"}}
    store.forget(peer.id)
    assert store.peers() == [] and store.base_of(peer.id) == {}


# ---------------------------------------------------------------- the apps, on two computers

UPSTREAM = "https://gitlab.gnome.org/GNOME/gthumb.git"


def make_app(changes=(("zoom", "A zoom box"),), name="gThumb"):
    now = time.time()
    a = apps.create(name, "appimage", UPSTREAM, base_ref="3.12.6", packages=["meson"], split=True,
                    changes=[{"id": cid, "title": title, "patch_ids": [], "added": now} for cid, title in changes])
    for cid, title in changes:
        apps.write_file(a["id"], f"changes/{cid}.patch", commit_patch("a" * 40, title, f"+{cid}", cid))
        apps.write_file(a["id"], f"changes/{cid}.md", f"# {title}\n")
    apps.write_file(a["id"], "build.sh", "meson setup build && ninja -C build\n")
    return library.prepared(apps.load(a["id"]))


def edit(a, cid, body, title=None):
    """A chat changed one of the app's changes (a new revision of it)."""
    apps.write_file(a["id"], f"changes/{cid}.patch", commit_patch("b" * 40, title or cid, body, cid))
    changes = [{**c, "rev": share.new_rev(c["rev"]), "title": title or c["title"]} if c["id"] == cid else c
               for c in a["changes"]]
    return apps.save({**a, "changes": changes})


def mine():
    (a, s, _), = library.local().values()
    return a, s


def pull(from_root, base=None):
    """What pulling one app from another computer does: its summary and bundle, as it has them now."""
    with computer(from_root):
        (a, s, data), = library.local().values()
    return s, share.read(data)


def test_an_app_arrives_whole_with_its_versions_and_is_the_same_app_there(tmp_path):
    with computer(tmp_path / "A"):
        make_app()
        a_app, a_sum = mine()
    theirs, got = pull(tmp_path / "A")
    with computer(tmp_path / "B"):
        assert library.plan(None, theirs, None) == "new"
        b = library.create(got, "f" * 32, "Desktop")
        b_app, b_sum = mine()
    assert b_sum["digest"] == a_sum["digest"] and b["share"]["id"] == a_app["share"]["id"]
    assert b["synced"]["built"] is False and b["synced"]["from"] == "Desktop" and b["synced"]["changes"] == ["zoom"]
    assert "installed" not in b or b["installed"] is None


def test_what_changed_on_one_computer_only_is_taken_and_comes_out_the_same(tmp_path):
    with computer(tmp_path / "A"):
        make_app()
    theirs, got = pull(tmp_path / "A")
    with computer(tmp_path / "B"):
        library.create(got, "f" * 32, "Desktop")
        _, base = mine()
    with computer(tmp_path / "A"):
        a, _ = mine()
        edit(a, "zoom", "+a better zoom")
    theirs, got = pull(tmp_path / "A")
    with computer(tmp_path / "B"):
        b, here = mine()
        assert library.plan(here, theirs, base) == "take"
        b, out = library.combine(b, got, base, "f" * 32, "Desktop")
        assert out["took"] == ["zoom"] and "better zoom" in apps.read_file(b["id"], "changes/zoom.patch")
        _, here = mine()
    assert here["digest"] == theirs["digest"]
    with computer(tmp_path / "A"):
        assert library.plan(mine()[1], here, base) == "same"


def test_one_change_edited_on_both_computers_is_kept_here_and_theirs_put_aside(tmp_path):
    with computer(tmp_path / "A"):
        make_app()
    _, got = pull(tmp_path / "A")
    with computer(tmp_path / "B"):
        library.create(got, "f" * 32, "Desktop")
        _, base = mine()
        b, _ = mine()
        edit(b, "zoom", "+zoom, the laptop's way")
    with computer(tmp_path / "A"):
        a, _ = mine()
        edit(a, "zoom", "+zoom, the desktop's way")
    theirs, got = pull(tmp_path / "A")
    with computer(tmp_path / "B"):
        b, here = mine()
        assert library.plan(here, theirs, base) == "merge"
        b, out = library.combine(b, got, base, "f" * 32, "Desktop")
        assert out["conflicts"] == ["zoom"] and "laptop's way" in apps.read_file(b["id"], "changes/zoom.patch")
        assert "desktop's way" in apps.read_file(b["id"], "sync/zoom.patch")
        assert [c["id"] for c in b["synced"]["conflicts"]] == ["zoom"]
        # the user keeps this one: a revision after both, which the desktop then takes as the newer
        b = library.resolve(b["id"], "zoom", "mine")
        assert b["synced"]["conflicts"] == [] and not (apps.dir_of(b["id"]) / "sync/zoom.patch").exists()
        _, here = mine()
    with computer(tmp_path / "A"):
        a, there = mine()
        _, back = pull(tmp_path / "B")
        a, out = library.combine(a, back, base, "e" * 32, "Laptop")
        assert out["took"] == ["zoom"] and "laptop's way" in apps.read_file(a["id"], "changes/zoom.patch")


def test_taking_theirs_in_a_conflict_makes_both_computers_the_same_again(tmp_path):
    with computer(tmp_path / "A"):
        make_app()
    _, got = pull(tmp_path / "A")
    with computer(tmp_path / "B"):
        library.create(got, "f" * 32, "Desktop")
        _, base = mine()
        edit(mine()[0], "zoom", "+laptop")
    with computer(tmp_path / "A"):
        edit(mine()[0], "zoom", "+desktop")
    theirs, got = pull(tmp_path / "A")
    with computer(tmp_path / "B"):
        b, _ = library.combine(mine()[0], got, base, "f" * 32, "Desktop")
        b = library.resolve(b["id"], "zoom", "theirs")
        assert "+desktop" in apps.read_file(b["id"], "changes/zoom.patch") and b["synced"]["built"] is False
        assert mine()[1]["digest"] == theirs["digest"]


def test_a_change_removed_on_one_computer_goes_unless_the_other_edited_it(tmp_path):
    with computer(tmp_path / "A"):
        make_app(changes=(("zoom", "A zoom box"), ("dark", "Dark viewer")))
    _, got = pull(tmp_path / "A")
    with computer(tmp_path / "B"):
        library.create(got, "f" * 32, "Desktop")
        _, base = mine()
    with computer(tmp_path / "A"):
        a, _ = mine()
        apps.save({**a, "changes": [c for c in a["changes"] if c["id"] != "dark"]})
    theirs, got = pull(tmp_path / "A")
    with computer(tmp_path / "B"):
        b, here = mine()
        b, out = library.combine(b, got, base, "f" * 32, "Desktop")
        assert out["dropped"] == ["dark"] and [c["id"] for c in b["changes"]] == ["zoom"]
    # one that had edited it meanwhile keeps it; one removed here, edited there, comes back
    assert library.decide({"id": "r2", "history": ["r1"]}, None, "r1") == "mine"
    assert library.decide({"id": "r1", "history": []}, None, "r1") == "drop"
    assert library.decide(None, {"id": "r2", "history": ["r1"]}, "r1") == "theirs"


def test_changes_added_on_each_computer_both_stay(tmp_path):
    with computer(tmp_path / "A"):
        make_app()
    _, got = pull(tmp_path / "A")
    with computer(tmp_path / "B"):
        library.create(got, "f" * 32, "Desktop")
        _, base = mine()
        b, _ = mine()
        apps.write_file(b["id"], "changes/raw.patch", commit_patch("c" * 40, "RAW files", "+raw", "raw"))
        apps.save({**b, "changes": [*b["changes"], {"id": "raw", "title": "RAW files", "rev": share.new_rev(), "patch_ids": []}]})
    with computer(tmp_path / "A"):
        a, _ = mine()
        apps.write_file(a["id"], "changes/dark.patch", commit_patch("d" * 40, "Dark viewer", "+dark", "dark"))
        apps.save({**a, "changes": [*a["changes"], {"id": "dark", "title": "Dark viewer", "rev": share.new_rev(), "patch_ids": []}]})
    theirs, got = pull(tmp_path / "A")
    with computer(tmp_path / "B"):
        b, _ = library.combine(mine()[0], got, base, "f" * 32, "Desktop")
        assert [c["id"] for c in b["changes"]] == ["zoom", "raw", "dark"]
        assert "+raw" in apps.read_file(b["id"], "series.patch") and "+dark" in apps.read_file(b["id"], "series.patch")


def test_an_app_removed_on_one_computer_is_asked_about_on_the_other_never_removed():
    s = {"digest": "1"}
    assert library.plan(s, None, s) == "gone_there"
    assert library.plan({"digest": "2"}, None, s) == "only_here"     # changed here since: the other gets it back
    assert library.plan(None, s, s) == "gone_here"
    assert library.plan(None, {"digest": "2"}, s) == "back"
    assert library.plan(s, s, None) == "same" and library.plan({"digest": "2"}, s, None) == "merge"


def test_an_app_of_the_same_name_from_another_computer_isnt_mistaken_for_this_ones(tmp_path):
    with computer(tmp_path / "A"):
        make_app()
    _, got = pull(tmp_path / "A")
    with computer(tmp_path / "B"):
        make_app()                                   # a gThumb of its own, never synced
        b = library.create(got, "f" * 32, "Desktop")
        assert b["name"] == "gThumb (Desktop)" and len(library.local()) == 2


def test_apps_sync_leaves_out_say_why():
    assert "add-ons" in library.syncable({"kind": "addon"})
    a = make_app()
    assert library.syncable(a) == ""
    assert "one by one" in library.syncable({**a, "split": False})


async def test_the_apps_own_tor_is_started_logged_into_and_stopped_with_it(tmp_path, monkeypatch):
    """Against a stand-in for tor (faketor.py), run as tor is: the cookie login, in which tor proves
    it read the cookie; ownership, so it goes with the app; bootstrap; an onion with clients."""
    import tempfile
    from pathlib import Path
    key = onion.OnionKey.new()
    monkeypatch.setenv("FAKE_TOR_ADDRESS", key.address)
    monkeypatch.setenv("FAKE_TOR_LOG", str(tmp_path / "commands"))
    clean = tor.tor_environment
    monkeypatch.setattr(tor, "tor_environment", lambda t, environ=None: {
        **clean(t), **{k: v for k, v in os.environ.items() if k.startswith("FAKE_TOR_")}})
    run = Path(tempfile.mkdtemp(prefix="dvm-", dir="/tmp"))
    states = []
    t = tor.Tor(tor.paths_for(tmp_path / "state", run), binary=Path(__file__).with_name("faketor.py"), on_change=states.append)
    await t.start()
    assert t.running and any(s["progress"] == 50 for s in states) and states[-1]["step"] == "ready"
    client = onion.ClientKey.new()
    sid = await t.add_onion(key, 7301, run / "tor" / "sync.sock", [client.public])
    assert sid == key.address and await t.wait_published(sid, 5)
    await t.allow_client(key.address, client)
    proc = t._proc
    await t.stop()
    assert proc.returncode is not None and not t.running          # gone when the app let go of it
    sent = (tmp_path / "commands").read_text().splitlines()
    assert [line.split()[0] for line in sent[:5]] == ["PROTOCOLINFO", "AUTHCHALLENGE", "AUTHENTICATE", "TAKEOWNERSHIP", "SETEVENTS"]
    assert f"ClientAuthV3={client.public}" in next(line for line in sent if line.startswith("ADD_ONION"))
    assert oct(os.stat(t.paths.torrc).st_mode & 0o777) == "0o600"


async def test_tor_that_isnt_there_or_wont_start_says_so(tmp_path):
    import tempfile
    from pathlib import Path
    run = Path(tempfile.mkdtemp(prefix="dvm-", dir="/tmp"))
    t = tor.Tor(tor.paths_for(tmp_path / "state", run), binary=Path("/bin/false"))
    with pytest.raises(tor.TorError, match="Tor didn't start"):
        await t.start()
    assert t.state["step"] == "failed"
