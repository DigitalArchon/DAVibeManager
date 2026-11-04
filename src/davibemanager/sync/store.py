"""What sync keeps, on this computer only: config_dir()/sync, never in a backup and never restored
over (a backup restored onto another computer must not make it this one).

- identity.json: this computer's id, its name, its onion service's key and its client key (the
  key the other computers let in). Made the first time sync is used.
- group.json: the group of the user's computers this one belongs to: its id and key (from which
  each two members' secret is worked out, pair_key), and the groups it was in before, while some of
  their computers haven't moved to this one yet (see service.py, "moving").
- members.json: the group's members, this computer among them: each one's id, name, onion
  address and client key (the public half), when it was added, when its entry last changed, and
  whether (when, and by whom) it was removed. Every two members exchange theirs whenever they talk
  (merge_members), so a computer added by one member, or removed by one, is soon known to all.
- status.json: what this computer knows of each other member: when they last synced, and why one
  couldn't be reached.
- pairing.json: a pairing under way (a code shown, or typed), so it goes on after a restart: a code
  works until it's used or cancelled, however long that takes.
- bases/<member id>.json: for each app, how it was when this computer and that member last agreed
  (library.summary): what tells a change on one side from a change on the other.

The folder is 0700 and each file 0600: the keys, the group's secret and a code shown are this
computer's alone.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..config import config_dir
from . import onion
from .pairing import DEVICE_ID, clean_name

GROUP_ID = re.compile(r"[0-9a-f]{32}")
MAX_MEMBERS = 64                    # computers in a group
MAX_ENTRIES = 256                   # and entries in its list, the removed ones' among them (the oldest go)


def folder() -> Path:
    d = config_dir() / "sync"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(d, 0o700)
    return d


def state_dir() -> Path:
    """Where tor's own files are kept (its guards, its consensus): $XDG_STATE_HOME/davibemanager."""
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    d = Path(base) / "davibemanager"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


def _write(path: Path, data) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, ensure_ascii=False)
    tmp.replace(path)


def _read(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _unb64(text: str, size: int) -> bytes:
    raw = base64.b64decode(str(text or ""), validate=True)
    if len(raw) != size:
        raise ValueError("a key of the wrong size")
    return raw


# ---------------------------------------------------------------- this computer

@dataclass
class Identity:
    id: str
    name: str
    onion_key: onion.OnionKey
    client_key: onion.ClientKey

    def info(self) -> dict:
        """What this computer says of itself when it's added to a group (pairing.checked_info)."""
        return {"id": self.id, "name": self.name, "onion": self.onion_key.address, "client": self.client_key.public}


def default_name() -> str:
    host = re.sub(r"\.(local|lan|home|localdomain)$", "", socket.gethostname() or "", flags=re.I)
    return clean_name(host or "This computer")


def identity(make: bool = True) -> Identity | None:
    """This computer's identity, made the first time it's asked for (`make` False: None until then)."""
    d = _read(folder() / "identity.json", None)
    try:
        if isinstance(d, dict) and DEVICE_ID.fullmatch(str(d.get("id") or "")):
            return Identity(d["id"], clean_name(d.get("name")), onion.OnionKey(_unb64(d["onion"], 32)),
                            onion.ClientKey(_unb64(d["client"], 32)))
    except (KeyError, ValueError):
        pass
    if not make:
        return None
    me = Identity(secrets.token_hex(16), default_name(), onion.OnionKey.new(), onion.ClientKey.new())
    save_identity(me)
    return me


def save_identity(me: Identity) -> None:
    _write(folder() / "identity.json", {"id": me.id, "name": me.name, "onion": _b64(me.onion_key.seed),
                                         "client": _b64(me.client_key.private)})


# ---------------------------------------------------------------- the group

@dataclass
class Group:
    id: str
    key: bytes
    old: list[dict] = field(default_factory=list)       # [{"id", "key": bytes}]: groups it was in before

    def key_of(self, group_id: str) -> bytes | None:
        if group_id == self.id:
            return self.key
        return next((o["key"] for o in self.old if o["id"] == group_id), None)


def new_group() -> Group:
    return Group(secrets.token_hex(16), secrets.token_bytes(32))


def group() -> Group | None:
    d = _read(folder() / "group.json", None)
    try:
        if isinstance(d, dict) and GROUP_ID.fullmatch(str(d.get("id") or "")):
            old = [{"id": o["id"], "key": _unb64(o["key"], 32)} for o in d.get("old", [])
                   if isinstance(o, dict) and GROUP_ID.fullmatch(str(o.get("id") or ""))]
            return Group(d["id"], _unb64(d["key"], 32), old)
    except (KeyError, ValueError, TypeError):
        pass
    return None


def save_group(g: Group | None) -> None:
    path = folder() / "group.json"
    if g is None:
        path.unlink(missing_ok=True)
        return
    _write(path, {"id": g.id, "key": _b64(g.key), "old": [{"id": o["id"], "key": _b64(o["key"])} for o in g.old[-4:]]})


def pair_key(key: bytes, a: str, b: str) -> bytes:
    """What two members prove which they are with (wire.hello_*): from the group's key and their ids."""
    lo, hi = sorted((a, b))
    return hmac.new(key, b"dvm-sync pair " + lo.encode() + b"|" + hi.encode(), hashlib.sha256).digest()


# ---------------------------------------------------------------- the members

def entry_of(me: Identity, have: dict | None = None, **changes) -> dict:
    """This computer's entry in its group's list: as it was (`have`), with its name, addresses and keys
    as they are now, and `changes`."""
    now = time.time()
    have = have or {}
    return {"id": me.id, "name": me.name, "onion": me.onion_key.address, "client": me.client_key.public,
            "updated": have.get("updated") or now, "added": have.get("added") or now, "removed": 0,
            "by": have.get("by", ""), **changes}


def checked_member(e) -> dict | None:
    """A member's entry from another computer, checked; None when it isn't one."""
    if not isinstance(e, dict):
        return None
    try:
        out = {"id": str(e.get("id") or ""), "name": clean_name(e.get("name")), "onion": str(e.get("onion") or ""),
               "client": str(e.get("client") or ""), "updated": float(e.get("updated") or 0),
               "added": float(e.get("added") or 0), "removed": float(e.get("removed") or 0),
               "by": str(e.get("by") or "")[:32]}
    except (TypeError, ValueError):
        return None
    soon = time.time() + 86400                  # a clock a day fast is wrong, not later
    if not DEVICE_ID.fullmatch(out["id"]) or not onion.valid_address(out["onion"]) \
            or not onion.CLIENT_PUBLIC.fullmatch(out["client"]) or not 0 < out["updated"] < soon \
            or not 0 <= out["added"] < soon or not 0 <= out["removed"] < soon:
        return None
    return out


def members() -> dict[str, dict]:
    d = _read(folder() / "members.json", {})
    out = {}
    for e in (d.values() if isinstance(d, dict) else []):
        if (c := checked_member(e)) is not None:
            out[c["id"]] = c
    return out


def save_members(roster: dict[str, dict]) -> None:
    gone = sorted((e for e in roster.values() if e["removed"]), key=lambda e: e["removed"])
    drop = {e["id"] for e in gone[:max(0, len(roster) - MAX_ENTRIES)]}
    _write(folder() / "members.json", {k: v for k, v in roster.items() if k not in drop})


def live(roster: dict[str, dict], but: str = "") -> list[dict]:
    """The members not removed (but `but`, this computer)."""
    return [e for e in roster.values() if not e["removed"] and e["id"] != but]


def newer(e: dict, have: dict) -> bool:
    """Whether another computer's entry for a member says more than this one's: a removal stands
    against anything but the member being added again after it (a computer renamed after it was
    removed isn't back); otherwise the entry changed last."""
    if bool(e["removed"]) != bool(have["removed"]):
        gone, there = (e, have) if e["removed"] else (have, e)
        return (gone["removed"] >= there["added"]) == (gone is e)
    return (e["updated"], e["added"]) > (have["updated"], have["added"])


def merge_members(mine: dict[str, dict], theirs, me: str) -> tuple[dict[str, dict], list[str]]:
    """Another computer's list of members, merged into this one's (store.newer). Of this computer's
    own entry only its removal is taken from others, and only one after it was last added: it says
    itself what it's called, where it is and with which key. Returns (members, the ids whose entry
    changed)."""
    out, changed = dict(mine), []
    for raw in (theirs if isinstance(theirs, list) else [])[:MAX_ENTRIES]:
        e = checked_member(raw)
        if e is None:
            continue
        have = out.get(e["id"])
        if e["id"] == me:
            if have is not None and e["removed"] and not have["removed"] and e["removed"] >= have["added"]:
                out[me] = {**have, "removed": e["removed"], "updated": e["updated"], "by": e["by"]}
                changed.append(me)
            continue
        if have is None:
            if not e["removed"] and len(live(out)) >= MAX_MEMBERS:
                continue
        elif not newer(e, have):
            continue
        elif not e["removed"] and not have["removed"]:
            e = {**e, "added": max(e["added"], have["added"])}
        if e != have:
            out[e["id"]] = e
            changed.append(e["id"])
    return out, changed


# ---------------------------------------------------------------- what this computer knows of the others

def status() -> dict[str, dict]:
    d = _read(folder() / "status.json", {})
    return {k: v for k, v in d.items() if DEVICE_ID.fullmatch(k) and isinstance(v, dict)} if isinstance(d, dict) else {}


def save_status(s: dict[str, dict]) -> None:
    _write(folder() / "status.json", s)


def pending_pairing() -> dict | None:
    d = _read(folder() / "pairing.json", None)
    return d if isinstance(d, dict) and d.get("role") in ("show", "join") and str(d.get("code") or "").isdigit() else None


def save_pending_pairing(d: dict | None) -> None:
    path = folder() / "pairing.json"
    if d is None:
        path.unlink(missing_ok=True)
    else:
        _write(path, d)


def base_of(member: str) -> dict:
    """The apps as they were when this computer and `member` last agreed: {share id: summary}."""
    if not DEVICE_ID.fullmatch(member):
        return {}
    d = _read(folder() / "bases" / f"{member}.json", {})
    return d if isinstance(d, dict) else {}


def save_base(member: str, base: dict) -> None:
    if not DEVICE_ID.fullmatch(member):
        raise ValueError("not a computer's id")
    d = folder() / "bases"
    d.mkdir(exist_ok=True, mode=0o700)
    _write(d / f"{member}.json", base)


def forget_base(member: str) -> None:
    if DEVICE_ID.fullmatch(member):
        (folder() / "bases" / f"{member}.json").unlink(missing_ok=True)


def leave_all() -> None:
    """No group any more (this computer left, or was removed): its members, their bases, its status."""
    save_group(None)
    for name in ("members.json", "status.json", "peers.json"):
        (folder() / name).unlink(missing_ok=True)
    for f in (folder() / "bases").glob("*.json") if (folder() / "bases").is_dir() else []:
        f.unlink(missing_ok=True)
