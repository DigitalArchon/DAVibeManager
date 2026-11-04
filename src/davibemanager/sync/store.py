"""What sync keeps, on this computer only: config_dir()/sync, never in a backup and never restored
over (a backup restored onto another computer must not make it this one).

- identity.json: this computer's id, its name, its onion service's key and its client key (the
  one other computers let in). Made the first time sync is used.
- peers.json: the computers paired with this one: each one's id, name, onion address and client
  key (the public half: this computer's onion lets it in), and the secret the two agreed on.
- bases/<peer id>.json: for each app, how it was when the two last agreed (library.summary):
  what tells a change on one side from a change on the other, and a removal from an app new.

The folder is 0700 and each file 0600: the keys and secrets are this computer's alone.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import socket
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..config import config_dir
from . import onion
from .pairing import DEVICE_ID, clean_name


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


@dataclass
class Identity:
    id: str
    name: str
    onion_key: onion.OnionKey
    client_key: onion.ClientKey

    def info(self) -> dict:
        """What this computer tells another when they pair."""
        return {"id": self.id, "name": self.name, "onion": self.onion_key.address, "client": self.client_key.public}


def default_name() -> str:
    host = re.sub(r"\.(local|lan|home|localdomain)$", "", socket.gethostname() or "", flags=re.I)
    return clean_name(host or "This computer")


def identity() -> Identity:
    """This computer's identity, made the first time it's asked for."""
    path = folder() / "identity.json"
    d = _read(path, None)
    try:
        if isinstance(d, dict) and DEVICE_ID.fullmatch(str(d.get("id") or "")):
            return Identity(d["id"], clean_name(d.get("name")), onion.OnionKey(_unb64(d["onion"], 32)),
                            onion.ClientKey(_unb64(d["client"], 32)))
    except (KeyError, ValueError):
        pass
    me = Identity(secrets.token_hex(16), default_name(), onion.OnionKey.new(), onion.ClientKey.new())
    save_identity(me)
    return me


def save_identity(me: Identity) -> None:
    _write(folder() / "identity.json", {"id": me.id, "name": me.name, "onion": _b64(me.onion_key.seed),
                                         "client": _b64(me.client_key.private)})


@dataclass
class Peer:
    id: str
    name: str
    onion: str                      # its onion address (without .onion)
    client: str                     # its client key's public half: this computer's onion lets it in
    secret: str                     # base64: what the two prove which they are with (wire.hello_*)
    paired: float = field(default_factory=time.time)
    synced: float = 0               # when the two last synced
    seen: float = 0                 # when it was last reached, or reached this one
    error: str = ""                 # why it couldn't be reached last time, in words

    @property
    def secret_bytes(self) -> bytes:
        return _unb64(self.secret, 32)

    def view(self) -> dict:
        return {k: v for k, v in asdict(self).items() if k not in ("secret", "client")}


def peers() -> list[Peer]:
    out = []
    for d in _read(folder() / "peers.json", []):
        try:
            p = Peer(**{k: d[k] for k in Peer.__dataclass_fields__ if k in d})
            p.secret_bytes
            if DEVICE_ID.fullmatch(p.id) and onion.valid_address(p.onion) and onion.CLIENT_PUBLIC.fullmatch(p.client):
                out.append(p)
        except (TypeError, KeyError, ValueError):
            continue
    return out


def save_peers(items: list[Peer]) -> None:
    _write(folder() / "peers.json", [asdict(p) for p in items])


def base_of(peer_id: str) -> dict:
    """The apps as they were when this computer and `peer_id` last agreed: {share id: summary}."""
    if not DEVICE_ID.fullmatch(peer_id):
        return {}
    d = _read(folder() / "bases" / f"{peer_id}.json", {})
    return d if isinstance(d, dict) else {}


def save_base(peer_id: str, base: dict) -> None:
    if not DEVICE_ID.fullmatch(peer_id):
        raise ValueError("not a computer's id")
    d = folder() / "bases"
    d.mkdir(exist_ok=True, mode=0o700)
    _write(d / f"{peer_id}.json", base)


def forget(peer_id: str) -> None:
    save_peers([p for p in peers() if p.id != peer_id])
    if DEVICE_ID.fullmatch(peer_id):
        (folder() / "bases" / f"{peer_id}.json").unlink(missing_ok=True)
