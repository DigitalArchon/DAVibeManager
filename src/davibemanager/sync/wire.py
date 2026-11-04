"""What two computers send each other, and how each proves which it is.

A connection is a stream through Tor (Tor's own encryption, end to end, to the onion's key). On
it go frames: one byte for the kind (J: a JSON message, B: bytes, an app's bundle) and four for
the length, then the frame. Each kind has its own limit, and reading waits only so long.

To reach a computer, the app asks its tor's SOCKS socket for the computer's onion. With
ExtendedErrors, tor says why one can't be reached (not online, or not letting this one in),
which `Unreachable` puts in words.

Once connected, two members of a group prove to each other that they are who they say, with the
secret the group's key gives those two (store.pair_key): each sends a random nonce, and each
answers with an HMAC of both, its role and both ids. Neither learns anything of the secret from
the other's answer, and an answer can't be replayed (the other's nonce is new each time). Tor's
client authorization already lets only members reach the service; this says which one it is. The
client says which group's key it uses (a computer not yet moved from a group it was in before
uses that one's), and a refusal says why: not that group, not a member, or removed.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import secrets
from pathlib import Path

PROTO = 2
MAX_JSON = 4 << 20                  # a message
MAX_BYTES = 26 << 20                # an app's bundle (share.MAX_FILE, and some)
READ_WAIT = 180                     # seconds one frame may take (Tor can be slow)
HELLO_WAIT = 60


class WireError(Exception):
    """The other end said something that can't be read, or nothing in time."""


class Refused(WireError):
    """The other computer didn't let this one in: `code` "group", "member", "removed" or "version"."""

    def __init__(self, code: str, why: str, removed: dict | None = None):
        super().__init__(why)
        self.code, self.why, self.removed = code, why, removed or {}


class Unreachable(WireError):
    """Tor couldn't reach the other computer: `why` in words, `code` tor's."""

    def __init__(self, code: int, why: str):
        super().__init__(why)
        self.code, self.why = code, why


# tor's SOCKS5 replies, its own (0xF0..) with ExtendedErrors (tor's socks-extensions.txt)
_WHY = {
    0x01: "Tor couldn't reach it",
    0x04: "it couldn't be reached",
    0x05: "its app didn't answer",
    0x06: "it took too long to answer",
    0xF0: "it isn't online, or DA Vibe Manager isn't running on it",
    0xF1: "it isn't online, or DA Vibe Manager isn't running on it",
    0xF2: "it couldn't be reached just now",
    0xF3: "it couldn't be reached just now",
    0xF4: "it doesn't let this computer in: it hasn't heard yet that this one was added, or it removed it",
    0xF5: "it doesn't let this computer in: it hasn't heard yet that this one was added, or it removed it",
    0xF6: "its address isn't one",
    0xF7: "it took too long to answer",
}


async def send(writer: asyncio.StreamWriter, msg: dict) -> None:
    data = json.dumps(msg, separators=(",", ":"), ensure_ascii=False).encode()
    if len(data) > MAX_JSON:
        raise WireError("a message too big to send")
    writer.write(b"J" + len(data).to_bytes(4, "big") + data)
    await writer.drain()


async def send_bytes(writer: asyncio.StreamWriter, data: bytes) -> None:
    if len(data) > MAX_BYTES:
        raise WireError("a file too big to send")
    writer.write(b"B" + len(data).to_bytes(4, "big"))
    writer.write(data)
    await writer.drain()


async def _frame(reader: asyncio.StreamReader, wait: float) -> tuple[bytes, bytes]:
    try:
        head = await asyncio.wait_for(reader.readexactly(5), wait)
        kind, size = head[:1], int.from_bytes(head[1:], "big")
        if kind not in (b"J", b"B") or size > (MAX_JSON if kind == b"J" else MAX_BYTES):
            raise WireError("a frame that isn't one")
        return kind, await asyncio.wait_for(reader.readexactly(size), wait)
    except asyncio.IncompleteReadError:
        raise WireError("the other computer closed the connection") from None
    except asyncio.TimeoutError:
        raise WireError("the other computer stopped answering") from None


async def recv(reader: asyncio.StreamReader, wait: float = READ_WAIT) -> dict:
    kind, data = await _frame(reader, wait)
    if kind != b"J":
        raise WireError("bytes where a message was due")
    try:
        msg = json.loads(data)
    except ValueError:
        raise WireError("a message that can't be read") from None
    if not isinstance(msg, dict):
        raise WireError("a message that isn't one")
    return msg


async def recv_bytes(reader: asyncio.StreamReader, wait: float = READ_WAIT) -> bytes:
    kind, data = await _frame(reader, wait)
    if kind != b"B":
        raise WireError("a message where bytes were due")
    return data


async def socks_connect(socket_path: Path, host: str, port: int, wait: float = 120):
    """A stream to host:port through tor's SOCKS socket (a unix one): (reader, writer)."""
    reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(str(socket_path)), 10)
    try:
        writer.write(b"\x05\x01\x00")                      # SOCKS5, one method: none
        await writer.drain()
        if await asyncio.wait_for(reader.readexactly(2), 10) != b"\x05\x00":
            raise WireError("tor's SOCKS socket didn't answer as one")
        name = host.encode()
        writer.write(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big"))
        await writer.drain()
        head = await asyncio.wait_for(reader.readexactly(4), wait)
        if head[0] != 5:
            raise WireError("tor's SOCKS socket didn't answer as one")
        if head[1] != 0:
            raise Unreachable(head[1], _WHY.get(head[1], f"Tor couldn't reach it (SOCKS {head[1]:#x})"))
        length = {1: 4, 4: 16}.get(head[3])
        if length is None:
            length = (await asyncio.wait_for(reader.readexactly(1), wait))[0]
        await asyncio.wait_for(reader.readexactly(length + 2), wait)    # the bound address: of no use here
        return reader, writer
    except asyncio.TimeoutError:
        writer.close()
        raise Unreachable(0x06, _WHY[0x06]) from None
    except asyncio.IncompleteReadError:
        writer.close()
        raise WireError("tor closed the connection") from None
    except BaseException:
        writer.close()
        raise


def _proof(secret: bytes, role: bytes, mine: bytes, theirs: bytes, client: str, server: str) -> str:
    return hmac.new(secret, b"dvm-sync " + role + mine + theirs + client.encode() + b"|" + server.encode(),
                    hashlib.sha256).hexdigest()


def _nonce(msg: dict) -> bytes:
    text = str(msg.get("nonce") or "")
    if len(text) != 64:
        raise WireError("a hello that isn't one")
    try:
        return bytes.fromhex(text)
    except ValueError:
        raise WireError("a hello that isn't one") from None


async def hello_as_client(reader, writer, me: str, them: str, group: str, secret: bytes) -> None:
    """Prove this computer is `me` (of `group`, with its key's `secret` for the two) to the computer
    `them` it connected to, and that it is `them`. Raises Refused when it isn't let in."""
    mine = secrets.token_bytes(32)
    await send(writer, {"t": "hello", "proto": PROTO, "id": me, "group": group, "nonce": mine.hex()})
    msg = await recv(reader, HELLO_WAIT)
    if msg.get("t") == "refused":
        removed = msg.get("removed") if isinstance(msg.get("removed"), dict) else None
        raise Refused(str(msg.get("code") or "member"), str(msg.get("why") or "it refused this computer")[:200], removed)
    if msg.get("t") != "hello" or msg.get("id") != them:
        raise WireError("the computer that answered isn't the one asked for")
    if msg.get("proto") != PROTO:
        raise WireError("its DA Vibe Manager is a different version: update both")
    theirs = _nonce(msg)
    if not hmac.compare_digest(str(msg.get("proof") or ""), _proof(secret, b"server", mine, theirs, me, them)):
        raise WireError("the computer that answered couldn't prove it's that one of the group")
    await send(writer, {"t": "auth", "proof": _proof(secret, b"client", theirs, mine, me, them)})
    msg = await recv(reader, HELLO_WAIT)
    if msg.get("t") != "welcome":
        raise WireError(str(msg.get("why") or "it didn't let this computer in")[:200])


async def hello_as_server(reader, writer, me: str, lookup) -> tuple[str, str]:
    """Who connected, proved: a member. `lookup(id, group)` gives the secret those two prove which
    they are with, or a refusal: ("group" | "member", why) or ("removed", {"by", "at"}). Returns
    (its id, the group whose key it used); raises Refused (having told it) when it isn't let in."""
    msg = await recv(reader, HELLO_WAIT)
    if msg.get("t") != "hello":
        raise WireError("a connection that didn't say hello")
    if msg.get("proto") != PROTO:
        await send(writer, {"t": "refused", "code": "version", "why": "its DA Vibe Manager is a different version: update both"})
        raise Refused("version", "a different version of the sync protocol")
    who, group = str(msg.get("id") or ""), str(msg.get("group") or "")
    secret = lookup(who, group)
    if not isinstance(secret, bytes):
        code, detail = secret if isinstance(secret, tuple) else ("member", None)
        why = {"group": "it isn't in this computer's group", "removed": "it was removed from this group"}.get(
            code, "it isn't one of this group's computers")
        await send(writer, {"t": "refused", "code": code, "why": why, **({"removed": detail} if code == "removed" else {})})
        raise Refused(code, why)
    theirs, mine = _nonce(msg), secrets.token_bytes(32)
    await send(writer, {"t": "hello", "proto": PROTO, "id": me, "nonce": mine.hex(),
                        "proof": _proof(secret, b"server", theirs, mine, who, me)})
    msg = await recv(reader, HELLO_WAIT)
    if msg.get("t") != "auth" or not hmac.compare_digest(str(msg.get("proof") or ""),
                                                          _proof(secret, b"client", mine, theirs, who, me)):
        await send(writer, {"t": "refused", "code": "member", "why": "it couldn't prove which computer it is"})
        raise Refused("member", "a computer that couldn't prove which it is")
    await send(writer, {"t": "welcome"})
    return who, group
