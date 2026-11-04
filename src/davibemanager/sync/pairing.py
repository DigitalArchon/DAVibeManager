"""Pairing two computers: a code shown on one and typed on the other, then the same six digits on both.

The code is 12 digits: 11 random ones and a check digit (Damm's: any one digit mistyped, or two
next to each other swapped, is told at once). From it both computers work out, with scrypt, a
secret only they know, and from that an onion service's key. The first publishes that onion
while it waits (ten minutes at most); the second, knowing the code, knows its address. Nobody
else can find it: the address is the key, and the key is the code's. A directory that stores
its descriptor could try codes against it, but each try costs a scrypt, so that nothing like the
codes' 100 billion could be tried before the code has stopped working.

Over that connection (Tor's, end to end) each sends what the other needs to reach it from then on:
its id, its name, its own onion address and its client key. Then both show six digits worked out
from what both sent, and from a random part of each. The second computer committed to its part
before it saw the first's, so someone in the middle (who would have needed the code, say read off
the screen) couldn't choose theirs to make the two screens' digits match. The user checks they
do, on both computers; only then does either keep the other.

Pure: the messages, checked, and what's worked out from them. service.py sends them.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import onion

PROTO = 1
DIGITS = 12
WAIT = 600                          # seconds a code works for
SALT = b"DA Vibe Manager sync pairing 1"
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1, "maxmem": 64 << 20}      # 32 MB and a tenth of a second, per try
VIRTUAL_PORT = 7300                 # the pairing onion's port (only the app's own peers ever ask it)
DEVICE_ID = re.compile(r"[0-9a-f]{32}")
NONCE = re.compile(r"[0-9a-f]{64}")

# Damm's quasigroup of order 10 (H. M. Damm, 2004): a check digit that catches every single-digit
# error and every swap of two adjacent digits
_DAMM = ((0, 3, 1, 7, 5, 9, 8, 6, 4, 2), (7, 0, 9, 2, 1, 5, 4, 8, 6, 3), (4, 2, 0, 6, 8, 7, 1, 3, 5, 9),
         (1, 7, 5, 0, 9, 8, 3, 4, 2, 6), (6, 1, 2, 3, 0, 4, 5, 9, 7, 8), (3, 6, 7, 4, 2, 0, 9, 5, 8, 1),
         (5, 8, 6, 9, 7, 2, 0, 1, 3, 4), (8, 9, 4, 5, 3, 6, 2, 0, 1, 7), (9, 4, 3, 8, 6, 1, 7, 2, 0, 5),
         (2, 5, 8, 1, 4, 3, 6, 7, 9, 0))


class PairingError(Exception):
    """What went wrong, in words for the window."""


def _damm(digits: str) -> int:
    interim = 0
    for d in digits:
        interim = _DAMM[interim][int(d)]
    return interim


def new_code() -> str:
    body = "".join(secrets.choice("0123456789") for _ in range(DIGITS - 1))
    return body + str(_damm(body))


def shown(code: str) -> str:
    """The code as the window shows it: in fours."""
    return " ".join(code[i:i + 4] for i in range(0, len(code), 4))


def read_code(text: str) -> str:
    """A code as the user typed it (spaces, dashes and all), checked. Raises PairingError."""
    code = re.sub(r"[\s\-.]", "", str(text or ""))
    if not code.isdigit() or len(code) != DIGITS:
        raise PairingError(f"A pairing code is {DIGITS} digits: the other computer shows it.")
    if _damm(code) != 0:
        raise PairingError("That code isn't right: a digit may be mistyped. Check it against the other computer.")
    return code


def code_secret(code: str) -> bytes:
    """What both computers work out from the code: a tenth of a second's scrypt, on purpose."""
    return hashlib.scrypt(code.encode(), salt=SALT, dklen=32, **SCRYPT)


def _derive(secret: bytes, what: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"dvm-sync " + what).derive(secret)


def pairing_onion(secret: bytes) -> onion.OnionKey:
    """The onion the first computer waits on, and the second finds: the code's own."""
    return onion.OnionKey(_derive(secret, b"pairing onion"))


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def checked_info(info) -> dict:
    """What a computer says of itself, checked: {"id", "name", "onion", "client"}."""
    if not isinstance(info, dict):
        raise PairingError("The other computer sent something that isn't a pairing.")
    out = {"id": str(info.get("id") or ""), "name": clean_name(info.get("name")),
           "onion": str(info.get("onion") or ""), "client": str(info.get("client") or "")}
    if not DEVICE_ID.fullmatch(out["id"]) or not onion.valid_address(out["onion"]) \
            or not onion.CLIENT_PUBLIC.fullmatch(out["client"]):
        raise PairingError("The other computer sent something that isn't a pairing.")
    return out


def clean_name(name) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]", "", str(name or "")).strip()[:60]
    return text or "Another computer"


def commitment(nonce: bytes, info: dict) -> str:
    return hashlib.sha256(b"dvm-sync commit" + nonce + canonical(info)).hexdigest()


def digits(secret: bytes, first: dict, second: dict, first_nonce: bytes, second_nonce: bytes) -> str:
    """The six digits both screens show (`first` is the computer that showed the code)."""
    mac = hmac.new(_derive(secret, b"digits"), canonical([first, second]) + first_nonce + second_nonce, hashlib.sha256)
    n = int.from_bytes(mac.digest()[:8], "big") % 10 ** 6
    return f"{n // 1000:03d} {n % 1000:03d}"


def pair_secret(secret: bytes, first: dict, second: dict, first_nonce: bytes, second_nonce: bytes) -> bytes:
    """The secret the two keep for each other, with which each proves which it is, later."""
    return hmac.new(_derive(secret, b"pair secret"), canonical([first["id"], second["id"]]) + first_nonce + second_nonce,
                    hashlib.sha256).digest()


def nonce_of(text) -> bytes:
    text = str(text or "")
    if not NONCE.fullmatch(text):
        raise PairingError("The other computer sent something that isn't a pairing.")
    return bytes.fromhex(text)


class Joining:
    """The second computer's side: it has typed the code."""

    def __init__(self, code: str, me: dict):
        self.secret = code_secret(code)
        self.me, self.nonce = me, secrets.token_bytes(32)
        self.them: dict | None = None
        self.their_nonce = b""

    def opening(self) -> dict:
        return {"t": "pair", "proto": PROTO, "info": self.me, "commit": commitment(self.nonce, self.me)}

    def answered(self, msg: dict) -> dict:
        """The first computer's answer; returns the reveal to send."""
        if not isinstance(msg, dict) or msg.get("t") != "pair" or msg.get("proto") != PROTO:
            raise PairingError("The other computer's DA Vibe Manager can't pair with this one: update both.")
        self.them, self.their_nonce = checked_info(msg.get("info")), nonce_of(msg.get("nonce"))
        if self.them["id"] == self.me["id"]:
            raise PairingError("That's this computer's own code.")
        return {"t": "reveal", "nonce": self.nonce.hex()}

    @property
    def digits(self) -> str:
        return digits(self.secret, self.them, self.me, self.their_nonce, self.nonce)

    @property
    def secret_for_them(self) -> bytes:
        return pair_secret(self.secret, self.them, self.me, self.their_nonce, self.nonce)


class Waiting:
    """The first computer's side: it showed the code, and waits on the code's onion."""

    def __init__(self, code: str, me: dict):
        self.code, self.secret = code, code_secret(code)
        self.me, self.nonce = me, secrets.token_bytes(32)
        self.them: dict | None = None
        self.their_commit = ""
        self.their_nonce = b""

    def opened(self, msg: dict) -> dict:
        """The second computer's opening; returns the answer to send."""
        if not isinstance(msg, dict) or msg.get("t") != "pair" or msg.get("proto") != PROTO:
            raise PairingError("The other computer's DA Vibe Manager can't pair with this one: update both.")
        self.them = checked_info(msg.get("info"))
        if self.them["id"] == self.me["id"]:
            raise PairingError("That's this computer's own code.")
        self.their_commit = str(msg.get("commit") or "")
        return {"t": "pair", "proto": PROTO, "info": self.me, "nonce": self.nonce.hex()}

    def revealed(self, msg: dict) -> None:
        if not isinstance(msg, dict) or msg.get("t") != "reveal":
            raise PairingError("The other computer sent something that isn't a pairing.")
        nonce = nonce_of(msg.get("nonce"))
        if not hmac.compare_digest(commitment(nonce, self.them), self.their_commit):
            raise PairingError("The other computer's answer didn't match what it first sent: nothing was paired.")
        self.their_nonce = nonce

    @property
    def digits(self) -> str:
        return digits(self.secret, self.me, self.them, self.nonce, self.their_nonce)

    @property
    def secret_for_them(self) -> bytes:
        return pair_secret(self.secret, self.me, self.them, self.nonce, self.their_nonce)
