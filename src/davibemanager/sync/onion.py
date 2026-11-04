"""The keys of the onion services sync uses, and the addresses they give.

An onion service's address is its ed25519 public key (Tor's rend-spec-v3, "Encoding onion
addresses"): base32 of the key, a two-byte checksum and the version, 56 characters. Tor is given
a service's key as ADD_ONION's ED25519-V3 blob, the 64-byte "expanded" secret key: SHA-512 of
the 32-byte seed, with the scalar half clamped (RFC 8032, 5.1.5). So the address is known here
from the seed alone, before tor has the key, and can be checked against what tor says.

Client authorization ("restricted discovery"): a service lists the x25519 public keys allowed to
read its descriptor (ADD_ONION ClientAuthV3=<base32>), and a client gives its tor the private
key it holds for that service (ONION_CLIENT_AUTH_ADD <address> x25519:<base64>). Without one
the descriptor can't be decrypted: for anyone else, the service isn't there.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

VERSION = 3
ADDRESS = re.compile(r"[a-z2-7]{56}")
CLIENT_PUBLIC = re.compile(r"[A-Z2-7]{52}")         # a client key's public half, as ClientAuthV3 takes it
_RAW = serialization.Encoding.Raw


def _checksum(public: bytes) -> bytes:
    return hashlib.sha3_256(b".onion checksum" + public + bytes([VERSION])).digest()[:2]


def address_of(public: bytes) -> str:
    """The onion address (without ".onion") of an ed25519 public key."""
    if len(public) != 32:
        raise ValueError("an onion service's key is 32 bytes")
    return base64.b32encode(public + _checksum(public) + bytes([VERSION])).decode().lower()


def valid_address(text: str) -> bool:
    """A v3 onion address, its checksum right ("name.onion" or the 56 characters alone)."""
    text = str(text or "").removesuffix(".onion")
    if not ADDRESS.fullmatch(text):
        return False
    raw = base64.b32decode(text.upper())
    return raw[34] == VERSION and raw[32:34] == _checksum(raw[:32])


@dataclass(frozen=True)
class OnionKey:
    """An onion service's key, kept as its 32-byte seed."""

    seed: bytes

    @classmethod
    def new(cls) -> OnionKey:
        return cls(secrets.token_bytes(32))

    @property
    def public(self) -> bytes:
        return Ed25519PrivateKey.from_private_bytes(self.seed).public_key().public_bytes(_RAW, serialization.PublicFormat.Raw)

    @property
    def address(self) -> str:
        return address_of(self.public)

    @property
    def tor_blob(self) -> str:
        """ADD_ONION's key argument: the expanded secret key, the scalar clamped as tor does."""
        h = bytearray(hashlib.sha512(self.seed).digest())
        h[0] &= 248
        h[31] &= 127
        h[31] |= 64
        return "ED25519-V3:" + base64.b64encode(bytes(h)).decode()


@dataclass(frozen=True)
class ClientKey:
    """A client authorization key (x25519), kept as its 32-byte private key."""

    private: bytes

    @classmethod
    def new(cls) -> ClientKey:
        return cls(X25519PrivateKey.generate().private_bytes(_RAW, serialization.PrivateFormat.Raw,
                                                             serialization.NoEncryption()))

    @property
    def public(self) -> str:
        """The public half as a service lists it (ADD_ONION ClientAuthV3=): base32, 52 characters."""
        raw = X25519PrivateKey.from_private_bytes(self.private).public_key().public_bytes(_RAW, serialization.PublicFormat.Raw)
        return base64.b32encode(raw).decode().rstrip("=")

    @property
    def tor_private(self) -> str:
        """ONION_CLIENT_AUTH_ADD's key argument."""
        return "x25519:" + base64.b64encode(self.private).decode()
