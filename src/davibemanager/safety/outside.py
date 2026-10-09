"""What came from the user's computer must never leave in a web search.

The assistant may search the web on its own, but only with what is in its sandbox (and the
user's own words). Everything the user sent it from their computer (the output of the commands
it asked to run) is remembered here, hashed, across all conversations and for as long as the
sandbox lives (the assistant may have kept some of it in /work). A query is refused when it
holds any of it:

- a distinctive token from that output: one with a digit, a path or address character, a dot
  between letters, or a long one (a version, an IP, a file or domain name, a serial);
- five words in a row from that output (a copied line);
- this computer's identity, wherever it came from: the user's login and real name, the host
  name, the home folder, and any e-mail address, MAC address or private IP address.

The same check is made on the address of every page the assistant reads with WebFetch (its path,
query and fragment), since an address carries data out as well as a search does, and on the host
name of every connection out of the sandbox (gateway.py), which is all the app sees of the rest:
inside HTTPS, what a program in the sandbox sends is unseen. So this keeps the assistant's own
searching clean; it can't stop a program in the sandbox from sending what it was given. What the
user sends from their computer is the boundary, which is why it waits for them by default.

Plain words are let through ("cinnamon", "firefox", "gThumb"): on their own they say nothing
about the user, and without them no search would be possible. The check is made in code, before the query
reaches the search provider; the assistant can only rephrase.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import pwd
import re
import socket
from pathlib import Path
from urllib.parse import unquote_plus, urlsplit

NGRAM = 5
_TOKEN = re.compile(r"[^\s\"'`()\[\]{}<>,;|*!?]+")
_WORD = re.compile(r"[a-z0-9]+")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_MAC = re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", re.I)
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
# technical words that look distinctive but say nothing about anyone
GENERIC = {"x86_64", "amd64", "i386", "i686", "aarch64", "arm64", "armhf", "utf-8", "utf8", "ipv4", "ipv6",
           "64-bit", "32-bit", "mp3", "mp4", "h264", "h265", "x11", "gtk3", "gtk4", "gtk-3", "gtk-4", "qt5", "qt6",
           "1080p", "720p", "4k", "2fa", "https://", "http://", "e.g.", "i.e."}
# logins too common to be told apart from a word in a query
COMMON_NAMES = {"user", "admin", "root", "guest", "home", "test", "linux", "ubuntu", "mint", "debian", "fedora",
                "desktop", "laptop", "computer", "pc", "localhost"}


def _h(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:20]


def _norm(tok: str) -> str:
    return tok.lower().strip(".:-_/")


def distinctive(tok: str) -> bool:
    t = tok.strip(".:")
    if len(t) < 3 or t.lower() in GENERIC:
        return False
    return (bool(re.search(r"\d", t)) or any(c in t for c in "/@\\_~=:%#")
            or bool(re.search(r"[A-Za-z]\.[A-Za-z]", t)) or len(t) >= 20)


def _ngrams(text: str) -> set[str]:
    words = _WORD.findall(text.lower())
    return {" ".join(words[i:i + NGRAM]) for i in range(len(words) - NGRAM + 1)}


def identity() -> list[str]:
    """This computer's names: login, real name, host name, home folder."""
    out = []
    try:
        pw = pwd.getpwuid(os.getuid())
        out += [pw.pw_name, pw.pw_dir]
        out += [p for p in re.split(r"[\s,]+", pw.pw_gecos or "") if len(p) >= 3]
    except KeyError:
        pass
    try:
        out += [socket.gethostname()]
    except OSError:
        pass
    return [x for x in dict.fromkeys(out) if x and len(x) >= 3 and x.lower() not in COMMON_NAMES]


def _private_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return not ip.is_global


class OutsideData:
    """The hashed tokens and word runs of everything sent from the user's computer."""

    def __init__(self, path: Path, names: list[str] | None = None):
        self.path = path
        self.names = identity() if names is None else names
        self.tokens: set[str] = set()
        self.runs: set[str] = set()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self.tokens, self.runs = set(data.get("tokens", [])), set(data.get("runs", []))
        except (OSError, ValueError):
            pass

    def add(self, text: str) -> None:
        tokens = {_h(_norm(t)) for t in _TOKEN.findall(text or "") if distinctive(t)}
        runs = {_h(r) for r in _ngrams(text or "")}
        if tokens <= self.tokens and runs <= self.runs:
            return
        self.tokens |= tokens
        self.runs |= runs
        self.save()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"tokens": sorted(self.tokens), "runs": sorted(self.runs)}), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)

    def clear(self) -> None:
        self.tokens, self.runs = set(), set()
        self.save()

    def check(self, query: str) -> list[str]:
        """The parts of `query` that came from the user's computer (empty: it may be searched)."""
        found: list[str] = []
        low = query.lower()
        for name in self.names:
            if re.search(rf"(?<![\w]){re.escape(name.lower())}(?![\w])", low):
                found.append(name)
        found += _EMAIL.findall(query) + _MAC.findall(query)
        found += [ip for ip in _IPV4.findall(query) if _private_ip(ip)]
        for t in _TOKEN.findall(query):
            if distinctive(t) and _h(_norm(t)) in self.tokens:
                found.append(t)
        words = _WORD.findall(low)
        for i in range(len(words) - NGRAM + 1):
            run = " ".join(words[i:i + NGRAM])
            if _h(run) in self.runs:
                found.append(run)
        return list(dict.fromkeys(found))

    def check_host(self, host: str) -> list[str]:
        """The parts of a host name the sandbox connects to that came from the user's computer: its
        labels before the site's own name (data.attacker.example), which is all of a connection
        the app can see; the site's name itself is not checked (github.com is in many outputs)."""
        labels = [x for x in str(host or "").lower().rstrip(".").split(".") if x]
        return self.check(" ".join(labels[:-2])) if len(labels) > 2 else []

    def check_url(self, url: str) -> list[str]:
        """The parts of a web address (beyond its host) that came from the user's computer."""
        try:
            parts = urlsplit(str(url or ""))
        except ValueError:
            return []
        rest = unquote_plus(" ".join((parts.path, parts.query, parts.fragment)))
        return self.check(" ".join(re.split(r"[/?&=#+;]+", rest)))
