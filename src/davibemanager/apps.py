"""The user's apps: one record per app, holding every change made to it.

An app (gThumb, mpv) is what the user knows: one upstream, one install. Its record keeps what is
needed to make it again on any future upstream version, without asking the assistant how:

- where it came from: the upstream repository, and the release it is built on;
- its changes, in the order their commits come: each with its title, its FEATURE notes, its own
  patch against the release (changes/<id>.patch) and the patch ids (git patch-id --stable) of its
  commits. Every commit names its change in a trailer, "DVM-Change: <id>";
- the patch series of all of them together against that release (series.patch), the script
  that builds and packages it (build.sh) and the Ubuntu packages the build needs;
- its builds (deliveries D<n>), which one is installed, how (Gear Lever, Shelly, a menu entry),
  and the one before it, to roll back to;
- what is known of upstream: the newest release, its change log and summary, a version the
  user chose to skip, and whether they want to hear about new ones at all.

All of it lives here, outside the sandbox, so resetting the sandbox loses nothing.

data_dir()/apps/<id>/app.json, series.patch, build.sh, changes/<change id>.md and .patch
"""

from __future__ import annotations

import json
import os
import re
import shutil
import time
from pathlib import Path
from urllib.parse import urlsplit

from .config import data_dir

MAX_CHANGES = 20


def root_dir() -> Path:
    d = data_dir() / "apps"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


def slug(text: str, fallback: str = "app") -> str:
    s = re.sub(r"[^a-z0-9]+", "-", str(text or "").lower()).strip("-")[:40]
    return s or fallback


def upstream_key(url: str) -> str:
    """A repository however it was written (case of the host, .git, a trailing slash): host and path."""
    p = urlsplit(url.strip())
    return f"{(p.hostname or '').lower()}{p.path.rstrip('/').removesuffix('.git').lower()}"


def same_upstream(a: str, b: str) -> bool:
    return bool(a and b) and upstream_key(a) == upstream_key(b)


def check_id(app_id: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,40}", app_id or ""):
        raise ValueError(f"No app {str(app_id)[:40]!r}")
    return app_id


def dir_of(app_id: str) -> Path:
    return root_dir() / check_id(app_id)


def load(app_id: str) -> dict | None:
    try:
        return json.loads((dir_of(app_id) / "app.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def save(app: dict) -> dict:
    d = dir_of(app["id"])
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    app = {**app, "updated": time.time()}
    tmp = d / "app.json.tmp"
    tmp.write_text(json.dumps(app, indent=1, ensure_ascii=False), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(d / "app.json")
    return app


def list_all() -> list[dict]:
    out = []
    for d in sorted(root_dir().iterdir()):
        if d.is_dir() and (a := load(d.name)):
            out.append(a)
    out.sort(key=lambda a: a.get("created", 0))
    return out


def remove(app_id: str) -> None:
    d = dir_of(app_id)
    if d.is_dir() and not d.is_symlink():
        shutil.rmtree(d)


def new_id(name: str) -> str:
    base = slug(name)
    taken = {d.name for d in root_dir().iterdir()}
    if base not in taken:
        return base
    n = 2
    while f"{base}-{n}" in taken:
        n += 1
    return f"{base}-{n}"


def create(name: str, kind: str, upstream: str, **fields) -> dict:
    app = {"id": new_id(name), "name": name, "kind": kind, "upstream": upstream, "created": time.time(),
           "changes": [], "builds": [], "installed": None, "previous": None, "watch": True, "skip": "",
           "update": {}, "packages": [], **fields}
    return save(app)


def find(apps: list[dict], *, upstream: str = "", kind: str = "", name: str = "") -> dict | None:
    """The app a delivery belongs to: the same upstream and kind, or (without an upstream, e.g. a
    script of the assistant's own) the same name and kind."""
    for a in apps:
        if kind and a.get("kind") != kind:
            continue
        if upstream and same_upstream(a.get("upstream", ""), upstream):
            return a
        if not upstream and not a.get("upstream") and name and slug(a.get("name", "")) == slug(name):
            return a
    return None


def write_file(app_id: str, name: str, text: str) -> Path:
    if not re.fullmatch(r"(series\.patch|build\.sh|changes/[a-z0-9-]{1,48}\.(md|patch)|changelog-[\w.+-]{1,80}\.json)", name):
        raise ValueError(f"not an app file: {name}")
    p = dir_of(app_id) / name
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    p.write_text(text, encoding="utf-8")
    return p


def read_file(app_id: str, name: str) -> str:
    try:
        return (dir_of(app_id) / name).read_text(encoding="utf-8")
    except OSError:
        return ""


def feature_text(app: dict) -> str:
    """Every change's notes, in order: the specification of the app as the user has it."""
    parts = []
    for c in app.get("changes", []):
        body = read_file(app["id"], f"changes/{c['id']}.md").strip()
        parts.append(f"# Change {c['id']}: {c['title']}\n\n{body}")
    return "\n\n".join(parts)



# ---------------------------------------------------------------- patch series, commit by commit

TRAILER = "DVM-Change"
_FROM = re.compile(r"^From ([0-9a-f]{7,64}) Mon Sep 17 00:00:00 2001$", re.M)


def split_patch(series: str) -> list[tuple[str, str]]:
    """A git format-patch series as (commit, its patch), in order."""
    starts = list(_FROM.finditer(series))
    return [(m.group(1), series[m.start():starts[i + 1].start() if i + 1 < len(starts) else len(series)])
            for i, m in enumerate(starts)]


def trailer_of(chunk: str) -> str:
    """The change a commit's patch names in its message, or ""."""
    msg = chunk.split("\n---\n", 1)[0]
    m = re.search(rf"^{TRAILER}:[ \t]*(\S+)[ \t]*$", msg, re.M)
    return m.group(1) if m else ""


def with_trailer(chunk: str, change: str) -> str:
    """A commit's patch whose message names `change` (as its only DVM-Change trailer)."""
    head, sep, rest = chunk.partition("\n---\n")
    if not sep:
        return chunk
    head = re.sub(rf"\n{TRAILER}:[^\n]*", "", head).rstrip("\n")
    hdrs, _, body = head.partition("\n\n")
    lines = body.strip("\n").splitlines()
    if not lines:
        body = f"{TRAILER}: {change}"
    elif re.match(r"^[A-Za-z][A-Za-z0-9-]*: ", lines[-1]) and len(lines) > 1:
        body = body.strip("\n") + f"\n{TRAILER}: {change}"     # its last paragraph is trailers already
    else:
        body = body.strip("\n") + f"\n\n{TRAILER}: {change}"
    return f"{hdrs}\n\n{body}{sep}{rest}"


def changed_lines(patch: str) -> int:
    return sum(1 for line in patch.splitlines() if line[:1] in "+-" and not line.startswith(("+++", "---")))
