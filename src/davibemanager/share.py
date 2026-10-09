"""One app, shared with someone else who uses DA Vibe Manager: a .vibe file.

It holds what makes the app, and nothing of the user's own: the official source and the release
it's built on, each change with its notes and patch, the build script and the packages the build
needs. Not the chats, the API key, the builds, or anything about this computer (where it's
installed, its schedule). It's a plain zip, not locked: there's nothing secret in it, and the
person given it can read the patches before importing (README.txt says how, with or without the app).

Importing reads it strictly (known names only, sizes bounded, every field checked), and a reviewer
outside the sandbox reads the changes before anything is built: a whole app is too much to review,
but its changes are small enough to read in full. What is imported is always built by the app
from the official source with the patches, in the sandbox; no build of someone else's is ever run.
It becomes a separate app (the default), or its changes join the user's own copy of that app.

**Versions.** A shared app keeps who it is across computers: a share id, and a revision for each
change and for its build script, made anew when a chat changes them (not when the app carries them
over to a new release by itself), with the revisions before. "It works" records the systems a
version is known to work on. So a file can be told apart from the user's copy of the same app:
newer (theirs has everything of yours, and more: update to it), the same, older (keep yours), or
changed on both sides. When the user gets a shared app working on their system, its card suggests
sharing that version back, since the copies elsewhere don't have the fix.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import secrets
import time
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from . import apps, sysinfo
from .conversation import fence
from .llm import prompts
from .models import UserError
from .netpolicy import InsecureURL, check_url, is_local_host

if TYPE_CHECKING:
    from .engine import Engine

SUFFIX = ".vibe"
FORMAT = 1
MAX_FILE = 25 << 20                 # the whole .vibe file
MAX_MEMBER = 8 << 20                # one file in it, unpacked
MAX_TOTAL = 30 << 20                # all of them, unpacked
REVIEW_CHARS = 180_000              # the most of the changes the reviewer is given
NAMES = re.compile(r"manifest\.json|README\.txt|build\.sh|changes/[a-z0-9-]{1,48}\.(md|patch)")
REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+/-]{0,99}")
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,80}")
CHANGE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,47}")
ZIP_TIME = (2020, 1, 1, 0, 0, 0)    # the same file for the same app, whenever it's exported

README = """\
{name}, as changed with DA Vibe Manager
{line}

This file holds the changes made to {name}, so someone else can have them too:

- the official source: {upstream}
- the release they're made on: {base}
- each change: changes/<id>.md says what it does, changes/<id>.patch is its code
- build.sh: how it's built and packaged

With DA Vibe Manager: My apps → Import an app, and choose this file. It's read first, and a
reviewer reads the changes before anything is built. The app is then built from the official
source with these changes, and kept up to date with the project's releases.

Without it, the patches are ordinary git patches:

    git clone {upstream} && cd {repo}
    git checkout {base}
    git am {patches}
"""


class ShareError(UserError):
    pass


# ---------------------------------------------------------------- versions

REV = re.compile(r"[0-9a-f]{12}")
SHARE_ID = re.compile(r"[0-9a-f]{32}")
SIG = re.compile(r"[0-9a-f]{16}")
HISTORY = 50                         # the revisions before a change's own that are kept


def new_rev(old: dict | None = None) -> dict:
    """A revision of a change or of the build script: its own id, and those it came from."""
    history = [*old.get("history", []), old["id"]][-HISTORY:] if old and old.get("id") else []
    return {"id": secrets.token_hex(6), "history": history}


def lineage(a: dict) -> dict:
    """The app with its share id and every revision it needs (made for an app from before)."""
    sh = dict(a.get("share") or {})
    sh.setdefault("id", secrets.token_hex(16))
    sh.setdefault("build", new_rev())
    sh.setdefault("works_on", [])
    sh.setdefault("shared", [])
    return {**a, "share": sh, "changes": [c if c.get("rev") else {**c, "rev": new_rev()} for c in a.get("changes", [])]}


def signature(a: dict) -> str:
    """One version of the app, as its revisions say: the same wherever it is."""
    a = lineage(a) if not a.get("share") else a
    parts = sorted(c["rev"]["id"] for c in a.get("changes", []) if c.get("rev")) + [a["share"]["build"]["id"]]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def revise(app: dict, before: dict, texts: dict[str, str], build_was: str, build_now: str, *, fitted: bool,
           notes_changed: set = frozenset()) -> dict:
    """The app after a delivery, with new revisions where a chat changed it: a new change, a change
    whose code or notes changed, the build script. `fitted`: carried over to another release (an
    update), which is the same version of the user's changes, made to fit; nothing gets a new
    revision then."""
    app = lineage(app)
    old = {c["id"]: c for c in before.get("changes", [])}
    changes = []
    for c in app["changes"]:
        was = old.get(c["id"])
        if was is None:
            changes.append({**c, "rev": new_rev()})
        elif fitted or not was.get("rev"):
            changes.append({**c, "rev": was.get("rev") or c["rev"]})
        else:
            same = (set(c.get("patch_ids") or []) == set(was.get("patch_ids") or [])) if c.get("patch_ids") and was.get("patch_ids") \
                else texts.get(c["id"]) == apps.read_file(app["id"], f"changes/{c['id']}.patch")
            changes.append({**c, "rev": was["rev"] if same and c["id"] not in notes_changed else new_rev(was["rev"])})
    sh = dict(app["share"])
    if not fitted and build_was.strip() and build_now.strip() and build_was != build_now:
        sh["build"] = new_rev(sh["build"])
    return {**app, "changes": changes, "share": sh}


def this_system() -> str:
    rel = sysinfo._os_release()
    return (rel.get("PRETTY_NAME") or " ".join(x for x in (rel.get("NAME"), rel.get("VERSION_ID")) if x) or "Linux")[:80]


def works_on(a: dict, sig: str | None = None) -> list[str]:
    """The systems this version (or `sig`) is known to work on."""
    sig = sig or signature(a)
    return list(dict.fromkeys(w["system"] for w in (a.get("share") or {}).get("works_on", []) if w.get("sig") == sig))


def record_works(a: dict, sig: str, system: str) -> dict:
    a = lineage(a)
    known = [w for w in a["share"]["works_on"] if not (w["sig"] == sig and w["system"] == system)]
    return {**a, "share": {**a["share"], "works_on": [*known, {"system": system, "sig": sig, "at": time.time()}][-50:]}}


def reshare(a: dict) -> dict | None:
    """Whether to suggest sharing this version: it was shared (given or received) before, this
    version differs from every one shared, and it works here. None when not."""
    sh = a.get("share") or {}
    if not sh.get("shared") or a.get("kind") != "appimage":
        return None
    sig = signature(a)
    here = this_system()
    if sig in sh["shared"] or sh.get("not_now") == sig or here not in works_on(a, sig):
        return None
    return {"system": here, "works_on": works_on(a, sig), "received": bool(a.get("imported"))}


def _how(mine: dict | None, theirs: dict | None) -> str:
    if mine is None:
        return "new"
    if theirs is None:
        return "mine_only"
    if mine["id"] == theirs["id"]:
        return "same"
    if mine["id"] in theirs.get("history", []):
        return "theirs_newer"
    if theirs["id"] in mine.get("history", []):
        return "mine_newer"
    return "both"


def relation(mine: dict, theirs: dict) -> dict:
    """How a shared file's version stands to the user's copy of the same app: "newer", "same",
    "older" or "both" (changed on both sides), with each change's and the build script's."""
    mine = lineage(mine)
    have = {c["id"]: c for c in mine["changes"]}
    items = [{"id": c["id"], "title": c["title"], "how": _how((have.get(c["id"]) or {}).get("rev"), c.get("rev"))}
             for c in theirs["changes"]]
    items += [{"id": c["id"], "title": c["title"], "how": "mine_only"} for c in mine["changes"]
              if c["id"] not in {x["id"] for x in theirs["changes"]}]
    build = _how(mine["share"]["build"], (theirs.get("share") or {}).get("build"))
    hows = {i["how"] for i in items} | {build}
    if hows <= {"same", "mine_only"} and "mine_only" not in hows:
        verdict = "same"
    elif hows & {"both"} or (hows & {"theirs_newer", "new"} and hows & {"mine_newer", "mine_only"}):
        verdict = "both"
    elif hows & {"theirs_newer", "new"}:
        verdict = "newer"
    else:
        verdict = "older"
    return {"verdict": verdict, "changes": items, "build": build}


def exportable(a: dict) -> str:
    """Why this app can't be shared ("" if it can)."""
    if a.get("kind") != "appimage":
        return "Only apps the app builds itself can be shared (not add-ons or source code)."
    if not a.get("upstream") or not a.get("base_ref"):
        return "It has no official source recorded."
    if not a.get("changes"):
        return "It has no changes to share."
    if not apps.read_file(a["id"], "build.sh").strip():
        return "It has no saved build script yet: it's made when it's next built."
    return ""


def pack(a: dict) -> bytes:
    """The .vibe file of an app: its changes in order, as the app keeps them."""
    why = exportable(a)
    if why:
        raise ShareError(why)
    a = lineage(a)
    changes = [{"id": c["id"], "title": c["title"], "rev": c["rev"]} for c in a["changes"]]
    manifest = {"format": FORMAT, "kind": "dvm-app", "exported": int(time.time()),
                "app": {"name": a["name"], "upstream": a["upstream"], "base_ref": a["base_ref"],
                        "packages": a.get("packages") or [], "changes": changes,
                        "share": {"id": a["share"]["id"], "build": a["share"]["build"], "sig": signature(a),
                                  "works_on": a["share"]["works_on"]}}}
    files = {"build.sh": apps.read_file(a["id"], "build.sh")}
    for c in changes:
        files[f"changes/{c['id']}.patch"] = apps.read_file(a["id"], f"changes/{c['id']}.patch")
        notes = apps.read_file(a["id"], f"changes/{c['id']}.md")
        if notes.strip():
            files[f"changes/{c['id']}.md"] = notes
    repo = apps.slug(a["upstream"].rstrip("/").rsplit("/", 1)[-1].removesuffix(".git"), "source")
    title = f"{a['name']}, as changed with DA Vibe Manager"
    files["README.txt"] = README.format(name=a["name"], line="=" * len(title), upstream=a["upstream"], base=a["base_ref"],
                                        repo=repo, patches=" ".join(f"../changes/{c['id']}.patch" for c in changes))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in [("manifest.json", json.dumps(manifest, indent=1, ensure_ascii=False))] + sorted(files.items()):
            info = zipfile.ZipInfo(name, ZIP_TIME)
            info.compress_type, info.external_attr = zipfile.ZIP_DEFLATED, 0o644 << 16
            z.writestr(info, text)
    return out.getvalue()


def _text(z: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    with z.open(info) as f:
        data = f.read(MAX_MEMBER + 1)
    if len(data) > MAX_MEMBER:
        raise ShareError(f"{info.filename} in it is too big.")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ShareError(f"{info.filename} in it isn't text.") from None


def read(path: Path) -> dict:
    """A .vibe file, read strictly: {"app": {name, upstream, base_ref, packages, changes}, "files": {name: text},
    "exported"}. Raises ShareError saying what's wrong with it."""
    if path.stat().st_size > MAX_FILE:
        raise ShareError("That file is too big to be a shared app.")
    try:
        z = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        raise ShareError("That isn't a shared app (a .vibe file).") from None
    with z:
        infos = {i.filename: i for i in z.infolist() if not i.is_dir()}
        if "manifest.json" not in infos:
            raise ShareError("That isn't a shared app (it has no manifest.json).")
        if sum(i.file_size for i in infos.values()) > MAX_TOTAL or len(infos) > 3 + 2 * apps.MAX_CHANGES:
            raise ShareError("That file holds too much to be a shared app.")
        files = {name: _text(z, i) for name, i in infos.items() if NAMES.fullmatch(name)}
    try:
        m = json.loads(files.pop("manifest.json"))
    except ValueError:
        raise ShareError("Its manifest.json isn't readable.") from None
    if not isinstance(m, dict) or m.get("kind") != "dvm-app":
        raise ShareError("That isn't a shared app.")
    if m.get("format") != FORMAT:
        raise ShareError("It was made by a newer DA Vibe Manager: update this one to import it.")
    return {"app": _checked(m.get("app"), files), "files": files, "exported": m.get("exported") or 0}


def _checked(a, files: dict) -> dict:
    if not isinstance(a, dict):
        raise ShareError("Its manifest doesn't describe an app.")
    name = re.sub(r"[\x00-\x1f\x7f]", "", str(a.get("name") or "")).strip()[:80]
    if not name:
        raise ShareError("The app in it has no name.")
    upstream = str(a.get("upstream") or "").strip()
    try:
        check_url(upstream, "Its official source")
        if not upstream.startswith("https://"):
            raise InsecureURL("it isn't https://")
        if is_local_host(urlsplit(upstream).hostname):
            raise InsecureURL("it's on a local network, not a public project")
    except InsecureURL as e:
        raise ShareError(f"Its source isn't a public https:// repository ({upstream[:100]}): {e}") from None
    base = str(a.get("base_ref") or "")
    if not REF.fullmatch(base) or ".." in base:
        raise ShareError("The release it's built on isn't a release's name.")
    packages = a.get("packages") or []
    if not isinstance(packages, list) or len(packages) > 200 or not all(isinstance(p, str) and PACKAGE.fullmatch(p) for p in packages):
        raise ShareError("Its list of build packages isn't one.")
    changes = a.get("changes")
    if not isinstance(changes, list) or not 1 <= len(changes) <= apps.MAX_CHANGES:
        raise ShareError("It has no changes, or too many.")
    out, seen = [], set()
    for c in changes:
        cid = str((c or {}).get("id") or "") if isinstance(c, dict) else ""
        if not CHANGE_ID.fullmatch(cid) or cid in seen:
            raise ShareError("One of its changes has no proper name.")
        seen.add(cid)
        patch = files.get(f"changes/{cid}.patch", "")
        commits = apps.split_patch(patch)
        if not commits:
            raise ShareError(f"Its change {cid} has no patch.")
        # every commit names its change, as the app's own do (DVM-Change), whatever the file said
        files[f"changes/{cid}.patch"] = "".join(apps.with_trailer(chunk, cid) for _, chunk in commits)
        title = re.sub(r"[\x00-\x1f\x7f]", "", str(c.get("title") or cid)).strip()[:200] or cid
        out.append({"id": cid, "title": title, "rev": _rev_of(c.get("rev"))})
    for extra in [n for n in files if n.startswith("changes/") and n.split("/")[1].rsplit(".", 1)[0] not in seen]:
        files.pop(extra)                    # notes or patches of no change it lists
    if not files.get("build.sh", "").strip():
        raise ShareError("It has no build script.")
    sh = a.get("share") if isinstance(a.get("share"), dict) else {}
    share_id = str(sh.get("id") or "")
    works = [{"system": re.sub(r"[\x00-\x1f\x7f]", "", str(w.get("system") or ""))[:80], "sig": str(w.get("sig") or ""),
              "at": w.get("at") if isinstance(w.get("at"), (int, float)) else 0}
             for w in (sh.get("works_on") if isinstance(sh.get("works_on"), list) else [])[:50] if isinstance(w, dict)]
    share = {"id": share_id if SHARE_ID.fullmatch(share_id) else secrets.token_hex(16), "build": _rev_of(sh.get("build")),
             "works_on": [w for w in works if w["system"] and SIG.fullmatch(w["sig"])], "shared": []}
    got = {"name": name, "upstream": upstream, "base_ref": base, "packages": packages, "changes": out, "share": share}
    share["sig"] = signature(got)
    return got


def _rev_of(r) -> dict:
    """A revision from a file, checked; a new one when it has none (a file from before them)."""
    if not isinstance(r, dict) or not REV.fullmatch(str(r.get("id") or "")):
        return new_rev()
    history = [h for h in (r.get("history") if isinstance(r.get("history"), list) else []) if isinstance(h, str) and REV.fullmatch(h)]
    return {"id": r["id"], "history": history[-HISTORY:]}


_BASE85 = re.compile(r"[0-9A-Za-z!#$%&()*+;<=>?@^_`{|}~-]+")


def for_review(patch: str) -> tuple[str, list[dict]]:
    """A patch as a reviewer can read it: each binary file (git's "GIT binary patch", its bytes
    encoded as lines of text) as one line saying what it is, since to a reader they're only noise,
    and a lot of it. Returns (text, [{"file", "bytes"}] of the binary files)."""
    out: list = []
    binaries: list[dict] = []
    file, inside = "", False
    for line in patch.split("\n"):
        if inside:
            m = re.fullmatch(r"(?:literal|delta) (\d+)", line)
            if m:
                if binaries[-1]["bytes"] is None:
                    binaries[-1]["bytes"] = int(m.group(1))
                continue
            if line == "" or _BASE85.fullmatch(line):
                continue
            inside = False
        if line.startswith("diff --git "):
            file = line.rsplit(" b/", 1)[-1]
        if line == "GIT binary patch":
            inside = True
            binaries.append({"file": file, "bytes": None})
            out.append(binaries[-1])
            continue
        out.append(line)
    text = "\n".join(f"[binary file {x['file']}, {x['bytes'] if x['bytes'] is not None else '?'} bytes: not shown, "
                     "its contents can't be read as text]" if isinstance(x, dict) else x for x in out)
    return text, binaries


_CAUTION = {"stop": 3, "care": 2, "": 1, "ok": 0}       # an unclear verdict is never the safest


def combined(outs: list[tuple[str, dict]]) -> dict:
    """The reviews of each change, as one: the most cautious verdict, and what each said."""
    parsed = [(title, out, parse_review(out["text"])) for title, out in outs]
    if len(parsed) == 1:
        return {"text": parsed[0][1]["text"], **parsed[0][2]}
    worst = max(parsed, key=lambda x: _CAUTION[x[2]["level"]])[2]
    return {"text": "\n\n".join(f"### {title}\n{out['text']}" for title, out, _ in parsed),
            "summary": " ".join(f"{title}: {r['summary']}" for title, _, r in parsed if r["summary"]),
            "concerns": "; ".join(f"{title}: {r['concerns']}" for title, _, r in parsed if r["concerns"]),
            "verdict": worst["verdict"], "level": worst["level"]}


def parse_review(text: str) -> dict:
    def line(key: str) -> str:
        # the last: the reviewer may quote what it read, and that can hold a "VERDICT:" line of its own
        found = re.findall(rf"^\W*{key}\W*:\s*(.+)$", text, re.I | re.M)
        return found[-1].strip().strip("*_ ").strip() if found else ""
    verdict = line("VERDICT")
    v = verdict.lower()
    level = "stop" if re.search(r"\b(do not|don't|never)\b", v) else "care" if "care" in v or "careful" in v \
        else "ok" if "safe" in v or "fine" in v else ""
    concerns = line("CONCERNS")
    if re.match(r"(?i)^(none|no|n/?a|nothing)\b", concerns):
        concerns = ""
    return {"summary": line("SUMMARY"), "concerns": concerns, "verdict": verdict, "level": level}


class Sharing:
    """Exports and imports, for the window."""

    def __init__(self, engine: "Engine"):
        self.e = engine
        self.pending: dict[str, dict] = {}     # an uploaded file's token -> what's in it, and its review

    # ---------------------------------------------------------------- export

    @staticmethod
    def folder() -> Path:
        """Where exports go: the user's Downloads folder (as their desktop names it), or home."""
        try:
            for line in (Path.home() / ".config/user-dirs.dirs").read_text().splitlines():
                if line.startswith("XDG_DOWNLOAD_DIR="):
                    p = Path(line.split("=", 1)[1].strip().strip('"').replace("$HOME", str(Path.home())))
                    if p.is_dir():
                        return p
        except OSError:
            pass
        d = Path.home() / "Downloads"
        return d if d.is_dir() else Path.home()

    def preview(self, app_id: str) -> dict:
        """What a .vibe file of this app would hold, for the user to read (and correct) first: each change's
        title and notes, and anything in them, or in the build script, that came from this computer (the
        check web searches have: names, paths, lines of command output)."""
        a = self.e.app_manager.app(app_id)
        why = exportable(a)
        if why:
            raise ShareError(why)
        outside = self.e._outside()
        changes = []
        for c in a["changes"]:
            notes = apps.read_file(a["id"], f"changes/{c['id']}.md").strip()
            changes.append({"id": c["id"], "title": c["title"], "notes": notes,
                            "flags": outside.check(f"{c['title']}\n{notes}")[:8]})
        return {"name": a["name"], "upstream": a["upstream"], "base_ref": a["base_ref"], "changes": changes,
                "build_flags": outside.check(apps.read_file(a["id"], "build.sh"))[:8], "folder": str(self.folder())}

    def export(self, app_id: str) -> dict:
        a = apps.save(lineage(self.e.app_manager.app(app_id)))      # its share id and revisions, kept from now on
        data = pack(a)
        folder = self.folder()
        stem = "".join(ch if ch.isalnum() or ch in "._+-" else "-" for ch in a["name"]).strip("-.") or a["id"]
        path, n = folder / f"{stem}{SUFFIX}", 2
        while path.exists():
            path, n = folder / f"{stem}-{n}{SUFFIX}", n + 1
        path.write_bytes(data)
        sig = signature(a)
        a = self.e.app_manager.app(app_id)
        apps.save({**a, "share": {**a["share"], "shared": [*[x for x in a["share"]["shared"] if x != sig], sig][-50:]}})
        self.e.log("app_exported", app=app_id, path=str(path), changes=len(a["changes"]), version=sig)
        return {"path": str(path), "folder": str(folder), "name": path.name, "size": len(data)}

    # ---------------------------------------------------------------- import

    def peek(self, path: Path) -> dict:
        """What's in an uploaded file, and where it could go; its review starts now."""
        got = read(path)
        token = secrets.token_hex(16)
        self.pending[token] = {**got, "review": {"status": "checking"}, "at": time.time()}
        for old in [t for t, p in self.pending.items() if time.time() - p["at"] > 86400]:
            self.pending.pop(old, None)
        self.e._spawn(self._review(token))
        return self.view(token)

    def view(self, token: str) -> dict:
        p = self._pending(token)
        a = p["app"]
        mine = [x for x in apps.list_all() if x.get("kind") == "appimage"]
        copies = [{"id": x["id"], "name": x["name"], **relation(x, a)} for x in mine
                  if (x.get("share") or {}).get("id") == a["share"]["id"]]
        same = [{"id": x["id"], "name": x["name"], "changes": [c["title"] for c in x.get("changes", [])]} for x in mine
                if apps.same_upstream(x.get("upstream", ""), a["upstream"]) and x["id"] not in {c["id"] for c in copies}]
        names = {apps.slug(x["name"]) for x in apps.list_all()}
        name = a["name"] if apps.slug(a["name"]) not in names else f"{a['name']} (shared)"
        changes = [{**c, "notes": p["files"].get(f"changes/{c['id']}.md", ""), "patch": for_review(p["files"][f"changes/{c['id']}.patch"])[0],
                    "lines": apps.changed_lines(p["files"][f"changes/{c['id']}.patch"])} for c in a["changes"]]
        return {"token": token, "app": {**a, "changes": changes}, "build_script": p["files"]["build.sh"],
                "exported": p["exported"], "review": p["review"], "yours": same, "copies": copies, "name": name,
                "works_on": works_on(a, a["share"]["sig"]), "this_system": this_system()}

    def _pending(self, token: str) -> dict:
        p = self.pending.get(token) if re.fullmatch(r"[0-9a-f]{32}", token or "") else None
        if p is None:
            raise ShareError("That file isn't open any more: choose it again.")
        return p

    async def _review(self, token: str) -> None:
        """A reviewer outside the sandbox reads the changes and build script: all of them at once, or,
        when they're too long for that, each change on its own (the most cautious verdict counts).
        Binary files go to it as a line each, not as git's encoding of their bytes."""
        p = self.pending.get(token)
        if p is None:
            return
        a, files = p["app"], p["files"]
        head = [f"App: {a['name']}. Official source, as the file says: {a['upstream']}, release {a['base_ref']}.",
                "The build script (runs in a sealed container to build it):\n" + fence(files["build.sh"][:20000])]
        if a["packages"]:
            head.append("Ubuntu packages the build installs: " + ", ".join(a["packages"]))
        sections, binaries = [], []
        for c in a["changes"]:
            patch, bins = for_review(files[f"changes/{c['id']}.patch"])
            binaries += [{"change": c["title"], **b} for b in bins]
            notes = files.get(f"changes/{c['id']}.md", "").strip()
            sections.append(f"Change {c['id']}: {c['title']}\n" + (f"What its notes say it does:\n{fence(notes[:8000])}\n" if notes
                            else "(it has no notes)\n") + "Its patch:\n" + fence(patch))
        whole = "\n\n".join([*head, *sections])
        if len(whole) <= REVIEW_CHARS:
            asks = [("", whole)]
        else:
            # too long for one reading: each change on its own, with the app and its build script
            titles = [c["title"] for c in a["changes"]]
            asks = []
            for c, section in zip(a["changes"], sections):
                others = "; ".join(t for t in titles if t != c["title"])
                note = (f"(The changes were too long to read together, so each is reviewed on its own. This is one of "
                        f"{len(titles)}; the others: {others}.)")
                asks.append((c["title"], "\n\n".join([*head, note, section])))
        outs, cut = [], False
        try:
            for title, context in asks:
                if len(context) > REVIEW_CHARS:
                    context, cut = context[:REVIEW_CHARS] + "\n[… the rest was too long to include]", True
                outs.append((title, await self.e._review(prompts.SHARED_CHANGES_PROMPT, context, "shared_app_review",
                                                         app=a["name"], change=title)))
        except Exception as e:  # noqa: BLE001 - shown on the card; the user decides
            p["review"] = {"status": "error", "error": str(e)}
            return
        p["review"] = {"status": "done", "model": outs[0][1]["model"], "partial": cut, "parts": len(outs),
                       "binaries": binaries, **combined(outs), "at": time.time()}
        self.e.log("shared_app_reviewed", app=a["name"], level=p["review"]["level"], partial=cut, parts=len(outs),
                   binaries=len(binaries))

    def accept(self, token: str, *, into: str = "", name: str = "", update: str = "") -> dict:
        """Import it: as an app of its own (the default), its changes into the user's copy `into`, or as
        the newer version of `update`, the user's copy of this same shared app."""
        p = self._pending(token)
        if p["review"].get("status") == "checking":
            raise ShareError("Wait for the review of its changes first: it's being read now.")
        a, files = p["app"], p["files"]
        review = {k: v for k, v in p["review"].items() if k != "text"}
        imported = {"at": time.time(), "exported": p["exported"], "changes": [c["id"] for c in a["changes"]],
                    "review": review, "built": False}
        if update:
            out = self._update(self.e.app_manager.app(update), a, files, imported)
        elif into:
            out = self._merge(self.e.app_manager.app(into), a, files, imported)
        else:
            out = self._separate(a, files, imported, name)
        self.pending.pop(token, None)
        self.e.app_manager.changed()
        return out

    def _separate(self, a: dict, files: dict, imported: dict, name: str) -> dict:
        name = re.sub(r"[\x00-\x1f\x7f]", "", name or a["name"]).strip()[:80]
        if not name:
            raise ShareError("Give it a name.")
        if any(apps.slug(x["name"]) == apps.slug(name) for x in apps.list_all()):
            raise ShareError(f"You have an app called {name} already: give this one another name, so both can be installed.")
        new = apps.create(name, "appimage", a["upstream"], base_ref=a["base_ref"], packages=a["packages"],
                          changes=[{**c, "patch_ids": [], "added": time.time()} for c in a["changes"]],
                          split=True, imported=imported,
                          share={**{k: v for k, v in a["share"].items() if k != "sig"}, "shared": [a["share"]["sig"]]})
        self._write(new["id"], files, a["changes"])
        self.e.log("app_imported", app=new["id"], changes=len(a["changes"]), into="")
        return {"app": new["id"], "name": name}

    def _merge(self, mine: dict, a: dict, files: dict, imported: dict) -> dict:
        if mine.get("kind") != "appimage" or not apps.same_upstream(mine.get("upstream", ""), a["upstream"]):
            raise ShareError(f"Your {mine['name']} comes from somewhere else: these changes can't join it.")
        if mine["id"] in self.e.app_manager.building:
            raise ShareError(f"Your {mine['name']} is being built: wait for it to finish.")
        if len(mine.get("changes", [])) + len(a["changes"]) > apps.MAX_CHANGES:
            raise ShareError(f"Your {mine['name']} would have too many changes.")
        mine = _split_already(mine)
        taken = {c["id"] for c in mine.get("changes", [])}
        added = []
        for c in a["changes"]:
            cid, n = c["id"], 2
            while cid in taken:
                cid, n = f"{c['id'][:44]}-{n}", n + 1
            taken.add(cid)
            patch = "".join(apps.with_trailer(chunk, cid) for _, chunk in apps.split_patch(files[f"changes/{c['id']}.patch"]))
            apps.write_file(mine["id"], f"changes/{cid}.patch", patch)
            if files.get(f"changes/{c['id']}.md"):
                apps.write_file(mine["id"], f"changes/{cid}.md", files[f"changes/{c['id']}.md"])
            added.append({"id": cid, "title": c["title"], "patch_ids": [], "added": time.time(),
                          "rev": c["rev"] if cid == c["id"] else new_rev()})
        changes = mine.get("changes", []) + added
        apps.write_file(mine["id"], "series.patch", "".join(apps.read_file(mine["id"], f"changes/{c['id']}.patch") for c in changes))
        packages = sorted(set(mine.get("packages") or []) | set(a["packages"]))
        apps.save({**mine, "changes": changes, "packages": packages,
                   "imported": {**imported, "changes": [c["id"] for c in added], "into": True, "base_ref": a["base_ref"]}})
        self.e.log("app_imported", app=mine["id"], changes=len(added), into=mine["id"])
        return {"app": mine["id"], "name": mine["name"]}

    def _update(self, mine: dict, a: dict, files: dict, imported: dict) -> dict:
        """The user's copy of this shared app, made the file's version: what they changed takes theirs
        (or comes new), what only the user has stays, and so does the release it's built on."""
        if (mine.get("share") or {}).get("id") != a["share"]["id"]:
            raise ShareError(f"This isn't a version of your {mine['name']}.")
        if mine["id"] in self.e.app_manager.building:
            raise ShareError(f"Your {mine['name']} is being built: wait for it to finish.")
        _split_already(mine)
        rel = relation(mine, a)
        if rel["verdict"] == "same":
            raise ShareError(f"Your {mine['name']} is this version already.")
        if rel["verdict"] == "older":
            raise ShareError(f"Your {mine['name']} is newer than this file: keep yours (share it, if they need it).")
        mine = lineage(mine)
        have = {c["id"]: c for c in mine["changes"]}
        take = {i["id"] for i in rel["changes"] if i["how"] in ("new", "theirs_newer", "both")}
        changes = []
        for c in a["changes"]:
            if c["id"] in take:
                apps.write_file(mine["id"], f"changes/{c['id']}.patch", files[f"changes/{c['id']}.patch"])
                if files.get(f"changes/{c['id']}.md"):
                    apps.write_file(mine["id"], f"changes/{c['id']}.md", files[f"changes/{c['id']}.md"])
                changes.append({**have.get(c["id"], {"added": time.time()}), "id": c["id"], "title": c["title"],
                                "rev": c["rev"], "patch_ids": []})
            else:
                changes.append(have[c["id"]])
        changes += [c for c in mine["changes"] if c["id"] not in {x["id"] for x in a["changes"]}]
        apps.write_file(mine["id"], "series.patch", "".join(apps.read_file(mine["id"], f"changes/{c['id']}.patch") for c in changes))
        sh = dict(mine["share"])
        if rel["build"] in ("theirs_newer", "both"):
            apps.write_file(mine["id"], "build.sh", files["build.sh"])
            sh["build"] = a["share"]["build"]
        known = {(w["system"], w["sig"]) for w in sh["works_on"]}
        sh["works_on"] = [*sh["works_on"], *(w for w in a["share"]["works_on"] if (w["system"], w["sig"]) not in known)][-50:]
        sh["shared"] = [*sh["shared"], a["share"]["sig"]][-50:]
        packages = sorted(set(mine.get("packages") or []) | set(a["packages"]))
        apps.save({**mine, "changes": changes, "packages": packages, "share": sh,
                   "imported": {**imported, "changes": sorted(take), "into": True, "update": rel["verdict"],
                                "base_ref": a["base_ref"]}})
        self.e.log("app_updated_from_share", app=mine["id"], took=sorted(take), build=rel["build"], verdict=rel["verdict"])
        return {"app": mine["id"], "name": mine["name"]}

    @staticmethod
    def _write(app_id: str, files: dict, changes: list[dict]) -> None:
        apps.write_file(app_id, "build.sh", files["build.sh"])
        for c in changes:
            apps.write_file(app_id, f"changes/{c['id']}.patch", files[f"changes/{c['id']}.patch"])
            if files.get(f"changes/{c['id']}.md"):
                apps.write_file(app_id, f"changes/{c['id']}.md", files[f"changes/{c['id']}.md"])
        apps.write_file(app_id, "series.patch", "".join(files[f"changes/{c['id']}.patch"] for c in changes))


def _split_already(a: dict) -> dict:
    """The user's app, before changes join it: it must keep each change's own patch already
    (AppManager.ensure_split makes them from an old record, but needs the sandbox)."""
    if a.get("changes") and not a.get("split"):
        raise ShareError(f"Your {a['name']} is from before changes were kept one by one: build it once (or improve it "
                         "in a chat), then add these.")
    return a
