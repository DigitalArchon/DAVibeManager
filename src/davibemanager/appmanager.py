"""Looking after the user's apps once they have them.

- Every delivery belongs to an app (apps.py). A new change to an app the user already has is
  built on top of its earlier ones (checked by patch id), so the user has one gThumb with all
  their changes, not one per request.
- New upstream releases are looked for about once a day, from the sandbox. When one is out, its
  change log is read there (the release's NEWS/CHANGELOG lines, commit subjects, the forge's
  release notes), checked in code for security fixes, and, if the user wants it in Settings,
  summarised by the reviewer (outside the sandbox: a change log is public).
- The user can skip that version, stop watching the app, read the change log or its summary,
  or rebuild (straight away, if they chose that in Settings).
- An app is always the official release with the user's changes, each its own run of commits
  naming it (a DVM-Change trailer), nothing merged in: checked in code at every delivery
  (check_branch), against the official repository itself. The app keeps its own copy of that
  repository, which the assistant can read but not change (mirror), and prepares the assistant's
  source from it (carry): never from anything else in the sandbox.
- A rebuild is first done by the app alone, in the sandbox: each change carried over to the new
  release on its own (a merge, scripts.CARRY), then the app's own build script, in a clean
  container. Only if a step fails is the assistant asked, with what carried over already done and
  exactly what didn't.
- Installing hands a checked AppImage to Gear Lever, Shelly, or a menu entry of our own
  (integrate.py), on the user's click only. The build before it is kept to roll back to.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import time
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

from . import appimage, apps, integrate, share, versions
from . import delivery as delivery_mod
from .config import REBUILD, data_dir
from .conversation import Conversation, fence
from .llm import prompts
from .models import UserError
from .netpolicy import InsecureURL, check_url
from .workspace import podman
from .workspace import scripts

if TYPE_CHECKING:
    from .engine import Engine

MIRRORS = "/var/lib/dvm/mirrors"         # the official sources, root's (scripts.MIRROR)
APPS_FOLDER = "/work/.dvm/apps"          # each app's series, build script and notes, for the sandbox
BOX_CHANGES = "/work/.dvm/changes"       # in the app's clean container: the changes it carries over, as it keeps them
SNAPSHOT_REPO = "/work/.dvm/snapshot.git"   # there, its own copy of what it checks and builds (Engine.box_snapshot)
BOX_SCRIPT = "/work/.dvm/build.sh"       # and the build script it builds with
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
BUILD_FOLDER = "/work/.dvm/build"        # where the app's own builds happen
# how long after the last look an app's official source is asked again, for each choice (a little
# under a day, a week, a month: the look happens when the app runs, not to the minute)
CHECK_EVERY = {"day": 20 * 3600, "week": 6.5 * 86400, "month": 29 * 86400}
BUILD_WINDOW = 2 * 3600                  # a scheduled build starts within this long after the quiet time
TICK = 300
BUILD_TIMEOUT = 3 * 3600
SECURITY_WORDS = re.compile(
    r"CVE-\d{4}-\d{3,}|\bsecurity\b|vulnerab|exploit|overflow|use[- ]after[- ]free|out[- ]of[- ]bounds|"
    r"denial[- ]of[- ]service|\bDoS\b|remote code|code execution|privilege|injection|malicious|crafted|"
    r"sanitiz|heap corruption|memory corruption|\bXSS\b|\bCSRF\b|path traversal", re.I)


class PortFailed(Exception):
    """The app's own work on an app failed (also its clean builds, Engine.box_build): at which step,
    its log, and (carrying changes over) what became of each change."""

    def __init__(self, step: str, log: str, changes: dict[str, str] | None = None):
        super().__init__(f"{step}: {log[-300:]}")
        self.step, self.log, self.changes = step, log, changes or {}


def security_lines(*texts: str, limit: int = 20) -> list[str]:
    """Lines of a change log that speak of security fixes (found in code, whatever a summary says)."""
    out: list[str] = []
    for text in texts:
        for line in (text or "").splitlines():
            line = line.strip(" -*\t")
            if line and SECURITY_WORDS.search(line) and line not in out:
                out.append(line[:300])
                if len(out) >= limit:
                    return out
    return out


def release_page(upstream: str, tag: str) -> str:
    base = upstream.strip().removesuffix(".git").rstrip("/")
    if not base.startswith("https://"):
        return ""
    host = base.split("/")[2].lower()
    if host in ("github.com", "codeberg.org"):
        return f"{base}/releases/tag/{tag}"
    if "gitlab" in host:
        return f"{base}/-/releases/{tag}"
    return f"{base}/-/tags/{tag}" if "gnome" in host else base


def parse_summary(text: str) -> dict:
    def line(key: str) -> str:
        m = re.search(rf"^\W*{key}\W*:\s*(.+)$", text, re.I | re.M)
        return m.group(1).strip().strip("*_ ").strip() if m else ""
    security = line("SECURITY")
    if re.match(r"(?i)^(none|no|n/?a|nothing)\b", security):
        security = ""
    importance = line("IMPORTANCE").lower()
    importance = next((k for k in ("security", "recommended", "optional") if k in importance), "")
    body = re.split(r"^\W*SUMMARY\W*:", text, maxsplit=1, flags=re.I | re.M)[0].strip()
    return {"text": body, "summary": line("SUMMARY"), "security": security, "importance": importance}


class AppManager:
    def __init__(self, engine: "Engine"):
        self.e = engine
        self._battery = False                     # on battery at the last tick
        self._build_lock = asyncio.Lock()
        self.building: dict[str, dict] = {}       # app id -> the rebuild in progress (step, started)

    # ---------------------------------------------------------------- views

    def apps(self) -> list[dict]:
        builds = {m["id"]: m for m in self.e.deliveries()}
        out = []
        for a in apps.list_all():
            installed = (a.get("installed") or {}).get("build")
            latest = a["builds"][-1] if a.get("builds") else ""
            out.append({**a, "latest": builds.get(latest), "installed_build": builds.get(installed),
                        "previous_build": builds.get((a.get("previous") or {}).get("build", "")),
                        "building": self.building.get(a["id"]),
                        "unshareable": share.exportable(a),
                        "export_build": self.export_build(a, builds),
                        "entry_missing": self.entry_missing(a),
                        "reshare": share.reshare(a),
                        "works_on": share.works_on(a) if a.get("share") else [],
                        "works_here": share.this_system() in (share.works_on(a) if a.get("share") else []),
                        "version": share.signature(a) if a.get("share") else "",
                        # the chat the assistant was asked to build it in, while it's there
                        "chat": a["chat"] if (a.get("chat") or {}).get("id") and Conversation.exists(a["chat"]["id"]) else None,
                        "schedule": {"check_every": self.check_every(a), "build_when": self.build_when(a),
                                     "own": {"check_every": a.get("check_every", ""), "build_when": a.get("build_when", "")},
                                     "waiting": self.waiting(a)}})
        return out

    def entry_missing(self, a: dict) -> bool:
        """Whether the menu entry we made for the installed app is gone (Omarchy's launcher has a
        Remove of its own, which deletes only the entry): the card offers it back."""
        inst = a.get("installed") or {}
        if inst.get("via") not in ("menu", "omarchy") or not inst.get("build"):
            return False
        s = self.e.cfg.settings
        return not integrate.by_key(inst["via"], Path(s.install_dir), data_dir() / "icons").present(inst)

    def changed(self) -> None:
        self.e.emit("apps", apps=self.apps())
        self.e.emit("deliveries", deliveries=self.e.deliveries())

    def app(self, app_id: str) -> dict:
        try:
            a = apps.load(apps.check_id(app_id))
        except ValueError:
            a = None
        if a is None:
            raise UserError(f"No app {app_id}")
        return a

    def migrate(self) -> None:
        """Apps for deliveries from before apps existed: one per line of deliveries."""
        by_line: dict[str, dict] = {}
        for meta in self.e.deliveries():
            if meta.get("app"):
                continue
            line = meta.get("line") or meta["id"]
            a = by_line.get(line)
            if a is None:
                a = apps.create(meta.get("name") or "app", meta.get("kind", "appimage"), meta.get("upstream", ""))
                d = delivery_mod.root_dir() / meta["id"]
                try:
                    feature = (d / "FEATURE.md").read_text(encoding="utf-8")
                except OSError:
                    feature = ""
                cid = apps.slug(meta.get("name") or "change", "change")
                apps.write_file(a["id"], f"changes/{cid}.md", feature)
                a["changes"] = [{"id": cid, "title": (meta.get("summary") or meta.get("name") or "")[:120],
                                 "added": meta.get("created", time.time()), "build": meta["id"], "patch_ids": []}]
            a = {**a, "builds": [*a["builds"], meta["id"]], "base_ref": meta.get("base_ref", ""),
                 "base_commit": meta.get("base_commit", ""), "repo": meta.get("repo", ""),
                 "upstream": meta.get("upstream", "") or a.get("upstream", ""),
                 "install_to": meta.get("install_to", "")}
            if meta.get("status") == "installed":
                a["installed"] = {"build": meta["id"], "via": "files", "path": meta.get("installed_to", ""),
                                  "at": meta.get("installed_at", 0)}
            if meta.get("update"):
                a["update"] = meta["update"]
            src = delivery_mod.root_dir() / meta["id"] / "changes.patch"
            if src.exists():
                apps.write_file(a["id"], "series.patch", src.read_text(encoding="utf-8", errors="replace"))
            by_line[line] = apps.save(a)
            delivery_mod.record(delivery_mod.root_dir() / meta["id"], {**meta, "app": a["id"]})

    # ---------------------------------------------------------------- recording a delivery

    async def patch_ids(self, patch: str) -> dict[str, str]:
        """git patch-id --stable of every commit in a patch series: commit -> patch id."""
        if not patch.strip():
            return {}
        rc, out = await podman.exec_agent(self.e.sandbox, ["git", "patch-id", "--stable"], input=patch.encode(), timeout=120)
        if rc != 0:
            return {}
        return {line.split()[1]: line.split()[0] for line in out.splitlines() if len(line.split()) == 2}

    def place(self, meta: dict, args: dict) -> tuple[dict | None, bool]:
        """(the app this delivery belongs to, or None for a new one; whether it is a port of the app's
        changes to another release rather than a new change)."""
        ref = str(args.get("updates") or args.get("app") or "").strip()
        if ref:
            if re.fullmatch(r"D\d+", ref):
                old = delivery_mod.load(delivery_mod.root_dir() / ref) or {}
                a = apps.load(old["app"]) if old.get("app") else None
            else:
                a = apps.load(ref) if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,40}", ref) else None
            if a is None:
                raise delivery_mod.DeliveryError(f"There is no app or earlier delivery {ref[:30]!r}")
            return a, bool(args.get("updates"))
        return apps.find(apps.list_all(), upstream=meta.get("upstream", ""), kind=meta["kind"], name=meta["name"]), False

    def left_out_error(self, app: dict, left_out: list[dict]) -> str:
        what = ", ".join(f"{c['id']} ({c['title']})" for c in left_out)
        return (f"{app['name']} already has the user's change(s) {what}, and this build leaves their commits out (no "
                f"commit names them in a DVM-Change trailer). Usually: build on top of them, in the tree the app "
                f"prepared (/work/apps/{app['id']}, branch dvm/work: the official release with them applied), or apply "
                f"{APPS_FOLDER}/{app['id']}/changes/<id>.patch to the release in order (git am -3). Only if the user has "
                "chosen to drop them: deliver this build as it is with leaves_out set to those change ids; the user "
                "confirms it on a card, and they are taken off the app's record. Never rebuild their commits only to "
                "revert them.")

    # ---------------------------------------------------------------- the official source, kept clean

    @staticmethod
    def mirror_path(upstream: str) -> str:
        return f"{MIRRORS}/{hashlib.sha256(apps.upstream_key(upstream).encode()).hexdigest()[:16]}.git"

    async def mirror(self, upstream: str) -> str:
        """The app's own copy of an official repository, fetched now (the mirrors' own user's, read-only
        to the assistant: scripts.MIRROR). Raises PortFailed("fetch")."""
        try:
            check_url(upstream, "The official source's address")
            if not upstream.startswith("https://"):
                raise InsecureURL("only https:// sources are used")
        except InsecureURL as e:
            raise PortFailed("fetch", str(e)) from None
        path = self.mirror_path(upstream)
        rc, out = await podman.exec_root(self.e.sandbox, ["sh", "-c", scripts.SAFE_DIRECTORY, "sh", path], timeout=60)
        if rc == 0:
            rc, out = await podman.exec_mirror(self.e.sandbox, ["sh", "-c", scripts.MIRROR, "sh", upstream, path])
        if rc != 0:
            raise PortFailed("fetch", out)
        return path

    async def official_commit(self, upstream: str, ref: str, where: str = "") -> str:
        """The commit an official release tag is, asked of the official repository itself (from the
        container `where`, else the sandbox); "" if it has no such tag."""
        rc, out = await podman.exec_agent(where or self.e.sandbox, ["env", "GIT_TERMINAL_PROMPT=0", "git", "ls-remote", upstream,
                                                           f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}"], timeout=90)
        if rc != 0:
            raise delivery_mod.DeliveryError(f"The official repository {upstream} couldn't be asked about {ref}: {out.strip()[-300:]}")
        found = dict(reversed(line.split("\t")) for line in out.splitlines() if line.count("\t") == 1)
        return found.get(f"refs/tags/{ref}^{{}}") or found.get(f"refs/tags/{ref}", "")

    async def ensure_split(self, a: dict) -> dict:
        """Each change's own patch (changes/<id>.patch), its commits naming it in a DVM-Change trailer:
        made once from series.patch for an app recorded before changes had them (their commits found
        by patch id; one no change claims goes with the one before it)."""
        if a.get("split") or not a.get("changes"):
            return a
        series = apps.read_file(a["id"], "series.patch")
        owner = {p: c["id"] for c in a["changes"] for p in c.get("patch_ids") or []}
        pids = await self.patch_ids(series)
        groups: dict[str, list[str]] = {}
        last = a["changes"][0]["id"]
        for sha, chunk in apps.split_patch(series):
            last = owner.get(pids.get(sha, ""), last)
            groups.setdefault(last, []).append(apps.with_trailer(chunk, last))
        for c in a["changes"]:
            apps.write_file(a["id"], f"changes/{c['id']}.patch", "".join(groups.get(c["id"], [])))
        apps.write_file(a["id"], "series.patch", "".join("".join(groups.get(c["id"], [])) for c in a["changes"]))
        return apps.save({**a, "split": True})

    def change_pairs(self, a: dict) -> list[str]:
        """The arguments scripts.CARRY takes for an app's changes: each change's id and patch, in order."""
        out: list[str] = []
        for c in a.get("changes", []):
            if apps.read_file(a["id"], f"changes/{c['id']}.patch").strip():
                out += [c["id"], f"{APPS_FOLDER}/{a['id']}/changes/{c['id']}.patch"]
        return out

    async def carry(self, a: dict, tree: str, onto: str, step: str = "", box: str = "") -> dict:
        """The app's source with the user's changes, made by the app at `tree`: the official `onto`
        with each change carried over to it (scripts.CARRY). {"head", "results": {change id: ok |
        merged | failed}, "log"}. Raises PortFailed when the source can't be had at all.
        In the sandbox, for the assistant to work on; or, in the app's own update, in its clean
        container `box`, from the changes as this app keeps them (not the sandbox's copies of them)."""
        await self.e._sandbox_running()
        a = await self.ensure_split(a)
        await self.sync(a)
        mirror = await self.mirror(a["upstream"])
        if box:
            await self.mirror_readable(box, mirror)
            pairs = []
            for c in a.get("changes", []):
                text = apps.read_file(a["id"], f"changes/{c['id']}.patch")
                if text.strip():
                    await podman.put_file(box, f"{BOX_CHANGES}/{c['id']}.patch", text.encode())
                    pairs += [c["id"], f"{BOX_CHANGES}/{c['id']}.patch"]
        else:
            pairs = self.change_pairs(a)
        rc, out = await podman.exec_agent(
            box or self.e.sandbox, ["sh", "-c", scripts.CARRY, "sh", mirror, a["upstream"], tree, a.get("base_ref") or onto,
                                    onto, *pairs], timeout=1800,
            on_line=(lambda line: self._step(step, line[7:]) if line.startswith("@@STEP ") else None) if step else None)
        results = {l.split()[1]: l.split()[2] for l in out.splitlines() if l.startswith("@@CHANGE ") and len(l.split()) == 3}
        head = next((l.split()[1] for l in out.splitlines() if l.startswith("@@HEAD ")), "")
        if rc not in (0, 3) or not head:
            failed = next((l[9:] for l in out.splitlines() if l.startswith("@@FAILED ")), "")
            raise PortFailed(failed.split(":")[0] or "apply", out)
        return {"head": head, "results": results, "log": out}

    async def prepare(self, a: dict) -> dict:
        """The assistant's tree for a new change to an app: /work/apps/<id>, the official release
        it is built on with the user's changes, as they are (see carry)."""
        return {"tree": self.tree(a), **await self.carry(a, self.tree(a), a.get("base_ref") or "")}

    @staticmethod
    def tree(a: dict) -> str:
        return f"/work/apps/{a['id']}"

    @staticmethod
    def remake_tree(a: dict) -> str:
        """Where an app made again, cleanly, is made (beside its old source, which is only read)."""
        return f"/work/apps/{a['id']}-clean"

    @staticmethod
    def menu_name(a: dict | None) -> str:
        """The name a build of this app must have in its menu entry, when that isn't the build's own:
        an app imported as one of its own, under the name the user gave it. (Its build script, from
        whoever shared it, names it as theirs: where apps live, it would take the place of any app of
        that name, the user's own copy of it too.) "" for any other app."""
        imp = (a or {}).get("imported") or {}
        if not imp or imp.get("into") or a.get("kind") != "appimage":
            return ""
        return f"{a['name']} ({integrate.TAG.upper()})"

    def desktop_name(self, a: dict) -> str:
        """The app's name in the menu entry of the build the user has (else its newest): a build made
        again keeps it, so installing it replaces that one."""
        did = (a.get("installed") or {}).get("build") or (a.get("builds") or [""])[-1]
        name = integrate.desktop_name(delivery_mod.root_dir() / did / "desktop") if did else ""
        return name or f"{a['name']} ({integrate.TAG.upper()})"

    # ---------------------------------------------------------------- recording a delivery

    async def mirror_readable(self, box: str, mirror: str) -> None:
        """Let the agent's user read a mirror in a clean container (git refuses another user's)."""
        rc, out = await podman.exec_root(box, ["sh", "-c", scripts.SAFE_DIRECTORY, "sh", mirror], timeout=60)
        if rc != 0:
            raise PortFailed("fetch", out)

    async def inspect(self, box: str, repo: str, base: str, head: str) -> dict:
        """The commits of `repo` (the app's own copy, in the clean container `box`) from `base` to `head`."""
        # the script as an argument, not a file: nothing could change it before it runs
        rc, out = await podman.exec_agent(box, ["python3", "-c", scripts.INSPECT, repo, base, head], timeout=120,
                                          env={"GIT_ATTR_SOURCE": EMPTY_TREE})
        try:
            return json.loads(out.strip().splitlines()[-1]) if rc == 0 else {}
        except (ValueError, IndexError):
            return {}

    async def check_branch(self, app: dict | None, port: bool, *, box: str, repo: str, base_ref: str, base: str, head: str,
                           origin: str, offered: list[str], by_assistant: bool, pids: dict[str, str] | None = None,
                           remake: bool = False) -> dict:
        """What a delivered branch must be, checked in code: the official release (asked of the
        official repository) with the user's changes, every commit naming its change, nothing
        merged in. A commit the very same as one of an earlier change's (its patch id, `pids`) is
        that change's, whatever it names (an app of the assistant's own has no tree the app
        prepared). With `remake` (the app made again, cleanly), the app's recorded source and release
        don't bind it: it is checked as a new app's is (the source the user saw offered, an official
        release), and its commits name the app's changes. Returns {"upstream", "commits" (each with
        its "change"), "order", "left_out": the app's changes it leaves out}."""
        Err = delivery_mod.DeliveryError
        # the app's own copy of the commit (Engine.box_snapshot), in its clean container: what is built
        info = await self.inspect(box, SNAPSHOT_REPO, base, head)
        if not info:
            raise Err(f"The app couldn't read the commits of {repo} from {base_ref or 'the start'} to HEAD.")
        commits = info["commits"]
        if info.get("shallow"):
            raise Err(f"{repo} is a shallow clone: its history can't be checked. Fetch it whole (git fetch --unshallow).")
        upstream = ""
        if base_ref:
            if app is not None and app.get("upstream") and not remake:
                upstream = app["upstream"]
                if origin and not apps.same_upstream(origin, upstream):
                    raise Err(f"This repository's origin is {origin}, but {app['name']}'s official source is "
                              f"{upstream}. An app is always the official release with the user's changes, never a "
                              f"copy or a fork of it: work in the tree the app prepared ({self.tree(app)}).")
            else:
                upstream = origin or ""
                try:
                    check_url(upstream, "The official source's address")
                    if not upstream.startswith("https://"):
                        raise InsecureURL("it isn't https://")
                except InsecureURL as e:
                    raise Err(f"origin must be the official repository, at its https:// address ({upstream[:120] or 'none'}: "
                              f"{e}). Clone it from the original project, not from a folder in /work or a fork.") from None
                if by_assistant and not any(apps.same_upstream(upstream, o) for o in offered):
                    raise Err(f"The user hasn't been shown where it comes from: call offer_build with upstream={upstream!r} "
                              "(the original project, not a fork), and wait for their yes.")
            if by_assistant:
                official = await self.official_commit(upstream, base_ref, box)
                if official and official != base:
                    raise Err(f"{base_ref} in the official repository is {official[:12]}, but this branch starts from "
                              f"{base[:12]}. Start from the official release itself (the tree the app prepared does).")
                if not official:
                    mirror = await self.mirror(upstream)
                    await self.mirror_readable(box, mirror)
                    rc, _ = await podman.exec_agent(box, ["git", "-C", mirror, "merge-base", "--is-ancestor",
                                                          base, "HEAD"], timeout=120)
                    rc2, out = await podman.exec_agent(box, ["git", "-C", mirror, "for-each-ref", "--count=1",
                                                             "--contains", base], timeout=120)
                    if rc != 0 and (rc2 != 0 or not out.strip()):
                        raise Err(f"{base_ref} ({base[:12]}) isn't a release or a commit of the official repository "
                                  f"{upstream}. Start from one of its releases (a tag).")
            if app is not None and not port and not remake and app.get("base_ref") and base_ref != app["base_ref"]:
                raise Err(f"{app['name']} is built on {app['base_ref']}: build the new change on it (the tree the app "
                          f"prepared is). Moving it to {base_ref} is an update, which the user starts in My apps.")
            latest = ((app or {}).get("update") or {}).get("latest")
            # an update is to the newest release; the app's own release is for changes added from a shared app
            if port and latest and base_ref not in (latest, (app or {}).get("base_ref")):
                raise Err(f"This update is to {latest}: start from it, not {base_ref}.")
        if any(c["merge"] for c in commits):
            raise Err("The branch has merge commits. Keep it a straight line of commits on the release (git rebase), so "
                      "each change can be carried over to new releases.")
        known = {c["id"] for c in (app or {}).get("changes", [])}
        same = {p: c["id"] for c in (app or {}).get("changes", []) for p in c.get("patch_ids") or []}
        order: list[str] = []
        for c in commits:
            named = set(c["changes"])
            if named <= {"new"} and same.get((pids or {}).get(c["sha"], "")):
                named = {same[pids[c["sha"]]]}
            if len(named) != 1:
                raise Err(f"Commit {c['sha'][:12]} ({c['subject'][:60]}) must name its change in one trailer: "
                          f'"DVM-Change: new" for your new change (git commit --trailer "DVM-Change: new"; for commits '
                          f"made already, git rebase {base[:12] or '--root'} -x 'git commit --amend --no-edit --trailer "
                          "\"DVM-Change: new\"'), or the id of the change it belongs to.")
            cid = named.pop()
            if cid != "new" and cid not in known:
                raise Err(f"Commit {c['sha'][:12]} names a change {cid!r} this app doesn't have"
                          + (f" (it has {', '.join(sorted(known))})" if known else "") + ': a new change is "new".')
            if port and cid == "new":
                raise Err("An update carries over the same changes: a commit of a new change (DVM-Change: new) belongs "
                          "in a delivery of its own, after this one.")
            if order and order[-1] != cid and cid in order:
                raise Err(f"The commits of the change {cid} are apart. Keep each change's commits together, in one run "
                          "(git rebase), so each can be carried over on its own.")
            c["change"] = cid
            if not order or order[-1] != cid:
                order.append(cid)
        left_out = [c for c in (app or {}).get("changes", []) if c["id"] not in order]
        return {"upstream": upstream, "commits": commits, "order": order, "left_out": left_out}

    # ---------------------------------------------------------------- each change's notes

    @staticmethod
    def check_notes(app: dict, raw) -> dict[str, dict]:
        """Notes (and titles) for some of an app's changes, as given (change id -> {"notes", "title"?}):
        checked, {id: {"notes", "title"}} with "title" "" when it stays. Raises DeliveryError."""
        Err = delivery_mod.DeliveryError
        if raw in (None, "", {}):
            return {}
        if not isinstance(raw, dict):
            raise Err("change_notes is an object: change id -> {notes, title}")
        have = {c["id"] for c in app.get("changes", [])}
        out = {}
        for cid, v in raw.items():
            if cid not in have:
                raise Err(f"{app['name']} has no change {cid!r}" + (f" (it has {', '.join(sorted(have))})" if have else ""))
            v = v if isinstance(v, dict) else {"notes": v}
            notes = str(v.get("notes") or "").strip()
            if not notes:
                raise Err(f"The notes for {cid} are empty")
            if len(notes) > delivery_mod.MAX_FEATURE:
                raise Err(f"The notes for {cid} are too long (64 KB at most)")
            out[cid] = {"notes": notes, "title": " ".join(str(v.get("title") or "").split())[:120]}
        return out

    @staticmethod
    def _added_lines(patch: str) -> Counter:
        """The lines a patch adds: a change's own code (what it removes, and the context around it,
        follow the project, and differ from release to release while the change stays the same)."""
        return Counter(l[1:] for l in patch.splitlines() if l.startswith("+") and not l.startswith("+++"))

    def stale_notes(self, app: dict, checked: dict, patch: str, given: dict) -> list[dict]:
        """The app's changes whose own code this delivery changes, and that have no new notes in `given`:
        their notes would describe old code."""
        owner = {c["sha"]: c.get("change") for c in checked.get("commits", [])}
        now: dict[str, str] = {}
        for sha, chunk in apps.split_patch(patch):
            if owner.get(sha):
                now[owner[sha]] = now.get(owner[sha], "") + chunk
        return [c for c in app.get("changes", []) if c["id"] in now and c["id"] not in given
                and self._added_lines(now[c["id"]]) != self._added_lines(apps.read_file(app["id"], f"changes/{c['id']}.patch"))]

    def _write_notes(self, a: dict, notes: dict[str, dict]) -> list[dict]:
        """The notes written, and the app's changes with their titles as they are now."""
        for cid, v in notes.items():
            apps.write_file(a["id"], f"changes/{cid}.md", v["notes"] + "\n")
        return [{**c, "title": notes[c["id"]]["title"] or c["title"]} if c["id"] in notes else c
                for c in a.get("changes", [])]

    async def set_notes(self, app_id: str, raw) -> dict:
        """New notes (and titles) for some of an app's changes, its code as it is: by the assistant
        (update_change_notes) or the user (Share…). A change whose notes change gets a new revision,
        so a copy shared before is told apart."""
        a = self.app(app_id)
        notes = self.check_notes(a, raw)
        if not notes:
            return a
        before = {cid: apps.read_file(app_id, f"changes/{cid}.md").strip() for cid in notes}
        titles = {c["id"]: c["title"] for c in a.get("changes", [])}
        changed = {cid for cid, v in notes.items() if v["notes"] != before[cid] or (v["title"] and v["title"] != titles[cid])}
        if not changed:
            return a
        a = share.lineage({**a, "changes": self._write_notes(a, {cid: notes[cid] for cid in changed})})
        a = apps.save({**a, "changes": [{**c, "rev": share.new_rev(c["rev"])} if c["id"] in changed else c
                                        for c in a["changes"]]})
        self.e.log("change_notes", app=app_id, changes=sorted(changed))
        self.changed()
        await self.sync(a)
        return a

    async def attach(self, d: Path, meta: dict, args: dict, patch: str, build_script: str,
                     packages: list[str], left_out: list[str] = (), checked: dict | None = None) -> dict:
        """Add a delivery to its app (made for it if it's new): the change it brings, or the port it is.
        Each change is stored as its own patch, from the commits that name it (`checked`:
        check_branch's). `left_out`: the app's changes the user agreed this build leaves out."""
        app, port = self.place(meta, args)
        old_app = dict(app) if app else None
        checked = checked or {"commits": [], "order": []}
        title = " ".join(str(args.get("change_title") or "").split())[:120]
        pids = await self.patch_ids(patch)
        named = {c["sha"]: c["change"] for c in checked["commits"] if c.get("change")}
        chunks = apps.split_patch(patch)
        old = {c["id"]: c for c in (app or {}).get("changes", [])}
        dropped = [old[i] for i in left_out if i in old]
        remake = bool(args.get("_remake"))
        if app is not None and not port and not remake:
            # a fix to how it's built alone (to work on another system: a library bundled) is a delivery too
            rebuilt = bool(build_script.strip()) and build_script != apps.read_file(app["id"], "build.sh")
            if not any(named.get(sha, "new") == "new" for sha, _ in chunks) and not dropped and not rebuilt:
                raise delivery_mod.DeliveryError("This build has no commits beyond the app's earlier changes, and the "
                                                 "same build script.")
        if app is None:
            app = apps.create(meta["name"], meta["kind"], meta.get("upstream", ""))
        cid = ""
        if any(named.get(sha, "new") == "new" for sha, _ in chunks):
            cid = apps.slug(title or args.get("name") or "change", "change")
            n, base_cid = 2, cid
            while cid in old or cid == "new":
                cid, n = f"{base_cid}-{n}", n + 1
        # as they were, for the versions of a shared app (share.revise): what a chat changed gets a new revision
        texts_before = {i: apps.read_file(app["id"], f"changes/{i}.patch") for i in old}
        build_before = apps.read_file(app["id"], "build.sh")
        groups: dict[str, list[tuple[str, str]]] = {}
        for sha, chunk in chunks:
            owner = named.get(sha, "new")
            owner = cid if owner == "new" else owner
            groups.setdefault(owner, []).append((sha, apps.with_trailer(chunk, owner)))
        notes = self.check_notes(app, args.get("change_notes")) if old else {}
        changes = []
        grew = []
        for owner, items in groups.items():
            text = "".join(c for _, c in items)
            lines = apps.changed_lines(text)
            if owner in old:
                was = old[owner]
                if port and was.get("lines") and lines > 2 * was["lines"] + 10:
                    grew.append(was["title"])
                change = {**was, "patch_ids": [pids[s] for s, _ in items if s in pids], "lines": lines}
            else:
                change = {"id": owner, "title": title or (meta.get("summary") or "").split(".")[0][:120] or "A change",
                          "added": time.time(), "build": meta["id"], "patch_ids": [pids[s] for s, _ in items if s in pids],
                          "lines": lines}
                apps.write_file(app["id"], f"changes/{owner}.md", str(args.get("feature", "")).strip() + "\n")
            apps.write_file(app["id"], f"changes/{owner}.patch", text)
            changes.append(change)
        # notes as the code is now: for changes this delivery changed (required: Engine._deliver), or any other
        changes = self._write_notes({**app, "changes": changes}, notes)
        series = "".join(c for items in groups.values() for _, c in items)
        ids = [pids[s] for items in groups.values() for s, _ in items if s in pids]
        previous = app["builds"][-1] if app.get("builds") else ""
        identical = bool(port and ids and ids == (app.get("patch_ids") or []))
        app = {**app, "name": meta["name"] or app["name"], "builds": [*app.get("builds", []), meta["id"]],
               "changes": changes[-apps.MAX_CHANGES:], "split": True,
               "left_out": [*app.get("left_out", []), *({"id": c["id"], "title": c["title"], "build": meta["id"],
                                                         "at": time.time()} for c in dropped)][-apps.MAX_CHANGES:],
               "base_ref": meta.get("base_ref", ""), "base_commit": meta.get("base_commit", ""),
               "head_commit": meta.get("head_commit", ""), "repo": self.tree(app),
               "upstream": meta.get("upstream", "") or app.get("upstream", ""), "patch_ids": ids,
               "packages": sorted(set(app.get("packages", [])) | set(packages)),
               "install_to": meta.get("install_to", "") or app.get("install_to", ""),
               "integration": meta.get("integration") or app.get("integration", ""),
               "try_steps": meta.get("try_steps") or app.get("try_steps", [])}
        if remake:
            app["remade"] = {"at": time.time(), "build": meta["id"], "was": {k: (old_app or {}).get(k, "") for k in
                                                                            ("upstream", "base_ref", "base_commit")}}
            app["update"] = {}                  # what was known of new releases was of the old source
        if port and (app.get("update") or {}).get("latest") == meta.get("base_ref"):
            app["update"] = {**app["update"], "status": "built", "build": meta["id"]}
        if port and ((app.get("update") or {}).get("port") or {}).get("tag") == meta.get("base_ref"):
            app["update"] = {k: v for k, v in app["update"].items() if k != "port"}     # what didn't fit, made to fit
        if (app.get("imported") or {}).get("built") is False:
            # a build with all its changes (check_branch keeps them), whoever made it
            app["imported"] = {**app["imported"], "built": True}
        apps.write_file(app["id"], "series.patch", series)
        if build_script:
            apps.write_file(app["id"], "build.sh", build_script)
        app = apps.save(share.revise(app, old_app or {}, texts_before, build_before, apps.read_file(app["id"], "build.sh"),
                                     fitted=port and not remake, notes_changed=set(notes)))
        merged = set(args.get("_merged") or [])                # in the new release now: not the user's choice
        chose = [c["title"] for c in dropped if c["id"] not in merged]
        meta.update(app=app["id"], change=cid, port=port, patch_ids=ids, share_sig=share.signature(app), **({"remake": app["remade"]["was"]} if remake else {}),
                    **({"left_out": chose} if chose else {}),
                    **({"merged": [c["title"] for c in dropped if c["id"] in merged]} if merged & {c["id"] for c in dropped} else {}),
                    **({"grew": grew} if grew else {}),
                    **({"identical_to": previous} if identical else {}),
                    **({"replaces": previous} if previous else {}))
        delivery_mod.record(d, meta)
        await self.sync(app)
        return app

    async def sync(self, app: dict | None = None) -> None:
        """Put each app's series, build script and notes where the assistant (and the app's own
        builds) can find them: /work/.dvm/apps/<id>/."""
        for a in [app] if app else apps.list_all():
            folder = f"{APPS_FOLDER}/{a['id']}"
            info = {k: a.get(k) for k in ("id", "name", "kind", "upstream", "base_ref", "repo", "install_to", "packages",
                                          "integration")}
            info["changes"] = [{"id": c["id"], "title": c["title"]} for c in a.get("changes", [])]
            try:
                await podman.put_file(self.e.sandbox, f"{folder}/app.json", json.dumps(info, indent=1).encode())
                await podman.put_file(self.e.sandbox, f"{folder}/FEATURE.md", apps.feature_text(a).encode())
                for name in ("series.patch", "build.sh", *(f"changes/{c['id']}.patch" for c in a.get("changes", []))):
                    text = apps.read_file(a["id"], name)
                    if text:
                        await podman.put_file(self.e.sandbox, f"{folder}/{name}", text.encode())
            except podman.PodmanError:
                return                          # the sandbox isn't up: done when it starts

    # ---------------------------------------------------------------- new releases

    async def check(self, app_id: str, quiet: bool = False) -> dict:
        """Ask the app's upstream (from the sandbox, through its proxy) for its release tags."""
        a = self.app(app_id)
        known = (a.get("update") or {}).get("latest")
        upstream, base = a.get("upstream") or "", a.get("base_ref") or ""
        info: dict = {"checked": time.time()}
        if not upstream or not base:
            info.update(status="none", why="It isn't based on a published version, so there's nothing to compare with.")
        else:
            try:
                check_url(upstream, "The upstream address")
                if not upstream.startswith("https://"):
                    raise InsecureURL("only https:// upstreams are checked")
                await self.e._sandbox_running()
                rc, out = await podman.exec_agent(
                    self.e.sandbox, ["env", "GIT_TERMINAL_PROMPT=0", "git", "ls-remote", "--tags", "--refs", upstream], timeout=90)
                if rc != 0:
                    raise RuntimeError(out.strip()[-300:] or f"git ls-remote failed ({rc})")
                tags = versions.tags_from_ls_remote(out)
                if base not in tags:
                    info.update(status="none", why=f"{base} isn't one of its release tags, so there's nothing to compare with.")
                else:
                    latest = versions.newer(base, tags)
                    info.update(status="available" if latest else "current", latest=latest or base)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 - shown on the card
                info.update(status="error", error=str(e)[-300:] or type(e).__name__)
        old = a.get("update") or {}
        if info.get("status") == "available" and old.get("latest") == info.get("latest"):
            info = {**old, **info}              # keep what is known of this release (its change log, summary)
        a = apps.save({**a, "update": info})
        self.e.log("update_check", app=app_id, **{k: v for k, v in info.items() if k in ("status", "latest", "error")})
        self.changed()
        fresh = info.get("status") == "available" and info.get("latest") != known
        if fresh and a.get("skip") != info["latest"]:
            await self._on_new_release(a, quiet)
        return apps.load(app_id)["update"]

    async def _on_new_release(self, a: dict, quiet: bool) -> None:
        s = self.e.cfg.settings
        tag = a["update"]["latest"]
        try:
            await self.changelog(a["id"])
            if s.changelog_summary == "auto":
                await self.summarize(a["id"])
        except Exception as e:  # noqa: BLE001 - the user can ask again from the card
            self.e.log("changelog_failed", app=a["id"], error=str(e))
        u = (apps.load(a["id"]) or a).get("update", {})
        security = bool(u.get("security_lines") or (u.get("summary") or {}).get("security"))
        when = self.build_when(a) if a.get("kind") == "appimage" else "ask"
        rebuilding = when == "auto"
        if quiet or rebuilding:
            body = ("It includes security fixes. " if security else "") + (
                "Building your version of it now (your computer may be slower for a while)." if rebuilding
                else f"Your version with your changes will be built at {s.build_time}, when your computer is quiet "
                     "(or now, from My apps)." if when == "scheduled"
                else "Your version with your changes can be updated: open My apps.")
            self.e.notify(f"{a['name']} {tag} is out", body)
        if rebuilding:
            self.e._spawn(self.rebuild(a["id"], by_user=False))

    async def changelog(self, app_id: str) -> dict:
        """What changed upstream since the app's release, read in the sandbox."""
        a = self.app(app_id)
        u = a.get("update") or {}
        if u.get("status") not in ("available", "built"):
            raise UserError("There's no newer version to read about.")
        tag = u["latest"]
        await self.e._sandbox_running()
        rc, out = await podman.exec_agent(
            self.e.sandbox, ["python3", "-c", scripts.CHANGELOG, a["upstream"], f"{BUILD_FOLDER}/changelog-{a['id']}", a["base_ref"], tag], timeout=300)
        try:
            log = json.loads(out.strip().splitlines()[-1]) if rc == 0 else None
        except (ValueError, IndexError):
            log = None
        if log is None:
            raise UserError(f"The change log couldn't be read: {out.strip()[-300:]}")
        log.update(tag=tag, since=a["base_ref"], page=log.get("url") or release_page(a["upstream"], tag), at=time.time())
        apps.write_file(app_id, f"changelog-{tag}.json", json.dumps(log, ensure_ascii=False))
        lines = security_lines(log.get("notes", ""), *log.get("news", {}).values(), "\n".join(log.get("commits", [])))
        a = apps.save({**a, "update": {**u, "changelog": True, "security_lines": lines, "page": log["page"],
                                        "commit_count": log.get("commit_count", 0)}})
        self.changed()
        return log

    def read_changelog(self, app_id: str) -> dict:
        a = self.app(app_id)
        tag = (a.get("update") or {}).get("latest", "")
        try:
            return json.loads(apps.read_file(app_id, f"changelog-{tag}.json") or "null") or {}
        except ValueError:
            return {}

    async def summarize(self, app_id: str) -> dict:
        a = self.app(app_id)
        log = self.read_changelog(app_id) or await self.changelog(app_id)
        a = self.app(app_id)
        u = a.get("update") or {}
        parts = [f"App: {a['name']}. The user runs {a['base_ref']}; the new release is {log['tag']} "
                 f"({log.get('commit_count', 0)} commits since)."]
        if log.get("notes"):
            parts.append("Release notes:\n" + fence(log["notes"][:12000]))
        for name, text in (log.get("news") or {}).items():
            parts.append(f"New lines in {name}:\n" + fence(text[:12000]))
        if log.get("commits"):
            parts.append("Commit subjects:\n" + fence("\n".join(log["commits"][:300])))
        if u.get("security_lines"):
            parts.append("Lines that mention security (found by keyword):\n" + fence("\n".join(u["security_lines"])))
        a = apps.save({**a, "update": {**u, "summary": {"status": "checking"}}})
        self.changed()
        try:
            out = await self.e._review(prompts.CHANGELOG_SUMMARY_PROMPT, "\n\n".join(parts), "changelog_summary", app=app_id)
        except Exception as e:
            a = self.app(app_id)
            apps.save({**a, "update": {**a["update"], "summary": {"status": "error", "error": str(e)}}})
            self.changed()
            raise
        summary = {"status": "done", "model": out["model"], **parse_summary(out["text"]), "at": time.time()}
        a = self.app(app_id)
        apps.save({**a, "update": {**a["update"], "summary": summary}})
        self.e.log("changelog_summary", app=app_id, **{k: v for k, v in summary.items() if k != "text"})
        self.changed()
        return summary

    def change_detail(self, app_id: str, change_id: str) -> dict:
        """One of the app's changes, as the app keeps it: its notes and its patch against the release."""
        a = self.app(app_id)
        c = next((c for c in a.get("changes", []) if c["id"] == change_id), None)
        if c is None:
            raise UserError(f"{a['name']} has no change {change_id[:40]!r}.")
        return {**c, "feature": apps.read_file(app_id, f"changes/{c['id']}.md"),
                # binary files as a line each, as for the reviewer (what's kept is the whole patch)
                "patch": share.for_review(apps.read_file(app_id, f"changes/{c['id']}.patch"))[0], "base_ref": a.get("base_ref", "")}

    # ---------------------------------------------------------------- versions of a shared app (share.py)

    def works_here(self, did: str) -> dict:
        """The user says this build works on this computer: its version is known to work on this system."""
        meta = delivery_mod.load(delivery_mod.root_dir() / did) if re.fullmatch(r"D\d{1,9}", did or "") else None
        if not meta or not meta.get("app"):
            raise UserError("That build isn't one of an app's.")
        a = self.app(meta["app"])
        sig = meta.get("share_sig") or share.signature(share.lineage(a))
        a = apps.save(share.record_works(a, sig, share.this_system()))
        self.e.log("works_here", app=a["id"], build=did, version=sig)
        self.changed()
        return {"works_on": share.works_on(a, sig), "reshare": share.reshare(a)}

    def reshare_later(self, app_id: str) -> None:
        a = self.app(app_id)
        if a.get("share"):
            apps.save({**a, "share": {**a["share"], "not_now": share.signature(a)}})
            self.changed()

    def skip(self, app_id: str) -> None:
        a = self.app(app_id)
        apps.save({**a, "skip": (a.get("update") or {}).get("latest", "")})
        self.changed()

    # ---------------------------------------------------------------- when: looking, and building

    def check_every(self, a: dict) -> str:
        """How often this app's official source is asked for new releases: its own choice, or Settings'."""
        if a.get("check_every") in CHECK_EVERY or a.get("check_every") == "manual":
            return a["check_every"]
        if a.get("watch") is False:
            return "manual"                     # "stop watching", from before each app chose
        return self.e.cfg.settings.check_every

    def build_when(self, a: dict) -> str:
        """When a new release of it is built with the user's changes: "ask", "scheduled" or "auto"."""
        return a.get("build_when") if a.get("build_when") in REBUILD else self.e.cfg.settings.rebuild

    def set_schedule(self, app_id: str, check_every: str | None = None, build_when: str | None = None) -> dict:
        """An app's own choices ("" for Settings' own)."""
        a = self.app(app_id)
        if check_every is not None:
            if check_every not in ("", *CHECK_EVERY, "manual"):
                raise UserError("How often to look is every day, week or month, or only when you ask.")
            a = {**a, "check_every": check_every, "watch": True}
        if build_when is not None:
            if build_when not in ("", *REBUILD):
                raise UserError("New versions are built when you say so, at the quiet time, or straight away.")
            a = {**a, "build_when": build_when}
        a = apps.save(a)
        self.changed()
        return a

    def set_watch(self, app_id: str, on: bool) -> None:
        self.set_schedule(app_id, check_every="" if on else "manual")

    @staticmethod
    def on_battery(root: Path = Path("/sys/class/power_supply")) -> bool:
        """Whether this computer runs on its battery now: it has one, and no mains supply is online
        (read by the app here, on the computer; never by the assistant)."""
        try:
            supplies = [p for p in root.iterdir() if (p / "type").is_file()]
        except OSError:
            return False
        kind = {p: (p / "type").read_text().strip() for p in supplies}
        mains = [p for p, k in kind.items() if k in ("Mains", "USB", "USB_C", "USB_PD")]
        if not any(k == "Battery" for k in kind.values()) or not mains:
            return False
        def online(p: Path) -> bool:
            try:
                return (p / "online").read_text().strip() == "1"
            except OSError:
                return False
        return not any(online(p) for p in mains)

    def in_build_window(self, now: float) -> bool:
        hh, mm = (int(x) for x in self.e.cfg.settings.build_time.split(":"))
        lt = time.localtime(now)
        return ((lt.tm_hour * 60 + lt.tm_min) - (hh * 60 + mm)) % 1440 * 60 < BUILD_WINDOW

    def waiting(self, a: dict) -> str:
        """Why a new release of this app isn't being built now: "" (it is, or it will be when asked),
        "scheduled" (at the quiet time) or "battery" (at the quiet time, once on mains power)."""
        u = a.get("update") or {}
        if u.get("status") != "available" or a.get("skip") == u.get("latest") or a["id"] in self.building:
            return ""
        if a.get("kind") != "appimage" or not apps.read_file(a["id"], "build.sh"):
            return ""
        if (u.get("port") or {}).get("tag") == u.get("latest"):
            return ""                           # tried by itself already: what's next is the user's
        if self.build_when(a) != "scheduled":
            return ""
        if not self.e.cfg.settings.build_on_battery and self._battery:
            return "battery"
        return "scheduled"

    async def tick(self, now: float | None = None) -> None:
        """Every few minutes, while the sandbox runs: ask the official sources that are due for new
        releases, and start the builds whose time has come (one at a time: rebuild's lock)."""
        now = time.time() if now is None else now
        if self.e.workspace.get("state") != "running":
            return
        self._battery = self.on_battery()
        for a in apps.list_all():
            every = self.check_every(a)
            if every in CHECK_EVERY and a.get("upstream") and a.get("base_ref") and \
                    now - (a.get("update") or {}).get("checked", 0) > CHECK_EVERY[every]:
                try:
                    await self.check(a["id"], quiet=True)
                except Exception as e:  # noqa: BLE001 - tried again next time
                    self.e.log("update_check_failed", app=a["id"], error=str(e))
        if not self.in_build_window(now):
            return
        for a in apps.list_all():
            if self.waiting(a) == "scheduled":
                self.e.log("scheduled_build", app=a["id"], to=a["update"]["latest"])
                # its place in the queue, until its build starts (rebuild's own takes it over)
                self.building[a["id"]] = {"step": "waiting", "started": now, "tag": a["update"]["latest"], "queued": True}
                self.e._spawn(self._scheduled(a["id"]))
        self.changed()

    async def _scheduled(self, app_id: str) -> None:
        try:
            await self.rebuild(app_id, by_user=False, queued=True)
        except Exception as e:  # noqa: BLE001 - shown on its card, tried again with the next release
            self.e.log("scheduled_build_failed", app=app_id, error=str(e))
        finally:
            if (self.building.get(app_id) or {}).get("queued"):
                self.building.pop(app_id, None)
                self.changed()

    async def watch(self) -> None:
        await asyncio.sleep(120)
        while True:
            try:
                await self.tick()
            except Exception as e:  # noqa: BLE001 - tried again at the next tick
                self.e.log("tick_failed", error=str(e))
            await asyncio.sleep(TICK)

    # ---------------------------------------------------------------- rebuilding

    def _step(self, app_id: str, step: str) -> None:
        if app_id in self.building:
            self.building[app_id]["step"] = step
            self.changed()

    async def rebuild(self, app_id: str, by_user: bool = True, queued: bool = False, tag: str = "") -> str:
        """Make the app again on its newest release (or on `tag`, its own release: an app imported,
        or changes added to it from a shared app), by the app alone if the changes apply and build;
        otherwise hand it to the assistant (only when the user asked for it now)."""
        a = self.app(app_id)
        u = a.get("update") or {}
        if tag and tag != a.get("base_ref"):
            raise UserError(f"{a['name']} is built on {a.get('base_ref')}: a newer version is built as an update.")
        if not tag and u.get("status") not in ("available", "built"):
            raise UserError("There's no newer version to build.")
        tag = tag or u["latest"]
        if app_id in self.building and not queued:
            raise UserError("It's being built already.")
        if a["kind"] != "appimage" or not apps.read_file(app_id, "build.sh"):
            # nothing to build it with but the assistant
            if by_user:
                await self.ask_assistant(app_id, None, tag)
            return ""
        self.building[app_id] = {"step": "waiting", "started": time.time(), "tag": tag}
        self.changed()
        try:
            async with self._build_lock:
                did = await self._port(a, tag)
        except PortFailed as f:
            self.building.pop(app_id, None)
            a = self.app(app_id)
            if f.step == "merged":
                apps.save({**a, "update": {**a["update"], "port": {"status": "merged", "changes": f.changes, "tag": tag,
                                                                    "at": time.time()}}})
                self.e.log("port_merged", app=app_id, to=tag)
                self.changed()
                self.e.notify(f"{a['name']} {tag} has your changes itself",
                              "The project made them part of it, so its own version does what yours does. Nothing was built.")
                return ""
            apps.save({**a, "update": {**a.get("update", {}), "port": {"status": "failed", "step": f.step, "log": f.log[-6000:],
                                                                        "changes": f.changes, "tag": tag, "at": time.time()}}})
            self.e.log("port_failed", app=app_id, step=f.step)
            self.changed()
            if by_user:
                try:
                    await self.ask_assistant(app_id, f, tag)
                except UserError as e:
                    # the card offers it again ("Let the assistant do it"), once it can be
                    self.e.emit("toast", level="error", text=f"{a['name']} didn't build by itself, and the assistant "
                                                             f"can't take it over now: {e}")
            else:
                self.e.notify(f"{a['name']} {tag} needs the assistant",
                              f"Your changes didn't carry over by themselves ({f.step}). Open My apps to let the assistant finish it.")
            return ""
        except Exception as e:  # noqa: BLE001 - any other end of the build is the user's to see, never silent
            self.building.pop(app_id, None)
            why = str(e).strip() or type(e).__name__
            a = self.app(app_id)
            apps.save({**a, "update": {**a.get("update", {}), "port": {"status": "failed", "step": "error", "log": why[-6000:],
                                                                        "changes": {}, "tag": tag, "at": time.time()}}})
            self.e.log("build_failed", app=app_id, to=tag, error=why)
            self.changed()
            self.e.notify(f"{a['name']} {tag} wasn't built", f"{why[:300]} Open My apps to try again, or let the assistant look at it.")
            if by_user:
                self.e.emit("toast", level="error", text=f"{a['name']} wasn't built: {why[:500]}")
            return ""
        self.building.pop(app_id, None)
        a = self.app(app_id)
        _, meta = self.e._delivery(did)
        same = " The change is identical to the one you have." if meta.get("identical_to") else ""
        self.e.notify(f"{a['name']} {tag} is ready", f"Built with your changes.{same} Open My apps to install it.")
        self.changed()
        return did

    async def _port(self, a: dict, tag: str) -> str:
        """The app alone: its changes carried over to `tag` change by change (scripts.CARRY), built with
        the saved build script, and delivered: all of it in a clean container, from the changes and
        build script as this app keeps them, so nothing the assistant left running in the sandbox can
        touch an update the user didn't watch being made."""
        aid = a["id"]
        work = f"{BUILD_FOLDER}/{aid}"
        script = apps.read_file(aid, "build.sh")
        async with self.e.clean_box(step=lambda label: self._step(aid, label)) as box:
            carried = await self.carry(a, f"{work}/src", tag, step=aid, box=box)
            if "failed" in carried["results"].values():
                raise PortFailed("apply", carried["log"], carried["results"])
            if carried["results"] and set(carried["results"].values()) == {"merged"}:
                raise PortFailed("merged", carried["log"], carried["results"])     # nothing of the user's left to add
            a = self.app(aid)
            head = await self.e.box_snapshot(box, f"{work}/src", tag)
            if head != carried["head"]:
                raise PortFailed("apply", f"The source made ({carried['head']}) isn't what was copied to build ({head}).")
            await podman.put_file(box, BOX_SCRIPT, script.encode())
            # built with only its own packages, as at delivery (raises PortFailed)
            built, _ = await self.e.box_build(box, head, BOX_SCRIPT, a.get("packages") or [], work,
                                              step=lambda label: self._step(aid, label), timeout=BUILD_TIMEOUT)
            args = {"kind": "appimage", "path": built, "repo": f"{work}/src", "base_ref": tag, "name": a["name"],
                    "_merged": [i for i, r in carried["results"].items() if r == "merged"],
                    "version": f"{tag}-dvm1", "summary": f"{a['name']} {tag}, with your changes: "
                    + "; ".join(c["title"] for c in a.get("changes", [])) + ".",
                    "feature": apps.feature_text(a), "updates": aid, "tested": "Built by the app from the official "
                    f"{tag} with the saved changes and build script.", "not_tested": "Not run at all: nobody has tried this "
                    "version yet, so try it before you rely on it.", "_own_build": True,
                    "_upstream": a["upstream"], "_box": box, "_head": head}
            self._step(aid, "deliver")
            return await self.e.make_delivery(args, entry=None)

    async def assistant(self, app_id: str) -> None:
        """The user's "Let the assistant do it": told what the app's own try ran into, on the release
        it tried."""
        port = ((self.app(app_id).get("update") or {}).get("port") or {})
        if port.get("status") == "failed":
            await self.ask_assistant(app_id, PortFailed(port.get("step", "apply"), port.get("log", ""), port.get("changes")),
                                     port.get("tag", ""))
        else:
            await self.ask_assistant(app_id, None)

    async def ask_assistant(self, app_id: str, failure: PortFailed | None, tag: str = "") -> None:
        """A new chat in which the assistant makes the app's changes on the new release (or on `tag`, its
        own, for changes from a shared app): in a tree the app prepared with what carried over by
        itself, told exactly which changes didn't and why."""
        a = self.app(app_id)
        u = a.get("update") or {}
        if self.e.busy:
            raise UserError("Wait for the assistant to finish (or stop it) first.")
        if not self.e.ready:
            raise UserError(self.e.assistant_status()["error"])
        await self.e._sandbox_running()
        await self.e.new_chat(mode="app", app=app_id)
        tag = tag or u["latest"]
        apps.save({**self.app(app_id), "chat": {"id": self.e.conv.id, "tag": tag, "at": time.time()}})
        self.changed()
        titles = {c["id"]: c["title"] for c in a.get("changes", [])}
        tree = self.tree(a)
        try:
            carried = await self.carry(a, tree, tag)
            prepared = f"The app has prepared {tree}: a fresh copy of the official {tag}, on branch dvm/work"
            done = [titles.get(i, i) for i, r in carried["results"].items() if r != "failed"]
            failed = [i for i, r in carried["results"].items() if r == "failed"]
            prepared += (f", with these changes carried over by themselves: {'; '.join(done)}." if done else ", with none of the changes carried over yet.")
            if failed:
                prepared += (" These didn't carry over, and are yours to make again on it: "
                             + "; ".join(f"{i} ({titles.get(i, i)})" for i in failed) + ". What git said:\n"
                             + fence(carried["log"][-4000:]))
        except PortFailed as f:
            prepared = (f"The app couldn't prepare the new version ({f.step}): clone {a['upstream']} into {tree}, make a "
                        f"branch dvm/work at {tag}, and apply the changes' patches in order (git am -3). What failed:\n"
                        + fence(f.log[-3000:]))
        own = tag == a.get("base_ref")
        text = (f"Please build my {a['name']} with its changes: some came from a shared app." if own
                else f"Please update my {a['name']} to version {tag}, with the same changes.")
        why = ("The app tried by itself first: " + {"apply": "not all the saved changes carry over to the new version as they are",
               "build": "it doesn't build with the saved build script in a clean container (only its build packages "
                        "installed)",
               "start": "a clean container to build in couldn't be started",
               "snapshot": "the source it made couldn't be copied to build",
               "fetch": "the new version couldn't be fetched", "packages": "the build tools couldn't be installed",
               "deliver": "what it built didn't pass the checks a delivery has",
               "error": "it stopped with an error"}.get(
               failure.step, failure.step) + "." + ("" if failure.step == "apply" else " Its output:\n" + fence(failure.log[-4000:]))) \
            if failure else "There's no saved build script for it yet: make one (build_script) as you deliver."
        task = (prompts.SHARED_BUILD_TASK if own else prompts.UPDATE_TASK).format(app=a["id"], name=a["name"], kind=a["kind"], upstream=a["upstream"],
                                          base=a["base_ref"], tag=tag, folder=f"{APPS_FOLDER}/{a['id']}", tree=tree,
                                          prepared=prepared, why=why,
                                          changes="\n".join(f"- {c['id']}: {c['title']}" for c in a.get("changes", [])),
                                          addon_note=f"Keep install_to=\"{a['install_to']}\". " if a.get("install_to") else "")
        self.e._user_entry(text)
        self.e.log("update_started", app=app_id, to=tag, after=failure.step if failure else "")
        self.e._start_turn(f"{text}\n\n{task}", note=False)

    # ---------------------------------------------------------------- installing

    def integrator(self):
        s = self.e.cfg.settings
        return integrate.choose(s.app_home, Path(s.install_dir), data_dir() / "icons")

    async def runtime(self) -> bytes:
        """The pinned AppImage runtime, from the sandbox image, checked against its pin."""
        path = data_dir() / "runtime-x86_64"
        from .workspace import pins
        if not path.exists() or delivery_mod.sha256_file(path) != pins.RUNTIME_SHA256:
            tmp = path.with_suffix(".part")
            tmp.unlink(missing_ok=True)
            await podman.copy_out(self.e.sandbox, "/usr/local/share/appimage/runtime-x86_64", tmp)
            if delivery_mod.sha256_file(tmp) != pins.RUNTIME_SHA256:
                tmp.unlink(missing_ok=True)
                raise appimage.AppImageError("the sandbox's AppImage runtime doesn't match its pin")
            tmp.replace(path)
        return path.read_bytes()

    def install(self, did: str) -> dict:
        """Install an AppImage build where the user's apps live (their click), replacing the one before."""
        d, meta = self.e._delivery(did)
        a = self.app(meta["app"])
        f = d / meta["file"]
        if delivery_mod.sha256_file(f) != meta["sha256"]:
            raise delivery_mod.DeliveryError("The AppImage in quarantine no longer matches its recorded sha256; not installed.")
        rt = data_dir() / "runtime-x86_64"
        if not meta.get("runtime_checked") or not rt.exists():
            raise delivery_mod.DeliveryError("Its AppImage runtime wasn't checked when it was delivered; not installed.")
        from .workspace import pins
        runtime = rt.read_bytes()
        # the kept runtime is checked against its pin each time: a restored backup brings its own copy
        if hashlib.sha256(runtime).hexdigest() != pins.RUNTIME_SHA256:
            raise delivery_mod.DeliveryError("The AppImage runtime kept to check builds against isn't the pinned one; "
                                             "not installed. Start the sandbox, and it's fetched again.")
        appimage.check_runtime(f, runtime)
        staging = data_dir() / "staging"
        staging.mkdir(parents=True, exist_ok=True, mode=0o700)
        staged = staging / integrate.stable_name(a)
        shutil.copyfile(f, staged)
        staged.chmod(0o755)
        try:
            info = self.integrator().install(staged, a, d / "desktop" if (d / "desktop").is_dir() else None)
        finally:
            staged.unlink(missing_ok=True)
        before = a.get("installed")
        self._drop_replaced(a, before, info)
        a = apps.save({**a, "installed": {**info, "build": did, "version": meta["version"], "at": time.time()},
                       "previous": before if before and before.get("build") != did else a.get("previous"),
                       "update": {**(a.get("update") or {}), **({"status": "current"} if (a.get("update") or {}).get("build") == did else {})}})
        for m in self.e.deliveries():
            if m.get("app") == a["id"] and m["id"] != did and m.get("status") == "installed":
                delivery_mod.record(delivery_mod.root_dir() / m["id"], {**m, "status": "replaced", "replaced_by": did})
        meta = delivery_mod.record(d, {**meta, "status": "installed", "installed_to": info["path"], "installed_via": info["via"],
                                       "installed_at": time.time()})
        self.e.log("installed", delivery=did, app=a["id"], via=info["via"], to=info["path"], sha256=meta.get("sha256"))
        self.changed()
        return meta

    # ---------------------------------------------------------------- removing an app

    def remove(self, app_id: str, keep_installed: bool = False) -> dict:
        """Take an app off My apps (the user's click): uninstalled the way it was installed (unless
        `keep_installed`), its builds and record deleted, and its folders in the sandbox. Its chats
        stay, no longer tied to it. Returns {"left": what stays on the computer, in words}."""
        a = self.app(app_id)
        if app_id in self.building:
            raise UserError(f"{a['name']} is being built: wait for it to finish first.")
        c = self.e.conv
        if self.e.busy and c and c.app == app_id:
            raise UserError(f"The assistant is working on {a['name']}: wait for it to finish (or stop it) first.")
        left = "" if keep_installed else self._uninstall(a)
        if keep_installed and (a.get("installed") or {}).get("path"):
            left = a["installed"]["path"]
        for m in self.e.deliveries():
            if m.get("app") == app_id:
                delivery_mod.remove(delivery_mod.root_dir(), m["id"])
        apps.remove(app_id)
        self.e.forget_app(app_id)
        self.e._spawn(self._clear_sandbox(a))
        self.e.log("app_removed", app=app_id, kept_installed=keep_installed, left=left)
        self.changed()
        return {"left": left}

    def _uninstall(self, a: dict) -> str:
        """Uninstall the app's installed build, the way it was installed. Raises UserError if it
        can't be (the window offers to remove it from My apps all the same, leaving it installed)."""
        inst = a.get("installed") or {}
        if not inst.get("build"):
            return ""
        meta = delivery_mod.load(delivery_mod.root_dir() / inst["build"]) or {}
        via = inst.get("via") or meta.get("installed_via") or ""
        s = self.e.cfg.settings
        integrator = integrate.by_key(via, Path(s.install_dir), data_dir() / "icons") if a.get("kind") == "appimage" else None
        try:
            if integrator is not None:
                return integrator.uninstall(inst, a, meta.get("sha256", ""))
            kept = [b for m in self.e.deliveries() if m.get("app") == a["id"] for b in m.get("backups", [])]
            return delivery_mod.uninstall({**meta, "kind": a.get("kind", meta.get("kind"))}, kept) if meta else ""
        except (integrate.IntegrationError, OSError) as e:
            raise UserError(f"{a['name']} couldn't be uninstalled: {e}") from None

    async def _clear_sandbox(self, a: dict) -> None:
        """Its folders in the sandbox (notes and patches, its source trees), so an app made later under
        the same id starts clean."""
        try:
            await podman.exec_root(self.e.sandbox, ["rm", "-rf", "--", f"{APPS_FOLDER}/{a['id']}", self.tree(a),
                                                     self.remake_tree(a), f"{BUILD_FOLDER}/{a['id']}"], timeout=300)
        except podman.PodmanError:
            pass                                # the sandbox isn't up: a later chat's tree is made afresh

    def _drop_replaced(self, a: dict, before: dict | None, now: dict) -> None:
        """A build installed under another menu name than the one before it (an imported app, given the
        name the user chose) is a second entry where apps live: the one before it goes, unless another
        app of the user's is installed there too. Best effort: it's said in the log if it can't be."""
        if not before or not before.get("path") or before.get("path") == now.get("path") or before.get("via") != now.get("via"):
            return
        if any((x.get("installed") or {}).get("path") == before["path"] for x in apps.list_all() if x["id"] != a["id"]):
            return
        s = self.e.cfg.settings
        integrator = integrate.by_key(before["via"], Path(s.install_dir), data_dir() / "icons")
        meta = delivery_mod.load(delivery_mod.root_dir() / before.get("build", "")) if before.get("build") else None
        try:
            if integrator is not None:
                integrator.uninstall(before, a, (meta or {}).get("sha256", ""))
        except (integrate.IntegrationError, OSError) as e:
            self.e.log("replaced_not_removed", app=a["id"], path=before["path"], error=str(e))

    # ---------------------------------------------------------------- a copy to run elsewhere

    @staticmethod
    def export_build(a: dict, builds: dict[str, dict]) -> str:
        """The build "Export AppImage" saves: the installed one, else the newest not set aside ("" if none)."""
        if a.get("kind") != "appimage":
            return ""
        installed = (a.get("installed") or {}).get("build", "")
        newest = [did for did in reversed(a.get("builds") or []) if (builds.get(did) or {}).get("status") not in ("rejected", "replaced")]
        return next((did for did in [installed, *newest] if (builds.get(did) or {}).get("kind") == "appimage"
                     and builds[did].get("file")), "")

    def export_appimage(self, app_id: str) -> dict:
        """A copy of the app's AppImage in the user's Downloads folder, to run on another computer or
        keep: the build as delivered (its checksum checked), under a name that says what it is."""
        a = self.app(app_id)
        did = self.export_build(a, {m["id"]: m for m in self.e.deliveries()})
        if not did:
            raise UserError(f"{a['name']} has no build to export yet: build it first.")
        d, meta = self.e._delivery(did)
        src = d / meta["file"]
        if not src.is_file() or delivery_mod.sha256_file(src) != meta["sha256"]:
            raise UserError("That build no longer matches what was delivered, so it isn't exported.")
        folder = share.Sharing.folder()
        stem = f"{delivery_mod.safe_name(a['name'])}-{delivery_mod.safe_name(meta.get('version'), 'build')}-x86_64"
        dest, n = folder / f"{stem}.AppImage", 2
        while dest.exists():
            dest, n = folder / f"{stem}-{n}.AppImage", n + 1
        tmp = dest.with_name(f".{dest.name}.part")
        try:
            shutil.copyfile(src, tmp)
            os.chmod(tmp, 0o755)
            tmp.replace(dest)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        self.e.log("appimage_exported", app=app_id, build=did, path=str(dest), sha256=meta["sha256"])
        return {"path": str(dest), "folder": str(folder), "name": dest.name, "size": dest.stat().st_size,
                "version": meta.get("version", ""), "sha256": meta["sha256"]}

    def rollback(self, app_id: str) -> dict:
        a = self.app(app_id)
        prev = (a.get("previous") or {}).get("build")
        if not prev:
            raise UserError("There's no earlier version to go back to.")
        try:
            meta = self.install(prev)
        except (OSError, delivery_mod.DeliveryError, appimage.AppImageError, integrate.IntegrationError) as e:
            raise UserError(f"Could not go back to it: {e}") from e
        self.e.log("rolled_back", app=app_id, to=prev)
        return meta
