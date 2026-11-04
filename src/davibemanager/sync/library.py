"""The apps as sync sees them, and how what changed on two computers comes together.

An app is synced as `share.py` packs it for someone else (its bundle): the official source and
release, each change's notes, patch and revision, the build script and its revision, the systems a
version works on. It's the same app on each computer by its share id (its app id may differ).
What belongs to one computer stays there: what's installed, the builds, the schedule, the chats.

For each app, a computer pulling from another compares three summaries: its own, the other's, and
the one both had when they last agreed (the base, store.base_of). What changed only on one side
wins; what changed on both is merged change by change, the revision histories saying which of two
edits is the newer (share._how). Two edits that don't descend from each other are a conflict: this
computer's is kept, and the other's is put aside (the app's sync/ folder) for the user to choose.
An app removed on one computer is never removed by sync on another: the user is asked.
"""

from __future__ import annotations

import hashlib
import secrets
import time

from .. import apps, share

HISTORY = share.HISTORY


def syncable(a: dict) -> str:
    """Why sync leaves this app out ("" when it doesn't)."""
    if a.get("kind") != "appimage":
        return "Only apps the app builds itself are synced for now (not add-ons or source code)."
    why = share.exportable(a)
    if why:
        return why
    if not a.get("split"):
        return "It's from before changes were kept one by one: build it once, and it's synced."
    return ""


def prepared(a: dict) -> dict:
    """The app with its share id and revisions kept (share.lineage makes them anew each time otherwise)."""
    if a.get("share") and all(c.get("rev") for c in a.get("changes", [])):
        return a
    return apps.save(share.lineage(a))


def bundle(a: dict) -> bytes:
    return share.pack(a, exported=0)


def summary(a: dict, data: bytes) -> dict:
    """What another computer is told of one app (and what a base keeps)."""
    return {"share": a["share"]["id"], "name": a["name"], "digest": hashlib.sha256(data).hexdigest(),
            "base_ref": a.get("base_ref", ""), "build": a["share"]["build"]["id"],
            "changes": {c["id"]: c["rev"]["id"] for c in a["changes"]}}


def local() -> dict[str, tuple[dict, dict, bytes]]:
    """This computer's apps that are synced: {share id: (app, summary, bundle)}."""
    out = {}
    for a in apps.list_all():
        if syncable(a):
            continue
        a = prepared(a)
        try:
            data = bundle(a)
        except share.ShareError:
            continue
        out[a["share"]["id"]] = (a, summary(a, data), data)
    return out


def plan(mine: dict | None, theirs: dict | None, base: dict | None) -> str:
    """What to do with one app, from its summaries here, there and when the two last agreed:
    "same"; "keep" (changed here only: the other computer takes it when it pulls); "take" (changed
    there only); "merge" (changed on both, or never agreed on); "new" (there only, never here);
    "back" (removed here, but changed there since: made again here, nothing being lost); "gone_here"
    (removed here, as it was there: nothing); "gone_there" (removed there, as it was here: ask);
    "only_here" (nothing to do)."""
    if mine and theirs:
        if mine["digest"] == theirs["digest"]:
            return "same"
        if base and theirs["digest"] == base["digest"]:
            return "keep"
        if base and mine["digest"] == base["digest"]:
            return "take"
        return "merge"
    if mine:
        if base and mine["digest"] == base["digest"]:
            return "gone_there"
        return "only_here"
    if theirs:
        if base is None:
            return "new"
        return "gone_here" if theirs["digest"] == base["digest"] else "back"
    return "same"


def decide(mine: dict | None, theirs: dict | None, base: str | None) -> str:
    """One change (or the build script), from its revisions here and there (dicts: id, history) and
    its revision's id when the two last agreed: "mine", "theirs", "drop" or "conflict"."""
    if mine and theirs:
        if mine["id"] == theirs["id"]:
            return "mine"
        if base == mine["id"]:
            return "theirs"
        if base == theirs["id"]:
            return "mine"
        return {"theirs_newer": "theirs", "mine_newer": "mine"}.get(share._how(mine, theirs), "conflict")
    if mine:
        return "drop" if base == mine["id"] else "mine"     # removed there as it was here; else here's own
    if theirs:
        return "drop" if base == theirs["id"] else "theirs"
    return "drop"


def merged_rev(mine: dict, theirs: dict) -> dict:
    """A revision after both (the user's choice in a conflict): its history holds each side's."""
    history = list(dict.fromkeys([*mine.get("history", []), mine["id"], *theirs.get("history", []), theirs["id"]]))
    return {"id": secrets.token_hex(6), "history": history[-HISTORY:]}


def _clash(name: str, share_id: str) -> bool:
    return any(apps.slug(x["name"]) == apps.slug(name) and (x.get("share") or {}).get("id") != share_id
               for x in apps.list_all())


def _series(app_id: str, changes: list[dict]) -> None:
    apps.write_file(app_id, "series.patch", "".join(apps.read_file(app_id, f"changes/{c['id']}.patch") for c in changes))


def _remove_file(app_id: str, name: str) -> None:
    (apps.dir_of(app_id) / name).unlink(missing_ok=True)


def create(got: dict, peer_id: str, peer_name: str) -> dict:
    """An app another computer has, made here: built here when the user says so."""
    theirs, files = got["app"], got["files"]
    name = theirs["name"]
    if _clash(name, theirs["share"]["id"]):
        name = f"{theirs['name']} ({peer_name})"[:80]
        n = 2
        while _clash(name, theirs["share"]["id"]):
            name, n = f"{theirs['name']} ({peer_name} {n})"[:80], n + 1
    now = time.time()
    changes = [{**c, "patch_ids": [], "added": now} for c in theirs["changes"]]
    sh = theirs["share"]
    new = apps.create(name, "appimage", theirs["upstream"], base_ref=theirs["base_ref"], packages=theirs["packages"],
                      changes=changes, split=True,
                      share={"id": sh["id"], "build": sh["build"], "works_on": sh["works_on"], "shared": []},
                      synced={"from": peer_name, "peer": peer_id, "at": now, "changes": [c["id"] for c in changes],
                              "built": False, "new": True})
    share.Sharing._write(new["id"], files, changes)
    return new


def combine(a: dict, got: dict, base: dict | None, peer_id: str, peer_name: str) -> tuple[dict, dict]:
    """This computer's app with what the other had (`got`: share.read of its bundle), change by change.
    Returns the app, saved, and what came of it: {"took", "dropped", "conflicts", "build", "release"}."""
    a = share.lineage(a)
    theirs, files = got["app"], got["files"]
    base = base or {}
    known = base.get("changes") or {}
    mine_c = {c["id"]: c for c in a["changes"]}
    theirs_c = {c["id"]: c for c in theirs["changes"]}
    order = [c["id"] for c in a["changes"]] + [c["id"] for c in theirs["changes"] if c["id"] not in mine_c]
    synced = dict(a.get("synced") or {})
    conflicts = {c["id"]: c for c in synced.get("conflicts", [])}
    now = time.time()
    out = {"took": [], "dropped": [], "conflicts": [], "build": "", "release": ""}
    changes = []
    for cid in order:
        m, t = mine_c.get(cid), theirs_c.get(cid)
        how = decide(m and m["rev"], t and t["rev"], known.get(cid))
        if how == "theirs":
            apps.write_file(a["id"], f"changes/{cid}.patch", files[f"changes/{cid}.patch"])
            if files.get(f"changes/{cid}.md", "").strip():
                apps.write_file(a["id"], f"changes/{cid}.md", files[f"changes/{cid}.md"])
            else:
                _remove_file(a["id"], f"changes/{cid}.md")
            changes.append({**(m or {"added": now}), "id": cid, "title": t["title"], "rev": t["rev"], "patch_ids": []})
            out["took"].append(cid)
        elif how == "drop":
            if m:
                _remove_file(a["id"], f"changes/{cid}.patch")
                _remove_file(a["id"], f"changes/{cid}.md")
                out["dropped"].append(cid)
        elif how == "conflict":
            changes.append(m)
            apps.write_file(a["id"], f"sync/{cid}.patch", files[f"changes/{cid}.patch"])
            if files.get(f"changes/{cid}.md", "").strip():
                apps.write_file(a["id"], f"sync/{cid}.md", files[f"changes/{cid}.md"])
            conflicts[cid] = {"id": cid, "title": t["title"], "rev": t["rev"], "from": peer_name, "peer": peer_id, "at": now}
            out["conflicts"].append(cid)
        else:
            changes.append(m)
        if how != "conflict" and cid in conflicts:
            conflicts.pop(cid)              # no longer two versions (the other computer took this one's, or one after)
            _remove_file(a["id"], f"sync/{cid}.patch")
            _remove_file(a["id"], f"sync/{cid}.md")
    if len(changes) > apps.MAX_CHANGES:
        raise share.ShareError(f"Together they'd have more than {apps.MAX_CHANGES} changes.")
    sh = dict(a["share"])
    how = decide(sh["build"], theirs["share"]["build"], base.get("build"))
    if how == "theirs":
        apps.write_file(a["id"], "build.sh", files["build.sh"])
        sh["build"], out["build"] = theirs["share"]["build"], "theirs"
        conflicts.pop("build", None)
        _remove_file(a["id"], "sync/build.sh")
    elif how == "conflict":
        apps.write_file(a["id"], "sync/build.sh", files["build.sh"])
        conflicts["build"] = {"id": "build", "title": "The build script", "rev": theirs["share"]["build"],
                              "from": peer_name, "peer": peer_id, "at": now}
        out["build"] = "conflict"
    elif "build" in conflicts and sh["build"]["id"] == theirs["share"]["build"]["id"]:
        conflicts.pop("build")
        _remove_file(a["id"], "sync/build.sh")
    name, release = a["name"], a.get("base_ref", "")
    if base and name == base.get("name") and theirs["name"] != name and not _clash(theirs["name"], sh["id"]):
        name = theirs["name"]
    if theirs["base_ref"] != release and (not base or release == base.get("base_ref")):
        # made to fit a release there (by that computer's own build, or its assistant), the changes with it:
        # this computer builds that release from them, rather than fitting them again itself
        release, out["release"] = theirs["base_ref"], theirs["base_ref"]
    known_works = {(w["system"], w["sig"]) for w in sh.get("works_on", [])}
    sh["works_on"] = [*sh.get("works_on", []), *(w for w in theirs["share"]["works_on"]
                                                  if (w["system"], w["sig"]) not in known_works)][-50:]
    rebuilt = bool(out["took"] or out["dropped"] or out["build"] == "theirs" or out["release"])
    if rebuilt or out["conflicts"] or out["build"] == "conflict" or conflicts != {c["id"]: c for c in synced.get("conflicts", [])}:
        synced = {**synced, "from": peer_name, "peer": peer_id, "at": now,
                  "changes": sorted(set(synced.get("changes", [])) | set(out["took"])),
                  "built": False if rebuilt else synced.get("built", True), "conflicts": list(conflicts.values())}
    packages = sorted(set(a.get("packages") or []) | set(theirs["packages"]))
    a = apps.save({**a, "name": name, "base_ref": release, "changes": changes, "share": sh, "packages": packages,
                   **({"synced": synced} if synced else {})})
    _series(a["id"], changes)
    return a, out


def resolve(app_id: str, item: str, keep: str) -> dict:
    """The user's choice in a conflict: `item` a change's id or "build"; `keep` "mine" or "theirs"."""
    a = share.lineage(apps.load(app_id) or {})
    synced = dict(a.get("synced") or {})
    conflicts = {c["id"]: c for c in synced.get("conflicts", [])}
    c = conflicts.pop(item, None)
    if c is None or keep not in ("mine", "theirs"):
        raise share.ShareError("There's no such choice to make any more.")
    rebuild = False
    if item == "build":
        sh = dict(a["share"])
        if keep == "theirs":
            apps.write_file(app_id, "build.sh", apps.read_file(app_id, "sync/build.sh"))
            sh["build"], rebuild = c["rev"], True
        else:
            sh["build"] = merged_rev(sh["build"], c["rev"])
        _remove_file(app_id, "sync/build.sh")
        a = {**a, "share": sh}
    else:
        changes = []
        for ch in a["changes"]:
            if ch["id"] == item:
                if keep == "theirs":
                    apps.write_file(app_id, f"changes/{item}.patch", apps.read_file(app_id, f"sync/{item}.patch"))
                    notes = apps.read_file(app_id, f"sync/{item}.md")
                    if notes.strip():
                        apps.write_file(app_id, f"changes/{item}.md", notes)
                    ch, rebuild = {**ch, "title": c["title"], "rev": c["rev"], "patch_ids": []}, True
                else:
                    ch = {**ch, "rev": merged_rev(ch["rev"], c["rev"])}
            changes.append(ch)
        _remove_file(app_id, f"sync/{item}.patch")
        _remove_file(app_id, f"sync/{item}.md")
        a = {**a, "changes": changes}
        _series(app_id, changes)
    synced = {**synced, "conflicts": list(conflicts.values()),
              **({"built": False, "changes": sorted(set(synced.get("changes", [])) | {item})} if rebuild else {})}
    return apps.save({**a, "synced": synced})
