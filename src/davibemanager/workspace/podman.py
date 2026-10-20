"""The builder's workspace container, through rootless Podman.

Each project with a workspace gets one container (`dvm-<project id>`) and three named volumes
(`-work` at /work, `-home` at /home/agent, and `-mirrors` at /var/lib/dvm, the official
repositories' copies, which the agent can read but not change). Nothing from the user's home is
mounted: the only host path inside is the project's gateway directory (two Unix sockets,
gateway.py). The container has no network of its own (--network=none); everything goes through
the gateway.

The container has no capabilities at all (podman gives a non-root --user whatever --cap-add
names, ambient set included, so nothing is added) and no-new-privileges, so the agent (uid 1000)
can't gain any. Only the app's own root exec (`exec_root`, used to install packages) runs with
capabilities, those of root in the container's user namespace; the agent can't start one. The
official repositories' copies are fetched by a user of their own (`exec_mirror`), without any.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from .. import podmansetup
from ..config import data_dir
from . import pins

IMAGE_REPO = "localhost/davibemanager-workspace"
LABEL = "au.com.digitalarchon.davibemanager.project"
IMAGE_DIR = Path(__file__).parent / "image"
GATEWAY_MOUNT = "/run/dvm"
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ROOT_ENV = ("-e", f"PATH={SYSTEM_PATH}", "-e", "HOME=/root")
# The app's own commands as the agent's user (exec_agent): what they print is what the app checks a
# delivery by, so nothing of the agent's may stand in for them. The image's PATH starts with the
# agent's ~/.local/bin (a "git" or "python3" there would answer instead), its ~/.gitconfig could
# rewrite the official repository's address (url.*.insteadOf), and a repository's own settings could
# run programs (hooks, fsmonitor) or make commits look like others (replace refs, grafts). Settings
# given in the environment come before the repository's own.
AGENT_ENV = (
    "-e", f"PATH={SYSTEM_PATH}", "-e", "HOME=/home/agent", "-e", "GIT_CONFIG_GLOBAL=/dev/null",
    "-e", "GIT_NO_REPLACE_OBJECTS=1", "-e", "GIT_GRAFT_FILE=/nonexistent/dvm-no-grafts", "-e", "GIT_TERMINAL_PROMPT=0",
    "-e", "GIT_CONFIG_COUNT=3",
    "-e", "GIT_CONFIG_KEY_0=core.hooksPath", "-e", "GIT_CONFIG_VALUE_0=/dev/null",
    "-e", "GIT_CONFIG_KEY_1=core.fsmonitor", "-e", "GIT_CONFIG_VALUE_1=false",
    "-e", "GIT_CONFIG_KEY_2=diff.external", "-e", "GIT_CONFIG_VALUE_2=",
)
# The official repositories' copies (the mirrors) are fetched as a user of their own, neither the
# agent (who must not change them) nor root (git talking to a server a shared file names, with
# every capability: in rootless Podman, root in the container is this computer's user).
MIRROR_USER = "999:999"
MIRROR_HOME = "/var/lib/dvm"
# seconds the output of a command that has exited may take to end (see run)
LINGER = 2


class PodmanError(RuntimeError):
    pass


class BuildError(PodmanError):
    """The image's build failed: `summary` says why in a sentence or two, `kind` what sort of trouble
    ("server": the package server refused, "network": it couldn't be reached, "certificate", or
    "other"), `host` where, and the exception's text adds the last of what the build printed."""

    def __init__(self, summary: str, details: str, *, kind: str = "other", host: str = ""):
        super().__init__(f"{summary}\n\nWhat the build printed last:\n{details}" if details else summary)
        self.summary, self.details, self.kind, self.host = summary, details, kind, host


def podman() -> str:
    path = shutil.which("podman")
    if not path:
        raise PodmanError(podmansetup.message() or "Podman isn't installed.")
    return path


async def works() -> str:
    """Whether rootless Podman runs for this user: "" if so, else what it said."""
    try:
        code, out = await run([podman(), "info", "--format", "{{.Host.Security.Rootless}}"], timeout=60)
    except (OSError, PodmanError) as e:
        return str(e)
    return "" if code == 0 and out.strip() == "true" else (out.strip() or f"podman info failed ({code})")[-1500:]


def volume_names(name: str) -> tuple[str, str]:
    return f"{name}-work", f"{name}-home"


def mirrors_volume(name: str) -> str:
    """The official repositories' copies: in a volume of their own, so the app's clean containers
    (start_check) can read them too, and nothing the agent runs can change them."""
    return f"{name}-mirrors"


def image_tag() -> str:
    """The workspace image's tag: a hash of everything it is built from."""
    h = hashlib.sha256()
    for f in ("Containerfile", "dvm-entry"):
        h.update((IMAGE_DIR / f).read_bytes())
    h.update(Path(pins.__file__).read_bytes())
    return f"{IMAGE_REPO}:{h.hexdigest()[:12]}"


# Where the image's packages come from: the dated snapshot (pins.py), or, only when the user chose it for
# when the snapshot server is unavailable, Ubuntu's live archive or a mirror of it. Either way apt checks
# every package against Ubuntu's signing key; only the snapshot gives the exact pinned versions.
SNAPSHOT_URI = f"https://snapshot.ubuntu.com/ubuntu/{pins.APT_SNAPSHOT}/"
ARCHIVE_URI = "https://archive.ubuntu.com/ubuntu/"
SOURCE_LABEL = "au.com.digitalarchon.davibemanager.apt-source"


def apt_cache_dir() -> Path:
    """apt's downloads while the image is built (mounted at /var/cache/apt/archives): what a failed
    build fetched is kept for the next one; a finished build empties it."""
    return data_dir() / "image-apt-cache"


def bundled_cli() -> Path:
    """The Claude Code binary that ships in the installed claude-agent-sdk."""
    import claude_agent_sdk
    path = Path(claude_agent_sdk.__file__).parent / "_bundled" / "claude"
    if not path.is_file():
        raise PodmanError(f"The Claude Code CLI isn't bundled with claude-agent-sdk here ({path}).")
    return path


def _ca_bundle() -> str:
    for ca in ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"):
        if Path(ca).is_file():
            return ca
    raise PodmanError("No CA certificate bundle found on this system (needed to build the workspace image).")


async def run(argv: list[str], *, timeout: float = 120, input: bytes | None = None,
              on_line: Callable[[str], None] | None = None) -> tuple[int, str]:
    """Run a podman command; returns (exit code, combined output)."""
    proc = await asyncio.create_subprocess_exec(
        *argv, stdin=asyncio.subprocess.PIPE if input is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    out: list[str] = []

    async def read():
        while line := await proc.stdout.readline():
            text = line.decode("utf-8", errors="replace")
            out.append(text)
            if on_line:
                on_line(text.rstrip("\n"))

    async def pump():
        reader = asyncio.ensure_future(read())
        try:
            if input is not None:
                proc.stdin.write(input)
                await proc.stdin.drain()
                proc.stdin.close()
            # What a command leaves running can hold its output open for good: `podman start`'s
            # conmon did, in the app (not in a shell), so the start waited out its whole timeout.
            # proc.wait() waits for the output to close too, so the exit is watched for instead.
            while proc.returncode is None and not reader.done():
                await asyncio.sleep(0.05)
            if not reader.done():
                done, _ = await asyncio.wait([reader], timeout=LINGER)
                if not done:
                    pipe = proc._transport.get_pipe_transport(1)
                    if pipe is not None:
                        pipe.close()
            return await proc.wait()
        finally:
            reader.cancel()

    try:
        rc = await asyncio.wait_for(pump(), timeout)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        if proc.returncode is None:
            proc.kill()
            # proc.wait() ends only once every pipe is closed too, and something the command started
            # (conmon, a build's child) may hold them open after it: they are closed here, not waited for
            for fd in (0, 1):
                pipe = proc._transport.get_pipe_transport(fd)
                if pipe is not None:
                    pipe.close()
            await proc.wait()
        raise
    return rc, "".join(out)


async def image_exists(tag: str) -> bool:
    rc, _ = await run([podman(), "image", "exists", tag])
    return rc == 0


async def build_image(on_line: Callable[[str], None] | None = None, *, source: str = SNAPSHOT_URI) -> str:
    """Build the workspace image if this exact one doesn't exist yet, its packages from `source`.
    Returns its tag. A failed build raises BuildError, saying why."""
    tag = image_tag()
    if await image_exists(tag):
        return tag
    cli = bundled_cli()
    digest = await asyncio.to_thread(lambda: hashlib.sha256(cli.read_bytes()).hexdigest())
    if digest != pins.CLAUDE_SHA256:
        raise PodmanError(f"The Claude Code CLI bundled with claude-agent-sdk ({digest[:16]}…) isn't the pinned one "
                          f"({pins.CLAUDE_SHA256[:16]}…). Update workspace/pins.py deliberately with the SDK.")
    cache = apt_cache_dir()
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="dvm-image-") as ctx:
        for f in ("Containerfile", "dvm-entry"):
            shutil.copy2(IMAGE_DIR / f, Path(ctx) / f)
        try:
            Path(ctx, "claude").hardlink_to(cli)
        except OSError:
            await asyncio.to_thread(shutil.copy2, cli, Path(ctx) / "claude")
        argv = [podman(), "build", "-t", tag, "-v", f"{_ca_bundle()}:/hostca.crt:ro,Z",
                "-v", f"{cache}:/var/cache/apt/archives:Z", "--label", f"{LABEL}=image", "--label", f"{SOURCE_LABEL}={source}",
                "--build-arg", f"APT_URI={source}"]
        for key in ("BASE_IMAGE", "APPIMAGETOOL_URL", "APPIMAGETOOL_SHA256", "RUNTIME_URL",
                    "RUNTIME_SHA256", "CLAUDE_SHA256"):
            argv += ["--build-arg", f"{key}={getattr(pins, key)}"]
        argv += ["-f", str(Path(ctx) / "Containerfile"), ctx]
        before, scratch = await build_containers(), _build_scratch()
        rc = None
        try:
            rc, out = await run(argv, timeout=3600, on_line=on_line)
        finally:
            if rc != 0:
                # a build that failed, or was stopped, leaves a Buildah container for each step it began,
                # and its scratch folders (one holds a copy of the build's files, the CLI's 200 MB among
                # them); stopping it gently doesn't help. Only those it made are removed. Its finished
                # steps' layers stay, so the next build starts from them
                await asyncio.shield(_remove_build_debris(before, scratch))
    if rc != 0:
        raise build_failure(out)
    return tag


async def build_containers() -> dict[str, str]:
    """Buildah's containers (builds' working containers, which `podman ps` shows only with --external):
    {id: its image's id}."""
    rc, out = await run([podman(), "ps", "-a", "--external", "--no-trunc", "--format", "{{.ID}}|{{.ImageID}}|{{.Status}}"])
    found = {}
    for line in out.splitlines() if rc == 0 else []:
        cid, _, rest = line.partition("|")
        image, _, status = rest.partition("|")
        if status.strip() == "Storage":
            found[cid] = image
    return found


UNMOUNT_AND_REMOVE = r"""
for d; do
  for m in "$d"/overlay/*/merge; do [ -d "$m" ] && umount "$m" 2>/dev/null; done
  rm -rf -- "$d"
done
"""


def _build_scratch() -> set[Path]:
    """Buildah's scratch folders (in TMPDIR, else /var/tmp, as Buildah chooses)."""
    tmp = Path(os.environ.get("TMPDIR") or "/var/tmp")
    try:
        return {p for p in tmp.glob("buildah*") if p.is_dir() and not p.is_symlink()}
    except OSError:
        return set()


async def _remove_build_debris(containers: dict[str, str], scratch: set[Path]) -> None:
    """What a failed or stopped build left, of its own: what wasn't there before it began."""
    await _remove_containers([c for c in await build_containers() if c not in containers])
    new = sorted(str(p) for p in _build_scratch() - scratch)
    if new:
        # in Podman's user namespace: what the build's steps wrote there belongs to this user's subordinate
        # ids, and the build context's overlay is still mounted there
        await run([podman(), "unshare", "sh", "-c", UNMOUNT_AND_REMOVE, "sh", *new], timeout=120)


async def _remove_containers(ids: list[str]) -> None:
    if ids:
        await run([podman(), "rm", "-f", *ids], timeout=120)


async def image_source(tag: str) -> str:
    """Where an image's packages came from (SOURCE_LABEL): "" if it doesn't say."""
    rc, out = await run([podman(), "image", "inspect", "--format", '{{index .Labels "%s"}}' % SOURCE_LABEL, tag])
    value = out.strip() if rc == 0 else ""
    return "" if value == "<no value>" else value


class BuildWatch:
    """A build's output, read as it comes: how far apt's downloads are, and any trouble it meets,
    in words for the window. The same reading explains a build that failed (build_failure)."""

    _GET = re.compile(r"^Get:(\d+) ")
    _TOTAL = re.compile(r"\b(\d+) newly installed\b")
    _FAILED = re.compile(r"^(?:Err:\d+|E: Failed to fetch|W: Failed to fetch) +(\S+)")
    _STATUS = re.compile(r"\b([1-5]\d\d) +([A-Za-z][A-Za-z -]*?) *\[IP: ")
    _RETRY = re.compile(r"^dvm-retry: try (\d+) of (\d+) (?:in (\d+)s|now)")
    _HOST = re.compile(r"(?:resolving|connect to|lookup) '?([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
    _NETWORK = ("Temporary failure resolving", "Could not resolve", "Could not connect", "Connection timed out",
                "Connection failed", "Network is unreachable", "No route to host", "no such host", "i/o timeout")
    _CERT = ("Certificate verification failed", "certificate verify failed", "x509:")

    def __init__(self) -> None:
        self.got = self.total = self.failures = 0
        self.host = self.status = ""
        self.kind = ""               # the latest trouble: "server", "network", "certificate" or "http"
        self.retry: tuple[int, int, int] | None = None     # (try, of, seconds it waits before it; 0 once it's begun)
        self.step = ""

    def feed(self, line: str) -> None:
        text = line.strip()
        if line.startswith("STEP "):
            self.step, self.kind, self.retry = line, "", None
            self.got = self.total = self.failures = 0
            return
        if m := self._RETRY.match(text):
            self.retry = (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))
            if not m.group(3):
                self.got = self.failures = 0     # a new try: apt counts afresh
            return
        if m := self._GET.match(text):
            self.got = int(m.group(1))
        elif m := self._TOTAL.search(text):
            self.total = int(m.group(1))
        if m := self._FAILED.match(text):
            self.failures += 1 if text.startswith("Err:") else 0
            self.host = urlparse(m.group(1)).hostname or self.host
        if m := self._STATUS.search(text):
            code = int(m.group(1))
            self.status = f"{code} {m.group(2).strip()}"
            self.kind = "server" if code >= 500 or code == 429 else "http"
        elif any(x in text for x in self._CERT):
            self.kind, self.status = "certificate", self._reason(text, self._CERT)
        elif any(x in text for x in self._NETWORK):
            self.kind, self.status = "network", self._reason(text, self._NETWORK)
            if m := self._HOST.search(text):
                self.host = m.group(1)

    @staticmethod
    def _reason(text: str, phrases: tuple) -> str:
        """Why, without the address apt puts before it (the same trouble reads the same on every line)."""
        at = min(i for i in (text.find(x) for x in phrases) if i >= 0)
        return text[at:].strip()[:160]

    def where(self) -> str:
        if self.host == urlparse(SNAPSHOT_URI).hostname:
            return f"Ubuntu's snapshot server ({self.host})"
        if self.host == urlparse(ARCHIVE_URI).hostname:
            return f"Ubuntu's archive ({self.host})"
        return f"the package server {self.host}" if self.host else "the package server"

    def progress(self) -> str:
        """What the build is doing, in a few words."""
        if self.got:
            return f"Downloading packages: {self.got} of {self.total}" if self.total >= self.got else \
                f"Downloading packages: {self.got} so far"
        return ""

    def trouble(self) -> str:
        """The trouble the build is meeting, while it carries on: "" when there's none."""
        if not self.kind:
            return ""
        what = {"server": f"{self.where()} is busy or down ({self.status})",
                "http": f"{self.where()} refused a download ({self.status})",
                "network": f"{self.where()} can't be reached ({self.status})",
                "certificate": f"the connection to {self.where()} couldn't be verified"}[self.kind]
        if self.failures > 1 and self.kind in ("server", "http"):
            what += f": {self.failures} downloads failed"
        if self.retry:
            n, of, secs = self.retry
            then = f"Waiting {secs} s before trying again (try {n} of {of})…" if secs else f"Trying again (try {n} of {of})…"
            return f"{what[0].upper()}{what[1:]}. {then}"
        return f"{what[0].upper()}{what[1:]}. It will be tried again…"


def _details(out: str, lines: int = 25) -> str:
    """The end of a build's output, without the RUN command podman repeats when a step fails (it's
    long, and says nothing of why)."""
    keep = []
    for line in out.splitlines():
        if line.startswith("Error: building at STEP"):
            m = re.search(r"(while running runtime: .*)$", line)
            line = "Error: the build step failed" + (f" ({m.group(1)})" if m else "")
        if line.strip():
            keep.append(line)
    return "\n".join(keep[-lines:])[-3000:]


def build_failure(out: str) -> BuildError:
    """Why a build failed, from what it printed."""
    w = BuildWatch()
    for line in out.splitlines():
        w.feed(line)
    details = _details(out)
    if w.kind == "server":
        tried = " It was tried again for about ten minutes." if w.retry else ""
        return BuildError(f"{w.where()} is busy or down: it answered {w.status}.{tried} Nothing is wrong with "
                          "your computer. Try again later.", details, kind="server", host=w.host)
    if w.kind == "network":
        return BuildError(f"{w.where()} couldn't be reached ({w.status}). Check that this computer is online, "
                          "then try again.", details, kind="network", host=w.host)
    if w.kind == "certificate":
        return BuildError(f"The connection to {w.where()} couldn't be verified (its certificate wasn't accepted), "
                          "so nothing was downloaded from it.", details, kind="certificate", host=w.host)
    if w.kind == "http":
        return BuildError(f"{w.where()} refused a download ({w.status}).", details, kind="other", host=w.host)
    return BuildError("Building the sandbox's image failed.", details)


def _check_limit(value: str, pattern: str, what: str) -> str:
    value = str(value).strip().lower()
    if not re.fullmatch(pattern, value):
        raise PodmanError(f"The workspace's {what} limit {value!r} isn't valid.")
    return value


def run_argv(name: str, image: str, gateway_dir: Path, *, project_id: str, memory: str = "8g",
             cpus: str = "4", pids: int = 4096, mounts: list[str] | None = None) -> list[str]:
    """`podman run` for a project's workspace: no network, no host paths but the gateway
    directory, no capabilities for the agent. `mounts`: its volumes (-v values), if not its own."""
    work, home = volume_names(name)
    mounts = mounts if mounts is not None else [f"{work}:/work", f"{home}:/home/agent", f"{mirrors_volume(name)}:{MIRROR_HOME}"]
    return [
        podman(), "run", "-d", "--name", name, "--hostname", "workspace",
        "--label", f"{LABEL}={project_id}",
        "--init",                                   # reap the builds' orphans
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit", str(int(pids)),
        "--memory", _check_limit(memory, r"\d+[bkmg]?", "memory"),
        "--cpus", _check_limit(cpus, r"\d+(\.\d+)?", "CPU"),
        "--user", "1000:1000",
        *(a for m in mounts for a in ("-v", m)),
        "-v", f"{gateway_dir}:{GATEWAY_MOUNT}:ro,z",          # its sockets: connecting needs no writing
        image,
    ]


_UNITS = {"": 1, "b": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30}


def wanted_limits(memory: str, cpus: str, pids: int) -> dict:
    """The limits a container is made with, as Podman records them (bytes, nano-CPUs, processes)."""
    m = re.fullmatch(r"(\d+)([bkmg]?)", _check_limit(memory, r"\d+[bkmg]?", "memory"))
    return {"memory": int(m.group(1)) * _UNITS[m.group(2)],
            "cpus": round(float(_check_limit(cpus, r"\d+(\.\d+)?", "CPU")) * 1e9), "pids": int(pids)}


async def limits(name: str) -> dict | None:
    """The limits the container was made with (what it gets again whenever it starts), or None."""
    rc, out = await run([podman(), "container", "inspect", "--format",
                         "{{.HostConfig.Memory}} {{.HostConfig.NanoCpus}} {{.HostConfig.PidsLimit}}", name])
    try:
        memory, cpus, pids = (int(x) for x in out.split())
    except ValueError:
        return None
    return {"memory": memory, "cpus": cpus, "pids": pids} if rc == 0 else None


async def update_limits(name: str, memory: str, cpus: str, pids: int) -> tuple[int, str]:
    """New limits for a running container, at once. Podman 4 doesn't record them, so the container
    gets the ones it was made with again when it next starts: Engine makes it again then."""
    w = wanted_limits(memory, cpus, pids)
    return await run([podman(), "update", "--memory", str(w["memory"]), "--memory-swap", str(2 * w["memory"]),
                      "--cpus", _check_limit(cpus, r"\d+(\.\d+)?", "CPU"), "--pids-limit", str(w["pids"]), name],
                     timeout=60)


async def state(name: str) -> str:
    """"running", "exited", "created", ..., or "missing"."""
    rc, out = await run([podman(), "container", "inspect", "--format", "{{.State.Status}}", name])
    return out.strip() if rc == 0 else "missing"


async def inspect_image(name: str) -> str:
    rc, out = await run([podman(), "container", "inspect", "--format", "{{.ImageName}}", name])
    return out.strip() if rc == 0 else ""


async def ensure_running(name: str, image: str, gateway_dir: Path, *, project_id: str, memory: str, cpus: str,
                         pids: int) -> str:
    """Start the project's container, creating it first if it doesn't exist. Returns its state."""
    current = await state(name)
    if current == "missing":
        rc, out = await run(run_argv(name, image, gateway_dir, project_id=project_id, memory=memory, cpus=cpus,
                                     pids=pids))
        if rc != 0:
            raise PodmanError("Could not create the workspace container:\n" + out[-2000:])
    elif current != "running":
        rc, out = await run([podman(), "start", name])
        if rc != 0:
            raise PodmanError("Could not start the workspace container:\n" + out[-2000:])
    return await state(name)


def check_name(sandbox: str) -> str:
    return f"{sandbox}-check"


async def start_check(sandbox: str, image: str, gateway_dir: Path, *, memory: str, cpus: str, pids: int) -> str:
    """A throwaway container for the app's own checks and builds: the sandbox's image as it was
    built, the same isolation and way out, nothing running in it but what the app runs, and of the
    sandbox's only its /work at /sandbox and its mirrors, both read-only (the app copies what it
    checks out of them first: nothing the agent leaves running can change it after). Its own /work
    and home are empty."""
    name = check_name(sandbox)
    await run([podman(), "rm", "-f", "-t", "3", name], timeout=60)
    work, _ = volume_names(sandbox)
    rc, out = await run(run_argv(name, image, gateway_dir, project_id="check", memory=memory, cpus=cpus, pids=pids,
                                 mounts=[f"{work}:/sandbox:ro", f"{mirrors_volume(sandbox)}:{MIRROR_HOME}:ro"]))
    if rc != 0:
        raise PodmanError("Could not start a clean container to build in:\n" + out[-2000:])
    return name


async def remove_check(sandbox: str) -> None:
    await run([podman(), "rm", "-f", "-t", "3", check_name(sandbox)], timeout=60)


async def has_mount(name: str, destination: str) -> bool:
    """Whether the container has something mounted at `destination` (one made before it had may not)."""
    rc, out = await run([podman(), "container", "inspect", "--format",
                         '{{range .Mounts}}{{if eq .Destination "%s"}}yes{{end}}{{end}}' % destination, name])
    return rc == 0 and out.strip() == "yes"


async def gateway_source(name: str) -> str:
    """The host directory mounted at /run/dvm in the container, or "" if none."""
    rc, out = await run([podman(), "container", "inspect", "--format",
                         '{{range .Mounts}}{{if eq .Destination "%s"}}{{.Source}}{{end}}{{end}}' % GATEWAY_MOUNT, name])
    return out.strip() if rc == 0 else ""


async def sees_gateway(name: str) -> bool:
    """Whether the gateway's sockets are visible inside the running container."""
    rc, _ = await run([podman(), "exec", name, "test", "-S", f"{GATEWAY_MOUNT}/model.sock", "-a", "-S",
                       f"{GATEWAY_MOUNT}/proxy.sock"], timeout=30)
    return rc == 0


async def recreate(name: str) -> None:
    """Remove the container but keep its volumes (all the assistant's files): the next start makes
    it afresh, with the current mounts and limits."""
    await run([podman(), "rm", "-f", "-t", "5", name], timeout=60)


async def logs(name: str, lines: int = 30) -> str:
    rc, out = await run([podman(), "logs", "--tail", str(lines), name], timeout=30)
    return out.strip()[-3000:]


async def stop(name: str) -> None:
    await run([podman(), "stop", "-t", "5", name], timeout=60)


async def remove(name: str) -> None:
    """Delete the container and its volumes: everything the builder had."""
    await run([podman(), "rm", "-f", "-t", "5", name], timeout=60)
    for vol in (*volume_names(name), mirrors_volume(name)):
        await run([podman(), "volume", "rm", "-f", vol], timeout=60)


APP_SANDBOX = "dvm-sandbox"               # the app's own sandbox (tests use others, and leave its images alone)


async def prune_images(keep: str) -> list[str]:
    """Remove the sandbox images of earlier versions of the app: each is a few GB. Not forced: one a
    container still uses stays. Returns those removed."""
    removed = []
    rc, out = await run([podman(), "images", "--format", "{{.Repository}}:{{.Tag}}", IMAGE_REPO])
    for tag in out.split() if rc == 0 else []:
        if tag != keep and tag.startswith(f"{IMAGE_REPO}:"):
            rc2, _ = await run([podman(), "image", "rm", tag], timeout=120)
            if rc2 == 0:
                removed.append(tag)
    return removed


async def exec_root(name: str, argv: list[str], *, timeout: float = 1800,
                    on_line: Callable[[str], None] | None = None) -> tuple[int, str]:
    """Run a command as root inside the container (the app's own use, never the agent's). The
    container itself has no capabilities, so this exec is given root's, within its user namespace.
    Its PATH and HOME are root's own: the image's PATH starts with the agent's ~/.local/bin, where an
    "apt-get", "git" or "sh" of the agent's would otherwise run as root."""
    return await run([podman(), "exec", "--privileged", "-u", "0", "-w", "/", *ROOT_ENV, name, *argv],
                     timeout=timeout, on_line=on_line)


# the agent's own folders: their tops belong to it. A volume made empty gets that from the image; one
# filled from elsewhere (copied in from another sandbox) keeps the owner it had, and the agent then
# couldn't make /work/.dvm, where the app hands it each app's files and takes its builds from
AGENT_FOLDERS = ("/work", "/home/agent")


async def own_folders(name: str) -> str:
    """Give the agent back the tops of its folders (only those, never what's in them) wherever they
    belong to someone else. Returns those changed ("" when none was)."""
    rc, out = await exec_root(name, ["find", *AGENT_FOLDERS, "-maxdepth", "0", "!", "-user", "agent",
                                     "-print", "-exec", "chown", "agent:agent", "{}", "+"], timeout=60)
    if rc != 0:
        raise PodmanError(f"The sandbox's folders couldn't be given to its user: {out.strip()[-300:]}")
    return out.strip()


async def exec_agent(name: str, argv: list[str], *, timeout: float = 120, input: bytes | None = None,
                     on_line: Callable[[str], None] | None = None, env: dict[str, str] | None = None) -> tuple[int, str]:
    """Run a command in the container as the agent's user (the app's own use: a port, a check), in
    AGENT_ENV (and `env`), from / (a repository the agent made of /work would otherwise be read for
    its settings)."""
    extra = [a for k, v in (env or {}).items() for a in ("-e", f"{k}={v}")]
    return await run([podman(), "exec", *(["-i"] if input is not None else []), "-w", "/", *AGENT_ENV, *extra, name, *argv],
                     timeout=timeout, input=input, on_line=on_line)


# The mirrors' folder made the mirrors user's. Podman gives a new volume to the container's user (the
# agent), so whatever is in a folder that isn't the mirrors user's yet may be the agent's: it is
# emptied (they are only copies, fetched again), never taken over. rm doesn't follow symlinks.
OWN_MIRRORS = r"""
set -eu
if [ "$(stat -c %u:%g "$1")" != "$2" ]; then
  find "$1" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
  chown "$2" "$1"
fi
chmod 755 "$1"
mkdir -p "$1/mirrors"
chown "$2" "$1/mirrors"
"""


async def own_mirrors(name: str) -> tuple[int, str]:
    """Make the mirrors' folder the mirrors user's (OWN_MIRRORS), as root."""
    return await exec_root(name, ["sh", "-c", OWN_MIRRORS, "sh", MIRROR_HOME, MIRROR_USER], timeout=120)


async def exec_mirror(name: str, argv: list[str], *, timeout: float = 1800) -> tuple[int, str]:
    """Run a command as the mirrors' own user (MIRROR_USER), without capabilities, its folder made
    its own first (own_mirrors)."""
    rc, out = await own_mirrors(name)
    if rc != 0:
        return rc, out
    return await run([podman(), "exec", "-u", MIRROR_USER, "-w", "/", "-e", f"PATH={SYSTEM_PATH}",
                      "-e", f"HOME={MIRROR_HOME}", "-e", "GIT_CONFIG_GLOBAL=/dev/null", "-e", "GIT_TERMINAL_PROMPT=0",
                      name, *argv], timeout=timeout)


async def put_file(name: str, path: str, data: bytes) -> None:
    """Write a file into the container, as the agent's user (so it can use it)."""
    rc, out = await run([podman(), "exec", "-i", "-w", "/", *AGENT_ENV, name, "/bin/sh", "-c",
                         'mkdir -p "$(dirname "$1")" && cat > "$1"', "sh", path], input=data, timeout=120)
    if rc != 0:
        raise PodmanError(f"Could not put {path} into the workspace: {out.strip()[-500:]}")


async def copy_out(name: str, src: str, dest: Path) -> None:
    """Copy a path out of the container. `podman cp` follows nothing outside the container."""
    rc, out = await run([podman(), "cp", f"{name}:{src}", str(dest)], timeout=600)
    if rc != 0:
        raise PodmanError(f"Could not copy {src} out of the workspace: {out.strip()[-500:]}")


def shell_argv(name: str) -> list[str]:
    """A terminal in the workspace, for the user to look around (as the agent's user)."""
    return [podman(), "exec", "-it", "--detach-keys=", "-w", "/work", "-e", "TERM=xterm-256color", name, "bash", "-l"]


async def list_containers() -> list[dict]:
    rc, out = await run([podman(), "ps", "-a", "--filter", f"label={LABEL}", "--format", "json"])
    if rc != 0:
        return []
    try:
        return json.loads(out or "[]")
    except ValueError:
        return []


# ---------------------------------------------------------------- removing it all (Settings → The sandbox)

async def remove_all(sandbox: str = APP_SANDBOX) -> list[str]:
    """Everything of the app's in Podman: its containers (the sandbox, its clean one, any other with the
    app's label) and their volumes, its images and the one they're built on, and the build's download
    cache. Nothing else of the user's. Returns what was removed."""
    removed = []
    # (rm -f succeeds for a name that isn't there: only what was there is said to be removed)
    names = {n for c in await list_containers() for n in c.get("Names") or []}
    names |= {n for n in (sandbox, check_name(sandbox)) if await state(n) != "missing"}
    rc, out = await run([podman(), "volume", "ls", "--format", "{{.Name}}"])
    volumes = set(out.split()) if rc == 0 else set()
    for name in sorted(names | {sandbox}):
        if (await run([podman(), "rm", "-f", "-t", "5", name], timeout=60))[0] == 0 and name in names:
            removed.append(name)
        for vol in (*volume_names(name), mirrors_volume(name)):
            if vol in volumes and (await run([podman(), "volume", "rm", "-f", vol], timeout=60))[0] == 0:
                removed.append(vol)
    rc, out = await run([podman(), "images", "--format", "{{.Repository}}:{{.Tag}}", IMAGE_REPO])
    for tag in [t for t in out.split() if t.startswith(f"{IMAGE_REPO}:")] if rc == 0 else []:
        if (await run([podman(), "image", "rm", "-f", tag], timeout=120))[0] == 0:
            removed.append(tag)
    removed += await _remove_build_leftovers()
    if (await run([podman(), "image", "rm", pins.BASE_IMAGE], timeout=120))[0] == 0:     # not forced: if in use, kept
        removed.append(pins.BASE_IMAGE.split("@")[0])
    if await clear_apt_cache():
        removed.append(str(apt_cache_dir()))
    return removed


async def _remove_build_leftovers() -> list[str]:
    """What builds of the app's image left: the untagged images of their steps, and the Buildah containers
    of steps a stopped build had begun. Theirs alone: each is built on the pinned base image, which is
    found by following their parents (nothing of the user's is built on that exact image by chance)."""
    rc, out = await run([podman(), "image", "inspect", "--format", "{{.Id}}", pins.BASE_IMAGE])
    base = out.strip() if rc == 0 else ""
    if not base:
        return []
    rc, out = await run([podman(), "images", "-a", "--no-trunc", "--format", "{{.ID}}|{{.Repository}}:{{.Tag}}"])
    tags = {}
    for line in out.splitlines() if rc == 0 else []:
        iid, _, tag = line.partition("|")
        tags[iid.removeprefix("sha256:")] = tag
    parents = {}
    if tags:
        rc, out = await run([podman(), "image", "inspect", "--format", "{{.Id}}|{{.Parent}}", *tags])
        for line in out.splitlines() if rc == 0 else []:
            iid, _, parent = line.partition("|")
            parents[iid] = parent.removeprefix("sha256:")

    def depth(iid: str) -> int:
        """How many steps above the base image `iid` is: 0 if it isn't built on it."""
        for n in range(1, 200):
            iid = parents.get(iid, "")
            if not iid:
                return 0
            if iid == base:
                return n
        return 0
    removed = []
    stale = [c for c, image in (await build_containers()).items() if image == base or depth(image)]
    await _remove_containers(stale)
    removed += [f"build container {c[:12]}" for c in stale]
    ours = sorted((i for i, tag in tags.items() if tag == "<none>:<none>" and depth(i)), key=depth, reverse=True)
    for iid in ours:                    # the last steps first: an image with others built on it can't go
        if (await run([podman(), "image", "rm", iid], timeout=120))[0] == 0:
            removed.append(f"build layer {iid[:12]}")
    return removed


async def clear_apt_cache() -> bool:
    """Delete the build's download cache. What apt wrote there as its own user belongs to one of this
    user's subordinate ids, so it's deleted inside Podman's user namespace."""
    cache = apt_cache_dir()
    if not cache.exists():
        return False
    await run([podman(), "unshare", "rm", "-rf", "--", str(cache)], timeout=120)
    return not cache.exists()


async def anything_else() -> list[str]:
    """What else this user has in Podman, once the app's things are gone: containers (Podman's and
    Buildah's), images and volumes. [] means Podman's storage holds nothing but leftovers."""
    found = []
    for what, argv in (("container", ["ps", "-a", "--external", "--format", "{{.Names}}"]),
                       ("image", ["images", "--format", "{{.Repository}}:{{.Tag}}"]),
                       ("volume", ["volume", "ls", "--format", "{{.Name}}"])):
        rc, out = await run([podman(), *argv], timeout=60)
        if rc != 0:
            return [f"Podman couldn't list its {what}s: {out.strip()[-200:]}"]
        found += [f"{what} {x}" for x in out.split() if x != "<none>:<none>"]
    return found


async def reset_storage() -> tuple[int, str]:
    """Delete all of this user's Podman storage (only when anything_else() found nothing of theirs)."""
    return await run([podman(), "system", "reset", "--force"], timeout=600)
