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

from .. import podmansetup
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
            await proc.wait()
        raise
    return rc, "".join(out)


async def image_exists(tag: str) -> bool:
    rc, _ = await run([podman(), "image", "exists", tag])
    return rc == 0


async def build_image(on_line: Callable[[str], None] | None = None) -> str:
    """Build the workspace image if this exact one doesn't exist yet. Returns its tag."""
    tag = image_tag()
    if await image_exists(tag):
        return tag
    cli = bundled_cli()
    digest = await asyncio.to_thread(lambda: hashlib.sha256(cli.read_bytes()).hexdigest())
    if digest != pins.CLAUDE_SHA256:
        raise PodmanError(f"The Claude Code CLI bundled with claude-agent-sdk ({digest[:16]}…) isn't the pinned one "
                          f"({pins.CLAUDE_SHA256[:16]}…). Update workspace/pins.py deliberately with the SDK.")
    with tempfile.TemporaryDirectory(prefix="dvm-image-") as ctx:
        for f in ("Containerfile", "dvm-entry"):
            shutil.copy2(IMAGE_DIR / f, Path(ctx) / f)
        try:
            Path(ctx, "claude").hardlink_to(cli)
        except OSError:
            await asyncio.to_thread(shutil.copy2, cli, Path(ctx) / "claude")
        argv = [podman(), "build", "-t", tag, "-v", f"{_ca_bundle()}:/hostca.crt:ro,Z",
                "--label", f"{LABEL}=image"]
        for key in ("BASE_IMAGE", "APT_SNAPSHOT", "APPIMAGETOOL_URL", "APPIMAGETOOL_SHA256", "RUNTIME_URL",
                    "RUNTIME_SHA256", "CLAUDE_SHA256"):
            argv += ["--build-arg", f"{key}={getattr(pins, key)}"]
        argv += ["-f", str(Path(ctx) / "Containerfile"), ctx]
        rc, out = await run(argv, timeout=3600, on_line=on_line)
    if rc != 0:
        raise PodmanError("Building the workspace image failed:\n" + out[-3000:])
    return tag


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


OLD_SANDBOX = "dla-sandbox"               # the sandbox's name before the app was renamed (DA Linux Agent)
NEW_SANDBOX = "dvm-sandbox"               # its name now: the only one the old one is ever moved into
OLD_IMAGE_REPO = "localhost/dalinuxagent-workspace"


async def move_old_sandbox(name: str, old: str = OLD_SANDBOX, old_images: str = OLD_IMAGE_REPO) -> str:
    """Once, after the rename: the old sandbox's volumes (the assistant's files, and the Claude Code
    sessions old chats resume) copied into this one's, then the old container, volumes and images
    removed. Owners, modes and links come through (podman volume export/import). Returns "moved",
    "" (nothing to move) or the reason it failed: the old volumes are kept then, and the sandbox
    starts empty (the user's apps live outside it).
    The user's own old sandbox goes into the app's own sandbox only, never another (a test's
    sandbox once took it, and the test then removed it with its own)."""
    if old == OLD_SANDBOX and name != NEW_SANDBOX:
        return ""
    pairs = list(zip(volume_names(old), volume_names(name)))
    have = [await run([podman(), "volume", "exists", v]) for pair in pairs for v in pair]
    if have[0][0] != 0 or any(rc == 0 for rc, _ in have[1::2]):
        return ""                               # no old sandbox, or this one has volumes already
    await run([podman(), "rm", "-f", "-t", "5", old, check_name(old)], timeout=60)
    for src, dest in pairs:
        if (await run([podman(), "volume", "exists", src]))[0] != 0:
            continue
        rc, out = await run([podman(), "volume", "create", dest])
        if rc == 0:
            r, w = os.pipe()
            try:
                exp = await asyncio.create_subprocess_exec(podman(), "volume", "export", src, stdout=w,
                                                           stderr=asyncio.subprocess.PIPE)
                imp = await asyncio.create_subprocess_exec(podman(), "volume", "import", dest, "-", stdin=r,
                                                           stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
            finally:
                os.close(r)
                os.close(w)
            (_, e1), (_, e2) = await asyncio.gather(exp.communicate(), imp.communicate())
            rc, out = (exp.returncode or imp.returncode), (e1 + e2).decode(errors="replace")
        if rc != 0:
            for _, d in pairs:
                await run([podman(), "volume", "rm", "-f", d], timeout=60)
            return f"copying {src} failed: {out.strip()[-500:]}"
    for src, _ in pairs:
        await run([podman(), "volume", "rm", "-f", src], timeout=60)
    rc, out = await run([podman(), "images", "--format", "{{.Repository}}:{{.Tag}}", old_images])
    for tag in out.split() if rc == 0 else []:
        await run([podman(), "image", "rm", tag], timeout=120)    # not forced: one still in use stays
    return "moved"


async def prune_images(keep: str) -> list[str]:
    """Remove the sandbox images of earlier versions of the app (and from before its rename): each is
    a few GB. Not forced: one a container still uses stays. Returns those removed."""
    removed = []
    for repo in (IMAGE_REPO, OLD_IMAGE_REPO):
        rc, out = await run([podman(), "images", "--format", "{{.Repository}}:{{.Tag}}", repo])
        for tag in out.split() if rc == 0 else []:
            if tag != keep and tag.startswith(f"{repo}:"):
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
# filled from elsewhere (the move from DA Linux Agent's sandbox) kept root's, and the agent then
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
