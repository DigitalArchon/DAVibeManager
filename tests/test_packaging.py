"""The AppImage build's definition, RECORD and the suite on what ships (packaging/): the wrapper
run whole against a Podman that only notes what it is asked, records.py on a package laid out as
pip leaves one, and test-locked.sh against an AppImage and a pip that are stand-ins, with nothing
downloaded. From DA Toolkit's tests/test_packaging.py (a8c43b3, 266a002, 60ef92d, Nov 2026); the
rest of the scripts' checks are in test_appimage_packaging.py."""

import base64
import csv
import hashlib
import importlib.util
import io
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / "packaging" / "appimage"
WRAPPER = (ROOT / "packaging" / "build-appimage.sh").read_text()
BUILD = (PACKAGING / "build.sh").read_text()
LOCKED = (ROOT / "packaging" / "test-locked.sh").read_text()
README = (ROOT / "packaging" / "README.md").read_text()


def _function(script: str, name: str) -> str:
    found = re.search(rf"^{name}\(\) \{{.*?^\}}\n", script, re.S | re.M)
    assert found, f"{name} is not where this test looks for it"
    return found.group(0)


def _commands(text: str) -> list[str]:
    """A script's commands, one to a line: a command continued over several lines is one."""
    return re.sub(r"\\\n\s*", " ", text).splitlines()


# ---------------------------------------------------------------- the build's definition, as committed

# Stands in for Podman: the builder image "exists", and a run is only noted. A lock run leaves
# a lock nobody has committed yet in its /out.
_PODMAN = """#!/bin/sh
printf '%s\\n' "$*" >> "$PODMAN_LOG"
if [ "$1" = run ]; then
    for arg in "$@"; do
        case "$arg" in *:/out:Z) out="${arg%:/out:Z}" ;; esac
        mode="$arg"
    done
    if [ "$mode" = lock ]; then echo "pytest==9.9.9" > "$out/test-requirements.lock"; fi
fi
exit 0
"""


def _stub(folder: Path, name: str, script: str) -> None:
    folder.mkdir(exist_ok=True)
    (folder / name).write_text(script if script.startswith("#!") else f"#!/bin/sh\n{script}\n")
    os.chmod(folder / name, 0o755)


def _git_env(tmp_path: Path, bin_dir: Path) -> dict:
    """git with no settings of this machine's, the stand-ins first on the path, and the build's
    cache and results under the test's own folder."""
    (tmp_path / "gitconfig").write_text("[user]\n\tname = T\n\temail = t@example.org\n")
    return {"PATH": f"{bin_dir}:{os.environ.get('PATH', '')}", "HOME": str(tmp_path), "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(tmp_path / "gitconfig"), "XDG_CACHE_HOME": str(tmp_path / "cache"),
            "DIST": str(tmp_path / "dist"), "PODMAN_LOG": str(tmp_path / "podman.log")}


def _commit_all(repo: Path, env: dict) -> None:
    for args in (("init", "-q"), ("add", "-A"), ("commit", "-q", "-m", "files")):
        subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True)


@pytest.fixture
def build_repo(tmp_path):
    """A repository with the wrapper and a build definition committed (the real pins and
    Containerfile), and the Podman above. Gives the repository, and a function that runs the
    wrapper there and returns how it ended and what Podman was asked."""
    if not shutil.which("git"):
        pytest.skip("no git")
    repo = tmp_path / "repo"
    (repo / "packaging" / "appimage").mkdir(parents=True)
    shutil.copy(ROOT / "packaging" / "build-appimage.sh", repo / "packaging")
    for name in ("pins.sh", "Containerfile", "build.sh", "sdists.lock"):
        shutil.copy(PACKAGING / name, repo / "packaging" / "appimage")
    (repo / "pyproject.toml").write_text('[project]\nname = "app"\nversion = "1.2.3"\n')
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("print('a')\n")
    _stub(tmp_path / "bin", "podman", _PODMAN)
    env = _git_env(tmp_path, tmp_path / "bin")
    _commit_all(repo, env)

    def build(mode, script="packaging/build-appimage.sh"):
        log = tmp_path / "podman.log"
        log.unlink(missing_ok=True)
        done = subprocess.run(["bash", script, mode], cwd=repo, env=env, capture_output=True, text=True, timeout=120)
        return done, (log.read_text().splitlines() if log.exists() else [])

    return repo, build


def _named(stderr: str) -> list[str]:
    return [line.strip() for line in stderr.splitlines() if line.startswith("  ")]


def test_a_commit_is_built_by_its_own_definition_in_the_builder_made_here(build_repo):
    repo, build = build_repo
    done, podman = build("build")
    assert done.returncode == 0, done.stderr
    assert "Nothing built" not in done.stderr and "Note:" not in done.stderr
    assert len(podman) == 2 and re.fullmatch(r"image exists davibemanager-appimage-builder:[0-9a-f]{12}", podman[0])
    # the image of that name on this machine and no other: Podman is never to ask a registry for it
    assert podman[1].startswith("run --rm --pull=never ") and podman[1].endswith(" build")
    assert f" {podman[0].split()[-1]} bash -c " in podman[1] and " -e VERSION=1.2.3 " in podman[1]
    # a source changed and not committed is not built, which the note says; nor is a file git doesn't
    # track any of the definition
    (repo / "src" / "app.py").write_text("print('b')\n")
    (repo / "packaging" / "appimage" / "notes.txt").write_text("to do\n")
    done, podman = build("build")
    assert done.returncode == 0 and len(podman) == 2
    assert "Note: uncommitted changes are not built" in done.stderr and "Nothing built" not in done.stderr


@pytest.mark.parametrize("mode", ["build", "check"])
def test_a_build_definition_that_is_not_the_commits_is_refused(build_repo, mode):
    """The wrapper read pins.sh (the base image's digest, the apt snapshot) and the Containerfile
    from the working tree to make the builder, and said "uncommitted changes are not built"."""
    repo, build = build_repo
    appimage = repo / "packaging" / "appimage"
    with open(appimage / "pins.sh", "a") as f:
        f.write('APT_SNAPSHOT="20270101T000000Z"\n')
    with open(appimage / "Containerfile", "a") as f:
        f.write("RUN true\n")
    (appimage / "sdists.lock").unlink()
    done, podman = build(mode)
    assert done.returncode == 1 and podman == [] and done.stdout == ""
    assert done.stderr.startswith("Nothing built.") and "HEAD (" in done.stderr and "git stash" in done.stderr
    assert _named(done.stderr) == ["packaging/appimage/Containerfile", "packaging/appimage/pins.sh",
                                   "packaging/appimage/sdists.lock"]
    assert not (repo.parent / "dist").exists() or not os.listdir(repo.parent / "dist")


def test_the_script_that_runs_must_be_the_commits_too(build_repo, tmp_path):
    repo, build = build_repo
    committed = (repo / "packaging" / "build-appimage.sh").read_text()
    elsewhere = tmp_path / "another-checkout.sh"
    elsewhere.write_text(committed.replace('mode="${1:-build}"', 'mode="${1:-check}"'))
    assert elsewhere.read_text() != committed
    done, podman = build("build", script=str(elsewhere))       # run from this repository, which is clean
    assert done.returncode == 1 and podman == [] and _named(done.stderr) == ["packaging/build-appimage.sh"]
    (repo / "packaging" / "build-appimage.sh").write_text(committed + "# changed\n")
    done, podman = build("build")
    assert done.returncode == 1 and podman == [] and _named(done.stderr) == ["packaging/build-appimage.sh"]


def test_lock_reads_the_working_tree_and_names_a_lock_that_is_new(build_repo):
    repo, build = build_repo
    with open(repo / "packaging" / "appimage" / "pins.sh", "a") as f:
        f.write("# a pin on its way to being changed\n")
    done, podman = build("lock")
    assert done.returncode == 0, done.stderr
    assert "Nothing built" not in done.stderr and podman[-1].endswith(" lock")
    assert (repo / "packaging" / "appimage" / "test-requirements.lock").read_text() == "pytest==9.9.9\n"
    assert "new, to git add: packaging/appimage/test-requirements.lock" in done.stdout


def test_an_unknown_mode_is_said_before_anything_is_made(build_repo):
    _, build = build_repo
    done, podman = build("--help")
    assert done.returncode == 2 and "usage: " in done.stderr and podman == []


def test_a_machine_without_what_the_wrapper_needs_is_told_which(tmp_path):
    """git, Podman, GNU tar and a python3 with tomllib: without git the first line failed with
    "command not found", and a python3 before 3.11 with a traceback after the builder was made."""
    bash = shutil.which("bash")
    tools = tmp_path / "bin"
    tools.mkdir()
    done = subprocess.run([bash, str(ROOT / "packaging" / "build-appimage.sh"), "build"], cwd=tmp_path,
                          env={"PATH": str(tools)}, capture_output=True, text=True, timeout=30)
    assert done.returncode == 1 and done.stdout == ""
    said = done.stderr.splitlines()
    assert said[0].startswith("Nothing built.") and "this machine lacks" in said[0]
    assert [line.split()[0] for line in said[1:]] == ["git", "Podman,", "GNU", "python3"]
    assert "3.11" in said[4] and "tomllib" in said[4]

    def lacking(**stubs):
        for name, script in stubs.items():
            _stub(tools, name, script)
        script = "set -euo pipefail\n" + _function(WRAPPER, "missing_host_tools") + "missing_host_tools"
        found = subprocess.run([bash, "-c", script], env={"PATH": str(tools)}, capture_output=True, text=True,
                               timeout=30)
        assert found.returncode == 0 and found.stderr == ""
        return [line.split()[0] for line in found.stdout.splitlines()]

    # another tar, and a python3 that has no tomllib to import
    assert lacking(git="exit 0", podman="exit 0", tar='echo "bsdtar 3.7.2 - libarchive 3.7.2"',
                   python3="exit 1") == ["GNU", "python3"]
    assert lacking(tar='echo "tar (GNU tar) 1.35"', python3="exit 0") == []
    for needed in ("Podman", "git", "GNU tar", "python3 3.11"):
        assert needed in README.split("## Building")[1].split("```")[0], needed


# ---------------------------------------------------------------- RECORD, of what is in the image

RECORDS = PACKAGING / "records.py"


def _record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def _installed(site: Path, name: str, files: dict[str, bytes]) -> Path:
    """A package as pip leaves it: its files, and a RECORD of them as pip writes one (the csv
    module's default dialect, sorted, lines ending \\r\\n, its own line last and bare)."""
    info = f"{name}-1.0.dist-info"
    rows = []
    for path, data in files.items():
        (site / path).parent.mkdir(parents=True, exist_ok=True)
        (site / path).write_bytes(data)
        rows.append((path, _record_hash(data), str(len(data))))
    out = io.StringIO(newline="")
    csv.writer(out).writerows(sorted(rows) + [(f"{info}/RECORD", "", "")])
    (site / info / "RECORD").write_bytes(out.getvalue().encode())
    return site / info / "RECORD"


def test_a_record_lists_what_is_in_the_image_and_nothing_of_the_wheel_it_came_from(tmp_path):
    """Six RECORDs still listed direct_url.json, with the hash of a file that held the hash of a
    wheel archive made in the build; others listed console scripts and Pillow libraries that were
    left out, and stripped extensions by the hashes they had before."""
    site = tmp_path / "usr" / "python" / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    built = _installed(site, "built", {
        "built/__init__.py": b"x = 1\n",
        "built/_ext.abi3.so": b"\x7fELFcode" + b"debug information" * 40,
        "built/odd, name.txt": b"a name with a comma is quoted\n",
        "built-1.0.dist-info/METADATA": b"Name: built\n",
        "built-1.0.dist-info/direct_url.json":
            b'{"archive_info": {"hash": "sha256=0d1e"}, "url": "file:///work/wheels/built-1.0-py3-none-any.whl"}',
        "../../../bin/built": b"#!/work/AppDir/usr/python/bin/python3\nimport built\n"})
    wheel = _installed(site, "wheel", {"wheel.py": b"y = 2\n", "wheel-1.0.dist-info/METADATA": b"Name: wheel\n"})
    before, untouched = built.read_bytes(), (wheel.read_bytes(), os.stat(wheel).st_mtime_ns)
    assert before.count(b"\r\n") == 7 and b'"built/odd, name.txt",sha256=' in before
    # what build.sh does to them once pip is done
    (site / "built-1.0.dist-info" / "direct_url.json").unlink()
    (tmp_path / "usr" / "python" / "bin" / "built").unlink()
    (site / "built" / "_ext.abi3.so").write_bytes(b"\x7fELFcode")              # stripped

    clean = [sys.executable, "-I", str(RECORDS), str(site)]
    done = subprocess.run(clean, capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    assert "2 lines of files left out dropped, 1 brought up to date, in 2 packages" in done.stdout
    expected = [line for line in before.split(b"\r\n")
                if not line.startswith((b"../../../bin/built,", b"built-1.0.dist-info/direct_url.json,"))]
    at = next(i for i, line in enumerate(expected) if line.startswith(b"built/_ext.abi3.so,"))
    expected[at] = b"built/_ext.abi3.so," + _record_hash(b"\x7fELFcode").encode() + b",8"
    after = built.read_bytes()
    assert after == b"\r\n".join(expected)                  # every other line as it was, in its place
    assert b"direct_url" not in after and b"/bin/" not in after
    # a RECORD with nothing to change is not written, and a second run finds nothing more to do
    assert (wheel.read_bytes(), os.stat(wheel).st_mtime_ns) == untouched
    again = subprocess.run(clean, capture_output=True, text=True, timeout=60)
    assert "0 lines of files left out dropped, 0 brought up to date" in again.stdout and built.read_bytes() == after

    empty = tmp_path / "empty"
    empty.mkdir()
    nothing = subprocess.run([sys.executable, "-I", str(RECORDS), str(empty)], capture_output=True, text=True)
    assert nothing.returncode != 0 and "no package's RECORD" in nothing.stderr


def test_records_are_brought_up_to_date_once_everything_is_left_out_and_before_the_bytecode():
    at = BUILD.index('"$W/buildpy/bin/python3" "$P/records.py" "$W"/AppDir/usr/python/lib/python3.*/site-packages')
    for earlier in ("-m pip uninstall -q -y pip", 'rm "$script"',
                    'rm -f "$site"/PIL/_imagingft', "-name direct_url.json -delete",
                    "-name __pycache__ -type d -prune"):
        assert BUILD.index(earlier) < at, earlier
    assert at < BUILD.index("-m compileall") < BUILD.index("mksquashfs")


# ---------------------------------------------------------------- the suite, on what ships

def _key(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def test_the_test_tools_are_pytests_alone_locked_and_installed_apart():
    """The suite ran only in a developer's venv made with --system-site-packages, 32 of whose 79
    packages were not the versions the AppImage has."""
    import tomllib

    asked = {_key(line.split(">=")[0].split("==")[0]) for line in
             (PACKAGING / "test-requirements.in").read_text().splitlines() if line and not line.startswith("#")}
    shipped = {_key(name) for name in
               re.findall(r"(?m)^([\w.-]+)(?:\[[^\]]*\])?==", (PACKAGING / "requirements.lock").read_text())}
    dev = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["optional-dependencies"]["dev"]
    # everything the dev extra asks for is in the image or in the test tools, and never in both:
    # what ships is tested as shipped
    assert {_key(re.match(r"[\w.-]+", dep).group(0)) for dep in dev} <= asked | shipped
    assert asked == {"pytest", "pytest-asyncio"} and not asked & shipped
    assert re.search(r"for name in [^;]*\btest-requirements\b[^;]*; do", BUILD)            # locked with the rest

    install = next(line for line in _commands(LOCKED) if " -m pip " in line and not line.lstrip().startswith("#"))
    for needed in ("-I -m pip --isolated ", " --require-hashes ", " --no-deps ", " --only-binary :all: ",
                   ' --target "$WORK/test-tools" ', ' -r "$LOCK"'):
        assert needed in install, needed
    assert "LOCK=packaging/appimage/test-requirements.lock" in LOCKED
    # the pinned Python whose pip that is comes as the build's does
    assert _function(LOCKED, "fetch").split("\n", 1)[1] == _function(BUILD, "fetch").split("\n", 1)[1]
    assert 'fetch "$PBS_URL" "$PBS_SHA256" "$CACHE/python.tar.gz"' in LOCKED
    # the image's Python, isolated; the tools' folder after the image's packages, not before them
    assert 'suite=("$PY" -I -B -c "$RUN" "$WORK/test-tools" -p no:cacheprovider "${@:--q}")' in LOCKED
    assert "sys.path.append(sys.argv.pop(1))" in LOCKED
    assert not any("PYTHONPATH" in line for line in LOCKED.splitlines() if not line.lstrip().startswith("#"))
    assert "packaging/test-locked.sh" in README.split("## Releasing")[1]


@pytest.fixture
def locked_repo(tmp_path):
    """A checkout with test-locked.sh, two tests and a davibemanager of one file; an "AppImage" that
    unpacks to a Python with that davibemanager installed (a venv of this Python's, with nothing else
    in it); and, in the build's cache, a "pinned Python" whose pip only links this Python's own
    pytest into the folder it is told to install into. curl fails if it is ever run."""
    import venv

    if not shutil.which("git"):
        pytest.skip("no git")
    repo = tmp_path / "repo"
    (repo / "packaging" / "appimage").mkdir(parents=True)
    shutil.copy(ROOT / "packaging" / "test-locked.sh", repo / "packaging")
    (repo / "src" / "davibemanager" / "web").mkdir(parents=True)
    (repo / "src" / "davibemanager" / "__init__.py").write_text('__version__ = "9.9"\n')
    (repo / "src" / "davibemanager" / "web" / "app.js").write_text("// the page\n")
    (repo / "tests").mkdir()
    (repo / "tests" / "test_shipped.py").write_text(
        "import sys\n\nimport davibemanager\n\n\ndef test_it_is_the_image_that_is_tested():\n"
        "    assert '/squashfs-root/usr/python/lib/' in davibemanager.__file__ and sys.flags.isolated\n"
        "    assert sys.path[-1].endswith('/test-tools') and sys.dont_write_bytecode\n")
    (repo / "tests" / "failing.py").write_text("def test_that_fails():\n    assert not 'what ships works'\n")
    (repo / ".gitignore").write_text("dist/\n")
    (repo / "packaging" / "appimage" / "test-requirements.lock").write_text(
        "pytest==9.9.9 \\\n    --hash=sha256:" + "0" * 64 + "\n")

    image = tmp_path / "image"
    venv.create(image, with_pip=False, symlinks=True)
    shutil.copytree(repo / "src" / "davibemanager", next(image.glob("lib/python3.*/site-packages")) / "davibemanager")
    (repo / "dist").mkdir()
    appimage = repo / "dist" / "DAVibeManager-9.9-x86_64.AppImage"
    _stub(repo / "dist", appimage.name, '[ "$1" = --appimage-extract ] || exit 64\n'
          f"mkdir -p squashfs-root/usr && cp -a {shlex.quote(str(image))} squashfs-root/usr/python")

    tools = []
    for name in ("pytest", "_pytest", "pluggy", "iniconfig", "packaging", "py", "pygments"):
        spec = importlib.util.find_spec(name)
        if spec:
            tools.append(spec.submodule_search_locations[0] if spec.submodule_search_locations else spec.origin)
    pip = ('#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$PIP_LOG"\n'
           'while [ $# -gt 0 ]; do\n    if [ "$1" = --target ]; then target="$2"; fi\n    shift\ndone\n'
           + "".join(f'ln -s {shlex.quote(tool)} "$target"/\n' for tool in tools))
    packed = io.BytesIO()
    with tarfile.open(fileobj=packed, mode="w:gz") as tar:
        entry = tarfile.TarInfo("python/bin/python3")
        entry.size, entry.mode = len(pip.encode()), 0o755
        tar.addfile(entry, io.BytesIO(pip.encode()))
    (tmp_path / "cache" / "davibemanager-appimage").mkdir(parents=True)
    (tmp_path / "cache" / "davibemanager-appimage" / "python.tar.gz").write_bytes(packed.getvalue())
    (repo / "packaging" / "appimage" / "pins.sh").write_text(
        'PBS_URL="https://downloads.invalid/python.tar.gz"\n'
        f'PBS_SHA256="{hashlib.sha256(packed.getvalue()).hexdigest()}"\n')

    _stub(tmp_path / "bin", "curl", 'echo "$*" >> "$CURL_LOG"; exit 22')
    env = {**_git_env(tmp_path, tmp_path / "bin"), "PIP_LOG": str(tmp_path / "pip.log"),
           "CURL_LOG": str(tmp_path / "curl.log"),
           # for systemd-run --user, where there is a user session: the suite's memory cap
           **{name: os.environ[name] for name in ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS") if name in os.environ}}
    _commit_all(repo, env)

    def locked(*args, **more):
        return subprocess.run(["bash", "packaging/test-locked.sh", *args], cwd=repo, env={**env, **more},
                              capture_output=True, text=True, timeout=180)

    locked.env = env
    return repo, locked, appimage


def test_the_suite_runs_on_the_images_python_and_packages_with_the_test_tools_last(locked_repo, tmp_path):
    repo, locked, appimage = locked_repo
    done = locked()
    assert done.returncode == 0, done.stdout + done.stderr
    assert "1 passed" in done.stdout
    assert re.search(r"Testing DAVibeManager-9\.9-x86_64\.AppImage: davibemanager 9\.9, Python 3\.\d+\.\d+ and the packages "
                     r"in the image, with the tests of [0-9a-f]{7,}\.", done.stdout)
    installs = (tmp_path / "pip.log").read_text().splitlines()
    assert len(installs) == 1 and installs[0].startswith("-I -m pip --isolated ")
    assert " --require-hashes " in installs[0] and installs[0].endswith(" -r packaging/appimage/test-requirements.lock")
    assert not (tmp_path / "curl.log").exists()             # the cache had the pinned Python, with its hash
    # nothing is left in the checkout, and the temporary folder is gone
    left = subprocess.run(["git", "status", "--porcelain", "--ignored"], cwd=repo, capture_output=True, text=True,
                          env=locked.env).stdout.split()
    assert left == ["!!", "dist/"]
    # a failing test fails the script, and pytest's arguments are the script's
    failed = locked("-q", "tests/failing.py")
    assert failed.returncode == 1 and "1 failed" in failed.stdout
    # another AppImage than dist/'s newest
    moved = tmp_path / "elsewhere.AppImage"
    shutil.move(appimage, moved)
    assert "no AppImage to run (none in dist/)" in locked().stderr
    assert "1 passed" in locked(APPIMAGE=str(moved)).stdout
    # a cached Python that is not the pinned one is fetched again, over https alone, and not used unchecked
    installs = (tmp_path / "pip.log").read_text()
    (tmp_path / "cache" / "davibemanager-appimage" / "python.tar.gz").write_bytes(b"something else")
    refetch = locked(APPIMAGE=str(moved))
    assert refetch.returncode != 0 and "passed" not in refetch.stdout
    assert (tmp_path / "curl.log").read_text().startswith("--proto =https --tlsv1.2 ")
    assert (tmp_path / "pip.log").read_text() == installs


def test_an_appimage_of_another_commit_or_no_lock_is_not_tested(locked_repo, tmp_path):
    repo, locked, _ = locked_repo
    (repo / "src" / "davibemanager" / "web" / "app.js").write_text("// the page, since the build\n")
    (repo / "src" / "davibemanager" / "added.py").write_text("")           # not in the image: no file of the image's differs
    done = locked()
    assert done.returncode == 1 and "passed" not in done.stdout
    assert "was not built from this checkout" in done.stderr and _named(done.stderr) == ["web/app.js"]
    assert not (tmp_path / "pip.log").exists()
    (repo / "packaging" / "appimage" / "test-requirements.lock").unlink()
    done = locked()
    assert done.returncode == 1 and "passed" not in done.stdout
    assert "test-requirements.lock is not there" in done.stderr and "build-appimage.sh lock" in done.stderr

