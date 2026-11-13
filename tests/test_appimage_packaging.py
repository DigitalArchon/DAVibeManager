"""The AppImage's build: what it takes from the machine it runs on, and what it puts in the image. The build
itself (packaging/build-appimage.sh check) is the real test that it is reproducible; these catch a change that
would quietly break it, run the parts of the scripts that read the machine, and hold every download and every
install to what the locks pin. Ported from DA Assistant's tests/test_appimage_packaging.py and
test_build_scripts.py (Nov 2026)."""

import marshal
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / "packaging" / "appimage"
BUILD = (PACKAGING / "build.sh").read_text()
WRAPPER = (ROOT / "packaging" / "build-appimage.sh").read_text()
APPRUN = (PACKAGING / "AppRun").read_text()


def commands(text: str) -> list[str]:
    """A script's commands, one to a line: a command continued over several lines is joined into one."""
    return re.sub(r"\\\n\s*", " ", text).splitlines()


# --- downloads, and what is installed

def test_every_download_is_https_only():
    """A hash proves what arrived, not that nobody saw it asked for: no download may fall back to http,
    through a redirect either (the sandbox's image, built on every computer, included)."""
    files = sorted((ROOT / "packaging").rglob("*.sh")) + [PACKAGING / "Containerfile",
                                                          ROOT / "src/davibemanager/workspace/image/Containerfile"]
    curls = []
    for path in files:
        for line in commands(path.read_text()):
            if line.lstrip().startswith("#"):
                continue
            for found in re.finditer(r"\bcurl\s+-[^;&|]*", line):         # each curl of a command, on its own
                curls.append(path.name)
                assert "--proto '=https' --tlsv1.2" in found.group(0), f"{path}: {found.group(0).strip()}"
    assert curls.count("build.sh") == 1 and curls.count("Containerfile") == 2
    # the source archives are fetched by Python, which follows a redirect to http by itself
    assert "class HttpsOnly(urllib.request.HTTPRedirectHandler)" in BUILD
    assert "urllib.request.urlopen(" not in BUILD


def test_every_package_installed_from_a_lock_is_hash_checked_and_nothing_else_is_installed():
    """The lock run once installed "pip==26.2.2" "pip-tools==7.6.1": versions, not files, and what they
    pulled in as it came on the day."""
    installs = 0
    for line in commands(BUILD):
        command = line.split(" #", 1)[0].strip()
        if command.startswith("#") or not re.search(r'pip"? install ', command):
            continue
        installs += 1
        if re.search(r' -r "[^"]+\.lock"', command):
            assert "--require-hashes" in command, command
        else:
            assert re.search(r'pip"? install( -[-\w]+)* "\$W/wheels"/\S+\.whl$', command), command
    assert installs >= 5
    assert '--require-hashes --no-deps -r "$P/lock-requirements.lock"' in BUILD
    assert '--require-hashes --only-binary :all: -r "$W/binary.lock"' in BUILD
    assert re.search(r"for name in [^;]*\block-requirements\b[^;]*; do", BUILD)


@pytest.mark.parametrize("name", ["requirements", "build-requirements", "sdists", "lock-requirements"])
def test_every_locked_package_carries_a_hash(name):
    entries = re.findall(r"^([\w.-]+)==([^\s]+)((?:\s*\\\s*--hash=sha256:\w+)*)", (PACKAGING / f"{name}.lock").read_text(), re.M)
    assert entries
    for package, version, hashes in entries:
        assert "--hash=sha256:" in hashes, f"{name}.lock: {package}=={version}"


def test_a_relock_keeps_what_is_pinned_unless_asked_to_upgrade():
    assert 'cp "$name.lock" "/out/$name.lock"' in BUILD and '"${UPGRADE:-0}" != 1' in BUILD
    assert '-e UPGRADE="${UPGRADE:-0}"' in WRAPPER


def test_the_lock_meets_every_floor_pyproject_sets():
    """A relock keeps what the lock already pins, so a floor added for an advisory (certifi's root, Brotli's
    decoder, pyasn1's and dnspython's denials of service) is only as good as the relock that followed it."""
    import tomllib

    def version(text):
        return tuple(int(part) for part in re.findall(r"\d+", text))
    deps = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["dependencies"]
    floors = [re.match(r"([A-Za-z0-9_.-]+)>=([0-9.]+)$", d).groups() for d in deps if re.match(r"[\w.-]+>=[\d.]+$", d)]
    assert ("pyasn1", "0.6.5") in floors and ("dnspython", "2.9.0") in floors
    pins = {re.sub(r"[-_.]+", "-", n).lower(): v for n, v in
            re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", (PACKAGING / "requirements.lock").read_text(), re.M)}
    for name, floor in floors:
        locked = pins[re.sub(r"[-_.]+", "-", name).lower()]
        assert version(locked) >= version(floor), f"{name}=={locked}"


def test_the_base_image_and_downloads_are_pinned():
    pins = (PACKAGING / "pins.sh").read_text()
    assert re.search(r'BASE_IMAGE="[^"]+@sha256:[0-9a-f]{64}"', pins)
    assert re.search(r'APT_SNAPSHOT="\d{8}T\d{6}Z"', pins)
    for name in ("PBS", "RUNTIME", "TOR"):
        assert re.search(rf'{name}_SHA256="[0-9a-f]{{64}}"', pins)
        assert f'fetch "${name}_URL" "${name}_SHA256"' in BUILD


# --- nothing of the build machine in the image

def test_nothing_of_the_build_machine_gets_in():
    for needed in ("-root-owned -no-xattrs", "--invalidation-mode unchecked-hash", "PYTHONHASHSEED=0",
                   '-ffile-prefix-map=$W/=', "direct_url.json -delete", 'grep -rlaF "$W/AppDir" "$W/AppDir"'):
        assert needed in BUILD, needed


def test_bytecode_names_its_source_as_it_is_inside_the_image(tmp_path):
    """compileall as build.sh runs it, on a folder laid out as the AppDir: each .pyc unchecked-hash, naming
    /usr/python/lib/..., not the folder the build ran in (every one of 4,938 named /work/AppDir/... in
    0.1.0b10)."""
    command = next(line for line in commands(BUILD) if "-m compileall" in line)
    # -B: its interpreter would otherwise write its own imports' bytecode first, dated, and compileall
    # would leave those as they are
    assert '"$PY" -B -m compileall' in command
    folder = tmp_path / "AppDir" / "usr" / "python" / "lib" / "python3.12"
    folder.mkdir(parents=True)
    (folder / "mod.py").write_text("def f():\n    return 1\n")
    subprocess.run(["bash", "-c", command], check=True,
                   env={"PATH": os.environ.get("PATH", ""), "PY": sys.executable, "W": str(tmp_path)})
    names = []
    for pyc in tmp_path.rglob("*.pyc"):
        data = pyc.read_bytes()
        assert int.from_bytes(data[4:8], "little") == 1, pyc          # unchecked-hash
        code = marshal.loads(data[16:])
        names += [code.co_filename, code.co_consts[0].co_filename]
    assert sorted(set(names)) == ["/usr/python/lib/python3.12/mod.py"]


def test_console_scripts_that_name_the_build_python_are_left_out(tmp_path):
    start = BUILD.index('for script in "$W"/AppDir/usr/python/bin/*; do')
    loop = BUILD[start:BUILD.index("\ndone\n", start) + 6]
    bin_dir = tmp_path / "AppDir" / "usr" / "python" / "bin"
    bin_dir.mkdir(parents=True)
    scripts = {"davibemanager": f"#!{tmp_path}/AppDir/usr/python/bin/python3\nfrom davibemanager.app import main\n",
               "pydoc3.12": "#!/bin/sh\n'''exec' \"$(dirname -- \"$0\")/python3.12\"\n",
               "python3.12": "\x7fELF\x02\x01\x01\0" + "\0" * 64}
    for name, text in scripts.items():
        (bin_dir / name).write_text(text, encoding="latin-1")
    (bin_dir / "python3").symlink_to("python3.12")
    subprocess.run(["bash", "-c", f"set -euo pipefail\n{loop}"], check=True,
                   env={"PATH": os.environ.get("PATH", ""), "W": str(tmp_path)})
    assert sorted(p.name for p in bin_dir.iterdir()) == ["pydoc3.12", "python3", "python3.12"]
    assert 'exec "$HERE/usr/python/bin/python3" -I -m davibemanager' in APPRUN    # not the script that went


# --- what the wrapper takes from the machine

def test_the_commit_is_built_as_committed_whatever_gits_settings(tmp_path):
    """A verifier's core.autocrlf, a smudge filter their attributes name: git archive hands each file through
    them, so the same commit made a different AppImage. The wrapper reads the files from git's objects
    instead, and sets their modes itself whatever the umask."""
    if not shutil.which("git"):
        pytest.skip("no git")
    assert 'EPOCH="$(git log -1 --format=%ct HEAD)"' in WRAPPER
    found = re.search(r"^export_head\(\) \{.*?^\}\n", WRAPPER, re.S | re.M)
    assert found, "export_head is not where this test looks for it"
    export = found.group(0)
    repo = tmp_path / "repo"
    (tmp_path / "attributes").write_text("*.txt filter=pear\n")
    (tmp_path / "gitconfig").write_text(f"[core]\n\tautocrlf = true\n\tattributesFile = {tmp_path}/attributes\n"
                                        "[filter \"pear\"]\n\tsmudge = sed s/apple/pear/\n\tclean = cat\n"
                                        "[user]\n\tname = T\n\temail = t@example.org\n")
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": str(tmp_path / "gitconfig")}
    committed = {"notes.txt": b"apple\nbanana\n", "tools/run.sh": b"#!/bin/sh\necho a\n"}

    def git(*args, cwd=repo):
        return subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True).stdout
    git("init", "-q", str(repo), cwd=tmp_path)
    for name, data in committed.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_bytes(data)
    (repo / "tools/run.sh").chmod(0o755)
    git("add", "-A")
    git("commit", "-q", "-m", "files")

    def unpack(tar: Path):
        out = tmp_path / f"out-{tar.parent.name}-{tar.name}"
        out.mkdir()
        subprocess.run(["tar", "-xf", str(tar), "-C", str(out)], check=True)
        return ({n: (out / n).read_bytes() for n in committed}, {n: (out / n).stat().st_mode & 0o777 for n in committed})

    (tmp_path / "archive.tar").write_bytes(git("archive", "--format=tar", "HEAD"))
    assert unpack(tmp_path / "archive.tar")[0] != committed        # what git archive would have built
    work = tmp_path / "work"
    work.mkdir()
    run_export = ["bash", "-c", f"set -euo pipefail\numask 077\nWORK={shlex.quote(str(work))}\n"
                                f'EPOCH="$(git log -1 --format=%ct HEAD)"\n{export}\nexport_head']
    subprocess.run(run_export, cwd=repo, env=env, check=True, capture_output=True)
    files, modes = unpack(work / "src.tar")
    assert files == committed and modes == {"notes.txt": 0o644, "tools/run.sh": 0o755}
    (repo / "link").symlink_to("notes.txt")
    git("add", "-A")
    git("commit", "-q", "-m", "a link")
    shutil.rmtree(work)
    work.mkdir()
    refused = subprocess.run(run_export, cwd=repo, env=env, capture_output=True, text=True)
    assert refused.returncode != 0 and "link is a blob of mode 120000" in refused.stderr


def test_the_builder_image_takes_no_mount_that_needs_relabelling():
    """:Z on the host's root-owned CA bundle: rootless Podman on an SELinux host (Fedora, RHEL) can't
    relabel it, so nobody there could rebuild a release."""
    assert not re.search(r"podman build[^\n]*-v ", WRAPPER)
    # 0644 whatever the umask: apt reads it as _apt, and COPY keeps the mode
    assert 'install -m 0644 "$ca" "$WORK/context/hostca.crt"' in WRAPPER
    containerfile = (PACKAGING / "Containerfile").read_text()
    assert "COPY hostca.crt /hostca.crt" in containerfile and re.search(r"rm [^\n]*/hostca\.crt", containerfile)


def test_the_results_go_where_dist_says():
    assert 'DIST="$(mkdir -p "${DIST:-dist}" && cd "${DIST:-dist}" && pwd)"' in WRAPPER
    assert 'run "$DIST" build' in WRAPPER and "$PWD/dist" not in WRAPPER


def _lookup(*candidates):
    """host_ca_bundle, as the wrapper defines it, given `candidates`."""
    found = re.search(r"^host_ca_bundle\(\) \{\n.*?^\}\n", WRAPPER, re.S | re.M)
    assert found, "the lookup is not where this test looks for it"
    return subprocess.run(["bash", "-c", found.group(0) + 'host_ca_bundle "$@"', "bash", *candidates],
                          capture_output=True, text=True, timeout=30)


def test_the_host_ca_bundle_is_looked_for_where_apprun_looks():
    listed = re.search(r"^CA_BUNDLES=\((.*?)\)", WRAPPER, re.S | re.M).group(1).split()
    apprun = [p for p in re.findall(r"(/etc/[\w./-]+)", APPRUN) if p.endswith((".crt", ".pem"))]
    assert listed == apprun and len(listed) == 5
    assert {"/etc/ssl/ca-bundle.pem", "/etc/pki/tls/cert.pem"} <= set(listed)     # openSUSE, and RHEL's other


def test_the_first_bundle_there_is_used_and_none_is_said_plainly(tmp_path):
    bundle = tmp_path / "ca-bundle.pem"
    bundle.write_text("certificates")
    done = _lookup(str(tmp_path / "missing.crt"), str(bundle), str(tmp_path / "also-missing.pem"))
    assert (done.returncode, done.stdout) == (0, f"{bundle}\n")
    done = _lookup("/nonexistent/one.crt", "/nonexistent/two.pem")
    assert done.returncode == 1 and done.stdout == ""
    assert "No CA bundle on this machine" in done.stderr and "/nonexistent/one.crt /nonexistent/two.pem" in done.stderr
    assert "ca-certificates" in done.stderr


def test_the_bundle_is_looked_for_only_to_make_the_builder():
    made = WRAPPER.index('if ! podman image exists "$TAG"; then')
    assert WRAPPER.index('ca="$(host_ca_bundle "${CA_BUNDLES[@]}")"') > made
    assert not re.search(r"(?m)^for ca in ", WRAPPER)


def test_apprun_is_valid_shell_and_runs_the_bundled_python_isolated():
    assert subprocess.run(["sh", "-n", str(PACKAGING / "AppRun")]).returncode == 0
    assert re.search(r'exec "\$HERE/usr/python/bin/python3" -I ', APPRUN)


def test_apprun_takes_the_hosts_bundle_from_any_of_the_five(tmp_path):
    """AppRun up to its exec, as if the host had only one bundle (each of the others pointed elsewhere)."""
    head = APPRUN[:APPRUN.index('exec "$HERE/usr/python/bin/python3"')]
    paths = [p for p in re.findall(r"(/etc/[\w./-]+)", APPRUN) if p.endswith((".crt", ".pem"))]
    for keep in paths:
        bundle = tmp_path / keep.strip("/").replace("/", "_")
        bundle.write_text("certificates")
        text = head
        for path in paths:
            text = text.replace(path, str(bundle) if path == keep else "/nonexistent" + path)
        out = subprocess.run(["sh", "-c", text + 'echo "$SSL_CERT_FILE|$REQUESTS_CA_BUNDLE"\n', str(tmp_path / "AppRun")],
                             env={"PATH": os.environ.get("PATH", "")}, capture_output=True, text=True, check=True).stdout
        assert out.strip() == f"{bundle}|{bundle}", keep
