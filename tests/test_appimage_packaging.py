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


def test_the_base_image_and_downloads_are_pinned():
    pins = (PACKAGING / "pins.sh").read_text()
    assert re.search(r'BASE_IMAGE="[^"]+@sha256:[0-9a-f]{64}"', pins)
    assert re.search(r'APT_SNAPSHOT="\d{8}T\d{6}Z"', pins)
    for name in ("PBS", "RUNTIME", "TOR"):
        assert re.search(rf'{name}_SHA256="[0-9a-f]{{64}}"', pins)
        assert f'fetch "${name}_URL" "${name}_SHA256"' in BUILD


def _lookup(*candidates):
    """host_ca_bundle, as the wrapper defines it, given `candidates`."""
    found = re.search(r"^host_ca_bundle\(\) \{\n.*?^\}\n", WRAPPER, re.S | re.M)
    assert found, "the lookup is not where this test looks for it"
    return subprocess.run(["bash", "-c", found.group(0) + 'host_ca_bundle "$@"', "bash", *candidates],
                          capture_output=True, text=True, timeout=30)
