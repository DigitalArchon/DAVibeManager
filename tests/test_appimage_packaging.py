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


def _lookup(*candidates):
    """host_ca_bundle, as the wrapper defines it, given `candidates`."""
    found = re.search(r"^host_ca_bundle\(\) \{\n.*?^\}\n", WRAPPER, re.S | re.M)
    assert found, "the lookup is not where this test looks for it"
    return subprocess.run(["bash", "-c", found.group(0) + 'host_ca_bundle "$@"', "bash", *candidates],
                          capture_output=True, text=True, timeout=30)
