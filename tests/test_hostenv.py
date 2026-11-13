"""The environment of the programs DA Vibe Manager starts for the user (hostenv.py): what the AppImage
and its AppRun set for DA Vibe Manager itself stays out of it (DA Toolkit's 8dfbd35, 31ad3fe, cb0b524)."""

import os
import re
import subprocess
from pathlib import Path

import pytest

from davibemanager import hostenv, hostrun
from davibemanager.hostenv import host_env

APPRUN = Path(__file__).resolve().parents[1] / "packaging" / "appimage" / "AppRun"
SYSTEM = "/etc/ssl/certs/ca-certificates.crt"


@pytest.fixture
def appimage(monkeypatch):
    """As DA Vibe Manager finds its environment when started from the AppImage."""
    monkeypatch.setenv("APPDIR", "/tmp/.mount_DAVibeM")
    monkeypatch.setenv("APPIMAGE", "/home/x/DAVibeManager.AppImage")
    for name in (*hostenv.APPRUN_VARS, hostenv.APPRUN_SET):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_the_bundles_named_here_are_the_ones_apprun_picks_from():
    if not APPRUN.exists():
        pytest.skip("no packaging/ beside these tests (not a source checkout)")
    text = APPRUN.read_text()
    listed = re.search(r"for bundle in \\\n((?:\s+\S+ \\\n)*\s+\S+); do", text).group(1)
    assert tuple(line.strip(" \\") for line in listed.splitlines()) == hostenv.APPRUN_CA_BUNDLES
    # and it sets only what the environment didn't: that is what makes leaving them out a restoring
    assert 'if [ -z "${SSL_CERT_FILE:-}" ]; then' in text and '[ -z "${REQUESTS_CA_BUNDLE:-}" ]' in text
    assert 'if [ -z "${DVM_TOR:-}" ]; then' in text


def _apprun_says(tmp_path, env: dict) -> dict:
    """What AppRun exports, run up to its exec in `env` (the bundles it looks for as they are here)."""
    text = APPRUN.read_text()
    head = text[:text.index('exec "$HERE/usr/python/bin/python3"')]
    out = subprocess.run(["sh", "-c", head + 'printf "%s|%s|%s|%s" "$SSL_CERT_FILE" "$REQUESTS_CA_BUNDLE" "$DVM_TOR" '
                          '"$DVM_APPRUN_SET"\n', str(tmp_path / "AppRun")],
                         env={"PATH": os.environ.get("PATH", ""), **env}, capture_output=True, text=True, check=True).stdout
    return dict(zip(("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "DVM_TOR", "DVM_APPRUN_SET"), out.split("|")))


def test_apprun_names_exactly_what_it_set(tmp_path):
    if not APPRUN.exists():
        pytest.skip("no packaging/ beside these tests (not a source checkout)")
    if not any(Path(b).is_file() for b in hostenv.APPRUN_CA_BUNDLES):
        pytest.skip("no host CA bundle here for AppRun to find")
    said = _apprun_says(tmp_path, {})
    assert said["SSL_CERT_FILE"] in hostenv.APPRUN_CA_BUNDLES and said["REQUESTS_CA_BUNDLE"] == said["SSL_CERT_FILE"]
    assert said["DVM_TOR"].endswith("/usr/lib/tor/tor")
    assert said["DVM_APPRUN_SET"].split() == ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "DVM_TOR"]
    # the user's own settings are left as they are, and not named
    said = _apprun_says(tmp_path, {"SSL_CERT_FILE": "/home/x/corp.pem", "DVM_TOR": "/usr/bin/tor"})
    assert (said["SSL_CERT_FILE"], said["REQUESTS_CA_BUNDLE"], said["DVM_TOR"]) == ("/home/x/corp.pem", "/home/x/corp.pem",
                                                                                    "/usr/bin/tor")
    assert said["DVM_APPRUN_SET"] == "REQUESTS_CA_BUNDLE"


def test_what_apprun_set_stays_out_of_child_programs(appimage):
    """SSL_CERT_FILE and REQUESTS_CA_BUNDLE, set by AppRun for DA Vibe Manager's own clients, reached every
    command it ran for the user: a Python tool with certificates of its own was pointed at the system's
    bundle there, and nowhere else. DVM_TOR named a tor inside the AppImage's mount."""
    appimage.setenv("SSL_CERT_FILE", SYSTEM)                 # as AppRun leaves them on Debian and its kin
    appimage.setenv("REQUESTS_CA_BUNDLE", SYSTEM)
    appimage.setenv("DVM_TOR", "/tmp/.mount_DAVibeM/usr/lib/tor/tor")
    appimage.setenv(hostenv.APPRUN_SET, "SSL_CERT_FILE REQUESTS_CA_BUNDLE DVM_TOR")
    env = host_env(TERM="xterm-256color")
    assert not {*hostenv.APPRUN_VARS, hostenv.APPRUN_SET, "APPDIR"} & set(env) and env["TERM"] == "xterm-256color"
    assert os.environ["SSL_CERT_FILE"] == SYSTEM                     # DA Vibe Manager's own, kept
    # an older AppRun that names nothing: each of the places it looks
    appimage.delenv(hostenv.APPRUN_SET)
    for bundle in hostenv.APPRUN_CA_BUNDLES:
        appimage.setenv("SSL_CERT_FILE", bundle)
        appimage.setenv("REQUESTS_CA_BUNDLE", bundle)
        assert not set(hostenv.CA_VARS) & set(host_env())


def test_the_users_own_ca_settings_reach_child_programs(appimage):
    # a bundle of their own in both (a company's CA): AppRun changed nothing, and nothing is taken away
    appimage.setenv("SSL_CERT_FILE", "/home/x/corp-ca.pem")
    appimage.setenv("REQUESTS_CA_BUNDLE", "/home/x/corp-ca.pem")
    env = host_env()
    assert (env["SSL_CERT_FILE"], env["REQUESTS_CA_BUNDLE"]) == ("/home/x/corp-ca.pem", "/home/x/corp-ca.pem")
    # their own REQUESTS_CA_BUNDLE beside the SSL_CERT_FILE that AppRun set
    appimage.setenv("SSL_CERT_FILE", SYSTEM)
    appimage.setenv("REQUESTS_CA_BUNDLE", "/home/x/corp-ca.pem")
    env = host_env()
    assert "SSL_CERT_FILE" not in env and env["REQUESTS_CA_BUNDLE"] == "/home/x/corp-ca.pem"
    # and outside an AppImage nothing is AppRun's
    appimage.delenv("APPDIR")
    appimage.delenv("APPIMAGE")
    appimage.setenv("REQUESTS_CA_BUNDLE", SYSTEM)
    env = host_env()
    assert (env["SSL_CERT_FILE"], env["REQUESTS_CA_BUNDLE"]) == (SYSTEM, SYSTEM)


def test_an_apprun_that_says_what_it_set_is_taken_at_its_word(appimage):
    # the user's own SSL_CERT_FILE, which happens to be the system's bundle; AppRun added the other
    appimage.setenv("SSL_CERT_FILE", SYSTEM)
    appimage.setenv("REQUESTS_CA_BUNDLE", SYSTEM)
    appimage.setenv(hostenv.APPRUN_SET, "REQUESTS_CA_BUNDLE")
    env = host_env()
    assert env["SSL_CERT_FILE"] == SYSTEM and "REQUESTS_CA_BUNDLE" not in env and hostenv.APPRUN_SET not in env
    appimage.setenv(hostenv.APPRUN_SET, "")                  # it set nothing: both are the user's
    assert set(hostenv.CA_VARS) <= set(host_env())
    appimage.setenv(hostenv.APPRUN_SET, "SSL_CERT_FILE REQUESTS_CA_BUNDLE PATH")     # and only its own are its to name
    env = host_env()
    assert not set(hostenv.CA_VARS) & set(env) and "PATH" in env


def test_an_extracted_appimages_apprun_is_taken_at_its_word_too(monkeypatch):
    """AppRun run from an extracted image (as the lab's tests run it) has no APPDIR or APPIMAGE around
    it: what it says it set still stays out of the user's commands."""
    for name in ("APPDIR", "APPIMAGE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SSL_CERT_FILE", SYSTEM)
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", SYSTEM)
    monkeypatch.setenv(hostenv.APPRUN_SET, "SSL_CERT_FILE REQUESTS_CA_BUNDLE")
    env = host_env()
    assert not {"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", hostenv.APPRUN_SET} & set(env)
    monkeypatch.delenv(hostenv.APPRUN_SET)                     # no AppRun at all: they are the user's own
    env = host_env()
    assert env["SSL_CERT_FILE"] == SYSTEM and env["REQUESTS_CA_BUNDLE"] == SYSTEM


async def test_a_command_the_assistant_runs_gets_none_of_it(appimage):
    appimage.setenv("SSL_CERT_FILE", SYSTEM)
    appimage.setenv("REQUESTS_CA_BUNDLE", SYSTEM)
    appimage.setenv(hostenv.APPRUN_SET, "SSL_CERT_FILE REQUESTS_CA_BUNDLE")
    res = await hostrun.run('echo "cert=[${SSL_CERT_FILE:-}] requests=[${REQUESTS_CA_BUNDLE:-}] appdir=[${APPDIR:-}]"',
                            as_root=False, timeout=10)
    assert res.output.strip() == "cert=[] requests=[] appdir=[]"
