"""The environment for programs DA Vibe Manager starts on the user's behalf (their shell, ssh,
the file manager). When DA Vibe Manager runs from an AppImage, the AppImage runtime adds variables
describing its own mount; they mean nothing to those programs, and another AppImage started
from a DA Vibe Manager terminal would misread them, so they are left out. So is what the AppImage's
AppRun sets for DA Vibe Manager itself (see _set_by_apprun)."""

from __future__ import annotations

import os

# where the system keeps its GObject introspection typelibs (Fedora, Debian/Ubuntu, Arch)
HOST_TYPELIB_DIRS = ("/usr/lib64/girepository-1.0", "/usr/lib/x86_64-linux-gnu/girepository-1.0",
                     "/usr/lib/girepository-1.0")
# AppRun's list of what it set (see _set_by_apprun) is the AppImage's own, like the runtime's variables
APPRUN_SET = "DVM_APPRUN_SET"
APPIMAGE_VARS = ("APPIMAGE", "APPDIR", "ARGV0", "OWD", "APPIMAGE_EXTRACT_AND_RUN", APPRUN_SET)
# The host CA bundles AppRun (packaging/appimage/AppRun) looks for, in its order: it points SSL_CERT_FILE
# at the first one there is, and REQUESTS_CA_BUNDLE at the same, when the user's environment sets neither.
APPRUN_CA_BUNDLES = ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                     "/etc/ssl/ca-bundle.pem", "/etc/pki/tls/cert.pem", "/etc/ssl/cert.pem")
CA_VARS = ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE")
# what AppRun may name as set by it: the CA variables, and the tor in the AppImage's mount
APPRUN_VARS = (*CA_VARS, "DVM_TOR")
# variables DA Vibe Manager changed for itself, with their values before (None: they weren't set)
ORIGINAL: dict[str, str | None] = {}


def set_for_self(name: str, value: str) -> None:
    """Set an environment variable for DA Vibe Manager's own process only: host_env() gives children
    the value it had before."""
    ORIGINAL.setdefault(name, os.environ.get(name))
    os.environ[name] = value


def _set_by_apprun(env) -> set[str]:
    """The variables AppRun set, which the user's environment did not have.

    AppRun sets SSL_CERT_FILE and REQUESTS_CA_BUNDLE so that DA Vibe Manager's own HTTP clients trust
    the host's CA store rather than the bundled one. Passed on, they changed what the user's programs
    trust: every command the assistant ran on this computer, and anything it started, got a CA setting
    the user never made, so a Python tool with certificates of its own (a cloud CLI, pip with a custom
    index) was pointed at the system bundle and behaved unlike the same tool outside DA Vibe Manager
    (DA Toolkit's 8dfbd35, 31ad3fe, cb0b524). DVM_TOR points into the AppImage's mount, which goes
    when DA Vibe Manager ends. AppRun only ever sets a variable that was unset or empty, so restoring
    the environment it found means leaving those out.

    An AppRun that says which it set (APPRUN_SET, the names separated by spaces) is taken at its word,
    however it was started: from the AppImage, or from an extracted one, where the runtime's own
    variables (APPDIR, APPIMAGE) aren't there to go by. One that doesn't (an older AppImage) is read by
    what it would have done: SSL_CERT_FILE naming one of the host bundles it picks from is its work, and
    REQUESTS_CA_BUNDLE equal to that too. A user who had set SSL_CERT_FILE to that very file loses
    nothing by its absence (it is the system's default), and one with a bundle of their own keeps both."""
    if APPRUN_SET in env:
        return set(env[APPRUN_SET].split()) & set(APPRUN_VARS)
    if not (env.get("APPDIR") or env.get("APPIMAGE")):
        return set()
    found = set()
    if env.get("SSL_CERT_FILE") in APPRUN_CA_BUNDLES:
        found.add("SSL_CERT_FILE")
        if env.get("REQUESTS_CA_BUNDLE") == env["SSL_CERT_FILE"]:
            found.add("REQUESTS_CA_BUNDLE")
    return found


def host_env(**extra: str) -> dict[str, str]:
    dropped = set(APPIMAGE_VARS) | _set_by_apprun(os.environ)
    env = {k: v for k, v in os.environ.items() if k not in dropped}
    for name, value in ORIGINAL.items():
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value
    env.update(extra)
    return env
