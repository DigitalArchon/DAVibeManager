"""Every program the app starts gets the environment as it was before the app changed it for
itself (hostenv.host_env): GTK_USE_PORTAL=0, which the portal's refusal of an undumpable process
asks of the app's own GTK, and the AppImage's own variables, are this process's alone (the DA
apps' security standard, Nov 2026). podman, the sandbox's guard and the system lookups were
started with this process's own environment."""

import ast
import asyncio
from pathlib import Path

from davibemanager import hostenv, sysinfo
from davibemanager.workspace import podman

SRC = Path(__file__).resolve().parents[1] / "src" / "davibemanager"
STARTS = {("subprocess", "run"), ("subprocess", "Popen"), ("subprocess", "call"),
          ("subprocess", "check_call"), ("subprocess", "check_output"),
          ("asyncio", "create_subprocess_exec"), ("asyncio", "create_subprocess_shell")}


def test_every_program_started_is_given_an_environment_of_its_own():
    """None inherits this process's own: each names env= (host_env, or tor's built from nothing)."""
    bare = []
    for path in SRC.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and isinstance(node.func.value, ast.Name) \
                    and (node.func.value.id, node.func.attr) in STARTS \
                    and not any(keyword.arg == "env" for keyword in node.keywords):
                bare.append(f"{path.relative_to(SRC)}:{node.lineno}")
    assert bare == []


def test_podman_and_the_system_lookups_get_the_portal_setting_back(monkeypatch):
    monkeypatch.setattr(hostenv, "ORIGINAL", {})
    monkeypatch.setenv("GTK_USE_PORTAL", "1")
    hostenv.set_for_self("GTK_USE_PORTAL", "0")
    code, out = asyncio.run(podman.run(["/bin/sh", "-c", 'printf "%s" "$GTK_USE_PORTAL"']))
    assert (code, out.strip()) == (0, "1")
    code, out = asyncio.run(podman.run(["/bin/sh", "-c", 'printf "%s %s" "$GTK_USE_PORTAL" "$EXTRA"'],
                                       env={"EXTRA": "x"}))
    assert out.strip() == "1 x"
    assert sysinfo._run(["/bin/sh", "-c", 'printf "%s %s" "$GTK_USE_PORTAL" "$LC_ALL"']) == "1 C"
