"""End to end with the real sandbox: the real Claude Code CLI in the real container, driven over
podman exec, its model reached through the real gateway, here a fake Anthropic server on this
machine's loopback (so no key and no cost). Also checks the isolation from inside the container.

Opt-in: needs rootless Podman, network access and a few minutes for the first image build.
    .venv/bin/python -m pytest -m podman -s
"""

import asyncio
import json
import os
import shutil

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route

from davibemanager.config import Config, Provider
from davibemanager.workspace import podman
from helpers import wait_for

pytestmark = [pytest.mark.podman, pytest.mark.skipif(not shutil.which("podman"), reason="needs podman")]

TOOL = "mcp__host__request_host_command"
# a build script for the app's own builds below: a small real AppImage of the note the change adds (no compiler)
BUILD = r"""set -eu
d="$(mktemp -d)/AppDir"; mkdir -p "$d"
printf '#!/bin/sh\ncat "$APPDIR/note"\n' > "$d/AppRun"; chmod +x "$d/AppRun"
cp dvm-note.txt "$d/note"
printf '[Desktop Entry]\nType=Application\nName=hexyl\nName[de]=hexyl auf Deutsch\nExec=hexyl\nIcon=hexyl\nCategories=Utility;\nTerminal=true\n' > "$d/hexyl.desktop"
python3 -c "import base64,sys; sys.stdout.buffer.write(base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='))" > "$d/hexyl.png"
ARCH=x86_64 appimagetool --no-appstream --runtime-file /usr/local/share/appimage/runtime-x86_64 "$d" "$DVM_OUT/hexyl-x86_64.AppImage"
"""
# Podman keeps its images under XDG_DATA_HOME: it must see the real one, not the test's
REAL_DATA_HOME = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
REAL_CONFIG_HOME = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")


def _sse(events):
    async def gen():
        for name, data in events:
            yield f"event: {name}\ndata: {json.dumps(data)}\n\n".encode()
    return StreamingResponse(gen(), media_type="text/event-stream")


def _message(blocks, stop):
    events = [("message_start", {"type": "message_start", "message": {
        "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-fake-big", "content": [],
        "stop_reason": None, "usage": {"input_tokens": 10, "output_tokens": 1}}})]
    for i, b in enumerate(blocks):
        if b["type"] == "text":
            events += [("content_block_start", {"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}}),
                       ("content_block_delta", {"type": "content_block_delta", "index": i, "delta": {"type": "text_delta", "text": b["text"]}})]
        else:
            events += [("content_block_start", {"type": "content_block_start", "index": i, "content_block": {
                "type": "tool_use", "id": b["id"], "name": b["name"], "input": {}}}),
                ("content_block_delta", {"type": "content_block_delta", "index": i, "delta": {
                    "type": "input_json_delta", "partial_json": json.dumps(b["input"])}})]
        events.append(("content_block_stop", {"type": "content_block_stop", "index": i}))
    events += [("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop}, "usage": {"output_tokens": 5}}),
               ("message_stop", {"type": "message_stop"})]
    return events


def fake_anthropic(seen: list):
    async def messages(request: Request):
        body = await request.json()
        results = [c for m in body.get("messages", []) if isinstance(m.get("content"), list)
                   for c in m["content"] if c.get("type") == "tool_result"]
        seen.append({"model": body.get("model"), "key": request.headers.get("x-api-key", ""),
                     "tools": [t.get("name") for t in body.get("tools", [])], "results": results})
        has_tool = TOOL in [t.get("name") for t in body.get("tools", [])]
        if has_tool and not results:
            blocks = [{"type": "text", "text": "Let me check your kernel."},
                      {"type": "tool_use", "id": "toolu_1", "name": TOOL,
                       "input": {"command": "echo KERNEL-$(uname -r)", "purpose": "Which kernel you run", "risk": "read_only"}}]
            stop = "tool_use"
        else:
            blocks, stop = [{"type": "text", "text": "Thanks, that's what I needed."}], "end_turn"
        if not body.get("stream"):
            return JSONResponse({"id": "msg_1", "type": "message", "role": "assistant", "model": body.get("model"),
                                 "content": [b for b in blocks if b["type"] == "text"], "stop_reason": "end_turn",
                                 "usage": {"input_tokens": 1, "output_tokens": 1}})
        return _sse(_message(blocks, stop))

    async def count(request: Request):
        return JSONResponse({"input_tokens": 100})

    return Starlette(routes=[Route("/v1/messages", messages, methods=["POST"]),
                             Route("/v1/messages/count_tokens", count, methods=["POST"])])


@pytest.fixture
async def fake_model():
    import uvicorn
    seen: list = []
    server = uvicorn.Server(uvicorn.Config(fake_anthropic(seen), host="127.0.0.1", port=0, log_level="warning", lifespan="off"))
    task = asyncio.create_task(server.serve())
    await wait_for(lambda: server.started, "fake model server")
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}", seen
    server.should_exit = True
    await task


async def test_the_assistant_in_its_sandbox_asks_and_gets_only_what_the_user_sends(tmp_path, fake_model, monkeypatch):
    from davibemanager import appmanager, apps, config, conversation, creds, delivery, engine as engine_mod
    monkeypatch.setenv("XDG_DATA_HOME", REAL_DATA_HOME)
    monkeypatch.setenv("XDG_CONFIG_HOME", REAL_CONFIG_HOME)
    app_data = tmp_path / "app"
    for mod in (config, conversation, delivery, engine_mod, apps, appmanager):
        monkeypatch.setattr(mod, "data_dir", lambda: app_data)
    monkeypatch.setattr(engine_mod, "SANDBOX", "dvm-test-sandbox")

    url, seen = fake_model
    cfg = Config(providers=[Provider("Fake", "", builder_url=url, builder_auth="x-api-key")])
    cfg.settings.builder_provider, cfg.settings.builder_model, cfg.settings.builder_small_model = "Fake", "claude-fake-big", "claude-fake-small"
    creds.set_secret("provider", "Fake", "sk-real-key")
    engine = engine_mod.Engine(cfg, lambda e: None, tmp_path / "rt", save_config=lambda c: None)
    monkeypatch.setattr(engine, "_gateway_dir", lambda: tmp_path / "gw")
    assert engine.ready, engine.assistant_status()       # (a setup problem must not look like a slow sandbox)
    await engine.start()
    try:
        await wait_for(lambda: engine.workspace.get("state") in ("running", "failed"), "sandbox", tries=60000)
        assert engine.workspace["state"] == "running", engine.workspace

        async def inside(cmd):
            rc, out = await podman.exec_agent("dvm-test-sandbox", ["sh", "-c", cmd], timeout=60)
            return out.strip()
        assert "CapEff:\t0000000000000000" in await inside("grep CapEff /proc/self/status")
        assert await inside("env | grep -c sk-real-key || true") == "0"
        assert "No such file" in await inside(f"ls {os.path.expanduser('~')} 2>&1")
        assert "403" in await inside("curl -sS -o /dev/null https://192.168.1.1 2>&1")
        assert "Plain http is refused" in await inside("curl -sS http://example.com 2>&1")
        assert "Couldn't connect" in await inside("curl -sS --noproxy '*' --max-time 5 https://1.1.1.1 2>&1")
        assert await inside("curl -sS -o /dev/null -w '%{http_code}' https://github.com") in ("200", "301")
        assert await inside("command -v xvfb-run") == "/usr/bin/xvfb-run"

        # ---- the separation from this computer, tried from inside, as the assistant would
        assert "NoNewPrivs:\t1" in await inside("grep NoNewPrivs /proc/self/status")
        mounts = (await inside("awk '{print $5, $6}' /proc/self/mountinfo")).splitlines()
        points = {m.split()[0] for m in mounts}
        # the kernel's own (/proc, /sys, /dev: the devices are looked at below) and Podman's
        standard = {p for p in points if p in ("/", "/proc", "/sys", "/dev") or p.startswith(("/proc/", "/sys/", "/dev/"))}
        standard |= {"/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/run/.containerenv", "/run/podman-init", "/run/secrets"}
        assert points - standard == {"/work", "/home/agent", "/run/dvm", "/var/lib/dvm"}, points - standard
        assert any(m.startswith("/run/dvm ro") for m in mounts)
        assert "Read-only file system" in await inside("touch /run/dvm/x 2>&1")
        assert "Permission denied" in await inside("touch /var/lib/dvm/x 2>&1")      # the mirrors: never the agent's
        devices = set((await inside("ls /dev")).split())
        assert not {d for d in devices if d.startswith(("sd", "nvme", "dri", "video", "snd", "kvm", "input", "hidraw", "bus"))}
        env = await inside("env")
        assert not any(f"{v}=" in env for v in ("DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR",
                                                "SSH_AUTH_SOCK"))
        procs = set((await inside("ps -eo comm=")).split())
        # only its own: its init, the gateway's relays, Claude Code, its shells; none of this computer's
        assert procs <= {"podman-init", "dvm-entry", "socat", "sh", "bash", "ps", "sleep", "claude", "node"}, procs
        # this computer's own sockets (the app's, X11, D-Bus) are in another network namespace
        socks = await inside(f"python3 -c \"import socket\nfor n in ['\\0davibemanager-{os.getuid()}', '\\0/tmp/.X11-unix/X0']:\n"
                             f"    s = socket.socket(socket.AF_UNIX)\n    try: s.connect(n); print('REACHED', n)\n"
                             f"    except OSError as e: print('no', e.errno)\"")
        assert "REACHED" not in socks and socks.count("no ") == 2, socks
        # the way out: public https only, never this computer, however it's written or resolved
        for target in ("localhost", "127.0.0.1", "[::1]", "0.0.0.0", "[::ffff:127.0.0.1]", "localtest.me", "10.0.2.2"):
            out = await inside(f"curl -sS --noproxy '' -x http://127.0.0.1:3128 -o /dev/null -w '%{{http_code}}' "
                               f"https://{target}/ 2>&1")
            assert "403" in out, (target, out)
        # the model gateway: the assistant's messages only, not the provider's other endpoints with the key
        out = await inside(f"curl -s -o /dev/null -w '%{{http_code}}' -H 'x-api-key: {engine.gateway.token}' "
                           "-H 'content-type: application/json' -d '{}' http://127.0.0.1:8080/v1/images/generations")
        assert out == "404", out
        # a sandbox moved from elsewhere whose folders' tops are root's: the agent gets them back
        rc, _ = await podman.exec_root("dvm-test-sandbox", ["chown", "root:root", "/work", "/home/agent"])
        assert rc == 0 and "Permission denied" in await inside("mkdir /work/.dvm-owned 2>&1")
        assert await podman.own_folders("dvm-test-sandbox") == "/work\n/home/agent"
        assert await inside("mkdir /work/.dvm-owned && stat -c %U /work /home/agent | sort -u") == "agent"
        assert await podman.own_folders("dvm-test-sandbox") == ""
        await inside("rmdir /work/.dvm-owned")
        # the app's root commands look for programs in root's own folders only, never the agent's
        rc, path = await podman.exec_root("dvm-test-sandbox", ["printenv", "PATH"])
        assert rc == 0 and "/home/agent" not in path, path
        rc, where = await podman.exec_root("dvm-test-sandbox", ["sh", "-c", "command -v sh apt-get git"])
        assert rc == 0 and all(w.startswith(("/usr/", "/bin/")) for w in where.split()), where

        # an app's official source: the app's own copy, root's, which the assistant reads but can't change
        # or put aside; and its source with a change, carried over to a newer release by the app
        up = "https://github.com/sharkdp/hexyl.git"
        mirror = await engine.app_manager.mirror(up)
        denied = await inside(f"touch {mirror}/HEAD 2>&1; mv /var/lib/dvm/mirrors /var/lib/dvm/x 2>&1; "
                              f"rm -rf {mirror} 2>&1 | head -1")
        assert denied.count("Permission denied") == 3, denied
        assert len(await inside(f"git -C {mirror} rev-parse v0.14.0^{{commit}}")) == 40
        patch = "/work/.dvm/test/note.patch"
        await inside(f"rm -rf /tmp/w && git clone -q {mirror} /tmp/w && cd /tmp/w && git checkout -q -b x v0.13.0 && "
                     "echo note > dvm-note.txt && git add -A && git -c user.name=t -c user.email=t@t commit -qm Note "
                     f"--trailer 'DVM-Change: note' && mkdir -p /work/.dvm/test && git format-patch --stdout v0.13.0..HEAD > {patch}")
        from davibemanager.workspace import scripts
        rc, out = await podman.exec_agent("dvm-test-sandbox", ["sh", "-c", scripts.CARRY, "sh", mirror, up, "/work/apps/hexyl-test",
                                                               "v0.13.0", "v0.14.0", "note", patch], timeout=300)
        assert rc == 0 and "@@CHANGE note ok" in out, out
        assert await inside("git -C /work/apps/hexyl-test remote get-url origin") == up
        assert await inside("git -C /work/apps/hexyl-test merge-base --is-ancestor v0.14.0 HEAD && cat /work/apps/hexyl-test/dvm-note.txt") == "note"
        assert await inside("git -C /work/apps/hexyl-test log -1 '--format=%(trailers:key=DVM-Change,valueonly)'") == "note"

        # the app's own builds, for real: an imported app on its own release, then its update to a new one;
        # each carried over, built and checked in a clean container, and delivered
        rc, note = await podman.exec_agent("dvm-test-sandbox", ["cat", patch])
        a = apps.create("hexyl", "appimage", up, base_ref="v0.13.0", split=True,
                        changes=[{"id": "note", "title": "A note", "added": 0, "patch_ids": []}],
                        imported={"at": 0, "changes": ["note"], "built": False, "review": {}})
        for name, text in (("changes/note.patch", note), ("series.patch", note), ("build.sh", BUILD)):
            apps.write_file(a["id"], name, text)
        engine.cfg.settings.second_opinion = "off"
        did = await engine.app_manager.rebuild(a["id"], by_user=False, tag="v0.13.0")
        a = apps.load(a["id"])
        assert did and a["builds"] == [did] and a["imported"]["built"] is True, a.get("update")
        meta = delivery.load(delivery.root_dir() / did)
        assert meta["upstream"] == up and meta["base_ref"] == "v0.13.0" and meta["port"], meta
        # imported as an app of its own: its menu entry named as the user named it, in the AppImage itself
        entry = (delivery.root_dir() / did / "desktop" / "app.desktop").read_text()
        assert meta["menu_name"] == "hexyl (DVM)" and "Name=hexyl (DVM)\n" in entry and "Name[de]" not in entry, entry
        assert "Exec=hexyl" in entry and "Terminal=true" in entry
        apps.save({**a, "update": {"status": "available", "latest": "v0.14.0"}})
        again = await engine.app_manager.rebuild(a["id"], by_user=False)
        a = apps.load(a["id"])
        assert again and a["update"]["status"] == "built" and a["base_ref"] == "v0.14.0", a["update"]

        engine.send("Which kernel am I on?")
        await wait_for(lambda: engine.requests, "the assistant's request", tries=18000)
        r = next(iter(engine.requests.values()))
        assert r.status == "pending" and engine.busy
        await asyncio.sleep(1)
        assert r.status == "pending" and len(seen) <= 3        # it waits for the user; nothing has run
        engine.run_request(r.id)
        await wait_for(lambda: r.status == "done", "the command")
        assert f"KERNEL-{os.uname().release}" in r.preview
        engine.send_request(r.id, r.preview.replace(os.uname().release, "edited-by-user"))
        await wait_for(lambda: engine.conv.chat and engine.conv.chat[-1]["kind"] == "assistant", "turn end", tries=18000)
        entry = engine.conv.chat[-1]
        assert not entry.get("error"), entry
        assert [p["t"] for p in entry["parts"]][:2] == ["text", "request"]
        sent = json.dumps([s["results"] for s in seen])
        assert "KERNEL-edited-by-user" in sent and os.uname().release not in sent   # only what the user sent
        assert all(s["model"] in ("claude-fake-big", "claude-fake-small") for s in seen)
        assert all(s["key"] == "sk-real-key" for s in seen)       # added by the gateway, never seen inside
        assert engine.conv.session
        # a backup takes the chat's Claude Code session out of the sandbox, so it can go on elsewhere
        engine._persist()
        copied = await engine.backups._sessions(tmp_path / "sessions")
        assert copied and list(copied.rglob(f"{engine.conv.session}.jsonl")), "the session wasn't found in the sandbox"
    finally:
        await engine.stop()
        await podman.remove("dvm-test-sandbox")
