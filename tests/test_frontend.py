"""The window's own tests (tests/js/*.test.cjs), run in Node against the real index.html, marked,
DOMPurify and app.js, fed a snapshot of a real Engine as the events socket sends it, so a change in
what the server sends reaches these tests too. Skipped where Node isn't installed.

They need a DOM: tests/js/sanitize.test.cjs uses jsdom, which is not one of this repository's
packages, and skips itself unless a jsdom is on Node's path (NODE_PATH=<a node_modules that has
jsdom>). The Markdown renderer's own layer, which needs no DOM, is checked in tests/test_web.py.

To run them on their own: DVM_STATE=<a snapshot> node --test tests/js/"""

import asyncio
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

JS = Path(__file__).parent / "js"
NODE = shutil.which("node")


@pytest.mark.skipif(not NODE, reason="Node isn't installed")
async def test_the_window_in_a_dom(env, tmp_path):
    engine, _, _ = env
    path = tmp_path / "state.json"
    path.write_text(json.dumps(engine.snapshot()), encoding="utf-8")
    # one process, so the timeout's kill ends all of it; a capped heap, so a page that runs away
    # fails here instead of taking the machine's memory
    run = await asyncio.to_thread(
        subprocess.run, [NODE, "--max-old-space-size=512", "--test", "--test-isolation=none", "--test-timeout=30000",
                         "--test-reporter=spec", *sorted(map(str, JS.glob("*.test.cjs")))],
        env={**os.environ, "DVM_STATE": str(path)}, capture_output=True, text=True, timeout=180, check=False)
    assert run.returncode == 0, run.stdout[-20000:] + run.stderr[-5000:]
