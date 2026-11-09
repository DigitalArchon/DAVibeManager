"""The window's own script (web/app.js), where it decides something on its own: its pure functions run
here in node, as the browser runs them (node's URL is the WHATWG parser a browser uses). Skipped where
there is no node."""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

APP_JS = Path(__file__).resolve().parents[1] / "src" / "davibemanager" / "web" / "app.js"
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="no node here to run the window's script")


def script(*names: str) -> str:
    """The constants and functions named, as app.js has them."""
    text = APP_JS.read_text(encoding="utf-8")
    parts = []
    for name in names:
        if m := re.search(rf"^const {name} = .*;$", text, re.M):
            parts.append(m.group(0))
            continue
        m = re.search(rf"^function {name}\(.*?^}}$", text, re.M | re.S)
        assert m, f"{name} isn't in app.js"
        parts.append(m.group(0))
    return "\n".join(parts)


def run(code: str, cases: list):
    """`test` (which `code` defines) of each case, as node gives it."""
    js = code + f"\nconst CASES = {json.dumps(cases)};\nconsole.log(JSON.stringify(CASES.map(test)));"
    done = subprocess.run([NODE, "-e", js], capture_output=True, text=True, timeout=30)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


LINKS = script("LINK_ENDS", "LINK_BREAKS", "LINK_UNSAFE", "isLocalHost", "insecureLink") + \
    "\nconst test = (url) => insecureLink(url);"


def test_plain_http_to_the_internet_is_insecure():
    urls = ["http://example.com/", "http://93.184.216.34/x", "HTTP://EXAMPLE.COM", "  http://example.com/  ",
            "http:example.com", "http://[2001:db8::1]/", "http://localhost.example.com/", "http://127.0.0.1.example.com/",
            "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"]   # no .onion rule here (netpolicy)
    assert run(LINKS, urls) == [True] * len(urls)


def test_an_address_that_cant_be_judged_as_written_is_insecure():
    urls = ["http://evil.example\\@localhost/", "http://127.0.0.1%2eevil.example/", "http://local\thost/",
            "ht\ttp://evil.example/", "http://", "http://[fe80::1%25eth0]/"]
    assert run(LINKS, urls) == [True] * len(urls)


def test_this_computer_and_its_network_are_not():
    urls = ["http://localhost:8080/", "http://127.0.0.1/", "http://127.9.8.7:1/", "http://[::1]:11434/",
            "http://192.168.1.201:11434/api", "http://10.0.0.2/", "http://172.20.1.1/", "http://[fd00::5]/",
            "http://[fe80::1]/", "http://printer.local/", "http://box.localhost/", "http://LOCALHOST./",
            "http://169.254.1.2/", "http://[::ffff:192.168.1.5]/", "http://0x7f000001/"]
    assert run(LINKS, urls) == [False] * len(urls)


def test_https_mailto_and_other_schemes_are_not():
    urls = ["https://example.com/", "HTTPS://example.com", "mailto:a@example.com", "ftp://x/", "", None]
    assert run(LINKS, urls) == [False] * len(urls)


def test_the_hosts_judged_local_are_netpolicys():
    """The window's reading of "this computer or its network" is the app's own (netpolicy.is_local_host)."""
    from davibemanager.netpolicy import is_local_host

    hosts = ["localhost", "127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.5", "fd12::1",
             "fe80::1", "169.254.10.1", "nas.local", "app.localhost", "example.com", "172.32.0.1", "8.8.8.8",
             "nas.lan", "10.0.0.1.evil.com", "2001:db8::1", "::ffff:10.0.0.1", "::ffff:8.8.8.8"]
    code = script("isLocalHost") + "\nconst test = (host) => isLocalHost(host);"
    assert run(code, hosts) == [is_local_host(h) for h in hosts]


def test_the_link_guard_and_the_mark_are_wired_in():
    text = APP_JS.read_text(encoding="utf-8")
    assert "markInsecure(DOMPurify.sanitize(" in text                     # every rendered answer
    assert "guardInsecureLinks();" in text.split("function init()")[1]    # at start
    assert 'document.addEventListener("click", ask, true)' in text and '"auxclick"' in text
    css = (APP_JS.parent / "style.css").read_text(encoding="utf-8")
    assert '.insecure-link::after { content: "⚠ not secure"; }' in css and "user-select: none !important" in css


def test_a_link_or_text_dropped_on_the_page_is_cancelled_and_files_are_attached():
    """Only files were cancelled (and attached): a link dropped on the window loaded in place of its page."""
    code = script("dropping") + """
const field = { closest: (sel) => (sel.includes("textarea") ? field : null) };
const page = { closest: () => null };
const test = ([types, where]) => dropping(types, where === "field" ? field : page);"""
    cases = [[["Files"], "page"], [["Files", "text/uri-list"], "field"], [["text/uri-list", "text/plain"], "page"],
             [["text/plain"], "page"], [["text/plain"], "field"], [[], "page"], [None, "page"]]
    assert run(code, cases) == ["files", "files", "cancel", "cancel", "default", "cancel", "cancel"]


def test_a_box_blacked_out_is_snapped_outwards_to_whole_pixels():
    """A fractional box is drawn anti-aliased: its edge pixels only partly black, with a trace of what was
    under them (DA Toolkit's editor, ported)."""
    code = script("snapBox") + "\nconst test = ([b, w, h]) => snapBox(b, w, h);"
    cases = [[{"x": 10.6, "y": 5.2, "w": 20.1, "h": 3.3}, 100, 100], [{"x": 95.5, "y": 0, "w": 10, "h": 10}, 100, 50]]
    assert run(code, cases) == [{"x": 10, "y": 5, "w": 21, "h": 4}, {"x": 95, "y": 0, "w": 5, "h": 10}]


def test_every_picture_goes_through_the_editor_before_it_is_attached():
    text = APP_JS.read_text(encoding="utf-8")
    flow = re.search(r"^async function addFiles\(list\) \{.*?^}$", text, re.M | re.S).group(0)
    assert 'file.type?.startsWith("image/")' in flow and "await redactPicture(file)" in flow
    editor = re.search(r"^function redactPicture\(file\) \{.*?^}$", text, re.M | re.S).group(0)
    assert 'ctx.fillStyle = "#000"' in editor and "if (!rects.length) { result = file; return; }" in editor


def test_each_row_of_sandbox_activity_says_what_it_was():
    """A picture described and a fetch refused read "undefined:undefined"."""
    code = script("connectionWhat") + "\nconst test = (e) => connectionWhat(e);"
    cases = [{"kind": "model", "model": "TEE/glm-5.3"}, {"kind": "vision", "model": "TEE/qwen2.5-vl-72b-instruct"},
             {"kind": "fetch", "url": "https://example.com/x"}, {"kind": "connect", "host": "example.com", "port": 443}]
    assert run(code, cases) == ["🤖 TEE/glm-5.3", "🖼 TEE/qwen2.5-vl-72b-instruct · describing a picture",
                                "🌐 https://example.com/x", "example.com:443"]
