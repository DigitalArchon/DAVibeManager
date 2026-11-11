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
        # one written over several lines: an object or array closed on a line of its own
        if m := re.search(rf"^const {name} = [{{\[]$.*?^[}}\]];$", text, re.M | re.S):
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
    """A picture described and a fetch refused read "undefined:undefined"; second opinions weren't listed."""
    code = script("connectionWhat", "REVIEW_WHAT") + "\nconst test = (e) => connectionWhat(e);"
    cases = [{"kind": "model", "model": "TEE/glm-5.3"}, {"kind": "vision", "model": "TEE/qwen2.5-vl-72b-instruct"},
             {"kind": "review", "model": "z-ai/glm-5.3", "purpose": "changelog_summary"},
             {"kind": "review", "model": "z-ai/glm-5.3", "purpose": "something new"},
             {"kind": "fetch", "url": "https://example.com/x"}, {"kind": "connect", "host": "example.com", "port": 443}]
    assert run(code, cases) == ["🤖 TEE/glm-5.3", "🖼 TEE/qwen2.5-vl-72b-instruct · describing a picture",
                                "🧐 z-ai/glm-5.3 · summarising a change log", "🧐 z-ai/glm-5.3 · second opinion",
                                "🌐 https://example.com/x", "example.com:443"]


def test_a_tee_replys_check_marks_the_request_it_was_whoever_made_it():
    """The assistant's requests, second opinions and pictures described are each marked with what their
    reply's check found (gateway._check_later, Engine._check_reply), and each shows its mark."""
    code = script("markChecked") + """
const test = (check) => {
  const rows = [{ kind: "model", id: "a", tee: "checking" }, { kind: "review", id: "b", tee: "checking" },
                { kind: "vision", id: "c", tee: "checking" }, { kind: "tee_reply", id: "d" }];
  markChecked(rows, check);
  return rows.map((e) => [e.tee || null, e.tee_detail || null]);
};"""
    waiting = [["checking", None]] * 3 + [[None, None]]
    cases = [{"of": "a", "tee": "verified"}, {"of": "b", "tee": "failed", "detail": "keys changed"},
             {"of": "c", "tee": "unchecked"}, {"of": "d", "tee": "failed"}, {"of": "nobody", "tee": "failed"}]
    assert run(code, cases) == [
        [["verified", None]] + waiting[1:],
        [waiting[0], ["failed", "keys changed"]] + waiting[2:],
        waiting[:2] + [["unchecked", None], waiting[3]],
        waiting, waiting]
    text = APP_JS.read_text(encoding="utf-8")
    assert "markChecked(st.network, ev.event);" in text
    assert 'const asked = ["model", "vision", "review"].includes(e.kind);' in text and "asked ? [\" \", privacyMark(e)]" in text


def tee_mark() -> str:
    """A TEE reply's mark as Sandbox activity shows it (teeMark): [words, colour, tooltip], or null."""
    return script("TEE_MARKS", "TEE_CLEAR", "TEE_TIPS", "teeMark") + "\nconst test = (e) => teeMark(e);"


def test_a_tee_replys_mark_says_what_is_the_gateways_word_and_that_it_passed_in_the_clear():
    """SealedLore's marks (Nov 11 2026): for a model RedPill serves, the attested enclave is its gateway, and the
    machine that ran the model is the gateway's word; every mark short of end-to-end encryption says the text
    passed NanoGPT in the clear. "Verified" read as though the model itself had been checked."""
    cases = [{"tee": "verified"}, {"tee": "signed"},
             {"tee": "unchecked", "tee_detail": "the reply came with no receipt to say the model's enclave answered"},
             {"tee": "failed"}, {"tee": "checking"}, {"kind": "model"}]
    verified, signed, unchecked, failed, checking, none = run(tee_mark(), cases)
    assert verified[:2] == ["TEE verified", "ok"]
    assert "that enclave is RedPill's gateway" in verified[2] and "which is the gateway's word, not checked" in verified[2]
    assert signed[0] == "TEE signed, text not compared" and "the machine running the model is the gateway's word" in signed[2]
    assert unchecked[:2] == ["TEE ⚠ reply not verified", "warn"] and "as Chutes doesn't" in unchecked[2]
    assert unchecked[2].endswith("(the reply came with no receipt to say the model's enclave answered)")
    for tip in (verified[2], signed[2], unchecked[2]):
        assert "passed NanoGPT's servers in the clear: a private model is end-to-end encrypted instead" in tip
    assert failed[1] == "danger" and "its receipt doesn't hold" in failed[2] and "attested again" in failed[2]
    assert checking[0] == "TEE · checking its signature…" and none is None
