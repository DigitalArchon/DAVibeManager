"""Web search: the assistant searches on its own, through the app, but never with anything that
came from the user's computer."""

import json

import httpx
import pytest

from davibemanager.hostrun import HostRequest
from davibemanager.llm import websearch
from davibemanager.safety.outside import OutsideData

HOST_OUTPUT = """\
gThumb 3.12.6
Description:    Linux Mint 22.1 Xia
tcp   ESTAB  0  0  192.168.1.20:3389  192.168.1.100:51234  users:(("xrdp",pid=1234,fd=12))
-rw-r--r-- 1 sam sam 48213 Oct  2 holiday_beach.jpg
SSID: KettleNet5G
Something odd happened while loading the thumbnail cache today
"""


@pytest.fixture
def outside(tmp_path):
    o = OutsideData(tmp_path / "outside.json", names=["sam", "mint-xia"])
    o.add(HOST_OUTPUT)
    return o


@pytest.mark.parametrize("query", [
    "gThumb drag to zoom fork", "gthumb click and drag zoom like ACDSee", "Linux Mint Cinnamon text scaling",
    "xrdp high cpu usage", "mpv lua burst screenshot script", "github gthumb merge request zoom rectangle",
    "1.1.1.1 dns over https",                     # a public address, not one of theirs
])
def test_what_is_in_the_sandbox_and_plain_names_may_be_searched(outside, query):
    assert outside.check(query) == []


@pytest.mark.parametrize("query, found", [
    ("gthumb 3.12.6 drag zoom", "3.12.6"),                          # their version
    ("xrdp connection from 192.168.1.100", "192.168.1.100"),      # their network
    ("linux mint 22.1 hidpi", "22.1"),
    ("recover holiday_beach.jpg", "holiday_beach.jpg"),           # their files
    ("KettleNet5G keeps dropping", "KettleNet5G"),                # their Wi-Fi
    ("odd happened while loading the thumbnail cache", "happened while loading the thumbnail"),   # a copied line
    ("sam home folder permissions", "sam"),                   # who they are
    ("mint-xia hostname", "mint-xia"),
    ("contact me at someone@example.org", "someone@example.org"),
    ("aa:bb:cc:dd:ee:ff vendor", "aa:bb:cc:dd:ee:ff"),
    ("router 10.0.0.1 login", "10.0.0.1"),
])
def test_anything_from_the_users_computer_is_found_in_a_query(outside, query, found):
    assert any(found.lower() in f.lower() for f in outside.check(query)), outside.check(query)


def test_it_is_remembered_hashed_and_a_reset_forgets_it(outside, tmp_path):
    again = OutsideData(tmp_path / "outside.json", names=[])
    assert again.check("gthumb 3.12.6") == ["3.12.6"]
    stored = (tmp_path / "outside.json").read_text()
    for secret in ("3.12.6", "KettleNet5G", "holiday", "192.168"):
        assert secret.lower() not in stored.lower()                 # no second plaintext copy
    again.clear()
    assert OutsideData(tmp_path / "outside.json", names=[]).check("gthumb 3.12.6") == []


class FakeSearch:
    def __init__(self, fail_first=0):
        self.requests, self.fail_first = [], fail_first

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.requests.append((str(request.url), request.headers.get("authorization"), body))
        if self.fail_first:
            self.fail_first -= 1
            return httpx.Response(503, json={"error": {"message": "provider down"}})
        return httpx.Response(200, json={"data": [{"title": "gThumb fork with box zoom", "url": "https://github.com/x/gthumb",
                                                   "content": "Adds drag-to-zoom."}], "metadata": {"cost": 0.005}})


@pytest.fixture
async def searching(env):
    engine, _, events = env
    engine.cfg.providers[0].base_url = "https://nano-gpt.com/api/v1"
    fake = FakeSearch()
    engine.search_http = httpx.AsyncClient(transport=httpx.MockTransport(fake.handler))
    return engine, fake, events


async def test_searches_run_here_with_the_key_perplexity_to_learn_and_kagi_to_find(searching):
    engine, fake, events = searching
    text = await engine.builder_search({"query": "gthumb drag to zoom fork", "sites": ["https://github.com/"]})
    url, auth, body = fake.requests[-1]
    assert url == "https://nano-gpt.com/api/web" and auth == "Bearer sk-test"
    assert body["provider"] == "perplexity" and body["query"] == "gthumb drag to zoom fork"
    assert body["includeDomains"] == ["github.com"]
    assert "https://github.com/x/gthumb" in text and "Untrusted web content" in text
    await engine.builder_search({"query": "gthumb official website", "purpose": "links"})
    assert fake.requests[-1][2]["provider"] == "kagi"
    logged = [e["event"] for e in events if e.get("type") == "network" and e["event"]["kind"] == "search"]
    assert logged[-1]["provider"] == "kagi" and logged[-1]["status"] == 200


async def test_a_query_with_anything_sent_from_this_computer_never_leaves(searching):
    engine, fake, _ = searching
    r = HostRequest.create(1, {"command": "gthumb --version", "purpose": "Check your gThumb", "risk": "read_only"})
    r.status, r.preview = "done", "gThumb 3.12.6 (built on KettleNet5G-box)\n"
    engine.requests[r.id] = r
    engine.send_request(r.id)                               # the user sends it to the assistant
    reply = await engine.builder_search({"query": "gThumb 3.12.6 zoom bug"})
    assert reply.startswith("Not searched") and "3.12.6" in reply
    assert fake.requests == []                              # nothing went out
    await engine.builder_search({"query": "gThumb zoom bug"})
    assert len(fake.requests) == 1


async def test_what_was_sent_before_this_check_existed_counts_too(env, tmp_path):
    from davibemanager.config import data_dir
    from davibemanager.conversation import Conversation
    engine, _, _ = env
    conv = Conversation.create()
    conv.requests = [{"id": 1, "sent_text": "Wi-Fi: KettleNet5G"}]
    conv.save()
    (data_dir() / "outside.json").unlink()
    engine.outside = None
    assert engine._outside().check("KettleNet5G dropping") == ["KettleNet5G"]


async def test_a_failing_provider_falls_back_and_searches_can_be_switched_off(searching):
    engine, fake, _ = searching
    fake.fail_first = 1
    await engine.builder_search({"query": "mpv burst screenshots"})
    assert [b["provider"] for _, _, b in fake.requests] == ["perplexity", websearch.FALLBACK]
    engine.cfg.settings.web_search = False
    with pytest.raises(Exception, match="switched off"):
        await engine.builder_search({"query": "mpv burst screenshots"})


async def test_searches_per_chat_are_limited(searching, monkeypatch):
    from davibemanager import engine as engine_mod
    engine, _, _ = searching
    monkeypatch.setattr(engine_mod, "SEARCHES_PER_CHAT", 2)
    for _ in range(2):
        await engine.builder_search({"query": "mpv scripts"})
    with pytest.raises(Exception, match="the most allowed"):
        await engine.builder_search({"query": "mpv scripts"})


def test_claude_codes_own_search_is_off_and_webfetch_tells_anthropic_nothing(tmp_path):
    from davibemanager.builder import bridge
    session = bridge.BuilderSession(container="c", wrapper=tmp_path / "claude", host=None, env=dict,
                                    emit=lambda *a, **k: None, on_session=print, on_change=print, on_turn_end=print)
    opts = session._options()
    assert "WebSearch" in opts.disallowed_tools and json.loads(opts.settings)["skipWebFetchPreflight"] is True


def test_a_web_address_is_checked_like_a_search(outside):
    assert outside.check_url("https://gitlab.gnome.org/GNOME/gthumb/-/issues?search=zoom") == []
    assert outside.check_url("https://gitlab.gnome.org/GNOME/gthumb/-/issues?search=3.12.6") == ["3.12.6"]
    assert outside.check_url("https://example.org/a/KettleNet5G") == ["KettleNet5G"]
    assert outside.check_url("https://example.org/p?ip=192.168.1.100&x=1") == ["192.168.1.100"]
    assert outside.check_url("https://example.org/?q=holiday_beach.jpg%20recover") == ["holiday_beach.jpg"]


async def test_webfetch_is_stopped_in_the_app_before_claude_code_reads_the_page(tmp_path):
    from davibemanager.builder import bridge

    class Host:
        def builder_fetch_check(self, url):
            return "Not fetched: it holds '3.12.6'" if "3.12.6" in url else ""
    session = bridge.BuilderSession(container="c", wrapper=tmp_path / "claude", host=Host(), env=dict,
                                    emit=lambda *a, **k: None, on_session=print, on_change=print, on_turn_end=print)
    hooks = session._options().hooks["PreToolUse"]
    assert hooks[0].matcher == "WebFetch"
    out = await hooks[0].hooks[0]({"tool_input": {"url": "https://x.org/?v=3.12.6"}}, "t1", None)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny" and "3.12.6" in out["hookSpecificOutput"]["permissionDecisionReason"]
    assert await hooks[0].hooks[0]({"tool_input": {"url": "https://x.org/releases"}}, "t2", None) == {}
