"""Private models in the sandbox: Claude Code's Anthropic requests as sealed chat completions,
with images described by a vision helper (or sent as they are, to a model that sees)."""

import json

import httpx
import pytest

from davibemanager.config import Config, Provider
from davibemanager.gateway import Gateway, Upstream
from davibemanager.llm import anthropic_bridge as bridge
from davibemanager.llm.client import ToolCall, TurnResult
from davibemanager.models import Models

PNG = b"\x89PNG\r\n\x1a\n fake"


class Seen:
    def __init__(self):
        self.calls = []

    async def describe(self, url, context):
        self.calls.append((url, context))
        return "A window titled gThumb with a zoom box drawn on the photo."


async def test_a_conversation_with_tools_and_images_becomes_chat_messages():
    seen = Seen()
    images = bridge.ImageDescriber(seen.describe, "private/glm-5-3-flash")
    body = {
        "system": [{"type": "text", "text": "You are Claude Code."}],
        "max_tokens": 32000, "stop_sequences": ["END"], "tool_choice": {"type": "any"}, "thinking": {"type": "disabled"},
        "tools": [{"name": "Bash", "description": "Run a command", "input_schema": {"type": "object", "properties": {"command": {"type": "string"}}}}],
        "messages": [
            {"role": "user", "content": "Add drag-to-zoom to gThumb"},
            {"role": "assistant", "content": [{"type": "text", "text": "Let me look at the screen."},
                                              {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"command": "import -window root s.png"}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": [
                {"type": "text", "text": "saved"}, bridge.b64_image(PNG)]}, {"type": "text", "text": "and?"}]},
            {"role": "user", "content": [bridge.b64_image(PNG)]},
        ]}
    messages, tools, params = await bridge.to_openai(body, images)
    assert messages[0] == {"role": "system", "content": "You are Claude Code."}
    assert messages[2]["tool_calls"][0]["function"] == {"name": "Bash", "arguments": json.dumps({"command": "import -window root s.png"})}
    assert messages[3]["role"] == "tool" and messages[3]["tool_call_id"] == "toolu_1"
    assert "saved" in messages[3]["content"] and "zoom box" in messages[3]["content"] and "private/glm-5-3-flash" in messages[3]["content"]
    assert messages[4] == {"role": "user", "content": "and?"}
    assert "zoom box" in messages[5]["content"]
    assert len(seen.calls) == 1                                    # the same image is described once
    assert seen.calls[0][0].startswith("data:image/png;base64,") and "look at the screen" in seen.calls[0][1]
    assert not any(isinstance(m.get("content"), list) for m in messages)   # no image reaches the text model
    assert tools[0]["function"]["parameters"]["properties"]["command"]["type"] == "string"
    assert params == {"max_tokens": 32000, "stop": ["END"], "tool_choice": "required"}   # no "thinking: none"


async def test_without_a_vision_helper_the_model_is_told_it_cant_see():
    messages, _, _ = await bridge.to_openai({"messages": [{"role": "user", "content": [bridge.b64_image(PNG)]}]},
                                            bridge.ImageDescriber(None))
    assert "can't see images" in messages[0]["content"]


async def test_a_model_that_sees_gets_the_images_themselves():
    seen = Seen()
    body = {"messages": [
        {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"command": "shot"}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": [
            {"type": "text", "text": "saved"}, bridge.b64_image(PNG)]}, {"type": "text", "text": "and?"}]},
        {"role": "user", "content": [bridge.b64_image(PNG)]},
        {"role": "user", "content": [{"type": "image", "source": {"type": "url", "url": "https://example.com/a.png"}}]},
    ]}
    messages, _, _ = await bridge.to_openai(body, bridge.ImageDescriber(seen.describe, "private/glm-5-3-flash"), native=True)
    tool, after, alone, by_url = messages[1:]
    # a tool message holds text: its image comes right after the tool results, labelled with the call
    assert tool["role"] == "tool" and "saved" in tool["content"] and "next message" in tool["content"]
    assert after["role"] == "user" and [p["type"] for p in after["content"]] == ["text", "image_url", "text"]
    assert "toolu_1" in after["content"][0]["text"] and after["content"][2]["text"] == "and?"
    assert after["content"][1]["image_url"]["url"].startswith("data:image/png;base64,")
    assert alone["content"][0]["type"] == "image_url"
    assert by_url["content"] == "[An image was here, but it couldn't be read.]"     # never fetched
    assert not seen.calls                                                          # nothing described


async def test_a_model_sees_by_its_override_else_by_what_the_provider_reports(tmp_path):
    listing = {"data": [{"id": "moonshotai/kimi-k3", "capabilities": {"vision": True}},
                        {"id": "TEE/kimi-k3", "capabilities": {"vision": True}},
                        {"id": "z-ai/glm-5.3", "capabilities": {"vision": False}}]}
    asked = []

    def handler(request):
        asked.append(request)
        return httpx.Response(200, json=listing)
    prov = Provider("NanoGPT", "https://nano-gpt.com/api/v1", vision_overrides={"z-ai/glm-5.3": "yes", "TEE/kimi-k3": "no"})
    m = Models(Config(providers=[prov]), save_config=lambda c: None, emit=lambda *a, **k: None, log=lambda *a, **k: None)
    m.key = lambda p: "sk"
    m.caps_http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    assert await m.sees(prov, "private/kimi-k3")              # its public twin's, the list loaded first
    assert await m.sees(prov, "moonshotai/kimi-k3")
    assert await m.sees(prov, "z-ai/glm-5.3") and not await m.sees(prov, "TEE/kimi-k3")     # the overrides
    assert not await m.sees(prov, "someone/unknown-model")
    assert len(asked) == 1                                    # the list is loaded once


async def events(text="", calls=(), reasoning=0):
    for _ in range(reasoning):
        yield "reasoning", "hmm"
    if text:
        yield "text", text[:3]
        yield "text", text[3:]
    yield "done", TurnResult(content=text, tool_calls=list(calls), finish_reason="tool_calls" if calls else "stop",
                             usage={"prompt_tokens": 120, "completion_tokens": 7})


def parse(raw: bytes) -> list[tuple[str, dict]]:
    out = []
    for chunk in raw.decode().strip().split("\n\n"):
        name, data = chunk.split("\n", 1)
        out.append((name.removeprefix("event: "), json.loads(data.removeprefix("data: "))))
    return out


async def test_the_reply_streams_back_as_anthropic_events():
    raw = b"".join([c async for c in bridge.sse(events("Hello!", [ToolCall("call_9", "Bash", '{"command": "ls"}')], 3),
                                                "private/glm-5-3", 100, ping_every=0)])
    evs = parse(raw)
    names = [n for n, _ in evs]
    assert names[0] == "message_start" and names[-1] == "message_stop" and "ping" in names
    text = "".join(d["delta"]["text"] for n, d in evs if n == "content_block_delta" and d["delta"]["type"] == "text_delta")
    assert text == "Hello!"
    tool = next(d["content_block"] for n, d in evs if n == "content_block_start" and d["content_block"]["type"] == "tool_use")
    assert tool["id"] == "call_9" and tool["name"] == "Bash"
    args = next(d["delta"]["partial_json"] for n, d in evs if d.get("delta", {}).get("type") == "input_json_delta")
    assert json.loads(args) == {"command": "ls"}
    delta = next(d for n, d in evs if n == "message_delta")
    assert delta["delta"]["stop_reason"] == "tool_use" and delta["usage"]["output_tokens"] == 7


async def test_a_reply_that_does_not_stream_is_one_message():
    msg = await bridge.message(events("Done."), "private/glm-5-3", 50)
    assert msg["content"] == [{"type": "text", "text": "Done."}] and msg["stop_reason"] == "end_turn"


class FakePrivate:
    def __init__(self):
        self.calls = []

    def stream(self, model, messages, tools=None, params=None):
        self.calls.append((model, messages, tools, params))
        return events("Hi from GLM")


@pytest.fixture
async def private_gw(tmp_path):
    fake, seen, log = FakePrivate(), Seen(), []
    g = Gateway(tmp_path / "gw", lambda: Upstream("https://nano-gpt.com/api/v1", "bearer", lambda: "sk", ("private/glm-5-3", "private/glm-5-3-flash"),
                                                 provider="NanoGPT", tier="e2ee", chat=lambda m: fake,
                                                 describe=seen.describe, vision_model="private/glm-5-3-flash"),
                on_event=log.append, http=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: pytest.fail("no plaintext request"))))
    await g.start()
    yield g, fake, seen, log
    await g.stop()


async def test_requests_for_a_private_model_are_sealed_never_forwarded(private_gw):
    g, fake, seen, log = private_gw
    async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(g.model_socket)), base_url="http://gw") as c:
        headers = {"authorization": f"Bearer {g.token}"}
        r = await c.post("/v1/messages/count_tokens", headers=headers, json={"model": "private/glm-5-3", "messages": []})
        assert r.json()["input_tokens"] > 0
        r = await c.post("/v1/messages?beta=true", headers=headers, json={
            "model": "claude-haiku-whatever", "stream": True, "max_tokens": 100,
            "messages": [{"role": "user", "content": [{"type": "text", "text": "what is on screen?"}, bridge.b64_image(PNG)]}]})
    assert r.status_code == 200 and "Hi from GLM" in "".join(
        d["delta"].get("text", "") for n, d in parse(r.content) if n == "content_block_delta")
    model, messages, tools, params = fake.calls[0]
    assert model == "private/glm-5-3-flash"                       # an unchosen model gets the small one
    assert "zoom box" in messages[-1]["content"] and seen.calls
    assert log[-1]["private"] and log[-1]["tier"] == "e2ee" and log[-1]["status"] == 200
    assert log[-1]["usage"] == {"input": 120, "output": 7, "cache_read": 0, "cache_write": 0}   # what the chat's cost counts


async def test_private_models_are_asked_for_low_reasoning_never_none(private_gw):
    g, fake, _, _ = private_gw
    async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(g.model_socket)), base_url="http://gw") as c:
        await c.post("/v1/messages", headers={"authorization": f"Bearer {g.token}"},
                     json={"model": "private/glm-5-3", "stream": True, "thinking": {"type": "disabled"},
                           "messages": [{"role": "user", "content": "hi"}]})
    assert fake.calls[-1][3]["reasoning_effort"] == "low"     # for GLM, "none" means reasoning without limit


async def test_progress_is_reported_while_the_model_reasons():
    seen = []
    raw = [c async for c in bridge.sse(events("ok", reasoning=4), "private/glm-5-3", 10, ping_every=0, progress=seen.append)]
    assert raw and seen and seen[-1]["reasoning_chars"] > 0


async def test_every_non_anthropic_model_is_translated_and_a_tee_model_checked_first(tmp_path):
    fake, guarded, upstream = FakePrivate(), [], []

    async def guard(model):
        guarded.append(model)
        if model.startswith("TEE/"):
            raise RuntimeError("attestation refused")

    def handler(request):
        upstream.append(json.loads(request.content)["model"])
        return httpx.Response(200, text="event: message_stop\ndata: {}\n\n", headers={"content-type": "text/event-stream"})
    models = ("z-ai/glm-5.3", "TEE/glm-5.3", "anthropic/claude-opus-5.5")
    g = Gateway(tmp_path / "gw", lambda: Upstream("https://nano-gpt.com/api/v1", "bearer", lambda: "sk", models, provider="NanoGPT",
                                                 chat=lambda m: fake, guard=guard),
                http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    await g.start()
    try:
        async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(g.model_socket)), base_url="http://gw") as c:
            h = {"authorization": f"Bearer {g.token}"}
            msg = {"stream": True, "messages": [{"role": "user", "content": "hi"}]}
            r = await c.post("/v1/messages", headers=h, json={"model": "z-ai/glm-5.3", **msg})
            said = "".join(d["delta"].get("text", "") for n, d in parse(r.content) if n == "content_block_delta")
            assert said == "Hi from GLM" and fake.calls[-1][3]["reasoning_effort"] == "low"
            r = await c.post("/v1/messages", headers=h, json={"model": "TEE/glm-5.3", **msg})
            assert r.status_code == 502 and "attestation refused" in r.text
            await c.post("/v1/messages", headers=h, json={"model": "anthropic/claude-opus-5.5", **msg})
            assert upstream == ["anthropic/claude-opus-5.5"]          # Claude goes straight through
        assert guarded == ["z-ai/glm-5.3", "TEE/glm-5.3"] and len(fake.calls) == 1
    finally:
        await g.stop()


async def test_the_gateway_sends_images_to_a_model_that_sees_and_describes_them_for_one_that_doesnt(tmp_path):
    fake, seen, log = FakePrivate(), Seen(), []

    async def sees(model):
        return model == "private/kimi-k3"
    g = Gateway(tmp_path / "gw", lambda: Upstream("https://nano-gpt.com/api/v1", "bearer", lambda: "sk", ("private/kimi-k3", "private/glm-5-3"),
                                                 provider="NanoGPT", tier="e2ee", chat=lambda m: fake, describe=seen.describe,
                                                 vision_model="private/glm-5-3-flash", sees=sees),
                on_event=log.append, http=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: pytest.fail("no plaintext request"))))
    await g.start()
    try:
        async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(g.model_socket)), base_url="http://gw") as c:
            h = {"authorization": f"Bearer {g.token}"}
            msg = {"stream": True, "messages": [{"role": "user", "content": [{"type": "text", "text": "what is on screen?"},
                                                                             bridge.b64_image(PNG)]}]}
            await c.post("/v1/messages", headers=h, json={"model": "private/kimi-k3", **msg})
            assert fake.calls[-1][1][-1]["content"][1]["type"] == "image_url" and not seen.calls
            assert log[-1]["sees"]
            await c.post("/v1/messages", headers=h, json={"model": "private/glm-5-3", **msg})
            assert "zoom box" in fake.calls[-1][1][-1]["content"] and seen.calls
            assert "sees" not in log[-1]
    finally:
        await g.stop()


async def test_a_reply_cut_off_at_its_length_says_so_and_hands_over_no_call_it_cut_short():
    """finish_reason "length" in the middle of a Write: not a tool call with no input (run with nothing it
    fails, and the model, never told why, writes it all again, paid each time), but max_tokens."""
    from davibemanager.llm import anthropic_bridge as bridge
    from davibemanager.llm.client import ToolCall, TurnResult

    async def events():
        yield "text", "Writing it."
        yield "done", TurnResult(content="Writing it.", finish_reason="length", tool_calls=[
            ToolCall("call_1", "Read", '{"file_path": "/work/a.c"}'),
            ToolCall("call_2", "Write", '{"file_path": "/work/zoom.c", "content": "#include <gtk/gtk.h>\\nstatic void on_')])
    msg = await bridge.message(events(), "z-ai/glm-5.3", 100)
    assert msg["stop_reason"] == "max_tokens"
    assert [(c["name"], c["input"]) for c in msg["content"] if c["type"] == "tool_use"] == [("Read", {"file_path": "/work/a.c"})]
    streamed = b"".join([c async for c in bridge.sse(events(), "z-ai/glm-5.3", 100)]).decode()
    assert '"stop_reason": "max_tokens"' in streamed and '"Write"' not in streamed


async def _post(g, body):
    async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(g.model_socket)), base_url="http://gw") as c:
        return await c.post("/v1/messages", headers={"authorization": f"Bearer {g.token}"}, content=json.dumps(body))


async def test_a_private_chat_is_never_sent_to_a_model_in_the_clear(tmp_path):
    """A chat begun on private GLM, the models then changed (its Claude Code still asks for private GLM, with
    all that was said), or a private model with quick tasks on a plain one: sealed, or refused, never sent
    in the clear in its place; nor a request without a model."""
    fake, log = FakePrivate(), []
    models = {"now": ("z-ai/glm-5.3", "z-ai/glm-5.3-flash")}
    g = Gateway(tmp_path / "gw", lambda: Upstream("https://nano-gpt.com/api/v1", "bearer", lambda: "sk", models["now"],
                                                 provider="NanoGPT", chat=lambda m: fake),
                on_event=log.append, http=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: pytest.fail("no plaintext"))))
    await g.start()
    try:
        msg = {"stream": True, "messages": [{"role": "user", "content": "what we said in private"}]}
        r = await _post(g, {**msg, "model": "private/glm-5-3"})                  # the models were changed since
        assert r.status_code == 403 and not fake.calls and "isn't sent to another in the clear" in r.text
        models["now"] = ("private/glm-5-3", "z-ai/glm-5.3-flash")                # quick tasks on a plain model
        for model in ("z-ai/glm-5.3-flash", "claude-haiku-4-5", None):
            r = await _post(g, {**msg, **({"model": model} if model else {})})
            assert r.status_code == 403 and not fake.calls, model
        models["now"] = ("private/glm-5-3", "private/glm-5-3")                   # (an empty one is the same model)
        r = await _post(g, msg)                                                  # no model: the private one, sealed
        assert r.status_code == 200 and fake.calls[-1][0] == "private/glm-5-3"
        r = await _post(g, {**msg, "model": "Private/GLM-5-3 "})                 # however it's written: sealed
        assert r.status_code == 200 and fake.calls[-1][0] == "private/glm-5-3"
        async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(g.model_socket)), base_url="http://gw") as c:
            r = await c.post("/v1/messages", headers={"authorization": f"Bearer {g.token}"}, content=b'["not", "a", "request"]')
        assert r.status_code == 400
    finally:
        await g.stop()


def test_tool_calls_a_server_gives_no_index_or_the_same_one_stay_apart():
    """Deltas keyed by index only: two calls without one became one "ReadRead" with '{…}{…}' for input."""
    from openai.types.chat import ChatCompletionChunk
    from davibemanager.llm.client import StreamAccumulator

    def chunk(calls, finish=None):
        return ChatCompletionChunk.model_validate({"id": "x", "object": "chat.completion.chunk", "created": 0, "model": "m",
                                                   "choices": [{"index": 0, "delta": {"tool_calls": calls}, "finish_reason": finish}]})
    acc = StreamAccumulator()                                   # each call under index 0 (no index: the same)
    for cid, path in (("a", "/a"), ("b", "/b")):
        acc.feed(chunk([{"index": 0, "id": cid, "type": "function", "function": {"name": "Read", "arguments": f'{{"file_path": "{path}"}}'}}]))
    acc.feed(chunk([], "tool_calls"))
    calls = acc.finish().tool_calls
    assert [(c.id, c.name, c.arguments) for c in calls] == [("a", "Read", '{"file_path": "/a"}'), ("b", "Read", '{"file_path": "/b"}')]
    acc = StreamAccumulator()                                   # the usual: one call in pieces, under its index
    for part in ('{"file_', 'path": "/a"}'):
        acc.feed(chunk([{"index": 0, **({"id": "a", "type": "function"} if part.startswith("{") else {}),
                         "function": {**({"name": "Read"} if part.startswith("{") else {}), "arguments": part}}]))
    assert [(c.id, c.arguments) for c in acc.finish().tool_calls] == [("a", '{"file_path": "/a"}')]


async def test_a_reply_that_isnt_streamed_counts_as_the_provider_billed_it(tmp_path):
    """Its cached tokens as cached, what NanoGPT billed for a routed model, and no usage made up from the
    gateway's own estimate when the provider gave none."""
    from davibemanager.llm.client import TurnResult
    log, usage = [], {"now": {"prompt_tokens": 100_000, "completion_tokens": 50, "cost": 0.0123,
                              "prompt_tokens_details": {"cached_tokens": 90_000}}}

    class Billed:
        def stream(self, model, messages, tools=None, params=None):
            async def go():
                yield "text", "ok"
                yield "done", TurnResult(content="ok", finish_reason="stop", usage=usage["now"])
            return go()
    g = Gateway(tmp_path / "gw", lambda: Upstream("https://nano-gpt.com/api/v1", "bearer", lambda: "sk", ("z-ai/glm-5.3",) * 2,
                                                 provider="NanoGPT", chat=lambda m: Billed(),
                                                 route=lambda m: {"priority": "speed", "fp8": True}),
                on_event=log.append, http=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: pytest.fail("x"))))
    await g.start()
    try:
        r = await _post(g, {"model": "z-ai/glm-5.3", "messages": [{"role": "user", "content": "hi"}]})
        assert r.status_code == 200
        assert log[-1]["usage"] == {"input": 10_000, "output": 50, "cache_read": 90_000, "cache_write": 0, "cost": 0.0123}
        assert log[-1]["route_held"] is True
        usage["now"] = None
        await _post(g, {"model": "z-ai/glm-5.3", "messages": [{"role": "user", "content": "hi"}]})
        assert "usage" not in log[-1]
    finally:
        await g.stop()


async def test_anthropics_server_tools_are_left_out():
    """Its web search runs on Anthropic's servers: a chat model given it as a function would call it,
    and nothing would run it."""
    body = {"messages": [{"role": "user", "content": "search"}], "tools": [
        {"type": "web_search_20250305", "name": "web_search", "max_uses": 8},
        {"name": "Read", "description": "Read a file", "input_schema": {"type": "object"}},
        {"type": "custom", "name": "Mine", "input_schema": {"type": "object"}}]}
    _, tools, _ = await bridge.to_openai(body, bridge.ImageDescriber(None))
    assert [t["function"]["name"] for t in tools] == ["Read", "Mine"]


async def test_the_billing_block_is_left_out_of_the_system_prompt():
    """Claude Code's first system block is for Anthropic's billing, with a fingerprint that differs
    between conversations (Claude Code 2.1.296: cc_version=2.1.296.cf4, then .9ec)."""
    body = {"system": [{"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.296.cf4; cc_entrypoint=sdk-py;"},
                       {"type": "text", "text": "You are a Claude agent.", "cache_control": {"type": "ephemeral"}},
                       {"type": "text", "text": "Build in /work."}],
            "messages": [{"role": "user", "content": "hi"}]}
    messages, _, _ = await bridge.to_openai(body, bridge.ImageDescriber(None))
    assert messages[0] == {"role": "system", "content": "You are a Claude agent.\nBuild in /work."}


async def test_system_messages_within_the_conversation_go_in_the_users_turn():
    """As Claude Code 2.1.296 sends them to a model it doesn't know: its environment, after the user's
    message. A chat template may refuse a system message anywhere but first."""
    body = {"system": "You are Claude Code.", "messages": [
        {"role": "user", "content": [{"type": "text", "text": "Add drag-to-zoom"}]},
        {"role": "system", "content": "# Environment\n - Primary working directory: /work"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "Bash", "input": {}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "ok"}]},
        {"role": "system", "content": [{"type": "text", "text": "The date changed."}]},
    ]}
    messages, _, _ = await bridge.to_openai(body, bridge.ImageDescriber(None))
    assert [m["role"] for m in messages] == ["system", "user", "assistant", "tool", "user"]
    assert messages[1]["content"] == ("Add drag-to-zoom\n\n<system-reminder>\n# Environment\n - Primary working "
                                      "directory: /work\n</system-reminder>")
    assert messages[4]["content"] == "<system-reminder>\nThe date changed.\n</system-reminder>"


async def test_the_usage_says_what_came_from_the_prompt_cache():
    """As Anthropic's does: input_tokens without the cached part, which is cache_read_input_tokens."""
    usage = {"prompt_tokens": 100_000, "completion_tokens": 50, "prompt_tokens_details": {"cached_tokens": 90_000}}

    async def cached():
        yield "text", "ok"
        yield "done", TurnResult(content="ok", finish_reason="stop", usage=usage)
    delta = next(d for n, d in parse(b"".join([c async for c in bridge.sse(cached(), "private/glm-5-3", 5)]))
                 if n == "message_delta")
    assert delta["usage"] == {"input_tokens": 10_000, "cache_creation_input_tokens": 0,
                              "cache_read_input_tokens": 90_000, "output_tokens": 50}
    msg = await bridge.message(cached(), "private/glm-5-3", 5)
    assert msg["usage"]["cache_read_input_tokens"] == 90_000 and msg["usage"]["input_tokens"] == 10_000
    assert bridge.anthropic_usage(None, 42) == {"input_tokens": 42, "output_tokens": 0}       # no usage: the estimate


async def test_a_quiet_model_is_kept_alive_with_pings_and_its_progress_reported():
    """The CLI gives up on a stream after 300 seconds without an event; attestation and a model
    that reasons without streaming it are quiet."""
    import asyncio

    async def slow():
        await asyncio.sleep(1.2)
        yield "text", "late"
        yield "done", TurnResult(content="late", finish_reason="stop")
    seen = []
    evs = parse(b"".join([c async for c in bridge.sse(slow(), "private/glm-5-3", 1, ping_every=0.5, progress=seen.append)]))
    names = [n for n, _ in evs]
    assert names.count("ping") >= 2 and names.index("ping") < names.index("content_block_start")
    assert len(seen) >= 2 and "late" in json.dumps(evs)


async def test_a_reply_abandoned_midway_closes_the_models_stream():
    """The CLI gone mid-reply (the user stopped it): the request is dropped at once."""
    import asyncio
    closed = asyncio.Event()

    async def endless():
        try:
            while True:
                yield "text", "more "
                await asyncio.sleep(0.01)
        finally:
            closed.set()
    stream = bridge.sse(endless(), "private/glm-5-3", 1)
    async for chunk in stream:
        if b"more" in chunk:
            break
    await stream.aclose()
    await asyncio.wait_for(closed.wait(), 1)
