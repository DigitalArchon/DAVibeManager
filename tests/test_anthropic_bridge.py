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


async def test_private_models_are_asked_for_the_chosen_reasoning_never_none(private_gw):
    g, fake, _, _ = private_gw
    async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(g.model_socket)), base_url="http://gw") as c:
        await c.post("/v1/messages", headers={"authorization": f"Bearer {g.token}"},
                     json={"model": "private/glm-5-3", "stream": True, "thinking": {"type": "disabled"},
                           "messages": [{"role": "user", "content": "hi"}]})
    assert fake.calls[-1][3]["reasoning_effort"] == "medium"  # the default; for GLM, "none" means reasoning without limit


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
            assert said == "Hi from GLM" and fake.calls[-1][3]["reasoning_effort"] == "medium"
            r = await c.post("/v1/messages", headers=h, json={"model": "TEE/glm-5.3", **msg})
            assert r.status_code == 502 and "attestation refused" in r.text
            await c.post("/v1/messages", headers=h, json={"model": "anthropic/claude-opus-5.5", **msg})
            assert upstream == ["anthropic/claude-opus-5.5"]          # Claude goes straight through
        # every model through the guard, Claude's too (one a provider marks TEE is attested first: test_tee.py)
        assert guarded == ["z-ai/glm-5.3", "TEE/glm-5.3", "anthropic/claude-opus-5.5"] and len(fake.calls) == 1
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


# ---------------------------------------------------------------- found by DA Private Coder (Nov 8 2026)

import asyncio  # noqa: E402
from contextlib import asynccontextmanager  # noqa: E402

from davibemanager.llm import params as params_mod  # noqa: E402
from davibemanager.llm.private_mode import PrivateModeError  # noqa: E402

BASE = "https://nano-gpt.com/api/v1"
ASK = {"stream": True, "messages": [{"role": "user", "content": "hi"}]}


@asynccontextmanager
async def translating(tmp_path, fake, models=("private/kimi-k3", "private/glm-5-3"), **up):
    log = []
    g = Gateway(tmp_path / "gw", lambda: Upstream(BASE, "bearer", lambda: "sk", models, provider="NanoGPT",
                                                 tier="e2ee", chat=lambda m: fake, **up),
                on_event=log.append, http=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: pytest.fail("no plaintext"))))
    await g.start()
    try:
        yield g, log
    finally:
        await g.stop()


class Refusing(FakePrivate):
    """A provider that refuses the request before any reply, or (`partway`) stops after half an answer."""

    def __init__(self, error, partway=False):
        super().__init__()
        self.error, self.partway = error, partway

    def stream(self, model, messages, tools=None, params=None):
        self.calls.append((model, messages, tools, params))

        async def go():
            if self.partway:
                yield "open", None
                yield "text", "Half an answer"
            raise self.error
            yield
        return go()


def nanogpt_refused(status, said='{"error":"Insufficient balance"}'):
    return PrivateModeError(f"NanoGPT refused the Private Mode request (HTTP {status}): {said}", status, said)


def network_down():
    cause = httpx.ConnectError("no route to host")
    e = PrivateModeError(f"NanoGPT's Private Mode check failed: {cause}")
    e.__cause__ = cause
    return e


async def test_a_request_the_provider_refuses_is_told_by_its_status_and_asked_again_only_when_that_helps(tmp_path):
    """An empty balance isn't a temporary server-side issue to be asked about ten times (it was a 502, and the
    chat said it was having trouble reaching the AI, for minutes): each refusal reaches Claude Code before any
    reply begins, by what it is."""
    for error, code, kind, retry in ((nanogpt_refused(402), 402, "billing_error", False),
                                     (nanogpt_refused(401), 403, "permission_error", False),
                                     (nanogpt_refused(400), 400, "invalid_request_error", False),
                                     (nanogpt_refused(429), 429, "rate_limit_error", True),
                                     (nanogpt_refused(503), 502, "api_error", True),
                                     (network_down(), 502, "api_error", True),
                                     (PrivateModeError("the reply wasn't sealed by the enclave; refused"), 502, "api_error", False)):
        for stream in (True, False):
            async with translating(tmp_path, Refusing(error)) as (g, log):
                r = await _post(g, {**ASK, "stream": stream, "model": "private/kimi-k3"})
            assert (r.status_code, r.json()["error"]["type"]) == (code, kind), (error, stream)
            assert ("x-should-retry" in r.headers) == (not retry), (error, stream)
            assert log[-1]["status"] == code and log[-1]["error"]
    async with translating(tmp_path, Refusing(nanogpt_refused(402))) as (g, log):
        said = (await _post(g, {**ASK, "model": "private/kimi-k3"})).json()["error"]["message"]
    assert "NanoGPT balance is too low for this request" in said and "Top it up" in said


async def test_a_model_that_stops_partway_says_so_in_the_stream_by_its_name(tmp_path):
    async with translating(tmp_path, Refusing(PrivateModeError("the model stopped: context length exceeded"), partway=True)) as (g, log):
        r = await _post(g, {**ASK, "model": "private/kimi-k3"})
    assert r.status_code == 200
    evs = parse(r.content)
    assert "".join(d["delta"].get("text", "") for n, d in evs if n == "content_block_delta") == "Half an answer"
    error = [d for n, d in evs if n == "error"][0]["error"]
    assert error["message"] == "private/kimi-k3: the model stopped: context length exceeded"
    assert log[-1]["status"] == 502 and "context length exceeded" in log[-1]["error"]


def test_the_nearest_effort_a_model_takes():
    glm = ["low", "high", "max"]
    assert [params_mod.nearest_effort(e, glm) for e in ("low", "medium", "high", "xhigh", "max")] == \
        ["low", "high", "high", "max", "max"]
    every = ["low", "medium", "high", "xhigh", "max"]
    assert [params_mod.nearest_effort(e, every) for e in every] == every
    assert params_mod.nearest_effort("max", ["minimal", "low", "medium", "high"]) == "high"
    assert params_mod.nearest_effort("low", ["none", "high"]) == "high"           # never none: GLM reasons without limit


def test_claude_models_take_what_anthropic_lists_however_their_name_is_written():
    takes = params_mod.claude_takes
    every, no_xhigh = params_mod.CLAUDE_EFFORTS, ("low", "medium", "high", "max")
    for model in ("anthropic/claude-opus-5.5", "claude-opus-5-5", "anthropic/claude-opus-5", "anthropic/claude-opus-4.8",
                  "anthropic/claude-opus-4.7:thinking", "anthropic/claude-sonnet-5.5", "anthropic/claude-sonnet-5",
                  "anthropic/claude-haiku-5.5", "anthropic/claude-fable-5.1", "anthropic/claude-opus-latest",
                  "claude-mythos-5-1", " Anthropic/Claude-Opus-5.5 "):
        assert takes(model) == (every, True), model
    assert takes("anthropic/claude-opus-4.6") == takes("anthropic/claude-sonnet-4.6:thinking") == (no_xhigh, True)
    assert takes("anthropic/claude-opus-4.5") == takes("claude-opus-4-5-20251101") == (("low", "medium", "high"), False)
    for model in ("anthropic/claude-haiku-4.5", "anthropic/claude-sonnet-4.5", "anthropic/claude-opus-4.1:thinking:8192",
                  "claude-sonnet-4-20250514", "claude-3-7-sonnet-20250219"):
        assert takes(model) == ((), False), model
    for model in ("claude-3-5-haiku-20241022", "z-ai/glm-5.3", "Gemma-4-31B-Claude-4.6-Opus-Reasoning-Distilled", ""):
        assert takes(model) is None, model


def test_a_claude_request_is_fitted_to_the_effort_chosen_as_near_as_its_model_goes():
    """As Claude Code 2.1.292 sends NanoGPT's names (measured Nov 10 2026): a 5.x model adaptive with an effort; a
    4.x one a budget and no effort (Opus 4.8 refuses a budget); Haiku 4.5 adaptive with an effort (it takes neither)."""
    fit = params_mod.fit_claude
    adaptive = {"type": "adaptive", "display": "omitted"}
    new = {"max_tokens": 128000, "thinking": dict(adaptive), "output_config": {"effort": "high"}}
    assert fit(new, "anthropic/claude-opus-5.5", "medium") == {"effort": "medium"}
    assert new == {"max_tokens": 128000, "thinking": adaptive, "output_config": {"effort": "medium"}}
    old = {"max_tokens": 32000, "thinking": {"type": "enabled", "budget_tokens": 31999, "display": "omitted"}}
    assert fit(old, "anthropic/claude-opus-4.8", "max") == {"effort": "max"}
    assert old["thinking"] == adaptive and old["output_config"] == {"effort": "max"}
    sonnet = {"max_tokens": 32000, "thinking": {"type": "enabled", "budget_tokens": 31999}}
    assert fit(sonnet, "anthropic/claude-sonnet-4.6", "low") == {"effort": "low"} and sonnet["thinking"] == {"type": "adaptive"}
    # Opus 4.5: no max, and it thinks by a budget, sized to the effort
    opus = {"max_tokens": 32000, "thinking": {"type": "adaptive"}}
    assert fit(opus, "anthropic/claude-opus-4.5", "max") == {"effort": "high", "budget": 31999}
    assert opus == {"max_tokens": 32000, "thinking": {"type": "enabled", "budget_tokens": 31999}, "output_config": {"effort": "high"}}
    haiku = {"max_tokens": 32000, "thinking": dict(adaptive), "output_config": {"effort": "high"}}
    assert fit(haiku, "anthropic/claude-haiku-4.5", "low") == {"effort": "", "budget": 4096}
    assert haiku == {"max_tokens": 32000, "thinking": {"type": "enabled", "budget_tokens": 4096, "display": "omitted"}}
    # the budget stays under max_tokens, and goes where there's no room for one (1,024 at least)
    small = {"max_tokens": 8000, "thinking": {"type": "enabled", "budget_tokens": 31999}}
    assert fit(small, "anthropic/claude-sonnet-4.5", "high") == {"effort": "", "budget": 7999}
    tiny = {"max_tokens": 1000, "thinking": {"type": "enabled", "budget_tokens": 31999},
            "output_config": {"format": {"type": "json_schema"}, "effort": "high"}}
    assert fit(tiny, "anthropic/claude-sonnet-4.5", "high") == {"effort": ""}
    assert tiny == {"max_tokens": 1000, "output_config": {"format": {"type": "json_schema"}}}


def test_a_claude_request_that_doesnt_think_is_left_as_it_came_but_never_with_an_effort_its_model_lacks():
    fit = params_mod.fit_claude
    quick = {"max_tokens": 512, "messages": []}
    assert fit(quick, "anthropic/claude-opus-5.5", "max") == {} and quick == {"max_tokens": 512, "messages": []}
    named = {"max_tokens": 512, "output_config": {"effort": "high"}}
    assert fit(named, "anthropic/claude-haiku-4.5", "high") == {"effort": ""} and named == {"max_tokens": 512}
    off = {"thinking": {"type": "disabled"}, "output_config": {"effort": "high"}}
    assert fit(off, "anthropic/claude-opus-4.6", "low") == {"effort": "low"}
    assert off == {"thinking": {"type": "disabled"}, "output_config": {"effort": "low"}}
    # a model not known here keeps what Claude Code sent, its effort the one chosen where it named one
    unknown = {"thinking": {"type": "enabled", "budget_tokens": 9000}, "output_config": {"effort": "high"}}
    assert fit(unknown, "someone/model", "low") == {"effort": "low"}
    assert unknown == {"thinking": {"type": "enabled", "budget_tokens": 9000}, "output_config": {"effort": "low"}}
    unnamed = {"thinking": {"type": "adaptive"}}
    assert fit(unnamed, "someone/model", "low") == {} and unnamed == {"thinking": {"type": "adaptive"}}
    assert params_mod.nearest_effort("medium", None) == "medium"
    kimi = ('Private Mode request failed (HTTP 400): {"error":{"message":"Kimi K3 supports thinking_effort values: '
            'low, high, max (parameter=thinking_effort, value=medium)"}}')
    deepseek = "DeepSeek V4.1 reasoning_effort must be low, high, xhigh, max, or an integer within [1, 100]"
    assert params_mod.efforts_named(kimi, "medium") == ("low", "high", "max")
    assert params_mod.efforts_named(deepseek, "medium") == ("low", "high", "xhigh", "max")
    assert params_mod.efforts_named("HTTP 400: max_tokens is too high", "low") == ()
    assert params_mod.efforts_named("reasoning effort is too high for this model", "max") == ()
    assert params_mod.effort_unsupported("Unsupported parameter: 'reasoning_effort' is not supported with this model.")
    assert not params_mod.effort_unsupported("reasoning_effort must be low, high, xhigh, max")


async def test_each_model_is_sent_the_nearest_effort_it_takes(tmp_path):
    """Measured live: private Kimi K3 refuses medium (HTTP 400, every request), and GLM 5.3 takes it and
    reasons at its default, max. So medium goes as high, to a model that takes no medium."""
    fake = FakePrivate()
    takes = {"private/kimi-k3": params_mod.PRIVATE_EFFORTS, "z-ai/glm-5.3": ("low", "high", "max")}

    async def efforts(model):
        return takes.get(model)
    models = ("z-ai/glm-5.3", "private/kimi-k3", "someone/unlisted")    # (a private main model: nothing in the clear)
    async with translating(tmp_path, fake, models, reasoning="medium", efforts=efforts) as (g, log):
        for model in models:
            await _post(g, {**ASK, "model": model})
    assert [c[0] for c in fake.calls] == list(models)
    assert [c[3]["reasoning_effort"] for c in fake.calls] == ["high", "high", "medium"]
    assert [(r["effort"], r.get("effort_asked")) for r in log] == [("high", "medium"), ("high", "medium"), ("medium", None)]


class Picky(FakePrivate):
    """Refuses any effort but those it names (as private DeepSeek V4.1 Flash does medium), or (`none`) any at all."""

    def __init__(self, none=False):
        super().__init__()
        self.none = none

    def stream(self, model, messages, tools=None, params=None):
        effort = (params or {}).get("reasoning_effort")
        if (self.none and effort) or (not self.none and effort not in ("low", "high", "xhigh", "max")):
            self.calls.append((model, messages, tools, params))
            said = "Unsupported parameter: 'reasoning_effort' is not supported with this model." if self.none \
                else "DeepSeek V4.1 reasoning_effort must be low, high, xhigh, max, or an integer within [1, 100]"

            async def refuse():
                raise nanogpt_refused(400, said)
                yield
            return refuse()
        return super().stream(model, messages, tools, params)


async def test_a_model_that_refuses_an_effort_is_asked_again_with_one_it_names_and_from_then_on(tmp_path):
    fake = Picky()
    async with translating(tmp_path, fake, ("someone/deepseek",), reasoning="medium") as (g, log):
        r = await _post(g, {**ASK, "model": "someone/deepseek"})
        assert r.status_code == 200 and "".join(d["delta"].get("text", "") for n, d in parse(r.content)
                                                if n == "content_block_delta") == "Hi from GLM"
        await _post(g, {**ASK, "model": "someone/deepseek"})
    assert [c[3]["reasoning_effort"] for c in fake.calls] == ["medium", "high", "high"]     # learned: refused once
    assert (log[-1]["effort"], log[-1]["effort_asked"]) == ("high", "medium")


async def test_a_model_that_takes_no_effort_is_asked_again_without_one_and_from_then_on(tmp_path):
    fake = Picky(none=True)
    async with translating(tmp_path, fake, ("someone/plain",)) as (g, log):
        for _ in range(2):
            assert (await _post(g, {**ASK, "model": "someone/plain"})).status_code == 200
    assert len(fake.calls) == 3 and "reasoning_effort" not in fake.calls[-1][3]


async def test_a_private_model_takes_the_private_efforts_not_its_tee_twins(tmp_path):
    """NanoGPT lists medium for TEE/deepseek-v4.1-flash; the private build refuses it. Second opinions and
    descriptions of pictures (Models.params) are held to the same."""
    listing = {"data": [{"id": "TEE/deepseek-v4.1-flash", "capabilities": {"vision": True, "reasoning": True},
                         "reasoning_efforts": ["none", "low", "medium", "high", "max"]},
                        {"id": "z-ai/glm-5.3", "capabilities": {"reasoning": True}, "reasoning_efforts": ["low", "high", "max"]}]}
    prov = Provider("NanoGPT", BASE)
    cfg = Config(providers=[prov])
    cfg.settings.generation = {"reasoning_effort": "medium"}
    m = Models(cfg, save_config=lambda c: None, emit=lambda *a, **k: None, log=lambda *a, **k: None)
    m.key = lambda p: "sk"
    m.caps_http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=listing)))
    assert await m.efforts(prov, "private/deepseek-v4-1-flash") == ("low", "high", "max")
    assert await m.efforts(prov, "z-ai/glm-5.3") == ("low", "high", "max")
    assert await m.efforts(prov, "someone/unlisted") is None
    assert m.params(prov, "private/deepseek-v4-1-flash")["reasoning_effort"] == "high"
    assert m.params(prov, "TEE/deepseek-v4.1-flash")["reasoning_effort"] == "medium"


async def test_whether_a_model_sees_is_never_guessed_when_nanogpts_list_cant_be_read(tmp_path, monkeypatch):
    """The list unread was taken for "it can't see", for as long as the app ran: a model that sees had its
    images described instead. Now a request with an image is refused to be asked again (nothing sent, nothing
    described), one without goes, and once the list is read it's kept."""
    from davibemanager import models as models_mod
    listing = {"data": [{"id": "TEE/kimi-k3", "capabilities": {"vision": True}}]}
    up = {"now": False}

    def handler(request):
        return httpx.Response(200, json=listing) if up["now"] else httpx.Response(503, text="down")
    prov = Provider("NanoGPT", BASE)
    m = Models(Config(providers=[prov]), save_config=lambda c: None, emit=lambda *a, **k: None, log=lambda *a, **k: None)
    m.key = lambda p: "sk"
    m.caps_http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(models_mod, "CAPS_RETRY_SECONDS", 0)            # asked again at once (30 s, live)
    fake, seen = FakePrivate(), Seen()
    shot = {"stream": True, "messages": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1",
                                                                       "content": [bridge.b64_image(PNG)]}]}]}
    assert bridge.has_images(shot) and not bridge.has_images(ASK)
    async with translating(tmp_path, fake, describe=seen.describe, vision_model="private/deepseek-v4-1-flash",
                           sees=lambda model: m.sees(prov, model)) as (g, log):
        r = await _post(g, {**shot, "model": "private/kimi-k3"})
        assert r.status_code == 503 and "x-should-retry" not in r.headers     # Claude Code asks again
        assert not fake.calls and not seen.calls
        assert (await _post(g, {**ASK, "model": "private/kimi-k3"})).status_code == 200    # no image: sent
        up["now"] = True
        assert (await _post(g, {**shot, "model": "private/kimi-k3"})).status_code == 200
        assert fake.calls[-1][1][-1]["content"][1]["type"] == "image_url" and not seen.calls   # Kimi K3 sees it
        up["now"] = False
        assert await m.sees(prov, "private/kimi-k3")                        # a list read once is kept
    assert [r["status"] for r in log] == [503, 200, 200]


async def test_one_new_image_in_two_requests_at_once_is_described_once():
    """The assistant's request and a subagent's, carrying the same new screenshot: one description, paid
    for once; one of them stopped leaves it to the other."""
    calls, gate = [], asyncio.Event()

    async def describe(url, context):
        calls.append(url)
        await gate.wait()
        return "A dialog with an OK button."
    images = bridge.ImageDescriber(describe, "private/deepseek-v4-1-flash")
    block = bridge.b64_image(PNG)
    first = asyncio.create_task(images.text_for(block, "main"))
    second = asyncio.create_task(images.text_for(block, "subagent"))
    await asyncio.sleep(0.01)
    first.cancel()
    gate.set()
    assert "OK button" in await second
    with pytest.raises(asyncio.CancelledError):
        await first
    assert "OK button" in await images.text_for(block, "later") and len(calls) == 1


class Reasons(FakePrivate):
    """A model that reasons before it answers; `refuse_field`: a provider that won't take reasoning handed back."""

    def __init__(self, refuse_field=False):
        super().__init__()
        self.refuse_field = refuse_field

    def stream(self, model, messages, tools=None, params=None):
        self.calls.append((model, messages, tools, params))
        refuse = self.refuse_field and any("reasoning_content" in m for m in messages)

        async def go():
            if refuse:
                raise PrivateModeError("Unrecognized request argument: messages[1].reasoning_content", 400)
            yield "open", None
            yield "reasoning", "Let me think."
            yield "text", "ok"
            yield "done", TurnResult(content="ok", finish_reason="stop", usage={"prompt_tokens": 10, "completion_tokens": 2})
        return go()


# the signature on our thinking blocks: Claude Code keeps it in its sessions, so it never changes
SIGNATURE = "da-vibe-manager"
THOUGHT = {"role": "assistant", "content": [{"type": "thinking", "thinking": "Earlier thought.", "signature": SIGNATURE},
                                            {"type": "text", "text": "Earlier answer."}]}


async def test_the_models_reasoning_is_shown_and_handed_back_as_claude_codes_is(tmp_path):
    """As with Claude: the reasoning shows as Claude Code's thinking (in the chat, faint), not when its
    thinking is off; and what Claude Code sends back of it reaches the model with the conversation."""
    fake = Reasons()
    async with translating(tmp_path, fake) as (g, log):
        r = await _post(g, {**ASK, "model": "private/glm-5-3"})
        evs = parse(r.content)
        assert [d["content_block"]["type"] for n, d in evs if n == "content_block_start"] == ["thinking", "text"]
        assert [d["delta"] for n, d in evs if n == "content_block_delta"][:2] == [
            {"type": "thinking_delta", "thinking": "Let me think."}, {"type": "signature_delta", "signature": SIGNATURE}]
        r = await _post(g, {**ASK, "model": "private/glm-5-3", "thinking": {"type": "disabled"}})
        assert [d["content_block"]["type"] for n, d in parse(r.content) if n == "content_block_start"] == ["text"]
        body = {"model": "private/glm-5-3", "messages": [{"role": "user", "content": "first"}, THOUGHT,
                                                         {"role": "user", "content": "next"}]}
        reply = (await _post(g, body)).json()
    assert reply["content"][0] == {"type": "thinking", "thinking": "Let me think.", "signature": SIGNATURE}
    sent = fake.calls[-1][1]
    assert [m.get("reasoning_content") for m in sent if m["role"] == "assistant"] == ["Earlier thought."]


async def test_a_provider_that_wont_take_reasoning_handed_back_is_asked_again_without_it_from_then_on(tmp_path):
    fake = Reasons(refuse_field=True)
    body = {**ASK, "model": "private/glm-5-3",
            "messages": [{"role": "user", "content": "first"}, THOUGHT, {"role": "user", "content": "next"}]}
    async with translating(tmp_path, fake) as (g, log):
        for _ in range(2):
            assert (await _post(g, body)).status_code == 200
    assert len(fake.calls) == 3                                   # refused once; then never sent again
    assert not any("reasoning_content" in m for m in fake.calls[-1][1])
    assert [r.get("reasoning_back") for r in log] == [False, False]   # the log says so


async def test_our_thinking_never_reaches_a_claude_model(tmp_path):
    """Another model's reasoning, signed as DA Vibe Manager's, would be refused by Anthropic's API (a chat
    begun on GLM, then on Claude Opus): taken out; Claude's own thinking goes as it is."""
    seen = []

    def nanogpt(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, text='event: message_stop\ndata: {"type":"message_stop"}\n\n',
                              headers={"content-type": "text/event-stream"})
    g = Gateway(tmp_path / "gw", lambda: Upstream(BASE, "bearer", lambda: "sk", ("anthropic/claude-opus-5.5",), provider="NanoGPT",
                                                 chat=lambda m: pytest.fail("not translated")),
                http=httpx.AsyncClient(transport=httpx.MockTransport(nanogpt)))
    claudes = {"type": "thinking", "thinking": "Claude's own.", "signature": "EqQBCkgIBRAB"}
    await g.start()
    try:
        r = await _post(g, {"model": "anthropic/claude-opus-5.5", "messages": [
            {"role": "user", "content": "first"}, THOUGHT, {"role": "user", "content": "next"},
            {"role": "assistant", "content": [claudes, {"type": "text", "text": "x"}]}, {"role": "user", "content": "more"}]})
    finally:
        await g.stop()
    assert r.status_code == 200
    history = seen[0]["messages"]
    assert history[1]["content"] == [{"type": "text", "text": "Earlier answer."}]
    assert history[3]["content"][0] == claudes


# --- an answer with no stream in it is said, never taken for an empty reply (SealedLore's e947938) ---------------

def _answering(status: int, content: bytes = b"", headers: dict | None = None):
    """A chat client whose provider answers every request so, and the requests it was sent."""
    from davibemanager.llm.client import LLMClient

    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(status, content=content, headers=headers or {})
    return LLMClient("https://example.test/v1", "k", httpx.AsyncClient(transport=httpx.MockTransport(handler))), seen


async def _streamed(client, exact: bool = False) -> list:
    return [e async for e in client.stream("z-ai/glm-5.3", [{"role": "user", "content": "hi"}], exact=exact)]


@pytest.mark.parametrize(("body", "kind"), [
    (b"<html><body>Sign in to the Wi-Fi</body></html>", "text/html"),
    (b"", "text/event-stream"),
    (b'{"id": "x", "choices": []}', "application/json"),
])
@pytest.mark.parametrize("exact", [False, True])
async def test_an_answer_with_no_stream_in_it_is_said_never_an_empty_reply(body, kind, exact):
    """A web page answering 200 where the API was expected (an address without its /v1, a sign-in page on a local
    network), or a body with no event in it, ended the assistant's turn with an empty reply and no reason: the SDK
    read it as a stream with nothing in it. A TEE model's reply (exact) went the same way."""
    from davibemanager.llm.secure_http import ProviderError

    client, seen = _answering(200, body, {"content-type": kind})
    with pytest.raises(ProviderError) as info:
        await _streamed(client, exact)
    said = str(info.value)
    assert f"https://example.test/v1/chat/completions answered HTTP 200 ({kind}) with no reply in it" in said
    assert "an address without its /v1" in said and info.value.status_code == 200
    assert len(seen) == 1, "nothing asked again"


async def test_a_stream_is_read_whatever_its_content_type_says():
    """Real servers label their streams every way (llama.cpp, proxies): a body with `data:` lines is the reply."""
    stream = b'data: {"id": "c", "choices": [{"delta": {"content": "fine"}, "finish_reason": "stop"}]}\n\ndata: [DONE]\n\n'
    for kind in ("text/html", "application/json", "text/plain", None):
        client, _ = _answering(200, stream, {"content-type": kind} if kind else {})
        events = await _streamed(client)
        assert "".join(v for k, v in events if k == "text") == "fine", kind
        assert events[-1][1].finish_reason == "stop" and events[-1][1].body_hash is None, "hashed only for a TEE reply"
    # and one that says nothing but [DONE] is an empty reply, as the endpoint sent it
    client, _ = _answering(200, b"data: [DONE]\n\n", {"content-type": "text/event-stream"})
    events = await _streamed(client)
    assert events[-1][0] == "done" and events[-1][1].content == ""


async def test_the_assistant_is_told_of_an_answer_with_no_stream_in_it_not_given_an_empty_reply(tmp_path):
    client, _ = _answering(200, b"<html>Not here</html>", {"content-type": "text/html; charset=utf-8"})
    async with translating(tmp_path, client, models=("z-ai/glm-5.3",)) as (g, log):
        r = await _post(g, {**ASK, "model": "z-ai/glm-5.3"})
        whole = await _post(g, {**ASK, "stream": False, "model": "z-ai/glm-5.3"})
    evs = parse(r.content)
    assert not [d for n, d in evs if n == "content_block_delta"]
    said = [d for n, d in evs if n == "error"][0]["error"]["message"]
    assert said.startswith("z-ai/glm-5.3: https://example.test/v1/chat/completions answered HTTP 200 (text/html)")
    assert log[0]["status"] == 502 and "with no reply in it" in log[0]["error"]
    # asked whole, it is refused by what it is, and not asked again: the address is wrong, not busy
    assert whole.status_code == 502 and "with no reply in it" in whole.json()["error"]["message"]
    assert whole.headers.get("x-should-retry") == "false"
