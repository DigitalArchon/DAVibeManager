"""Private models in the sandbox: Claude Code's Anthropic requests as sealed chat completions,
with images described by a vision helper."""

import json

import httpx
import pytest

from davibemanager.gateway import Gateway, Upstream
from davibemanager.llm import anthropic_bridge as bridge
from davibemanager.llm.client import ToolCall, TurnResult

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
