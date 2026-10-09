"""A fake OpenAI-compatible streaming endpoint, and helpers shared by the engine tests."""

import asyncio
import json

import httpx

BASE = "https://fake.example/api/v1"


def sse(*chunks):
    lines = []
    for delta, finish in chunks:
        body = {"id": "c1", "object": "chat.completion.chunk", "created": 0, "model": "m",
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
        lines.append(f"data: {json.dumps(body)}\n\n")
    lines.append("data: [DONE]\n\n")
    return "".join(lines)


def tool_call_stream(args: dict, text="Let's check that.", name="propose_commands"):
    raw = json.dumps(args)
    half = len(raw) // 2
    return sse(
        ({"role": "assistant", "content": text}, None),
        ({"tool_calls": [{"index": 0, "id": "call_1", "type": "function",
                          "function": {"name": name, "arguments": raw[:half]}}]}, None),
        ({"tool_calls": [{"index": 0, "function": {"arguments": raw[half:]}}]}, None),
        ({}, "tool_calls"),
    )


def text_stream(text="Done."):
    return sse(({"role": "assistant", "content": text}, None), ({}, "stop"))


class FakeAPI:
    def __init__(self):
        self.responses = []    # queued SSE bodies
        self.completions = []  # queued texts for non-streaming requests
        self.requests = []     # captured request JSON

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={"object": "list", "data": [
                {"id": "anthropic/claude-opus-5.5", "object": "model", "created": 0, "owned_by": "x"},
                {"id": "TEE/glm-5.3", "object": "model", "created": 0, "owned_by": "x"},
                {"id": "private/glm-5-3", "object": "model", "created": 0, "owned_by": "x"}]})
        body = json.loads(request.content)
        self.requests.append(body)
        assert request.headers["authorization"] == "Bearer sk-test"
        if not body.get("stream"):
            return httpx.Response(200, json={"id": "c", "object": "chat.completion", "created": 0, "model": body["model"],
                                             "choices": [{"index": 0, "finish_reason": "stop",
                                                          "message": {"role": "assistant", "content": self.completions.pop(0)}}]})
        return httpx.Response(200, text=self.responses.pop(0), headers={"content-type": "text/event-stream"})


async def wait_for(cond, what="condition", tries=300):
    for _ in range(tries):
        if cond():
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"{what} did not happen")
