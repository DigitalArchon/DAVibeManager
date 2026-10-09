"""Claude Code speaks the Anthropic Messages API; NanoGPT's private (end-to-end encrypted)
models speak OpenAI chat completions, sealed on this machine by llm/private_mode.py. This
translates between the two, in the gateway, so the assistant in the sandbox can run on a
private model while its requests are sealed to an attested enclave before they leave.

Images in a request (screenshots the assistant took, PNGs it read) are not sent to a text-only
model: a vision helper, a private model too, describes each one for what the assistant is
doing, and the description takes the image's place. Descriptions are cached by the image's hash,
since the whole conversation, images included, is sent again with every request.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from typing import AsyncIterator, Awaitable, Callable

VISION_PROMPT = """\
You are the eyes of an AI assistant that cannot see images. It is building and testing software \
in a sandbox, and has just looked at this image. Describe what it needs to know to carry on: \
transcribe all visible text exactly (titles, labels, menus, buttons, error messages, terminal \
output), then describe the layout and the state of the controls (what is selected, enabled, \
highlighted), anything that looks wrong or broken (missing icons, overlapping or cut-off text, \
blank areas, error dialogs), and anything relevant to what it is doing. Be precise and factual; \
say plainly what you can't make out. Do not give advice."""

Describe = Callable[[str, str], Awaitable[str]]   # (data URL, context) -> description


def _text_of(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text")
    return ""


def _data_url(block: dict) -> str | None:
    src = block.get("source") or {}
    if src.get("type") == "base64" and src.get("data"):
        return f"data:{src.get('media_type', 'image/png')};base64,{src['data']}"
    if src.get("type") == "url" and src.get("url"):
        return None                      # never fetched: the sandbox's own files come as base64
    return None


class ImageDescriber:
    """Describes images through the vision helper, once per image."""

    def __init__(self, describe: Describe | None, model: str = ""):
        self._describe = describe
        self.model = model
        self._cache: dict[str, str] = {}

    async def text_for(self, block: dict, context: str) -> str:
        url = _data_url(block)
        if url is None:
            return "[An image was here, but it couldn't be read.]"
        digest = hashlib.sha256(url.encode()).hexdigest()
        if digest not in self._cache:
            if self._describe is None:
                return "[An image was here. You can't see images, and no vision helper is set up.]"
            try:
                self._cache[digest] = await self._describe(url, context)
            except Exception as e:  # noqa: BLE001 - the assistant should know, and can carry on without it
                return f"[An image was here, but the vision helper couldn't describe it: {e}]"
        return f"[Image, described for you by a vision model ({self.model}):]\n{self._cache[digest]}"


async def to_openai(body: dict, images: ImageDescriber) -> tuple[list[dict], list[dict] | None, dict]:
    """An Anthropic Messages request as (messages, tools, params) for a chat-completions model."""
    messages: list[dict] = []
    system = _text_of(body.get("system"))
    if system:
        messages.append({"role": "system", "content": system})
    context = ""                          # what the assistant last said: the vision helper's brief
    for m in body.get("messages", []):
        role, content = m.get("role"), m.get("content")
        if isinstance(content, str):
            messages.append({"role": role, "content": content})
            if role == "assistant":
                context = content[-1500:]
            continue
        if role == "assistant":
            text, calls = [], []
            for b in content or []:
                if b.get("type") == "text":
                    text.append(b.get("text", ""))
                elif b.get("type") == "tool_use":
                    calls.append({"id": b.get("id") or f"toolu_{secrets.token_hex(8)}", "type": "function",
                                  "function": {"name": b.get("name", ""), "arguments": json.dumps(b.get("input") or {})}})
            msg: dict = {"role": "assistant", "content": "\n\n".join(t for t in text if t) or None}
            if calls:
                msg["tool_calls"] = calls
            if msg["content"] is None and not calls:
                msg["content"] = ""
            messages.append(msg)
            context = (msg["content"] or context)[-1500:]
            continue
        # a user message: tool results become "tool" messages (OpenAI wants them right after the
        # call), and everything else one user message after them
        rest: list[str] = []
        for b in content or []:
            kind = b.get("type")
            if kind == "tool_result":
                parts = b.get("content")
                if isinstance(parts, list):
                    texts = []
                    for p in parts:
                        if p.get("type") == "image":
                            texts.append(await images.text_for(p, context))
                        elif p.get("type") == "text":
                            texts.append(p.get("text", ""))
                    out = "\n".join(texts)
                else:
                    out = str(parts or "")
                if b.get("is_error"):
                    out = f"[error] {out}"
                messages.append({"role": "tool", "tool_call_id": b.get("tool_use_id", ""), "content": out or "(no output)"})
            elif kind == "text":
                rest.append(b.get("text", ""))
            elif kind == "image":
                rest.append(await images.text_for(b, context))
            elif kind == "document":
                rest.append("[A document was attached here; it can't be shown to this model.]")
        if rest:
            messages.append({"role": "user", "content": "\n\n".join(rest)})
    tools = [{"type": "function", "function": {"name": t["name"], "description": t.get("description", ""),
                                               "parameters": t.get("input_schema") or {"type": "object"}}}
             for t in body.get("tools") or [] if t.get("name")]
    params: dict = {}
    if body.get("max_tokens"):
        params["max_tokens"] = int(body["max_tokens"])
    if body.get("temperature") is not None:
        params["temperature"] = body["temperature"]
    if body.get("top_p") is not None:
        params["top_p"] = body["top_p"]
    if body.get("stop_sequences"):
        params["stop"] = body["stop_sequences"][:4]
    choice = body.get("tool_choice") or {}
    if tools and choice.get("type") == "any":
        params["tool_choice"] = "required"
    elif tools and choice.get("type") == "tool" and choice.get("name"):
        params["tool_choice"] = {"type": "function", "function": {"name": choice["name"]}}
    elif choice.get("type") == "none":
        tools = []
    # Claude Code's "thinking" setting isn't passed on: the gateway sets the effort (never "none":
    # GLM with its thinking off reasons all the more, in its answer)
    return messages, tools or None, params


def estimate_tokens(body: dict) -> int:
    """A rough count for /v1/messages/count_tokens (about four characters a token)."""
    return max(1, len(json.dumps(body, ensure_ascii=False)) // 4)


_STOP = {"stop": "end_turn", "tool_calls": "tool_use", "length": "max_tokens", "content_filter": "end_turn"}


def _sse(event: str, data: dict) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n".encode()


def _arguments(raw: str) -> dict:
    try:
        value = json.loads(raw or "{}")
        return value if isinstance(value, dict) else {"value": value}
    except ValueError:
        return {}


async def sse(events: AsyncIterator[tuple[str, object]], model: str, input_estimate: int,
              ping_every: float = 5.0, stats: dict | None = None,
              progress: Callable[[dict], None] | None = None) -> AsyncIterator[bytes]:
    """The private model's stream as Anthropic server-sent events. Reasoning isn't passed on
    (Anthropic thinking blocks carry signatures this can't make); pings keep the stream alive."""
    msg_id = f"msg_{secrets.token_hex(12)}"
    yield _sse("message_start", {"type": "message_start", "message": {
        "id": msg_id, "type": "message", "role": "assistant", "model": model, "content": [],
        "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": input_estimate, "output_tokens": 0}}})
    index, text_open, last_ping = 0, False, time.monotonic()
    result = None
    stats = stats if stats is not None else {}
    started = time.monotonic()
    stats.update(first_token=None, reasoning_chars=0, text_chars=0)
    try:
        async for kind, val in events:
            if stats["first_token"] is None:
                stats["first_token"] = round(time.monotonic() - started, 1)
            if kind == "reasoning":
                stats["reasoning_chars"] += len(val)
            elif kind == "text":
                stats["text_chars"] += len(val)
            if kind == "text" and val:
                if not text_open:
                    yield _sse("content_block_start", {"type": "content_block_start", "index": index,
                                                       "content_block": {"type": "text", "text": ""}})
                    text_open = True
                yield _sse("content_block_delta", {"type": "content_block_delta", "index": index,
                                                   "delta": {"type": "text_delta", "text": val}})
            elif kind == "done":
                result = val
            elif time.monotonic() - last_ping > ping_every:
                last_ping = time.monotonic()
                if progress:
                    progress({"seconds": round(last_ping - started), "reasoning_chars": stats["reasoning_chars"]})
                yield _sse("ping", {"type": "ping"})
    except Exception as e:  # noqa: BLE001 - told to the CLI the way Anthropic tells errors mid-stream
        yield _sse("error", {"type": "error", "error": {"type": "api_error", "message": f"Private model: {e}"}})
        return
    if text_open:
        yield _sse("content_block_stop", {"type": "content_block_stop", "index": index})
        index += 1
    for call in (result.tool_calls if result else []):
        yield _sse("content_block_start", {"type": "content_block_start", "index": index, "content_block": {
            "type": "tool_use", "id": call.id or f"toolu_{secrets.token_hex(8)}", "name": call.name, "input": {}}})
        yield _sse("content_block_delta", {"type": "content_block_delta", "index": index, "delta": {
            "type": "input_json_delta", "partial_json": json.dumps(_arguments(call.arguments))}})
        yield _sse("content_block_stop", {"type": "content_block_stop", "index": index})
        index += 1
    usage = (result.usage if result else None) or {}
    stats["output_tokens"] = usage.get("completion_tokens")
    if usage:
        stats["usage"] = usage
    stop = "tool_use" if result and result.tool_calls else _STOP.get((result.finish_reason if result else "") or "stop", "end_turn")
    yield _sse("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                                 "usage": {"input_tokens": usage.get("prompt_tokens", input_estimate),
                                           "output_tokens": usage.get("completion_tokens", 0)}})
    yield _sse("message_stop", {"type": "message_stop"})


async def message(events: AsyncIterator[tuple[str, object]], model: str, input_estimate: int) -> dict:
    """The private model's reply as one Anthropic message (for requests that don't stream)."""
    text, result = "", None
    async for kind, val in events:
        if kind == "text":
            text += val
        elif kind == "done":
            result = val
    content: list[dict] = [{"type": "text", "text": text}] if text else []
    for call in (result.tool_calls if result else []):
        content.append({"type": "tool_use", "id": call.id or f"toolu_{secrets.token_hex(8)}", "name": call.name,
                        "input": _arguments(call.arguments)})
    usage = (result.usage if result else None) or {}
    stop = "tool_use" if result and result.tool_calls else _STOP.get((result.finish_reason if result else "") or "stop", "end_turn")
    return {"id": f"msg_{secrets.token_hex(12)}", "type": "message", "role": "assistant", "model": model,
            "content": content, "stop_reason": stop, "stop_sequence": None,
            "usage": {"input_tokens": usage.get("prompt_tokens", input_estimate), "output_tokens": usage.get("completion_tokens", 0)}}


def b64_image(data: bytes, media: str = "image/png") -> dict:
    """An Anthropic image block (tests)."""
    return {"type": "image", "source": {"type": "base64", "media_type": media, "data": base64.b64encode(data).decode()}}
