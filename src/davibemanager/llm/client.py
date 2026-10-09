"""OpenAI-compatible streaming client (NanoGPT, local servers, any compatible endpoint)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import AsyncIterator
from urllib.parse import urlparse

from openai import AsyncOpenAI

from ..netpolicy import check_url, is_local_host

# standard: plaintext to a cloud provider. tee: runs in an enclave, but the prompt passes the
# provider's gateway in the clear. e2ee: sealed on this machine to an attested enclave's key
# (NanoGPT Private Mode, llm/private_mode.py). local: your own hardware.
TIERS = ("standard", "tee", "e2ee", "local")

# Project sensitivity -> model tiers it permits
SENSITIVITY_TIERS = {
    "open": {"standard", "tee", "e2ee", "local"},
    "confidential": {"e2ee", "local"},
    "sovereign": {"local"},
}


def is_private_mode(model_id: str) -> bool:
    """NanoGPT Private Mode: only ever sent sealed (llm/private_mode.py)."""
    return model_id.startswith("private/")


def is_local_url(base_url: str) -> bool:
    """Whether a base URL counts as the Local tier (allowed for Confidential and Sovereign):
    this machine or the local network, as netpolicy.is_local_host defines it. This trusts the LAN:
    an Ollama server on another machine at home qualifies."""
    if base_url.startswith("training://"):
        return True  # scripted training provider: nothing leaves the machine
    return is_local_host(urlparse(base_url).hostname)


def detect_tier(model_id: str, base_url: str, overrides: dict[str, str] | None = None) -> str:
    """The model's tier. An override can only describe what the transport really is: it can
    lower a model (call a TEE model standard), or mark a cloud model as TEE, but never claim
    e2ee for a model that isn't sent sealed or local for an endpoint that isn't local, since
    either would let plaintext into a Confidential or Sovereign project."""
    actual = _actual_tier(model_id, base_url)
    wanted = (overrides or {}).get(model_id)
    if wanted not in TIERS:
        return actual
    # raising standard -> tee is safe: a TEE model is attested before every send, failing closed
    if _RANK[wanted] <= _RANK[actual] or (actual, wanted) == ("standard", "tee"):
        return wanted
    return actual


_RANK = {"standard": 0, "tee": 1, "e2ee": 2, "local": 3}


def _actual_tier(model_id: str, base_url: str) -> str:
    if is_local_url(base_url):
        return "local"
    if is_private_mode(model_id):
        return "e2ee"
    parts = model_id.lower().split("/")
    if "tee" in parts or parts[0] == "phala" or model_id.lower().endswith(("-tee", ":tee")):
        return "tee"
    return "standard"


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: str  # raw JSON text as streamed

    def parsed(self) -> dict:
        return json.loads(self.arguments or "{}")


@dataclass
class TurnResult:
    content: str = ""
    reasoning: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str | None = None
    usage: dict | None = None
    id: str | None = None  # the completion's id: a TEE model's reply signature is looked up by it


class LLMClient:
    def __init__(self, base_url: str, api_key: str | None, http_client=None):
        check_url(base_url, "The provider's base URL")
        # Local servers often need no key, but the SDK insists on a value.
        self._client = AsyncOpenAI(base_url=base_url, api_key=api_key or "not-needed", max_retries=1, timeout=300,
                                   http_client=http_client)

    async def list_models(self) -> list[str]:
        page = await self._client.models.list()
        return sorted(m.id for m in page.data)

    async def stream(
        self, model: str, messages: list[dict], tools: list[dict] | None = None, params: dict | None = None
    ) -> AsyncIterator[tuple[str, object]]:
        """Yield ("text"|"reasoning", str) deltas and ("tool", name) as each tool call starts,
        then ("done", TurnResult)."""
        if is_private_mode(model):
            raise RuntimeError(f"{model} is a Private Mode model and is only ever sent sealed; nothing was sent")
        kwargs: dict = {"model": model, "messages": messages, "stream": True,
                        "stream_options": {"include_usage": True}}
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        kwargs.update(_split_params(params))
        acc = StreamAccumulator()
        stream = await self._client.chat.completions.create(**kwargs)
        try:
            async for chunk in stream:
                for event in acc.feed(chunk):
                    yield event
        finally:
            await stream.close()     # stopped or cancelled: drop the connection, so the provider stops generating
        yield "done", acc.finish()

    async def complete(self, model: str, messages: list[dict], params: dict | None = None) -> str:
        if is_private_mode(model):
            raise RuntimeError(f"{model} is a Private Mode model and is only ever sent sealed; nothing was sent")
        resp = await self._client.chat.completions.create(model=model, messages=messages, **_split_params(params))
        self.last_usage = resp.usage.model_dump() if resp.usage else None     # what it cost (Engine.spend)
        return resp.choices[0].message.content or ""


# provider extensions sent in the request body, whatever the SDK version knows about:
# reasoning_effort, NanoGPT's prompt_caching (Claude cache boundary and lifetime), and its
# provider (which host runs the model: llm/routes.py)
_EXTRA_BODY = ("reasoning_effort", "prompt_caching", "provider")


def _split_params(params: dict | None) -> dict:
    """Standard sampling fields as SDK arguments; provider extensions in the extra body."""
    params = dict(params or {})
    extra = {k: params.pop(k) for k in _EXTRA_BODY if params.get(k)}
    for k in _EXTRA_BODY:
        params.pop(k, None)
    if extra:
        params["extra_body"] = extra
    return params


class StreamAccumulator:
    """Turns chat.completion.chunk objects into deltas and a final TurnResult."""

    def __init__(self) -> None:
        self.result = TurnResult()
        self._calls: dict[int, ToolCall] = {}

    def feed(self, chunk) -> list[tuple[str, str]]:
        events: list[tuple[str, str]] = []
        if getattr(chunk, "id", None) and not self.result.id:
            self.result.id = chunk.id
        if chunk.usage:
            self.result.usage = chunk.usage.model_dump()
        if not chunk.choices:
            return events
        choice = chunk.choices[0]
        if choice.finish_reason:
            self.result.finish_reason = choice.finish_reason
        delta = choice.delta
        if delta is None:
            return events
        extra = delta.model_extra or {}
        reasoning = extra.get("reasoning_content") or extra.get("reasoning")
        if isinstance(reasoning, str) and reasoning:
            self.result.reasoning += reasoning
            events.append(("reasoning", reasoning))
        if delta.content:
            self.result.content += delta.content
            events.append(("text", delta.content))
        for tc in delta.tool_calls or []:
            call = self._calls.setdefault(tc.index, ToolCall(id="", name="", arguments=""))
            if tc.id:
                call.id = tc.id
            if tc.function:
                if tc.function.name:
                    if not call.name:
                        # arguments stream silently; this tells the UI the model is still working
                        events.append(("tool", tc.function.name))
                    call.name += tc.function.name
                if tc.function.arguments:
                    call.arguments += tc.function.arguments
        return events

    def finish(self) -> TurnResult:
        self.result.tool_calls = [self._calls[i] for i in sorted(self._calls)]
        for i, call in enumerate(self.result.tool_calls):
            if not call.id:
                call.id = f"call_{i}"
        return self.result
