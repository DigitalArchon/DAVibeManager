"""OpenAI-compatible streaming client (NanoGPT, local servers, any compatible endpoint)."""

from __future__ import annotations

import codecs
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import AsyncIterator
from urllib.parse import urlparse

from openai import APIError, AsyncOpenAI, DefaultAsyncHttpxClient
from openai.types.chat import ChatCompletionChunk

from ..netpolicy import check_key, check_url, is_local_host, shown
from .secure_http import ProviderError

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
    """NanoGPT Private Mode: only ever sent sealed (llm/private_mode.py). However it's written
    ("Private/…", a space before it): when in doubt, sealed."""
    return str(model_id or "").strip().lower().startswith("private/")


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
    # a TEE model's reply, read with `exact` (LLMClient.stream): its receipt's id and nano-gpt's route
    # (its headers), and the hash of every byte its stream carried, which the signed record names
    receipt_id: str | None = None
    tee_route: str | None = None
    body_hash: str | None = None


class LLMClient:
    def __init__(self, base_url: str, api_key: str | None, http_client=None):
        check_url(base_url, "The provider's base URL")
        check_key(api_key, urlparse(base_url).hostname or "the provider")     # one no header can carry: nothing sent
        # Local servers often need no key, but the SDK insists on a value. A redirect is never followed
        # (the SDK's own client would): the request, the user's words in it, would go wherever the
        # provider points, plain http included (as the gateway's forwarder, which refuses them too)
        self._client = AsyncOpenAI(base_url=base_url, api_key=api_key or "not-needed", max_retries=1, timeout=300,
                                   http_client=http_client or DefaultAsyncHttpxClient(follow_redirects=False))

    async def list_models(self) -> list[str]:
        page = await self._client.models.list()
        return sorted(m.id for m in page.data)

    async def stream(
        self, model: str, messages: list[dict], tools: list[dict] | None = None, params: dict | None = None,
        *, exact: bool = False,
    ) -> AsyncIterator[tuple[str, object]]:
        """Yield ("open", None) once the provider has taken the request and its reply has begun,
        ("text"|"reasoning", str) deltas and ("tool", name) as each tool call starts, then ("done",
        TurnResult). With `exact` (a TEE model's reply, checked against its signed record afterwards:
        llm/tee.py check_reply), every byte of the stream is hashed, to its end, and the receipt's
        headers kept, on the TurnResult. An answer with not one event in it (a web page where the API
        was expected) is an error saying so, never an empty reply (`_read`)."""
        if is_private_mode(model):
            raise RuntimeError(f"{model} is a Private Mode model and is only ever sent sealed; nothing was sent")
        kwargs: dict = {"model": model, "messages": messages, "stream": True,
                        "stream_options": {"include_usage": True}}
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        kwargs.update(_split_params(params))
        acc = StreamAccumulator()
        async for event in self._read(kwargs, acc, exact=exact):
            yield event
        yield "done", acc.finish()

    async def _read(self, kwargs: dict, acc: StreamAccumulator, *, exact: bool) -> AsyncIterator[tuple[str, object]]:
        """The stream as the SDK would read it (its chunks, an error chunk raised as its APIError),
        but by this client: so that, with `exact`, every byte it carries is hashed, the "[DONE]" and
        anything after it too, the hash the signed record names being of the exact bytes the stream
        carried (SealedLore's openai_compat._lines, Nov 2026); and so that an answer with not one SSE
        data line in it is told for what it is. The SDK read that as a stream with nothing in it, so a
        web page answering 200 where the API was expected, or an empty body, ended the assistant's
        turn with an empty reply and no reason (SealedLore's e947938). A body with data lines is read
        whatever its content type says, and one that says nothing but "[DONE]" is the empty reply its
        endpoint sent. A stream that ends with neither a finish reason nor "[DONE]" was cut off
        (`_cut_off`): what arrived is no reply. Stopped or cancelled, the connection is dropped, so the
        provider stops generating."""
        digest = hashlib.sha256()
        async with self._client.chat.completions.with_streaming_response.create(**kwargs) as response:
            if exact:
                headers = response.headers
                acc.result.receipt_id = headers.get("x-receipt-id") or headers.get("x-tee-signature-id")
                acc.result.tee_route = headers.get("x-tee-verification-route")
            yield "open", None                 # the provider took it, and its reply has begun
            done = seen = False
            async for line in _lines(response.iter_bytes(), digest):
                if done or not line.startswith("data:"):
                    continue
                seen = True
                data = line[5:].strip()
                if data == "[DONE]":
                    done = True                # read on (nothing after it is taken): the hash covers it all
                    continue
                try:
                    parsed = json.loads(data)
                except ValueError:
                    raise RuntimeError(f"the provider's stream held a line that isn't JSON: {data[:200]!r}") from None
                if not isinstance(parsed, dict):
                    raise RuntimeError(f"the provider's stream held a line that isn't a chunk: {data[:200]!r}")
                if parsed.get("error"):
                    error = parsed["error"]
                    message = error.get("message") if isinstance(error, dict) else None
                    raise APIError(message if isinstance(message, str) and message else "An error occurred during streaming",
                                   response.http_request, body=error)
                for event in acc.feed(ChatCompletionChunk.model_construct(**parsed)):
                    yield event
            if not seen:
                raise _no_stream(response)
            if not done and acc.result.finish_reason is None:
                # it ended saying neither why nor that it had: the connection closed mid-answer
                raise _cut_off(response)
        if exact:
            acc.result.body_hash = "sha256:" + digest.hexdigest()

    async def complete(self, model: str, messages: list[dict], params: dict | None = None, *,
                       exact: bool = False) -> str:
        """The reply's text. With `exact` (a TEE model's, checked against its signed record afterwards), it
        is read as a stream, every byte of it hashed as the gateway's are (stream, exact): a stream's bytes are
        what NanoGPT's signed record was seen to hash, live on every model that named a receipt (SealedLore,
        Nov 2026); a reply that isn't streamed was never compared, and could only be "signed", its text not
        compared (tee.check_reply). The reply's id, receipt and hash are then on `last_reply`."""
        if is_private_mode(model):
            raise RuntimeError(f"{model} is a Private Mode model and is only ever sent sealed; nothing was sent")
        self.last_reply = None
        if exact:
            text = ""
            async for kind, value in self.stream(model, messages, params=params, exact=True):
                if kind == "text":
                    text += value
                elif kind == "done":
                    self.last_reply = value
                    self.last_usage = value.usage       # what it cost (Engine.spend)
            return text
        resp = await self._client.chat.completions.create(model=model, messages=messages, **_split_params(params))
        self.last_usage = resp.usage.model_dump() if resp.usage else None     # what it cost (Engine.spend)
        return resp.choices[0].message.content or ""


def _no_stream(response) -> ProviderError:
    """An answer that carried no event stream at all (a web page where the API was expected, a sign-in page on a
    local network), as the error to raise: nothing in it was a reply, and an empty one would say nothing of why.
    Its status and content type are named, and where it came from, without a password written into the address
    (SealedLore's streaming._no_stream). Its status, a success, says asking again won't help."""
    kind = response.headers.get("content-type", "").split(";")[0].strip() or "no content type"
    return ProviderError(
        f"{shown(str(response.http_request.url))} answered HTTP {response.status_code} ({kind[:80]}) with no reply "
        "in it, not the stream a chat endpoint sends: a web page answers like this where the API was expected (an "
        "address without its /v1, say).",
        status_code=response.status_code,
    )


def _cut_off(response) -> ProviderError:
    """A stream that ended without the provider saying the reply was done (no finish reason and no "[DONE]"),
    as the error to raise: the connection closed mid-answer, at a proxy's time limit or a server that crashed.
    What had arrived was taken for the whole reply: a command cut short in the middle, a tool call with half
    its arguments (DA Toolkit's 87f270f). A reply the provider ended itself ("length", "content_filter") is
    not this: it is whole as far as it goes, and says why it stopped."""
    return ProviderError(
        "the reply stopped before it was finished: the connection closed mid-answer, and "
        f"{shown(str(response.http_request.url))} never said the reply was complete. What arrived of it is not a "
        "whole reply, so nothing in it was taken; asking again may work.",
        status_code=response.status_code,
    )


async def _lines(chunks, digest) -> AsyncIterator[str]:
    """The stream's lines, each byte also fed to `digest` as it arrives, decoded of any content
    encoding (the bytes the receipt's hash is of: SealedLore's openai_compat._lines)."""
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    pending = ""
    async for chunk in chunks:
        digest.update(chunk)
        pending += decoder.decode(chunk)
        *complete, pending = re.split(r"\r\n|\r|\n", pending)
        for line in complete:
            yield line
    pending += decoder.decode(b"", final=True)
    if pending:
        yield pending


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
        # each call in the order it came, and the call each of the server's indexes is now: a server that gives
        # no index, or the same one to every call, would otherwise merge them ("ReadRead", '{…}{…}')
        self._calls: list[ToolCall] = []
        self._at: dict[int | None, int] = {}

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
            slot = self._at.get(tc.index)
            if slot is None or (tc.id and self._calls[slot].id and tc.id != self._calls[slot].id):
                self._calls.append(ToolCall(id="", name="", arguments=""))
                slot = self._at[tc.index] = len(self._calls) - 1
            call = self._calls[slot]
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
        self.result.tool_calls = list(self._calls)
        for i, call in enumerate(self.result.tool_calls):
            if not call.id:
                call.id = f"call_{i}"
        return self.result
