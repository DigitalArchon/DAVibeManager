"""OpenAI-compatible streaming client (NanoGPT, local servers, any compatible endpoint)."""

from __future__ import annotations

import codecs
import contextvars
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import AsyncIterator
from urllib.parse import urlparse

import httpx
from openai import APIError, AsyncOpenAI, DefaultAsyncHttpxClient, Timeout
from openai.types.chat import ChatCompletionChunk

from ..netpolicy import check_key, check_url, is_local_host, shown
from .secure_http import (ACCEPT_ENCODING, MAX_BODY_BYTES, MAX_ERROR_BYTES, ProviderError, encoded, loads,
                          local_http_options, too_much)

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


# How long a model server gets to accept the connection, beside the minutes a reply may take to come
# (300 s between its pieces). The two were one number until Nov 2026, so a local model server that was
# switched off showed "thinking" for ten minutes and more (two attempts) before it failed (DA Toolkit's 2d1aa54).
CONNECT_TIMEOUT = 10
# A stream is read no further than this without a line's end. A stream's line (one event) is a few kilobytes, a
# picture sent inline a few megabytes: a longer one is no reply, and reading on would hold memory for as long as the
# provider sent (SealedLore's providers/streaming.MAX_LINE_CHARS).
MAX_LINE_CHARS = 32 * 1024 * 1024
_NEWLINE = re.compile(r"\r\n|\r|\n")


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


# The fields of a chat completions message. A message in the conversation may carry more for
# another API (an Anthropic turn's own content blocks, "native"; the state it was answered
# under, "state_before": llm/anthropic_api.py), which an OpenAI-compatible provider never sees.
OPENAI_MESSAGE_KEYS = ("role", "content", "tool_calls", "tool_call_id", "name")
# The reply sent for a tool call the conversation never answered (a case saved before the
# engine answered every call): a request with an unanswered call is refused.
NO_RESULT = "(no result: the turn ended before this tool call was answered)"


def openai_messages(messages: list[dict]) -> list[dict]:
    """`messages` as chat completions takes them: anything another API keeps on them left out,
    every tool call answered before the next message (as anthropic_api.render does), and no
    tool message that answers no call."""
    out: list[dict] = []
    pending: list[str] = []          # tool call ids of the last assistant message not yet answered
    for m in messages:
        role = m.get("role")
        if role == "tool":
            if m.get("tool_call_id") not in pending:
                # An answer to no call of the assistant message before it (a case saved mid-turn
                # by an earlier version, its answers added after a later message): a provider
                # refuses the whole request for one, so it is left out. The call itself was
                # answered in its place, with NO_RESULT.
                continue
            pending.remove(m.get("tool_call_id"))
        elif pending:
            out += [{"role": "tool", "tool_call_id": i, "content": NO_RESULT} for i in pending]
            pending = []
        out.append(m if all(k in OPENAI_MESSAGE_KEYS for k in m) else {k: v for k, v in m.items() if k in OPENAI_MESSAGE_KEYS})
        if role == "assistant":
            pending = [c.get("id") for c in m.get("tool_calls") or []]
    return out + [{"role": "tool", "tool_call_id": i, "content": NO_RESULT} for i in pending]


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: str  # raw JSON text as streamed

    def parsed(self) -> dict:
        return loads(self.arguments or "{}")


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
    # when the request went (time.time(), just before it was sent): a TEE reply's receipt must have been
    # served after it, or it was another request's handed back (tee.check_reply; SealedLore's 1a61096)
    sent_at: float | None = None


def only_what_it_was_given(sdk_client) -> None:
    """OpenAI's SDK client, made to send only what this app gave it.

    The SDK reads OpenAI's environment variables whenever a client is built, whatever address it is
    for: OPENAI_ORG_ID and OPENAI_PROJECT_ID become headers of every request, and OPENAI_CUSTOM_HEADERS
    adds any header at all, an Authorization that replaces the provider's key among them. Those were
    set for OpenAI's own service, by another tool or in the user's shell; a provider here is an address
    and a key from Settings, so none of it goes to NanoGPT or a local server (DA Toolkit's 624a4be).
    (The key and the address are always passed, so the variables for those are never read.) The SDK
    takes no argument that says so: what it read is cleared from the client as it is built, by a
    subclass, so that a copy the SDK makes of it (`with_options`), built the same way, is cleared too.
    This app passes no default header, so none is lost."""
    for name in ("organization", "project"):
        if hasattr(sdk_client, name):
            setattr(sdk_client, name, None)
    sdk_client._custom_headers = {}
    if hasattr(sdk_client, "_ambient_authorizations"):      # the Authorization values OPENAI_CUSTOM_HEADERS held
        sdk_client._ambient_authorizations = frozenset()


def reading_options(base_url: str) -> dict:
    """`local_http_options`, and what every client reading a provider's answers takes (httpx's, or
    an SDK's, which is httpx2's): only gzip and deflate asked for (secure_http.ACCEPT_ENCODING; httpx
    asks for br too whenever brotli is installed, whose output per piece has no bound), and its
    bodies read only so far (`capped_lines`)."""
    return {"headers": {"Accept-Encoding": ACCEPT_ENCODING}, "event_hooks": {"response": [capped_lines]},
            **local_http_options(base_url)}


class _OpenAI(AsyncOpenAI):
    """OpenAI's client, sending only what it was given here (only_what_it_was_given)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        only_what_it_was_given(self)


class LLMClient:
    def __init__(self, base_url: str, api_key: str | None, http_client=None):
        check_url(base_url, "The provider's base URL")
        check_key(api_key, urlparse(base_url).hostname or "the provider")     # one no header can carry: nothing sent
        # Local servers often need no key, but the SDK insists on a value. A redirect is never followed
        # (the SDK's own client would): the request, the user's words in it, would go wherever the
        # provider points, plain http included (as the gateway's forwarder, which refuses them too). And a
        # server on this computer or its network is reached directly, whatever proxy the environment names.
        # Nothing the environment holds for OpenAI's own service goes with it (_OpenAI), and a server that
        # takes no connection fails in seconds (CONNECT_TIMEOUT), not after the minutes a reply may take
        self._client = _OpenAI(base_url=base_url, api_key=api_key or "not-needed", max_retries=1,
                               timeout=Timeout(300, connect=CONNECT_TIMEOUT),
                               http_client=http_client or DefaultAsyncHttpxClient(
                                   follow_redirects=False, **reading_options(base_url)))

    async def list_models(self) -> list[str]:
        page = await self._client.models.list()
        # an entry without an id, or that is no model at all, is left out: sorting None beside text raised
        # Python's own error, and the whole list was lost to it (until Nov 2026)
        return sorted({m.id for m in page.data if isinstance(getattr(m, "id", None), str) and m.id})

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
        acc.result.sent_at = time.time()
        async with self._client.chat.completions.with_streaming_response.create(**kwargs) as response:
            if exact:
                headers = response.headers
                acc.result.receipt_id = headers.get("x-receipt-id") or headers.get("x-tee-signature-id")
                acc.result.tee_route = headers.get("x-tee-verification-route")
            yield "open", None                 # the provider took it, and its reply has begun
            done = seen = False
            async for line in read_lines(response.iter_bytes(), digest, response.http_request.url):
                if done or not line.startswith("data:"):
                    continue
                seen = True
                data = line[5:].strip()
                if data == "[DONE]":
                    done = True                # read on (nothing after it is taken): the hash covers it all
                    continue
                try:
                    parsed = loads(data)
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
        whole = WHOLE_BODY.set(True)        # a reply not streamed: read no further than MAX_BODY_BYTES
        try:
            resp = await self._client.chat.completions.create(model=model, messages=messages, **_split_params(params))
        finally:
            WHOLE_BODY.reset(whole)
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
    not this: it is whole as far as it goes, and says why it stopped.
    It carries no status, as a connection that failed carries none: asking again may work, and the status of
    the answer it was cut from (200) said it wouldn't. Until Nov 2026 it carried that one, so Claude Code was
    told not to ask again (x-should-retry: false) for a request that isn't streamed, in words that said asking
    again may work."""
    return ProviderError(
        "the reply stopped before it was finished: the connection closed mid-answer, and "
        f"{shown(str(response.http_request.url))} never said the reply was complete. What arrived of it is not a "
        "whole reply, so nothing in it was taken; asking again may work.",
    )


def too_long(url) -> ProviderError:
    """A provider sent a line of more than MAX_LINE_CHARS with no end."""
    return ProviderError(f"{shown(str(url))} sent a line of more than {MAX_LINE_CHARS // (1024 * 1024)} MB "
                         "with no end, which isn't a reply; it was not read further.")


async def read_lines(chunks, body=None, url="the provider") -> AsyncIterator[str]:
    """The stream's lines (ended by CRLF, CR or LF, as an event stream's are, and nothing else),
    each byte also fed to `body` (a hash) as it arrives, decoded of any transfer encoding
    (SealedLore's providers/openai_compat._lines). Each piece is split once, so a long line costs
    its length and no more: the line so far was joined to each piece that came and split again,
    whole, which took time growing with the square of its length; and a line past MAX_LINE_CHARS
    is a ProviderError, nothing more read (SealedLore's streaming.read_lines). `chunks`: the
    response's bytes as they arrive; `url`: where they came from, for the error."""
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    line: list[str] = []            # the line not yet ended, in the pieces it came in
    length = 0
    held_cr = False                 # a CR at a piece's end may be the first half of a CRLF

    def ended(text: str, final: bool) -> list[str]:
        nonlocal length, held_cr
        if held_cr:
            text = "\r" + text
        held_cr = not final and text.endswith("\r")
        if held_cr:
            text = text[:-1]
        out = []
        parts = _NEWLINE.split(text)
        for index, part in enumerate(parts):
            length += len(part)
            if length > MAX_LINE_CHARS:
                raise too_long(url)
            line.append(part)
            if index < len(parts) - 1:
                out.append("".join(line))
                line.clear()
                length = 0
        return out

    async for chunk in chunks:
        if body is not None:
            body.update(chunk)
        for done in ended(decoder.decode(chunk), final=False):
            yield done
    for done in ended(decoder.decode(b"", final=True), final=True):
        yield done
    if line and length:
        yield "".join(line)


# Set while a reply that isn't streamed is asked for (LLMClient.complete, and the like): its body
# is read no further than MAX_BODY_BYTES whatever its content type says (`capped_lines`).
WHOLE_BODY: contextvars.ContextVar[bool] = contextvars.ContextVar("whole_body", default=False)


async def capped_lines(response: httpx.Response) -> None:
    """A response hook for every client reading a provider's answers (OpenAI's and Anthropic's SDKs',
    and the app's own: `reading_options`): whatever is read of it (the Messages API's event stream, a
    reply not streamed, a model list) is read no further than MAX_LINE_CHARS without a line's end, as
    the streams this app reads are (`read_lines`). Counted in the bytes as decoded of any content
    encoding, which is what the SDK holds: a few compressed megabytes can be a line of gigabytes. The
    SDK's own readers keep a line until it ends, joining each piece to what came before.

    And as every DA app reads an answer (Nov 2026): one compressed in a way that wasn't asked for
    (br, zstd: secure_http.ACCEPT_ENCODING) is refused unread; an error's body, and a redirect's (httpx
    reads one it follows whole before following it), is read to MAX_ERROR_BYTES and no further, the
    rest left unread; and a body that isn't an event stream (or
    one asked for whole: WHOLE_BODY) to MAX_BODY_BYTES in all. A refusal raises out of the SDK's
    reading as it is."""
    coding = encoded(response)
    if coding:
        raise ProviderError(f"{shown(str(response.request.url))} sent its answer compressed as "
                            f"{coding[:20]!r}, which wasn't asked for; it was not read.",
                            status_code=response.status_code)
    read = response.aiter_bytes
    error = response.status_code >= 300            # an error's, or a redirect's
    stream = (not WHOLE_BODY.get()
              and str(response.headers.get("content-type", "")).lower().startswith("text/event-stream"))
    limit = MAX_ERROR_BYTES if error else None if stream else MAX_BODY_BYTES

    async def aiter_bytes(chunk_size: int | None = None) -> AsyncIterator[bytes]:
        run = total = 0
        pieces = read(chunk_size)
        try:
            async for chunk in pieces:
                if limit is not None and total + len(chunk) > limit:
                    if error:
                        yield chunk[:limit - total]     # an error's first words, the rest left unread
                        await response.aclose()
                        return
                    raise too_much(response, limit)
                total += len(chunk)
                end = max(chunk.rfind(b"\n"), chunk.rfind(b"\r"))
                run = len(chunk) - end - 1 if end >= 0 else run + len(chunk)
                if run > MAX_LINE_CHARS:
                    raise too_long(response.request.url)
                yield chunk
        finally:
            await pieces.aclose()
    response.aiter_bytes = aiter_bytes     # read (aread, aiter_lines, the SDKs' streams) through it


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
