"""Tinfoil's own API, end-to-end encrypted, with no relay in between.

Preliminary, as SealedLore's (its providers/tinfoil_direct.py, 3.1.0b13, Nov 2026, built offline
against captures of Tinfoil's public listing and attestation bundle, then run with the author's
account), from which this is ported in this app's async shape. This copy is the one DA Vibe
Manager's and DA Private Coder's llm/tinfoil_direct.py are, line for line but their imports and
names (each app's test_shared_code holds them to it): a change is made here first, then copied.

The same router as NanoGPT's `private/` models (llm/private_mode.py), reached directly:
`https://inference.tinfoil.sh/v1` (llm/privacy.py TINFOIL_BASE_URL). What differs from the relay:

- **Attestation** from Tinfoil's own bundle service, `https://atc.tinfoil.sh` (`direct_verify`):
  the SDK's bundle path (private_mode.tinfoil_verify), under the same guard (llm/sdk_guard.py),
  never its router lookup (`get_router_address`, plain urllib). The bundle is asked for by this
  endpoint's own host (ATC hands out either of Tinfoil's two routers' bundles to a plain request,
  and each router has a TLS key of its own) and must name it, or nothing is attested: the key and
  the headers go only where the key was bound. The whole attempt has `ATTEMPT_SECONDS`.
- **The TLS key is pinned** (`TlsPin`): the router terminates TLS inside the enclave, and the
  attestation binds its key. As the handshake with the host completes, before a byte of the
  request leaves, the certificate's key must be the attested one, behind a proxy's tunnel too; and
  no request's headers go out on a connection whose key wasn't checked. A mismatch sends nothing
  and attests again next time. Each request has a pin of its own, on a connection of its own.
- **Requests**: `POST {base}/chat/completions`, sealed by EHBP (private_mode.sealing_transport,
  through the environment's proxy), with the key and nothing else of ours in the clear; no
  preflight, no relay's headers. A reply counts only as a 2xx EHBP opened, a stream only with its
  finish reason and `[DONE]`.
- **The listing** (`GET {base}/models`) is the one unsealed request to the host, and goes without
  the key: its chat models only, their prices per million tokens (Tinfoil reports none in a
  stream, so a reply's cost is estimated from them), context windows and reasoning efforts.
  `reasoning_effort` is sent only as one the model lists (anything else is a 400). A model gone
  from it is `ModelRetired`.

The router scopes its prompt cache to the API identity and a secret sealed in the body: ours,
random per client and kept in memory only (private_mode.Enclave.cache_secret).

What isn't proved here: that the router hands a request only to attested model enclaves (that is
its published code, whose build the attestation checks, not something this app checks), and what
Tinfoil's servers see: the account, the model, timing, sizes and cost, never the text.
"""

from __future__ import annotations

import asyncio
import hashlib
import threading
from functools import partial
from typing import Any, AsyncIterator, Callable
from urllib.parse import urlparse

import httpx
from openai.types.chat import ChatCompletionChunk

from .. import netpolicy as netguard
from .client import StreamAccumulator, openai_messages, read_lines
from .dcap import since_boot
from .private_mode import (
    CACHE_SECRET_FIELD, Enclave, ModelRetired, PrivateModeError, Verified, _reading, environment_proxy, relay_said,
    sealing_transport, tinfoil_verify)
from .privacy import TINFOIL_BASE_URL
from .secure_http import ProviderError, loads

# Tinfoil's attestation bundle service: one request for /attestation is the whole trust root,
# checked by the SDK.
ATC_URL = "https://atc.tinfoil.sh"
SERVICE_NAME = "Tinfoil"
# A whole attestation, the SDK's every fetch in it, as the standard gives one.
ATTEMPT_SECONDS = 180.0
TIMEOUT_SECONDS = 300.0
LISTING_TIMEOUT_SECONDS = 30.0
# The listing is read again after this long (a model retired meanwhile).
LISTING_MAX_AGE_SECONDS = 10 * 60
# Reasoning efforts as the listing names them, least to most.
EFFORT_SCALE = ("none", "minimal", "low", "medium", "high", "xhigh", "max")
# The fields a request may carry, the router's for a direct client: NanoGPT's list
# (private_mode.ALLOWED_FIELDS) less `chat_template_kwargs`, which is the relay's own per-family
# shaping. The cache secret is added after.
DIRECT_FIELDS = frozenset({
    "frequency_penalty", "logit_bias", "max_tokens", "messages", "model", "parallel_tool_calls",
    "presence_penalty", "reasoning_effort", "response_format", "seed", "stop", "stream", "stream_options",
    "temperature", "tool_choice", "tools", "top_p", "user",
})
_ASSISTANT_REASONING_FIELDS = ("reasoning", "reasoning_content", "reasoning_details")
PIN_MISMATCH = ("Tinfoil's TLS key isn't the attested one: nothing was sent. The enclave is attested "
                "again before the next try.")
NOT_PINNED = "the connection to Tinfoil wasn't checked against the attested TLS key, so nothing was sent"


def _host(url: str) -> str:
    try:
        return (urlparse(str(url or "").strip()).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def api_base(base_url: str) -> str:
    """The endpoint's address as requests use it: without a password written into it or a trailing
    slash, and with /v1 when it names no path (Tinfoil's API is under /v1)."""
    base = netguard.without_password(str(base_url or "").strip()).rstrip("/")
    if not urlparse(base).path.strip("/"):
        base += "/v1"
    return base


# --- the attestation ---------------------------------------------------------------------------


def within(seconds: float, work: Callable[[], Verified]) -> Verified:
    """`work` on a thread of its own, given `seconds`: what it returns, or what it raised, or a
    refusal once the time is up (the thread is left to finish on its own; nothing it brings is
    used)."""
    done = threading.Event()
    result: list[Verified] = []
    failure: list[BaseException] = []

    def run() -> None:
        try:
            result.append(work())
        except BaseException as exc:  # noqa: BLE001 - handed back to the caller
            failure.append(exc)
        finally:
            done.set()

    threading.Thread(target=run, name="tinfoil-attest", daemon=True).start()
    if not done.wait(seconds):
        raise PrivateModeError(f"Tinfoil's router wasn't attested within {seconds / 60:g} minutes; nothing was sent")
    if failure:
        raise failure[0]
    return result[0]


def direct_verify(host: str, bundle_url: str, cache_secret: str, *, seconds: float = ATTEMPT_SECONDS,
                  verify: Callable[..., Verified] = tinfoil_verify) -> Verified:
    """Attest Tinfoil's router from its own bundle service (network; a worker thread), for the
    endpoint at `host`, the bundle asked for by that host: refused unless the bundle's enclave, as
    the SDK verified it (its certificate's names included), is `host`, and the attestation names a
    TLS key to pin."""
    verified = within(seconds, lambda: verify(bundle_url, cache_secret, base_url=f"https://{host}",
                                              enclave=host, service="tinfoil"))
    attested = _host(f"https://{verified.enclave}")
    if attested != host:
        raise PrivateModeError(
            f"Tinfoil's attestation is for {attested or 'no host'}, not {host}, this provider's address: its key "
            f"goes only where it was saved for, so nothing was sent. Set the provider's address to "
            f"https://{attested}/v1 if that is Tinfoil's.")
    key = verified.tls_public_key
    if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
        raise PrivateModeError("Tinfoil's attestation names no TLS key to check the connection against, so "
                               "nothing was sent")
    return verified


# --- the TLS pin ---------------------------------------------------------------------------------


class TlsPinMismatch(PrivateModeError):
    """The host's TLS key isn't the attested one, or wasn't checked."""


def spki_sha256(certificate_der: bytes) -> str:
    """The sha256 of a certificate's key (its SubjectPublicKeyInfo, DER), in hex: what Tinfoil's
    attestation binds, as its SDK compares it."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    certificate = x509.load_der_x509_certificate(certificate_der)
    key = certificate.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(key).hexdigest()


class TlsPin:
    """For httpcore's `trace` extension (an async client's, so a coroutine): the TLS key of `host`
    must be `expected`, checked as each handshake with it completes, before anything is written on
    the connection; and no request's headers go out until one was (a CONNECT to a proxy excepted:
    it carries none of ours). Behind a proxy the handshake with the host is the one inside the
    tunnel; the proxy's own (an https proxy) is told apart by the name it was made for."""

    def __init__(self, host: str, expected: str) -> None:
        self.host = host.lower().rstrip(".")
        self.expected = expected.lower()
        self.checked = False
        self._making: str | None = None

    async def __call__(self, event_name: str, info: dict[str, Any]) -> None:
        try:
            self.observe(event_name, info)
        except TlsPinMismatch:
            if event_name.endswith(".start_tls.complete"):
                # the connection whose key isn't the attested one is shut at once, nothing written on it
                close = getattr(info.get("return_value"), "aclose", None)
                if callable(close):
                    try:
                        await close()
                    except Exception:  # noqa: BLE001 - going anyway
                        pass
            raise

    def observe(self, event_name: str, info: dict[str, Any]) -> None:
        if event_name.endswith(".start_tls.started"):
            self._making = str(info.get("server_hostname") or "").lower().rstrip(".")
        elif event_name.endswith(".start_tls.complete"):
            name, self._making = self._making, None
            if name and name != self.host:
                return  # a proxy's own TLS: the host's is made inside it
            self._check(info.get("return_value"))
        elif event_name.endswith(".send_request_headers.started"):
            request = info.get("request")
            if getattr(request, "method", b"") == b"CONNECT":
                return
            if not self.checked:
                raise TlsPinMismatch(NOT_PINNED)

    def _check(self, stream: Any) -> None:
        extra = getattr(stream, "get_extra_info", None)
        ssl_object = extra("ssl_object") if callable(extra) else None
        try:
            certificate = ssl_object.getpeercert(True) if ssl_object is not None else None
            found = spki_sha256(certificate) if certificate else ""
        except Exception:  # noqa: BLE001 - anything unreadable is a mismatch
            found = ""
        if found != self.expected:
            self.checked = False
            raise TlsPinMismatch(PIN_MISMATCH)
        self.checked = True


# --- the listing -------------------------------------------------------------------------------------


def _price(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None
    return float(value)


def listing_entries(data: Any) -> dict[str, dict[str, Any]]:
    """Tinfoil's `/v1/models` as listing entries: its chat models only, each with its prices per
    million tokens (`pricing`: prompt, completion, input_cache_read, unit), context window and the
    efforts it takes (`reasoning_efforts`, Tinfoil's `supported_efforts`)."""
    items = data.get("data") if isinstance(data, dict) else None
    entries: dict[str, dict[str, Any]] = {}
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict) or item.get("type") != "chat":
            continue
        model_id = item.get("id")
        if not isinstance(model_id, str) or not model_id.strip():
            continue
        efforts = item.get("supported_efforts")
        efforts = [e for e in efforts if e in EFFORT_SCALE] if isinstance(efforts, list) else []
        entry: dict[str, Any] = {
            "id": model_id,
            "name": item.get("name") if isinstance(item.get("name"), str) else model_id,
            "description": item.get("description") if isinstance(item.get("description"), str) else "",
            "owned_by": "Tinfoil",
            "reasoning_efforts": efforts,
            "capabilities": {"reasoning": item.get("reasoning") is True, "vision": item.get("multimodal") is True,
                             "tool_calling": item.get("tool_calling") is True},
        }
        context = item.get("context_window")
        if isinstance(context, int) and not isinstance(context, bool) and context > 0:
            entry["context_length"] = context
        pricing = item.get("pricing")
        if isinstance(pricing, dict):
            prompt = _price(pricing.get("inputTokenPricePer1M"))
            completion = _price(pricing.get("outputTokenPricePer1M"))
            if prompt is not None and completion is not None:
                prices: dict[str, Any] = {"prompt": prompt, "completion": completion, "unit": "per_million_tokens"}
                cached = _price(pricing.get("cachedInputTokenPricePer1M"))
                if cached is not None:
                    prices["input_cache_read"] = cached
                entry["pricing"] = prices
        entries[model_id] = entry
    return entries


class Listing:
    """Tinfoil's listing, fetched without the key and kept a while; shared by the clients of one
    provider."""

    def __init__(self, base_url: str, *, client: httpx.AsyncClient | None = None,
                 clock: Callable[[], float] = since_boot) -> None:
        self.url = api_base(base_url) + "/models"
        netguard.check(self.url)
        self._client = client
        self._clock = clock
        self._lock = asyncio.Lock()
        self._entries: dict[str, dict[str, Any]] | None = None
        self._at = 0.0

    async def fetch(self) -> dict[str, dict[str, Any]]:
        """The chat models; PrivateModeError when the listing can't be read."""
        async with self._lock:
            if self._entries is not None and 0 <= self._clock() - self._at < LISTING_MAX_AGE_SECONDS:
                return dict(self._entries)
            client = self._client or httpx.AsyncClient(**_reading(timeout=LISTING_TIMEOUT_SECONDS,
                                                                  follow_redirects=False))
            try:
                # No key, no header of ours but what httpx sends: it is public.
                response = await client.get(self.url, headers={"Accept": "application/json"})
                if response.status_code >= 300:
                    raise PrivateModeError(f"Tinfoil's model list answered HTTP {response.status_code}",
                                           response.status_code)
                entries = listing_entries(loads(response.content))
            except (httpx.HTTPError, ProviderError) as exc:
                raise PrivateModeError(f"Tinfoil's model list couldn't be read: {relay_said(str(exc))}") from exc
            except ValueError as exc:
                raise PrivateModeError("Tinfoil's model list wasn't JSON") from exc
            finally:
                if self._client is None:
                    await client.aclose()
            self._entries, self._at = entries, self._clock()
            return dict(entries)

    async def known(self) -> dict[str, dict[str, Any]] | None:
        """The listing as last read, fetched once if it is old or never was; None when it can't be
        read."""
        try:
            return await self.fetch()
        except PrivateModeError:
            return None


# --- the request -----------------------------------------------------------------------------------


def chosen_effort(wanted: str | None, efforts: list[str] | None) -> str | None:
    """The `reasoning_effort` to send: `wanted` if the model lists it, else the nearest it lists
    (the higher on a tie; "none" only when asked for), and nothing when it lists none or the
    listing is unknown: a value the model doesn't list is refused with a 400."""
    if not wanted or not efforts:
        return None
    if wanted in efforts:
        return wanted
    if wanted == "none" or wanted not in EFFORT_SCALE:
        return None
    listed = [e for e in efforts if e in EFFORT_SCALE and e != "none"]
    if not listed:
        return None
    target = EFFORT_SCALE.index(wanted)
    return min(listed, key=lambda e: (abs(EFFORT_SCALE.index(e) - target), -EFFORT_SCALE.index(e)))


def direct_body(model: str, messages: list[dict], tools: list[dict] | None, params: dict | None,
                efforts: list[str] | None, cache_secret: str) -> dict:
    """The body sealed to the router: the messages as chat completions takes them (an assistant's
    reasoning left out), a stream with its usage, the tools, the effort only as the model lists one,
    nothing the router doesn't take, and our cache secret."""
    msgs = []
    for m in openai_messages(messages):
        if m.get("role") == "assistant":
            m = {k: v for k, v in m.items() if k not in _ASSISTANT_REASONING_FIELDS}
        msgs.append(m)
    body: dict = {**(params or {}), "model": model, "messages": msgs, "stream": True,
                  "stream_options": {"include_usage": True}}
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    effort = chosen_effort(body.pop("reasoning_effort", None) or None, efforts)
    if effort:
        body["reasoning_effort"] = effort
    body = {k: v for k, v in body.items() if k in DIRECT_FIELDS}
    body[CACHE_SECRET_FIELD] = cache_secret  # sealed with the body; never seen by anyone in between
    return body


def listing_capabilities(entries: dict[str, dict[str, Any]]) -> dict[str, dict]:
    """The listing's entries in capabilities.parse's shape (vision, reasoning, efforts, tools,
    context, max_output), with each model's `pricing` beside it (per million tokens)."""
    out = {}
    for model_id, entry in entries.items():
        caps = entry.get("capabilities") or {}
        out[model_id] = {"vision": bool(caps.get("vision")), "reasoning": bool(caps.get("reasoning")),
                         "efforts": list(entry.get("reasoning_efforts") or []), "tools": bool(caps.get("tool_calling")),
                         "context": entry.get("context_length"), "max_output": entry.get("max_output_tokens"),
                         "pricing": entry.get("pricing")}
    return out


def _https_host(base: str) -> str:
    """`base`'s host, once it is an https address to a host (the attestation names the host the key
    may go to, and the pin needs TLS): else PrivateModeError, nothing sent."""
    netguard.check(base)
    host = _host(base)
    if urlparse(base).scheme != "https" or not host:
        raise PrivateModeError(f"{netguard.shown(base)} isn't an https address, which Tinfoil's attestation and "
                               "its TLS pin need; nothing was sent")
    return host


class TinfoilState:
    """What every client of one Tinfoil provider shares, held as one object (a provider's, for as
    long as the app keeps the provider): the attested router (`enclave`: its attestation, made again
    when old, and our prompt cache's secret, in memory only) and the keyless listing. `on_attested`:
    told each new attestation, for the app's log."""

    def __init__(self, base_url: str = TINFOIL_BASE_URL, *, enclave: Enclave | None = None,
                 listing: Listing | None = None, plain_http: httpx.AsyncClient | None = None,
                 on_attested: Callable[[Any], None] | None = None):
        self.base = api_base(base_url)
        self.host = _https_host(self.base)
        self.enclave = enclave or Enclave(ATC_URL, verifier=partial(direct_verify, self.host), on_attested=on_attested)
        self.listing = listing or Listing(self.base, client=plain_http)


class TinfoilDirectClient:
    """The same streaming interface as LLMClient and PrivateModeClient (stream, complete,
    list_models), every request sealed to Tinfoil's attested router and sent straight to Tinfoil
    over a connection pinned to its attested TLS key. `state`: shared by the clients of one provider
    (`TinfoilState`; a client made without one has its own); `transport_factory`: the sealing
    transport for an attested key and a proxy (private_mode.sealing_transport)."""

    def __init__(self, base_url: str, api_key: str | None, state: TinfoilState | None = None, *,
                 transport_factory: Callable[[str, str | None], httpx.AsyncBaseTransport] = sealing_transport):
        self.base = api_base(base_url)
        self.host = _https_host(self.base)
        if not api_key:
            raise PrivateModeError("An API key is required for Tinfoil.")
        netguard.check_key(api_key, self.host)
        self._api_key = api_key
        self.state = state or TinfoilState(self.base)
        if self.state.host != self.host:
            raise PrivateModeError(f"this client is for {self.host}, its attestation for {self.state.host}; nothing "
                                   "was sent")
        self.enclave = self.state.enclave
        self.listing = self.state.listing
        self._transport_factory = transport_factory
        self.last_usage: dict | None = None     # the last `complete`'s

    @property
    def endpoint(self) -> str:
        return self.base + "/chat/completions"

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._api_key}"}

    # --- the listing ----------------------------------------------------------------------------

    async def list_models(self) -> list[str]:
        """Tinfoil's chat models, fetched without the key."""
        return sorted(await self.listing.fetch())

    async def list_models_detailed(self) -> tuple[list[str], dict[str, dict]]:
        """(the chat models, each one's listing entry: prices, context, efforts)."""
        entries = await self.listing.fetch()
        return sorted(entries), entries

    async def check_offered(self, model: str) -> dict | None:
        """The model's listing entry; `ModelRetired`, with what is offered instead, if Tinfoil no
        longer lists it. None when the list couldn't be read (the router still refuses a model it
        doesn't have)."""
        entries = await self.listing.known()
        if entries is None:
            return None
        if model not in entries:
            raise ModelRetired(model, sorted(entries), service="Tinfoil")
        return entries[model]

    async def attest(self, model: str = "", fresh: bool = False):
        """Attest the router (the enclave is Tinfoil's router whatever `model`; with one, first
        make sure Tinfoil still lists it). `fresh`: attested now, whatever attestation is kept."""
        if model:
            await self.check_offered(model)
        return (await self.enclave.current(fresh)).attestation

    # --- one request ----------------------------------------------------------------------------

    async def stream(self, model: str, messages: list[dict], tools: list[dict] | None = None,
                     params: dict | None = None, *, opened: bool = False) -> AsyncIterator[tuple[str, object]]:
        """Yield ("text"|"reasoning"|"tool", str) deltas, then ("done", TurnResult). With `opened`,
        ("open", None) first, once the enclave's sealed reply has begun."""
        entry = await self.check_offered(model)
        efforts = list(entry.get("reasoning_efforts") or []) if entry is not None else None
        for attempt in (0, 1):
            started = False
            verified = await self.enclave.current()  # attested before anything goes to the host
            from ehbp import EHBPError, KeyConfigMismatchError
            try:
                async for event in self._one_request(model, messages, tools, params, efforts, verified, opened):
                    started = started or event[0] != "open"
                    yield event
                return
            except KeyConfigMismatchError as e:
                if started or attempt:
                    raise PrivateModeError(f"the enclave refused our key twice: {relay_said(str(e))}") from e
            except TlsPinMismatch:
                # whatever answers at the host isn't the enclave attested: attest again before anything more
                self.enclave.invalidate(verified)
                raise
            except EHBPError as e:
                raise PrivateModeError(f"the encrypted reply couldn't be opened: {e}") from e
            self.enclave.invalidate(verified)  # key rotated: attest again and retry once

    async def _one_request(self, model: str, messages: list[dict], tools: list[dict] | None, params: dict | None,
                           efforts: list[str] | None, verified: Verified,
                           opened: bool) -> AsyncIterator[tuple[str, object]]:
        if not verified.tls_public_key:
            raise TlsPinMismatch(NOT_PINNED)
        body = direct_body(model, messages, tools, params, efforts, self.enclave.cache_secret)
        headers = {**self._headers(), "Accept": "text/event-stream"}
        # a pin for this request alone, on a connection of its own (a client per request): what one
        # handshake found is never another's
        pin = TlsPin(self.host, verified.tls_public_key)
        acc = StreamAccumulator()
        saw_done = False
        route = environment_proxy(self.base)
        async with httpx.AsyncClient(transport=self._transport_factory(verified.hpke_public_key, route),
                                     **_reading(timeout=TIMEOUT_SECONDS, follow_redirects=False)) as client:
            async with client.stream("POST", self.endpoint, json=body, headers=headers,
                                     extensions={"trace": pin}) as resp:
                from ehbp.protocol import RESPONSE_NONCE_HEADER
                if resp.status_code >= 400:
                    text = (await resp.aread()).decode(errors="replace")
                    # written by Tinfoil's servers, not the enclave: never sealed, so said as that, and short
                    error = PrivateModeError(f"Tinfoil's request failed (HTTP {resp.status_code}); Tinfoil said "
                                             f"(unauthenticated): {relay_said(text)}", resp.status_code, text)
                    error.through_enclave = RESPONSE_NONCE_HEADER in resp.headers
                    raise error
                # EHBP passes a reply that isn't a success through as it came, unsealed: only a sealed one counts
                if not 200 <= resp.status_code < 300 or RESPONSE_NONCE_HEADER not in resp.headers:
                    raise PrivateModeError(f"the reply wasn't sealed by the enclave (HTTP {resp.status_code}); refused",
                                           resp.status_code)
                if opened:
                    yield "open", None
                async for line in read_lines(resp.aiter_bytes(), url=resp.request.url):
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        saw_done = True
                        break
                    try:
                        parsed = loads(data)
                    except ValueError:
                        continue
                    if isinstance(parsed, dict) and parsed.get("error") and not parsed.get("choices"):
                        # the enclave stopped partway and said why (inside the seal): said as it is
                        err = parsed["error"]
                        said = err.get("message") if isinstance(err, dict) else err
                        code = err.get("code") if isinstance(err, dict) else None
                        raise PrivateModeError(f"the model stopped: {str(said)[:300]}",
                                               code if isinstance(code, int) else None, data[:2000])
                    try:
                        chunk = ChatCompletionChunk.model_validate(parsed)
                    except ValueError:
                        continue
                    for event in acc.feed(chunk):
                        yield event
        result = acc.finish()
        if not (result.finish_reason and saw_done):
            raise PrivateModeError("the encrypted reply ended before it was complete")
        yield "done", result

    async def complete(self, model: str, messages: list[dict], params: dict | None = None) -> str:
        """The reply's text; what it cost on `last_usage`."""
        text = ""
        async for kind, val in self.stream(model, messages, params=params):
            if kind == "text":
                text += val
            elif kind == "done":
                self.last_usage = val.usage
        return text


def listed_cost(usage: dict | None, entry: dict | None) -> float | None:
    """A reply's cost from its listed prices per million tokens (Tinfoil reports none in a
    stream): cached prompt tokens at the cache price where listed. None without both."""
    prices = (entry or {}).get("pricing")
    if not isinstance(usage, dict) or not isinstance(prices, dict):
        return None
    prompt = usage.get("prompt_tokens")
    completion = usage.get("completion_tokens")
    if not isinstance(prompt, int) or not isinstance(completion, int):
        return None
    details = usage.get("prompt_tokens_details")
    cached = details.get("cached_tokens") if isinstance(details, dict) else 0
    cached = cached if isinstance(cached, int) and 0 <= cached <= prompt else 0
    cache_price = prices.get("input_cache_read", prices["prompt"])
    return ((prompt - cached) * prices["prompt"] + cached * cache_price + completion * prices["completion"]) / 1e6
