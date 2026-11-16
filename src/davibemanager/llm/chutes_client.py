"""Chutes' end-to-end encrypted models: every message sealed on this computer to the key of one
Chutes instance whose TDX quote, for our nonce, binds that key; and Chutes' public model list.

Preliminary, as SealedLore's (its providers/chutes_provider.py and chutes_catalog.py, 3.1.0b13,
Nov 2026: built and tested without an account, then run with the author's: five instances
discovered and each attested, its key binding held live, sealed replies opened, a nonce never used
twice, the listed prices what Chutes charged), from which this is ported in this app's shape: the
discovery and attestation are blocking (a worker thread, as llm/tee.py's are), the sealed request
streams on the event loop. This copy is the one DA Vibe Manager's and DA Private Coder's
llm/chutes_client.py are, line for line but their imports and names (each app's test_shared_code
holds them to it): a change is made here first, then copied.

The framing is llm/chutes_e2ee.py; the hardware's checks are llm/tee.py's own for a Chutes instance
(`TeeClient.check_instance`: Intel's DCAP chain, no debug TD, the TLS certificate's key bound into
the quote and signing our nonce and that quote, NVIDIA's verdict on the GPUs for the nonce the
quote binds). What this adds, for each request:

1. **Discovery** (`_discover`): `GET api.chutes.ai/e2e/instances/{chute_id}`, with the key: at
   most five instances, each with its ML-KEM-768 key and ten single-use nonces, good for 60
   seconds. The chute comes from the model list (llm.chutes.ai, keyless), its confidential models
   alone.
2. **Attestation** (`_attest_pool`), before any nonce of an instance is used: every instance not
   attested in the last REATTEST_SECONDS (by its id and its key's hash, on a clock that runs on
   while the machine sleeps) is. Chutes' evidence is limited to 60 calls a minute for all its
   users together, so as few are made as will do: one for the whole chute
   (`/chutes/{id}/evidence?nonce=`, keyless), or, for an instance first seen since the last of
   those, its own (`/instances/{id}/evidence`, with the key). A 429 is waited out within
   ATTEMPT_SECONDS only. Each instance's evidence goes through tee.py's checks, then two of this
   client's own: the quote's report data begins with sha256(nonce + its key), so the hardware
   vouches for the key a request is sealed to (`key_bound`), and its MRTD and RTMR0-3 are a set
   Chutes publishes (`measured`). An instance whose GPUs NVIDIA didn't vouch for is left out
   (`gpus_unproved`). One that fails is left out, said, and never sealed to; with none left the
   model is refused. Leaving one out is safe here, unlike for TEE/ models through NanoGPT: this
   client chooses the instance, and what is sealed to one key can't be opened by another.
3. **The request** (`stream`): sealed to the chosen instance, `POST /e2e/invoke`, streamed, the
   nonce used once and never again. The reply's pieces are each opened with the stream key made
   for our response key, and each held to its number (`StreamOpener`: Chutes' closed library
   numbers them, seen live), so a piece dropped, repeated or out of its place, and a stream that
   ends before the sealed end, is refused in words and nothing of the refused piece is shown. A
   seal that doesn't hold refuses and doubts every instance's attestation, so they are attested
   again before the next request (`ChutesState.doubt`). Anything Chutes writes in refusing is said
   as its, unauthenticated (`relay_said`).

The attestation is always "partial" (tee.WORKLOAD_UNMEASURED, tee.MEASUREMENTS_LISTED): the
workload that makes and uses the key is admitted by Chutes' signature, not measured, and the
measured sets are Chutes' list.

A Chutes endpoint (llm.chutes.ai, or claude.chutes.ai speaking Anthropic's Messages API) offers
every model Chutes lists (`list_chutes_models`); its -TEE models (llm/privacy.py `chutes_tee`) come
here, always, whatever the endpoint speaks, and its others go through the endpoint's ordinary
client.

**The key** goes from an endpoint at one of Chutes' own hosts, the key saved for one of them
(privacy.CHUTES_KEY_ORIGINS: llm.chutes.ai, api.chutes.ai, claude.chutes.ai), to
https://api.chutes.ai, where Chutes' end-to-end encryption is, over https, and nowhere else
(`not_chutes`, `_key`): the one stated exception to "a key goes only to the origin it was entered
for". Nothing is ever redirected, and nothing is ever sent unsealed but the discovery, the evidence
and the two public lists.
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import re
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable

import httpx
from openai.types.chat import ChatCompletionChunk

from .. import netpolicy as netguard
from .chutes_e2ee import (
    MeasurementSet, SealBroken, SealError, StreamOpener, confidential_models, is_chute_id, key_bound,
    listed_models, measured, mlkem_refusal, public_key, published_measurements, seal_request)
from .client import StreamAccumulator, openai_messages, read_lines
from .dcap import since_boot
from .privacy import CHUTES_E2EE_ORIGIN, CHUTES_KEY_ORIGINS, chutes_tee, key_origin, shown_origin
from .private_mode import _reading, relay_said
from .secure_http import ProviderError, loads, make_client
from .tee import (
    ATTEMPT_SECONDS, ATTESTATION_TIMEOUT_SECONDS, GPU_SHORTFALLS, GPUS_UNVERIFIED, KEY_BINDING_UNCHECKED,
    MEASUREMENTS_LISTED, NO_GPU_EVIDENCE, REATTEST_SECONDS, WORKLOAD_UNMEASURED, Attestation, TeeClient, TeeRefused,
    _Checks, failure_words)

CHUTES_ORIGIN = CHUTES_E2EE_ORIGIN
MODELS_URL = "https://llm.chutes.ai/v1/models"
MEASUREMENTS_URL = CHUTES_ORIGIN + "/servers/tdx/measurements"
INVOKE_URL = CHUTES_ORIGIN + "/e2e/invoke"
# What the instance's workload maps to its model's own route (chutes run.py).
E2E_PATH = "/v1/chat/completions"
# Discovery: at most this many instances, each with this many nonces (chutes-api router.py), good
# for NONCE_LIFE_SECONDS; a nonce is used only while this much of its life is left, for the request
# to reach Chutes in time.
MAX_INSTANCES = 5
MAX_NONCES = 10
NONCE_LIFE_SECONDS = 60
NONCE_MARGIN_SECONDS = 10
DISCOVERY_TIMEOUT_SECONDS = 30.0
LISTING_TIMEOUT_SECONDS = 30.0
TIMEOUT_SECONDS = 300.0
# The model list and the published measurements are read again after this.
LISTING_SECONDS = 60 * 60
# Since the last whole chute's evidence, an instance first seen is attested with its own evidence,
# while there are this many or fewer: more, and the chute's again (a single call either way, of the
# 60 a minute Chutes allows everyone together).
INSTANCE_LEVEL_MOST = 2
# A 429 asking to wait this long, or more than the attempt has left, isn't waited out.
EVIDENCE_WAIT_DEFAULT_SECONDS = 5.0
# A busy instance (a 429 to the sealed request) is asked once more after at most this long.
BUSY_WAIT_MOST_SECONDS = 10.0
# What Chutes writes in refusing, as much as is said of it.
SAID_CHARS = 200
# What a sealed request carries of the body (the rest is dropped before sealing): what vLLM's chat
# route takes. The tools too, here (SealedLore sends none): this app's models answer by calling
# them, and vLLM takes them where the model is served with a tool parser.
ALLOWED_FIELDS = frozenset({
    "chat_template_kwargs", "frequency_penalty", "logit_bias", "max_tokens", "messages", "model",
    "parallel_tool_calls", "presence_penalty", "reasoning_effort", "response_format", "seed", "stop", "stream",
    "stream_options", "temperature", "tool_choice", "tools", "top_p", "user",
})
_ASSISTANT_REASONING_FIELDS = ("reasoning", "reasoning_content", "reasoning_details")
# Chutes' models run on vLLM, which takes no reasoning effort for them: their chat template switches
# thinking on or off. Live (SealedLore, Nov 15 2026, every -TEE model): sent nothing, the Qwen models
# thought 435-468 tokens and ran out of a 400-token limit before a word; with these, none at all. A
# template that knows neither name is unchanged.
THINKING_OFF = {"enable_thinking": False, "thinking": False}
THINKING_OFF_EFFORTS = frozenset({"none", "minimal", "low"})
# A discovery nonce as Chutes makes them (secrets.token_urlsafe(24)): nothing else goes into a header.
_TOKEN = re.compile(r"[A-Za-z0-9_-]{16,128}")
EVIDENCE_LIMIT = ("Chutes allows 60 calls a minute for everyone's evidence together, and the limit was "
                  "reached; this may pass if tried again in a minute")
CHUTES_BASE_HINT = "https://llm.chutes.ai/v1 or https://claude.chutes.ai"


def not_chutes(base_url: str, saved_for: str = "") -> str | None:
    """Why Chutes' end-to-end encryption can't go through the endpoint at `base_url`, its key saved
    for `saved_for` (privacy.key_origin's form), or None: its discovery, evidence and sealed
    requests are api.chutes.ai's, and the key goes there only from an endpoint at one of Chutes' own
    hosts, saved for one of them (privacy.CHUTES_KEY_ORIGINS: the one exception to a key going only
    to the origin it was entered for)."""
    if key_origin(base_url) not in CHUTES_KEY_ORIGINS:
        return (f"{netguard.shown(base_url)} isn't one of Chutes' own addresses: its end-to-end encrypted models "
                f"are sent only through {CHUTES_ORIGIN}, from a provider at {CHUTES_BASE_HINT}, so nothing was "
                "sent. Set the provider's address to that.")
    if saved_for and saved_for not in CHUTES_KEY_ORIGINS:
        return (f"The key was saved for {shown_origin(saved_for)}, which isn't one of Chutes' own "
                f"addresses, so it isn't sent to {CHUTES_ORIGIN}; nothing was sent. Enter your Chutes key for "
                "this provider (Settings → AI providers).")
    return None


class NotOffered(ProviderError):
    """Chutes doesn't list the model as one that runs in a TEE: never sent. A variant
    ("…-TEE:THINKING") is none of those Chutes lists either: its router reads the variant on the
    ordinary route alone, which is in the clear."""

    def __init__(self, model: str, offered: list[str]) -> None:
        variant = ":" in model
        super().__init__(
            f"{relay_said(model, 120)} isn't one of Chutes' end-to-end encrypted models (those it lists as "
            "confidential compute); nothing was sent"
            + (". A variant after a colon isn't one Chutes lists: choose the model itself" if variant else ""))
        self.model = model
        self.offered = offered


@dataclass
class _Instance:
    """One instance as discovery lists it: its id, key and unused nonces."""

    instance_id: str
    pubkey: str
    nonces: list[str]

    @property
    def key_sha256(self) -> str:
        return hashlib.sha256(self.pubkey.encode()).hexdigest()


@dataclass
class _Pool:
    """A discovery's instances, good until `until` (on the state's clock)."""

    chute_id: str
    instances: list[_Instance]
    until: float
    # Those discovery listed with a key that isn't one (never sealed to).
    unusable: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class InstanceState:
    """What attesting one instance found: attested (with what its checks found and the published
    set it matched) or left out, and why."""

    instance_id: str
    key_sha256: str
    attested_at: float
    passed: bool
    why: str = ""
    checks: _Checks | None = None
    measurement: str = ""


class ChutesState:
    """What the clients of one provider share: the lists, the instances' attestations, discovery's
    nonces. Thread-safe."""

    def __init__(self, clock: Callable[[], float] = since_boot) -> None:
        self.clock = clock
        self.lock = threading.Lock()
        # One attestation at a time: a second request waits, then finds it done.
        self.attesting = threading.Lock()
        self.models: dict[str, dict[str, Any]] | None = None
        self.models_at = 0.0
        self.measurements: list[MeasurementSet] | None = None
        self.measurements_at = 0.0
        self.instances: dict[tuple[str, str], InstanceState] = {}
        self.pools: dict[str, _Pool] = {}
        self.chute_level_at: dict[str, float] = {}
        self.attestations: dict[str, Attestation] = {}

    def fresh(self, instance: _Instance) -> InstanceState | None:
        """The instance's attestation while it is in force (REATTEST_SECONDS)."""
        state = self.instances.get((instance.instance_id, instance.key_sha256))
        if state is not None and 0 <= self.clock() - state.attested_at < REATTEST_SECONDS:
            return state
        return None

    def doubt(self) -> None:
        """A reply's seal didn't hold: every instance is attested again, with the whole chute's
        evidence, and discovered again, before the next request."""
        with self.lock:
            self.instances.clear()
            self.pools.clear()
            self.chute_level_at.clear()
            self.attestations.clear()


def gpus_unproved(check: _Checks, short: str) -> tuple[str, bool] | None:
    """Why an instance whose GPUs NVIDIA didn't vouch for (tee.GPU_SHORTFALLS) is left out, and
    whether only for now (NVIDIA's service or its keys out of reach: tried again next time); None
    when its verdict held. The model runs on those GPUs and a request is sealed to that instance
    alone, so a TEE/ model's partial is no instance's here."""
    found = [what for what in check.shortfalls if what in GPU_SHORTFALLS]
    if not found:
        return None
    if NO_GPU_EVIDENCE in found:
        return f"instance {short} offered no GPU evidence for NVIDIA to check", False
    if GPUS_UNVERIFIED in found:
        return (f"instance {short}'s GPUs couldn't be checked just now: NVIDIA's attestation service couldn't "
                "be reached", True)
    return (f"instance {short}'s GPUs couldn't be checked just now: NVIDIA's signing keys couldn't be fetched, "
            "so its verdict is unchecked", True)


def chutes_body(model: str, messages: list[dict], tools: list[dict] | None = None,
                params: dict | None = None) -> dict:
    """The body sealed to the instance (less our response key): the messages as chat completions
    takes them (an assistant's reasoning left out), streamed with the model server's usage at its
    end, the tools, only the fields vLLM's route takes. The lowest reasoning ("none", "minimal",
    "low") switches the template's thinking off (`THINKING_OFF`); a higher level leaves the model's
    own."""
    msgs = []
    for m in openai_messages(messages):
        if m.get("role") == "assistant":
            m = {k: v for k, v in m.items() if k not in _ASSISTANT_REASONING_FIELDS}
        msgs.append(m)
    body: dict = {**(params or {}), "model": model.strip(), "messages": msgs, "stream": True,
                  # the model server's own count, sealed with the rest (live: its last chunk)
                  "stream_options": {"include_usage": True}}
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    if (params or {}).get("reasoning_effort") in THINKING_OFF_EFFORTS:
        own = body.get("chat_template_kwargs")
        body["chat_template_kwargs"] = {**THINKING_OFF, **(own if isinstance(own, dict) else {})}
    return {k: v for k, v in body.items() if k in ALLOWED_FIELDS}


class ChutesE2EEClient:
    """The same streaming interface as LLMClient (stream, complete, list_models), for Chutes' -TEE
    models, every request sealed to an attested instance. The provider's address and key as the
    app holds them (`key_origin`: where the key was saved for, privacy.key_origin's form; "" when not
    recorded). Hooks, replaceable for tests: `client` (the blocking client discovery, evidence and
    the public lists go through: no redirect followed), `checks_client`, `intel` and `nvidia`
    (llm/tee.py's), `stream_transport` (the sealed request's), `state` (shared by the clients of
    one provider: the attestations and nonces), `clock`; `on_attested`: told each attestation that
    checked an instance anew (an Attestation), for the app's log, never failing it."""

    def __init__(self, base_url: str, api_key: str | None, *, key_origin: str = "", client: httpx.Client | None = None,
                 checks_client: httpx.Client | None = None, intel: Callable[..., Any] | None = None,
                 nvidia: Callable[..., int] | None = None, state: ChutesState | None = None,
                 stream_transport: httpx.AsyncBaseTransport | None = None,
                 clock: Callable[[], float] = since_boot, on_attested: Callable[[Attestation], None] | None = None):
        self.base_url = base_url
        self.key_origin = key_origin
        self._api_key = api_key or ""
        self.state = state or ChutesState(clock)
        self._client = client or make_client(CHUTES_ORIGIN, follow_redirects=False)
        self._owns = client is None
        self._checks_client = checks_client
        self._intel = intel
        self._nvidia = nvidia
        self._stream_transport = stream_transport
        self._on_attested = on_attested
        self._stop = threading.Event()
        # The instance the last request was sealed to; what the last `complete` cost.
        self.last_instance: str | None = None
        self.last_usage: dict | None = None

    def close(self) -> None:
        """Stop waiting out a rate limit, and close the blocking client if it is this one's."""
        self._stop.set()
        if self._owns:
            self._client.close()

    # --- the public lists, keyless --------------------------------------------------------

    def models(self) -> dict[str, dict[str, Any]]:
        """Chutes' end-to-end encrypted models (`confidential_models`), priced, kept LISTING_SECONDS
        (network: a worker thread)."""
        state = self.state
        with state.lock:
            if state.models is not None and 0 <= state.clock() - state.models_at < LISTING_SECONDS:
                return state.models
        try:
            listing = self._public_json(MODELS_URL, "Chutes' model list")
        except ProviderError:
            with state.lock:
                if state.models is not None:
                    return state.models  # an older list still says which chute is which
            raise
        models = confidential_models(listing)
        with state.lock:
            state.models, state.models_at = models, state.clock()
        return models

    def _measurements(self) -> list[MeasurementSet]:
        state = self.state
        with state.lock:
            if state.measurements is not None and 0 <= state.clock() - state.measurements_at < LISTING_SECONDS:
                return state.measurements
        try:
            sets = published_measurements(self._public_json(MEASUREMENTS_URL, "Chutes' published measurements"))
        except (ProviderError, SealError) as exc:
            raise TeeRefused(f"Chutes' published measurements couldn't be read ({failure_words(exc)}), so no "
                             "instance can be checked; nothing was sent") from exc
        with state.lock:
            state.measurements, state.measurements_at = sets, state.clock()
        return sets

    def _public_json(self, url: str, what: str) -> Any:
        """A public list (no key, nothing of ours in it): its JSON, or ProviderError."""
        status, _headers, body = self._request("GET", url, timeout=LISTING_TIMEOUT_SECONDS)
        if status != 200:
            raise ProviderError(f"{what} couldn't be read (HTTP {status})", status_code=status)
        try:
            return loads(body)
        except ValueError as exc:
            raise ProviderError(f"{what} isn't JSON") from exc

    def still_offered(self, model: str) -> bool | None:
        """Whether Chutes still lists `model` as end-to-end encrypted; None when its list couldn't
        be read."""
        try:
            return model.strip() in self.models()
        except ProviderError:
            return None

    def check_offered(self, model: str) -> None:
        """Raise NotOffered (with what is offered) if Chutes doesn't list `model`."""
        self._chute_for(model)

    def _chute_for(self, model: str) -> tuple[str, str]:
        bare = model.strip()
        models = self.models()
        entry = models.get(bare)
        if entry is None:
            raise NotOffered(bare, sorted(models))
        return bare, str(entry["chute_id"])

    async def list_models(self) -> list[str]:
        return sorted(await asyncio.to_thread(self.models))

    async def list_models_detailed(self) -> tuple[list[str], dict[str, dict]]:
        models = await asyncio.to_thread(self.models)
        return sorted(models), dict(models)

    # --- HTTP ------------------------------------------------------------------------------

    def _key(self) -> str:
        """The key, once it may go to api.chutes.ai: refused, nothing sent, otherwise. The provider
        is at one of Chutes' own hosts and the key saved for one of them (`not_chutes`), the one
        exception to a key going only to the origin it was entered for."""
        refusal = not_chutes(self.base_url, self.key_origin)
        if refusal:
            raise ProviderError(refusal)
        if not self._api_key:
            raise ProviderError("Chutes' end-to-end encrypted models need a Chutes API key; nothing was sent")
        return netguard.check_key(self._api_key, "Chutes")

    def _request(self, method: str, url: str, *, keyed: bool = False, timeout: float,
                 **kwargs: Any) -> tuple[int, httpx.Headers, bytes]:
        """One request: its status, headers and body (read only so far: secure_http.capped_body). The
        key goes only to api.chutes.ai; no redirect is followed, nor read as anything but a
        refusal."""
        headers = dict(kwargs.pop("headers", None) or {})
        if keyed:
            key = self._key()
            if key_origin(url) != key_origin(CHUTES_ORIGIN):  # never: every keyed URL is built here
                raise ProviderError(f"refusing to send the Chutes key to {netguard.shown(url)}")
            headers["Authorization"] = f"Bearer {key}"
        try:
            response = self._client.request(method, url, headers=headers, timeout=timeout, **kwargs)
        except httpx.HTTPError as exc:
            raise ProviderError(f"{httpx.URL(url).host} couldn't be reached ({type(exc).__name__})") from exc
        if 300 <= response.status_code < 400:
            raise ProviderError(f"{httpx.URL(url).host} redirected (HTTP {response.status_code}); nothing was "
                                "followed", status_code=response.status_code)
        return response.status_code, response.headers, response.content

    @staticmethod
    def _said(body: bytes) -> str:
        """What Chutes wrote in refusing, as it may be quoted (never sealed)."""
        try:
            data = loads(body)
        except ValueError:
            return relay_said(body.decode("utf-8", errors="replace"), SAID_CHARS)
        if isinstance(data, dict):
            data = data.get("detail") or data.get("error") or data.get("message") or ""
            if isinstance(data, dict):
                data = data.get("message") or ""
        return relay_said(str(data), SAID_CHARS) if isinstance(data, (str, int, float)) else ""

    def _refusal(self, what: str, status: int, body: bytes, headers: httpx.Headers) -> ProviderError:
        said = self._said(body)
        error = ProviderError(f"{what} (HTTP {status})" + (f"; Chutes said (unauthenticated): {said}" if said else ""),
                              status_code=status)
        retry = headers.get("retry-after")
        try:
            error.retry_after = float(retry) if retry is not None else None
        except ValueError:
            error.retry_after = None
        return error

    # --- discovery --------------------------------------------------------------------------

    def _discover(self, model: str, chute_id: str) -> _Pool:
        """Discovery's instances, keys and nonces (with the key), held to their shape."""
        asked = self.state.clock()
        status, headers, body = self._request("GET", f"{CHUTES_ORIGIN}/e2e/instances/{chute_id}", keyed=True,
                                              timeout=DISCOVERY_TIMEOUT_SECONDS)
        if status != 200:
            raise self._refusal(f"Chutes listed no instance of {model} to seal to", status, body, headers)
        try:
            data = loads(body)
        except ValueError as exc:
            raise ProviderError("Chutes' list of instances isn't JSON") from exc
        listed = data.get("instances") if isinstance(data, dict) else None
        if not isinstance(listed, list) or not listed:
            raise ProviderError(f"Chutes listed no instance of {model} to seal to")
        life = data.get("nonce_expires_in")
        if isinstance(life, bool) or not isinstance(life, (int, float)) or life <= 0:
            life = NONCE_LIFE_SECONDS
        pool = _Pool(chute_id=chute_id, instances=[],
                     until=asked + min(float(life), NONCE_LIFE_SECONDS) - NONCE_MARGIN_SECONDS)
        seen: set[str] = set()
        for item in listed[:MAX_INSTANCES]:
            if not isinstance(item, dict) or not is_chute_id(item.get("instance_id")):
                continue
            instance_id = item["instance_id"]
            if instance_id in seen:
                continue
            seen.add(instance_id)
            nonces = [n for n in dict.fromkeys(item.get("nonces") or [])
                      if isinstance(n, str) and _TOKEN.fullmatch(n)][:MAX_NONCES]
            pubkey = item.get("e2e_pubkey")
            try:
                public_key(pubkey)
            except SealError as exc:
                pool.unusable[instance_id] = str(exc)
                continue
            pool.instances.append(_Instance(instance_id, pubkey, nonces))
        if not pool.instances:
            reasons = "; ".join(sorted(set(pool.unusable.values()))) or "none had a usable id"
            raise TeeRefused(f"Chutes listed no instance of {model} with a key to seal to ({reasons}); "
                             "nothing was sent")
        return pool

    # --- attestation ------------------------------------------------------------------------

    def attest(self, model: str) -> Attestation:
        """Discover `model`'s instances and attest any not attested in the last REATTEST_SECONDS
        (network; a worker thread): what was proved. Takes no nonce."""
        refusal = mlkem_refusal()
        if refusal:
            raise ProviderError(refusal)
        self._key()  # before anything is fetched: the address and the key may go there
        bare, chute_id = self._chute_for(model)
        pool = self._pool(bare, chute_id)
        return self._attest_pool(bare, pool)

    def _pool(self, model: str, chute_id: str) -> _Pool:
        with self.state.lock:
            pool = self.state.pools.get(chute_id)
            if pool is not None and self.state.clock() < pool.until:
                return pool
        pool = self._discover(model, chute_id)
        with self.state.lock:
            self.state.pools[chute_id] = pool
        return pool

    def _tee(self, model: str) -> TeeClient:
        # no key: the checks' own fetches are Intel's and NVIDIA's
        return TeeClient(CHUTES_ORIGIN, "", model, client=self._checks_client, intel=self._intel,
                         nvidia=self._nvidia)

    def _attest_pool(self, model: str, pool: _Pool) -> Attestation:
        """Every instance of `pool` attested, or left out and said; the record."""
        state = self.state
        with state.attesting:
            needing = [i for i in pool.instances if state.fresh(i) is None]
            left_out: dict[str, str] = dict(pool.unusable)
            if needing:
                deadline = time.monotonic() + ATTEMPT_SECONDS
                tee = self._tee(model)
                try:
                    with tee.attempt(deadline):
                        left_out.update(self._attest(tee, model, pool.chute_id, needing, deadline))
                finally:
                    tee.close()
            attestation = self._record(model, pool, left_out)
            with state.lock:
                state.attestations[pool.chute_id] = attestation
            if needing and self._on_attested:
                try:
                    self._on_attested(attestation)
                except Exception:  # noqa: BLE001 - only its report
                    pass
            return attestation

    def _attest(self, tee: TeeClient, model: str, chute_id: str, needing: list[_Instance],
                deadline: float) -> dict[str, str]:
        """Attest `needing`; what couldn't even be checked this time, by id (not kept: tried again
        next time). What was checked is kept in the state."""
        sets = self._measurements()
        state = self.state
        with state.lock:
            last = state.chute_level_at.get(chute_id)
        recent = last is not None and 0 <= state.clock() - last < REATTEST_SECONDS
        whole = len(needing) > INSTANCE_LEVEL_MOST or not recent
        found: dict[str, tuple[dict[str, Any], str]] = {}
        unheard: dict[str, str] = {}
        if whole:
            try:
                body, nonce = self._evidence(f"/chutes/{chute_id}/evidence", model, deadline)
            except ProviderError as exc:
                if time.monotonic() >= deadline:
                    raise
                why = f"its evidence couldn't be had ({failure_words(exc)})"
                return {i.instance_id: why for i in needing}
            with state.lock:
                state.chute_level_at[chute_id] = state.clock()
            items = body.get("evidence") if isinstance(body.get("evidence"), list) else []
            for item in items:
                if isinstance(item, dict) and is_chute_id(item.get("instance_id")):
                    found.setdefault(item["instance_id"], (item, nonce))
            for name, why in (("failed_instance_ids", "Chutes couldn't fetch its evidence"),
                              ("excluded_instance_ids", "Chutes left its evidence out")):
                listed = body.get(name)
                for instance_id in listed if isinstance(listed, list) else []:
                    if isinstance(instance_id, str) and instance_id not in found:
                        unheard[instance_id] = why
        for instance in needing:
            if instance.instance_id in found or instance.instance_id in unheard:
                continue
            # First seen since the chute's last evidence: its own, with the key.
            try:
                item, nonce = self._evidence(f"/instances/{instance.instance_id}/evidence", model, deadline,
                                             keyed=True)
            except ProviderError as exc:
                if time.monotonic() >= deadline:
                    raise
                unheard[instance.instance_id] = f"its evidence couldn't be had ({failure_words(exc)})"
                continue
            found[instance.instance_id] = (item, nonce)
        checkable = [i for i in needing if i.instance_id in found]
        with ThreadPoolExecutor(max_workers=max(1, min(8, len(checkable)))) as workers:
            results = list(workers.map(lambda i: self._check(tee, i, *found[i.instance_id], sets, deadline),
                                       checkable))
        with state.lock:
            for instance, result in zip(checkable, results, strict=True):
                if isinstance(result, str):
                    unheard[instance.instance_id] = result  # not checked: tried again next time
                else:
                    state.instances[(result.instance_id, result.key_sha256)] = result
        for instance in needing:
            if instance.instance_id not in found:
                unheard.setdefault(instance.instance_id, "Chutes sent no evidence for it")
        return {i.instance_id: unheard[i.instance_id] for i in needing if i.instance_id in unheard}

    def _evidence(self, path: str, model: str, deadline: float, *,
                  keyed: bool = False) -> tuple[dict[str, Any], str]:
        """Chutes' evidence for a fresh nonce of ours, and the nonce. A 429 (Chutes' 60 a minute for
        everyone) is waited out while the attempt has time; past that, refused in words."""
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TeeRefused(f"{model}'s attestation wasn't done within {ATTEMPT_SECONDS / 60:g} minutes, and "
                                 "was given up; this may pass if tried again")
            nonce = secrets.token_hex(32)
            status, headers, body = self._request("GET", CHUTES_ORIGIN + path, keyed=keyed, params={"nonce": nonce},
                                                  timeout=min(ATTESTATION_TIMEOUT_SECONDS, left))
            if status == 429:
                error = self._refusal("Chutes' evidence", status, body, headers)
                wait = max(1.0, error.retry_after or EVIDENCE_WAIT_DEFAULT_SECONDS)
                if wait >= deadline - time.monotonic() - 1:
                    raise TeeRefused(EVIDENCE_LIMIT)
                if self._stop.wait(wait):
                    raise ProviderError("stopped while waiting for Chutes' evidence; nothing was sent")
                continue
            if status != 200:
                raise self._refusal(f"Chutes didn't give {model}'s evidence", status, body, headers)
            try:
                data = loads(body)
            except ValueError as exc:
                raise ProviderError(f"Chutes' evidence for {model} isn't JSON") from exc
            if not isinstance(data, dict):
                raise ProviderError(f"Chutes' evidence for {model} isn't an object")
            return data, nonce

    def _check(self, tee: TeeClient, instance: _Instance, item: dict[str, Any], nonce: str,
               sets: list[MeasurementSet], deadline: float) -> InstanceState | str:
        """tee.py's checks of one instance's evidence, then the key binding and the measurements:
        attested, or left out and why (kept until it is REATTEST_SECONDS old); or, when it couldn't
        be checked at all this time (a fetch of Intel's that failed), why, as text (not kept). The
        attempt's time running out refuses the whole attestation."""
        now = self.state.clock()
        short = instance.instance_id[:8]

        def left_out(why: str) -> InstanceState:
            return InstanceState(instance.instance_id, instance.key_sha256, now, False, why)

        try:
            check = tee.check_instance(item, nonce)
        except ProviderError as exc:
            if time.monotonic() >= deadline:
                raise
            if isinstance(exc, TeeRefused):
                return left_out(failure_words(exc))
            return f"it couldn't be checked just now ({failure_words(exc)})"
        gpus = gpus_unproved(check, short)
        if gpus is not None:
            why, for_now = gpus
            return why if for_now else left_out(why)
        facts = check.quote
        if facts is None or not key_bound(facts.report_data, nonce, instance.pubkey):
            return left_out(f"instance {short}'s quote doesn't bind the key Chutes lists for it to our nonce")
        found = measured(facts.mrtd, facts.rtmrs, sets)
        if found is None:
            return left_out(f"instance {short}'s measurements aren't among the sets Chutes publishes")
        return InstanceState(instance.instance_id, instance.key_sha256, now, True, checks=check,
                             measurement=f"{found.name} ({found.version})" if found.version else found.name)

    def _record(self, model: str, pool: _Pool, left_out: dict[str, str]) -> Attestation:
        """What was proved of `pool`'s instances: always partial. Refuses when none was attested."""
        attested: list[InstanceState] = []
        for instance in pool.instances:
            state = self.state.fresh(instance)
            if state is None:
                left_out.setdefault(instance.instance_id, "it couldn't be attested")
            elif state.passed:
                attested.append(state)
            else:
                left_out[instance.instance_id] = state.why
        if not attested:
            reasons = "; ".join(f"{i[:8]}: {why}" for i, why in left_out.items())
            raise TeeRefused(f"none of the instances Chutes listed for {model} could be attested ({reasons}); "
                             "nothing was sent")
        check = _Checks(f"{len(attested)} of {len(pool.instances) + len(pool.unusable)} instances Chutes listed "
                        f"for {model} attested: each one's TDX quote binds the key a request is sealed to, for "
                        "our nonce")
        for state in attested:
            if state.checks is not None:
                check.merge(state.checks)
        check.fall_short(WORKLOAD_UNMEASURED)
        check.fall_short(MEASUREMENTS_LISTED)
        check.note("attested: " + ", ".join(f"{s.instance_id[:8]} ({s.measurement})" for s in attested))
        for instance_id, why in left_out.items():
            check.note(f"left out, never sealed to: {instance_id[:8]} ({why})")
        return _chutes_attestation(check, len(attested), sorted({s.measurement for s in attested if s.measurement}))

    def attest_public(self, model: str) -> Attestation:
        """What can be checked of `model`'s instances without the key (network; a worker thread):
        Chutes' public evidence for the whole chute, for a nonce of ours, the first MAX_INSTANCES of
        it through tee.py's checks and the published measurements. The key binding isn't checked:
        only discovery, with the key, names each instance's key (KEY_BINDING_UNCHECKED). For a check
        without a key; never for a request: nothing is sealed to what it found."""
        bare, chute_id = self._chute_for(model)
        sets = self._measurements()
        deadline = time.monotonic() + ATTEMPT_SECONDS
        tee = self._tee(bare)
        try:
            with tee.attempt(deadline):
                body, nonce = self._evidence(f"/chutes/{chute_id}/evidence", bare, deadline)
                listed = body.get("evidence") if isinstance(body.get("evidence"), list) else []
                items = [item for item in listed
                         if isinstance(item, dict) and is_chute_id(item.get("instance_id"))][:MAX_INSTANCES]

                def check(item: dict[str, Any]) -> tuple[str, _Checks | str, str]:
                    short = item["instance_id"][:8]
                    try:
                        found = tee.check_instance(item, nonce)
                    except ProviderError as exc:
                        if time.monotonic() >= deadline:
                            raise
                        return item["instance_id"], failure_words(exc), ""
                    gpus = gpus_unproved(found, short)
                    if gpus is not None:
                        return item["instance_id"], gpus[0], ""
                    facts = found.quote
                    known = measured(facts.mrtd, facts.rtmrs, sets) if facts is not None else None
                    if known is None:
                        return item["instance_id"], f"instance {short}'s measurements aren't a set Chutes publishes", ""
                    return item["instance_id"], found, f"{known.name} ({known.version})" if known.version else known.name

                with ThreadPoolExecutor(max_workers=max(1, min(8, len(items)))) as workers:
                    results = list(workers.map(check, items))
        finally:
            tee.close()
        attested = [(i, c, n) for i, c, n in results if isinstance(c, _Checks)]
        left_out = {i: c for i, c, _n in results if isinstance(c, str)}
        if not attested:
            reasons = "; ".join(f"{i[:8]}: {why}" for i, why in left_out.items()) or "Chutes' evidence listed none"
            raise TeeRefused(f"none of {bare}'s instances in Chutes' public evidence hold up ({reasons})")
        record = _Checks(f"{len(attested)} of the {len(results)} instances of {bare} checked from Chutes' public "
                         "evidence, for our nonce, hold up: Intel's chain, NVIDIA's verdict and a published image")
        for _instance, found, _name in attested:
            record.merge(found)
        record.fall_short(WORKLOAD_UNMEASURED)
        record.fall_short(MEASUREMENTS_LISTED)
        record.fall_short(KEY_BINDING_UNCHECKED)
        record.note("attested: " + ", ".join(f"{i[:8]} ({name})" for i, _c, name in attested))
        for instance_id, why in left_out.items():
            record.note(f"left out: {instance_id[:8]} ({why})")
        return _chutes_attestation(record, len(attested), sorted({name for _i, _c, name in attested}))

    def _instance_and_nonce(self, model: str, chute_id: str) -> tuple[_Instance, str]:
        """An attested instance and one of its nonces, taken: never used again, whatever becomes of
        the request. Discovered again when the nonces have run out or aged past their use."""
        for _round in range(2):
            pool = self._pool(model, chute_id)
            self._attest_pool(model, pool)
            with self.state.lock:
                if self.state.clock() < pool.until:
                    ready = [i for i in pool.instances
                             if i.nonces and (s := self.state.fresh(i)) is not None and s.passed]
                    if ready:
                        instance = random.choice(ready)
                        return instance, instance.nonces.pop(0)
                if self.state.pools.get(chute_id) is pool:
                    del self.state.pools[chute_id]
        raise ProviderError(f"Chutes' nonces for {model} ran out or expired before a request could be sealed; "
                            "nothing was sent")

    def _ready(self, model: str) -> tuple[str, str, str, _Instance, str]:
        """Everything a request needs before it is sealed (network; a worker thread): the key, the
        model and its chute, an attested instance and a nonce of it."""
        refusal = mlkem_refusal()
        if refusal:
            raise ProviderError(refusal)
        key = self._key()  # before anything is fetched: the address and the key may go there
        bare, chute_id = self._chute_for(model)
        instance, nonce = self._instance_and_nonce(bare, chute_id)
        return key, bare, chute_id, instance, nonce

    # --- one request ----------------------------------------------------------------------------

    async def stream(self, model: str, messages: list[dict], tools: list[dict] | None = None,
                     params: dict | None = None, *, opened: bool = False) -> AsyncIterator[tuple[str, object]]:
        """Yield ("text"|"reasoning"|"tool", str) deltas, then ("done", TurnResult), as LLMClient's
        stream does; with `opened`, ("open", None) first, once the sealed reply has begun. Every
        request streams, each piece held to its number."""
        for attempt in (0, 1):
            key, bare, chute_id, instance, nonce = await asyncio.to_thread(self._ready, model)
            sealed = seal_request(instance.pubkey, chutes_body(bare, messages, tools, params))
            opener = StreamOpener(sealed.response_key)
            self.last_instance = instance.instance_id
            acc = StreamAccumulator()
            sent_at = time.time()
            try:
                async for event in self._invoke(key, chute_id, instance, nonce, sealed.blob, opener, acc, opened):
                    yield event
                break
            except ProviderError as exc:
                # A busy instance (429: refused before anything ran) is asked once more, with a fresh nonce
                # and perhaps another instance; nothing else is sent again (it may have run, and be paid for).
                if attempt or exc.status_code != 429:
                    raise
                await asyncio.sleep(min(BUSY_WAIT_MOST_SECONDS, max(1.0, getattr(exc, "retry_after", None) or 1.0)))
        try:
            opener.finish()
        except SealError as exc:
            raise ProviderError(f"the encrypted reply couldn't be read ({exc}); refused") from exc
        result = acc.finish()
        # The sealed usage is the model server's own; Chutes' unsealed copy is its word, taken only for
        # a cost estimate when the sealed one is missing.
        result.usage = dict(opener.usage or opener.plain_usage) or None
        result.finish_reason = opener.finish_reason
        result.sent_at = sent_at
        yield "done", result

    async def _invoke(self, key: str, chute_id: str, instance: _Instance, nonce: str, blob: bytes,
                      opener: StreamOpener, acc: StreamAccumulator, opened: bool) -> AsyncIterator[tuple[str, object]]:
        """One sealed request and its reply's deltas as they open."""
        options = _reading(timeout=TIMEOUT_SECONDS, follow_redirects=False)
        if self._stream_transport is not None:
            options["transport"] = self._stream_transport
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/octet-stream",
                   "Accept": "text/event-stream", "X-Chute-Id": chute_id, "X-Instance-Id": instance.instance_id,
                   "X-E2E-Nonce": nonce, "X-E2E-Stream": "true", "X-E2E-Path": E2E_PATH}
        try:
            async with httpx.AsyncClient(**options) as client:
                async with client.stream("POST", INVOKE_URL, content=blob, headers=headers) as resp:
                    status = resp.status_code
                    if 300 <= status < 400:
                        raise ProviderError(f"{httpx.URL(INVOKE_URL).host} redirected (HTTP {status}); nothing was "
                                            "followed", status_code=status)
                    if status != 200:
                        if status == 403:
                            # "Invalid, expired, or already-used nonce": the rest of this discovery's nonces are no
                            # better; the next request discovers again.
                            with self.state.lock:
                                if self.state.pools.get(chute_id) is not None:
                                    del self.state.pools[chute_id]
                        raise self._refusal("Chutes refused the sealed request", status, await resp.aread(),
                                            resp.headers)
                    if opened:
                        yield "open", None
                    async for line in read_lines(resp.aiter_bytes(), url=resp.request.url):
                        for item in self._opened(opener, line):
                            for event in acc.feed(_chunk(item)):
                                yield event
        except httpx.HTTPError as exc:
            raise ProviderError(f"{httpx.URL(INVOKE_URL).host} couldn't be reached ({type(exc).__name__})") from exc

    def _opened(self, opener: StreamOpener, line: str) -> list[dict[str, Any]]:
        """One line of Chutes' stream, opened (`StreamOpener.feed`): the model server's chunks it
        held, in their counted order, or a refusal in words. Nothing a refused piece held is ever
        read as the model's."""
        try:
            return opener.feed(line)
        except SealBroken as exc:
            self.state.doubt()
            raise ProviderError(f"the encrypted reply couldn't be opened ({exc}); refused, and Chutes' instances "
                                "are attested again before anything more is sent") from exc
        except SealError as exc:
            raise ProviderError(f"the encrypted reply couldn't be read ({exc}); refused") from exc

    async def complete(self, model: str, messages: list[dict], params: dict | None = None) -> str:
        """The reply's text; what it cost on `last_usage`."""
        text = ""
        async for kind, val in self.stream(model, messages, params=params):
            if kind == "text":
                text += val
            elif kind == "done":
                self.last_usage = val.usage
        return text


class ChutesClient:
    """One Chutes provider's chat, as LLMClient's interface (stream, complete, list_models): its -TEE
    models (privacy.chutes_tee) always through `e2ee`, sealed end to end, whatever the provider
    speaks; every other model through `plain`, the app's ordinary client for the provider's address
    (OpenAI-compatible at llm.chutes.ai, Anthropic's Messages API at claude.chutes.ai, where the key
    goes as a bearer token: privacy.anthropic_bearer). The model list is Chutes' public one, every
    model (`list_chutes_models`), whatever the provider speaks. `plain` is never handed a -TEE
    model: an app's plain client refuses one too (privacy.plain_refusal)."""

    def __init__(self, base_url: str, e2ee: ChutesE2EEClient, plain: Any, *, http: httpx.AsyncClient | None = None):
        self.base_url = base_url
        self.e2ee = e2ee
        self.plain = plain
        self._http = http
        self.last_usage: dict | None = None

    def sealed(self, model: str) -> bool:
        """Whether `model` goes end-to-end encrypted (one of Chutes' -TEE models on its host)."""
        return chutes_tee(model, self.base_url)

    def _for(self, model: str) -> Any:
        return self.e2ee if self.sealed(model) else self.plain

    async def stream(self, model: str, messages: list[dict], tools: list[dict] | None = None,
                     params: dict | None = None, *, opened: bool = False) -> AsyncIterator[tuple[str, object]]:
        if self.sealed(model):
            stream = self.e2ee.stream(model, messages, tools, params, opened=opened)
        elif opened:
            stream = self.plain.stream(model, messages, tools, params, opened=True)
        else:
            stream = self.plain.stream(model, messages, tools, params)
        async for event in stream:
            yield event

    async def complete(self, model: str, messages: list[dict], params: dict | None = None) -> str:
        client = self._for(model)
        text = await client.complete(model, messages, params)
        self.last_usage = getattr(client, "last_usage", None)
        return text

    async def list_models(self) -> list[str]:
        return sorted(await list_chutes_models(self._http))

    async def list_models_detailed(self) -> tuple[list[str], dict[str, dict]]:
        """(every model Chutes lists, its capabilities: `listing_capabilities`, with `confidential`)."""
        listed = await list_chutes_models(self._http)
        return sorted(listed), listing_capabilities(listed)


def _chunk(item: dict[str, Any]) -> ChatCompletionChunk:
    """A sealed chunk of the model server's stream as the accumulator reads it: the fields a chunk
    must have and the server left out (vLLM's carry them all) filled in, never anything of its text,
    and its usage left to the opener (`StreamOpener.usage`, read whatever its shape). One that still
    can't be read is refused, not passed over: it is the model's own words."""
    choices = item.get("choices")
    item = {k: v for k, v in item.items() if k != "usage"}
    data = {"id": "", "object": "chat.completion.chunk", "created": 0, "model": "", **item,
            "choices": [{"index": at, **choice} if isinstance(choice, dict) else choice
                        for at, choice in enumerate(choices if isinstance(choices, list) else [])]}
    try:
        return ChatCompletionChunk.model_validate(data)
    except ValueError as exc:
        raise ProviderError("the encrypted reply carried a piece that couldn't be read as the model's stream; "
                            "refused") from exc


def listing_capabilities(entries: dict[str, dict[str, Any]]) -> dict[str, dict]:
    """Chutes' listing (`list_chutes_models`, `ChutesE2EEClient.models`) in capabilities.parse's
    shape (vision, reasoning, efforts, tools, context, max_output), with each model's `pricing` (per
    million tokens) and whether Chutes lists it as confidential compute beside it. Chutes lists no
    reasoning efforts: its models' thinking is their chat template's (`THINKING_OFF`)."""
    out = {}
    for model_id, entry in entries.items():
        caps = entry.get("capabilities") or {}
        inputs = (entry.get("architecture") or {}).get("input_modalities") or []
        out[model_id] = {"vision": "image" in inputs, "reasoning": bool(caps.get("reasoning")), "efforts": [],
                         "tools": bool(caps.get("tool_calling")), "context": entry.get("context_length"),
                         "max_output": entry.get("max_output_tokens"), "pricing": entry.get("pricing"),
                         "confidential": entry.get("confidential_compute") is True}
    return out


def _chutes_attestation(check: _Checks, instances: int, measurements: list[str]) -> Attestation:
    attestation = check.attestation("instance", instances=instances)
    attestation.encrypted = True
    attestation.service = "chutes"
    attestation.hardware = "Intel TDX"
    attestation.measurement = "; ".join(measurements)
    return attestation


# --- Chutes' public model list, for an ordinary Chutes provider ---------------------------------


async def list_chutes_models(http: httpx.AsyncClient | None = None) -> dict[str, dict[str, Any]]:
    """Every model Chutes lists (llm.chutes.ai/v1/models: public), by id, read without the key and
    nothing of ours in the request: what a Chutes provider offers, whatever it speaks
    (claude.chutes.ai's own listing isn't documented). Each entry as chutes_e2ee.listed_models makes
    it: its chute, whether it is confidential compute, its price per million tokens. How private
    each model is is its id's (privacy.chutes_tee): its -TEE ones go end-to-end encrypted, the
    others in the clear."""
    client = http or httpx.AsyncClient(**_reading(timeout=LISTING_TIMEOUT_SECONDS, follow_redirects=False))
    try:
        response = await client.get(MODELS_URL, headers={"Accept": "application/json"})
    except (httpx.HTTPError, ProviderError) as exc:
        raise ProviderError(f"couldn't fetch Chutes' model list: {type(exc).__name__}") from exc
    finally:
        if http is None:
            await client.aclose()
    if response.status_code >= 300:
        raise ProviderError(f"Chutes' model list couldn't be read (HTTP {response.status_code})",
                            status_code=response.status_code)
    try:
        return listed_models(loads(response.content))
    except ValueError as exc:
        raise ProviderError("Chutes' model list wasn't JSON") from exc
