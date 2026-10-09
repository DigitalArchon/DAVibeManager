"""NanoGPT Private Mode: end-to-end encrypted chat with an attested enclave.

NanoGPT's `private/*` models run in Tinfoil's confidential-computing enclaves. Unlike the
`TEE/*` models, whose prompts pass NanoGPT's gateway in the clear, a Private Mode request body
is sealed on this machine to a key only the attested enclave holds, and the reply comes back
sealed the same way. NanoGPT relays ciphertext: it sees the account, the model, timing, sizes
and usage.

NanoGPT ships this as a Node proxy (`@nanogpt/private-mode`) run with `npx ...@latest`, so the
code holding the plaintext would come from, and be updated by, the party the encryption is
meant to keep out. Instead this module does what the proxy does using Tinfoil's own Python SDK,
pinned exactly in pyproject.toml. The design follows SealedLore's providers/private_mode.py:

1. **Attest** (`Enclave.current`): Tinfoil's `SecureClient.verify` fetches the attestation
   bundle through NanoGPT's relay and checks it against the hardware vendor's roots (AMD SEV-SNP
   or Intel TDX) and Sigstore's record of the router release. The report binds the enclave's
   HPKE key. The latest release is looked up from Tinfoil's GitHub; an older one is reported,
   not refused, because rollouts lag.
2. **Preflight**: NanoGPT checks balance, reserves a charge and issues a cache scope. We send its
   sha256 as NanoGPT requires, but the sealed body carries **our own** random cache secret, so
   no one else (NanoGPT included) can probe our prompt cache.
3. **Seal** the body with EHBP (HPKE X25519 + AES-GCM) to the attested key and decrypt the reply.
   The transport refuses a 2xx reply that isn't sealed; we also refuse one NanoGPT doesn't mark
   as Private Mode, and a stream that ends without its final chunk. Nothing is ever sent
   unsealed and nothing falls back to the plain endpoint (`LLMClient` refuses `private/*`).

The attestation is redone once it is five minutes old, and once more if the enclave says the
key has changed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import time
from dataclasses import asdict, dataclass
from typing import AsyncIterator, Callable
from urllib.parse import urlparse

import httpx
from openai.types.chat import ChatCompletionChunk

from .client import StreamAccumulator, is_private_mode

RELAY_PATH = "/api/v1/private/tinfoil"
ROUTER_REPO = "tinfoilsh/confidential-model-router"
PRIVATE_HOSTS = frozenset({"nano-gpt.com", "api.nano-gpt.com"})
MAX_AGE_SECONDS = 5 * 60
TIMEOUT_SECONDS = 300.0
PREFLIGHT_TIMEOUT_SECONDS = 30.0
ENCLAVE_URL_HEADER = "X-Tinfoil-Enclave-Url"
CACHE_SECRET_FIELD = "user_cache_secret"
REQUIRED_STEPS = ("verifyCode", "verifyEnclave", "compareMeasurements")

# Request fields Tinfoil's router accepts (the proxy's PRIVATE_TINFOIL_CHAT_COMPLETION_BODY_FIELDS,
# @nanogpt/private-mode 0.2.22). Anything else is dropped before sealing.
ALLOWED_FIELDS = frozenset({
    "chat_template_kwargs", "frequency_penalty", "logit_bias", "max_tokens", "messages", "model",
    "parallel_tool_calls", "presence_penalty", "reasoning_effort", "response_format", "seed", "stop",
    "stream", "stream_options", "temperature", "tool_choice", "tools", "top_p", "user",
})
_ASSISTANT_REASONING_FIELDS = ("reasoning", "reasoning_content", "reasoning_details")


class PrivateModeError(Exception):
    def __init__(self, message: str, status_code: int | None = None, body: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


def offers_private_mode(base_url: str) -> bool:
    return (urlparse(base_url).hostname or "").lower() in PRIVATE_HOSTS


def relay_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    return f"{parsed.scheme}://{parsed.netloc}{RELAY_PATH}"


@dataclass(frozen=True)
class Attestation:
    enclave: str
    hardware: str
    measurement: str
    release_digest: str
    release_tag: str
    latest_release: str   # set when a newer release than the attested one exists
    latest_checked: bool
    hpke_key_sha256: str
    verified_at: float

    @property
    def summary(self) -> str:
        release = self.release_tag or f"release {self.release_digest[:12]}"
        if self.latest_release:
            currency = f"older than the latest ({self.latest_release})"
        elif self.latest_checked:
            currency = "latest release"
        else:
            currency = "latest release couldn't be checked"
        return f"{self.enclave} runs {ROUTER_REPO} {release} ({currency}), measured by {self.hardware}"

    def to_dict(self) -> dict:
        return {**asdict(self), "summary": self.summary}


@dataclass(frozen=True)
class Verified:
    hpke_public_key: str
    enclave: str
    attestation: Attestation


def _hardware(document: dict) -> str:
    kind = str(((document.get("enclaveMeasurement") or {}).get("measurement") or {}).get("type"))
    if "sev-snp" in kind:
        return "AMD SEV-SNP"
    if "tdx" in kind:
        return "Intel TDX"
    return kind


def tinfoil_verify(relay: str, cache_secret: str) -> Verified:
    """Attest Tinfoil's router through NanoGPT's relay. Blocking network I/O: run in a thread."""
    from tinfoil import SecureClient
    from tinfoil.github import fetch_latest_release

    # The cache secret is passed explicitly, or the SDK would create one under ~/.tinfoil;
    # this client only verifies, it never sends a request.
    client = SecureClient(base_url=relay + "/", attestation_bundle_url=relay, transport="ehbp",
                          user_cache_secret=cache_secret)
    truth = client.verify()
    document = client.get_verification_document().to_dict()
    steps = document.get("steps") or {}
    incomplete = [s for s in REQUIRED_STEPS if (steps.get(s) or {}).get("status") != "success"]
    if document.get("securityVerified") is not True or incomplete or not truth.hpke_public_key:
        raise PrivateModeError("the enclave's attestation was incomplete"
                               + (f" ({', '.join(incomplete)} did not succeed)" if incomplete else ""))
    digest = document.get("releaseDigest") or truth.digest
    tag, latest, checked = str(document.get("releaseTag") or ""), "", False
    try:
        release = fetch_latest_release(ROUTER_REPO)
        checked = True
        if release.digest == digest:
            tag = tag or release.tag
        else:
            latest = release.tag
    except Exception:  # noqa: BLE001 - reported, never fatal
        pass
    return Verified(
        hpke_public_key=truth.hpke_public_key,
        enclave=client.enclave,
        attestation=Attestation(
            enclave=client.enclave, hardware=_hardware(document),
            measurement=str(document.get("enclaveFingerprint") or ""), release_digest=digest,
            release_tag=tag, latest_release=latest, latest_checked=checked,
            hpke_key_sha256=hashlib.sha256(truth.hpke_public_key.encode()).hexdigest(),
            verified_at=time.time()),
    )


Verifier = Callable[[str, str], Verified]


class Enclave:
    """The attested enclave one provider seals to; re-attests when stale or rotated."""

    def __init__(self, relay: str, verifier: Verifier = tinfoil_verify,
                 clock: Callable[[], float] = time.monotonic):
        self.relay = relay
        # Ours, not NanoGPT's: see the module docstring. In memory only.
        self.cache_secret = secrets.token_hex(32)
        self._verifier = verifier
        self._clock = clock
        self._lock = asyncio.Lock()
        self._verified: Verified | None = None
        self._at = 0.0

    @property
    def attestation(self) -> Attestation | None:
        return self._verified.attestation if self._verified else None

    async def current(self) -> Verified:
        async with self._lock:
            fresh = self._verified is not None and 0 <= self._clock() - self._at < MAX_AGE_SECONDS
            if not fresh:
                self._verified = None
                try:
                    self._verified = await asyncio.to_thread(self._verifier, self.relay, self.cache_secret)
                except PrivateModeError:
                    raise
                except Exception as e:  # noqa: BLE001 - the SDK's own errors
                    raise PrivateModeError(
                        f"the private model's enclave couldn't be attested: {e}; nothing was sent") from e
                self._at = self._clock()
            return self._verified

    def invalidate(self, verified: Verified | None = None) -> None:
        if verified is None or self._verified is verified:
            self._verified = None


def sealing_transport(public_key_hex: str) -> httpx.AsyncBaseTransport:
    from ehbp import AsyncEHBPTransport

    return AsyncEHBPTransport.from_public_key_hex(public_key_hex, inner=_NonEmptyBodyTransport())


class _NonEmptyBodyTransport(httpx.AsyncHTTPTransport):
    """EHBP passes empty bodies through unsealed; we never send one to the enclave."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        from ehbp.protocol import ENCAPSULATED_KEY_HEADER

        if ENCAPSULATED_KEY_HEADER not in request.headers:  # httpx headers are case-insensitive
            raise PrivateModeError("refusing to send an unsealed request to the enclave")
        return await super().handle_async_request(request)


def shape_body(model: str, upstream: str, messages: list[dict], tools: list[dict] | None,
               cache_secret: str, params: dict | None = None) -> dict:
    """The body Tinfoil's router takes, shaped as the proxy does for the fields we send."""
    msgs = []
    for m in messages:
        if m.get("role") == "assistant":
            m = {k: v for k, v in m.items() if k not in _ASSISTANT_REASONING_FIELDS}
        msgs.append(m)
    body: dict = {"model": upstream, "messages": msgs, "stream": True,
                  "stream_options": {"include_usage": True}}
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    body.update(params or {})
    if upstream.startswith("glm-5"):
        body["chat_template_kwargs"] = {"thinking": (params or {}).get("reasoning_effort") != "none"}
    body = {k: v for k, v in body.items() if k in ALLOWED_FIELDS}
    body[CACHE_SECRET_FIELD] = cache_secret  # sealed with the body; never seen by NanoGPT
    return body


class PrivateModeClient:
    """Same streaming interface as LLMClient, but every request is sealed to an attested enclave."""

    def __init__(self, base_url: str, api_key: str | None, enclave: Enclave,
                 transport_factory: Callable[[str], httpx.AsyncBaseTransport] = sealing_transport,
                 plain_http: httpx.AsyncClient | None = None):
        if not offers_private_mode(base_url):
            raise PrivateModeError(f"{base_url} does not offer NanoGPT Private Mode")
        if not api_key:
            raise PrivateModeError("An API key is required for Private Mode.")
        self.enclave = enclave
        self._api_key = api_key
        self._transport_factory = transport_factory
        self._plain = plain_http

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._api_key}"}

    async def attest(self) -> Attestation:
        return (await self.enclave.current()).attestation

    async def _preflight(self, model: str, body_bytes: int) -> tuple[str, str]:
        client = self._plain or httpx.AsyncClient(timeout=PREFLIGHT_TIMEOUT_SECONDS)
        try:
            resp = await client.post(self.enclave.relay + "/preflight",
                                     json={"model": model, "requestBodyBytes": body_bytes},
                                     headers=self._headers())
        except httpx.HTTPError as e:
            raise PrivateModeError(f"NanoGPT's Private Mode check failed: {e}") from e
        finally:
            if self._plain is None:
                await client.aclose()
        if resp.status_code >= 400:
            raise PrivateModeError(f"NanoGPT refused the Private Mode request (HTTP {resp.status_code}): "
                                   f"{resp.text[:300]}", resp.status_code, resp.text)
        try:
            data = resp.json()
        except ValueError as e:
            raise PrivateModeError("NanoGPT's Private Mode check wasn't JSON") from e
        scope = str(data.get("cacheScope") or "").strip()
        upstream = str(data.get("upstreamModel") or "").strip()
        if len(scope) != 64 or not upstream:
            raise PrivateModeError("NanoGPT's Private Mode check didn't say where to send the request")
        return scope, upstream

    async def stream(self, model: str, messages: list[dict], tools: list[dict] | None = None,
                     params: dict | None = None) -> AsyncIterator[tuple[str, object]]:
        """Yield ("text"|"reasoning", str) deltas, then ("done", TurnResult)."""
        from ehbp import EHBPError, KeyConfigMismatchError

        if not is_private_mode(model):
            raise PrivateModeError(f"{model} isn't a Private Mode model; nothing was sent")
        for attempt in (0, 1):
            started = False
            verified = None
            try:
                verified = await self.enclave.current()  # attested before anything, even the charge
                async for event in self._one_request(model, messages, tools, verified, params):
                    started = True
                    yield event
                return
            except KeyConfigMismatchError as e:
                if started or attempt:
                    raise PrivateModeError(f"the enclave refused our key twice: {e}") from e
            except PrivateModeError as e:
                missing_seal = e.status_code == 400 and "missing_encrypted_body_header" in e.body
                if started or attempt or not missing_seal:
                    raise
            except EHBPError as e:
                raise PrivateModeError(f"the encrypted reply couldn't be opened: {e}") from e
            self.enclave.invalidate(verified)  # key rotated: attest again and retry once

    async def _one_request(self, model: str, messages: list[dict], tools: list[dict] | None,
                           verified: Verified, params: dict | None = None) -> AsyncIterator[tuple[str, object]]:
        probe = shape_body(model, model, messages, tools, self.enclave.cache_secret, params)
        scope, upstream = await self._preflight(model, len(json.dumps(probe).encode()))
        body = shape_body(model, upstream, messages, tools, self.enclave.cache_secret, params)
        headers = {
            **self._headers(),
            "Accept": "text/event-stream",
            "x-nanogpt-private-model": model,
            "x-nanogpt-private-stream": "true",
            "x-nanogpt-private-cache-scope": hashlib.sha256(scope.encode()).hexdigest(),
            "x-query-source": "api",
            ENCLAVE_URL_HEADER: f"https://{verified.enclave}",
        }
        acc = StreamAccumulator()
        saw_done = False
        async with httpx.AsyncClient(transport=self._transport_factory(verified.hpke_public_key),
                                     timeout=TIMEOUT_SECONDS, follow_redirects=False) as client:
            async with client.stream("POST", self.enclave.relay + "/v1/chat/completions",
                                     json=body, headers=headers) as resp:
                if resp.status_code >= 400:
                    text = (await resp.aread()).decode(errors="replace")
                    raise PrivateModeError(f"Private Mode request failed (HTTP {resp.status_code}): {text[:300]}",
                                           resp.status_code, text)
                if resp.headers.get("x-nanogpt-private-mode") != "tinfoil":
                    raise PrivateModeError("the reply didn't come back through Private Mode; refused")
                async for line in resp.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        saw_done = True
                        break
                    try:
                        chunk = ChatCompletionChunk.model_validate(json.loads(data))
                    except ValueError:
                        continue
                    for event in acc.feed(chunk):
                        yield event
        result = acc.finish()
        if not (result.finish_reason and saw_done):
            raise PrivateModeError("the encrypted reply ended before it was complete")
        yield "done", result

    async def complete(self, model: str, messages: list[dict], params: dict | None = None) -> str:
        text = ""
        async for kind, val in self.stream(model, messages, params=params):
            if kind == "text":
                text += val
            elif kind == "done":
                self.last_usage = val.usage
        return text


async def list_private_models(base_url: str, http: httpx.AsyncClient | None = None) -> list[str]:
    """The relay's public list of Private Mode model ids (no key needed)."""
    client = http or httpx.AsyncClient(timeout=30)
    try:
        resp = await client.get(relay_url(base_url) + "/models", headers={"Accept": "application/json"})
        resp.raise_for_status()
        return sorted(m["id"] for m in resp.json().get("data", []) if is_private_mode(str(m.get("id", ""))))
    finally:
        if http is None:
            await client.aclose()
