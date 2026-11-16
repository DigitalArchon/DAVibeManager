"""Chutes' end-to-end encrypted models (llm/chutes_client.py; ported from SealedLore's tests), the
whole flow offline: a fake api.chutes.ai and llm.chutes.ai answering as
Chutes' code does, its instances keys of our own (an ML-KEM-768 key, a TLS
key bound into a quote with the registers of a published set), Intel's and
NVIDIA's checks stood in for (the real ones hold real Chutes evidence in
tests/test_chutes_evidence.py). Discovery, attestation and its cache, the
nonces, the sealed request and its reply, and every refusal."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import secrets
import struct
import uuid
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from davibemanager.llm import chutes_client as module
from davibemanager.llm import chutes_e2ee, dcap
from davibemanager.llm.chutes_client import (
    EVIDENCE_LIMIT,
    THINKING_OFF,
    ChutesE2EEClient,
    ChutesState,
    NotOffered,
    chutes_body,
    list_chutes_models,
    not_chutes,
)
from davibemanager.llm.chutes_e2ee import INFO_REQUEST, INFO_STREAM, derive_key, stream_nonce
from davibemanager.llm.secure_http import ProviderError
from davibemanager.llm.tee import (
    KEY_BINDING_UNCHECKED,
    MEASUREMENTS_LISTED,
    NRAS_URL,
    REATTEST_SECONDS,
    SHORTFALL_COSTS,
    WORKLOAD_UNMEASURED,
    TeeRefused,
    what_was_attested,
)

mlkem = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mlkem")
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

CHUTE = "9ecb73cc-909b-5334-9cd8-74985945cff5"
MODEL = "test/Model-TEE"
MRTD = bytes(range(48))
RTMRS = tuple(bytes([i]) * 48 for i in (1, 2, 3, 4))
UP_TO_DATE = dcap.Result(status="UpToDate", platform="UpToDate", qe="UpToDate", notes=["ok"])
REPLY = {
    "id": "chatcmpl-7",
    "choices": [
        {
            "message": {
                "role": "assistant",
                "content": "The door opens.",
                "reasoning_content": "Hm.",
            },
            "finish_reason": "stop",
        }
    ],
    "usage": {
        "prompt_tokens": 40,
        "completion_tokens": 5,
        "prompt_tokens_details": {"cached_tokens": 8},
    },
}


def tdx_quote(report_data: bytes, mrtd: bytes = MRTD, rtmrs: tuple = RTMRS) -> bytes:
    """A version 4 TDX quote with its registers and report data in place and
    nothing signed (Intel's check is stood in for)."""
    header = (
        struct.pack("<HHI", 4, dcap.ECDSA_P256, dcap.TDX_TEE_TYPE)
        + bytes(4)
        + dcap.INTEL_QE_VENDOR_ID
        + bytes(20)
    )
    body = bytearray(584)
    body[136:184] = mrtd
    for offset, value in zip((328, 376, 424, 472), rtmrs, strict=True):
        body[offset : offset + 48] = value
    body[520:584] = report_data
    inner = struct.pack("<HI", dcap.PCK_CHAIN, 0)
    cert = bytes(dcap.QE_REPORT_LEN) + bytes(64) + struct.pack("<H", 0) + inner
    signature = bytes(128) + struct.pack("<HI", dcap.QE_REPORT_DATA, len(cert)) + cert
    return header + bytes(body) + struct.pack("<I", len(signature)) + signature


class FakeInstance:
    """An instance: its ML-KEM key, its TLS key and certificate, its registers."""

    tls = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def __init__(self, *, mrtd: bytes = MRTD, binds: str | None = None) -> None:
        from datetime import UTC, datetime

        from cryptography import x509

        self.id = str(uuid.uuid4())
        self.key = mlkem.MLKEM768PrivateKey.generate()
        self.pubkey = base64.b64encode(self.key.public_key().public_bytes_raw()).decode()
        self.mrtd = mrtd
        # The key its quote binds: its own unless told to bind another's.
        self.binds = binds
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "sek8s")])
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.tls.public_key())
            .serial_number(1)
            .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
            .not_valid_after(datetime(2027, 1, 1, tzinfo=UTC))
            .sign(self.tls, hashes.SHA256())
        )

    def evidence(self, nonce: str, *, signer=None) -> dict:
        spki = self.cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        bound = hashlib.sha256((nonce + (self.binds or self.pubkey)).encode()).digest()
        quote = tdx_quote(bound + hashlib.sha256(spki).digest(), self.mrtd)
        gpu = [{"arch": "HOPPER", "evidence": "e", "certificate": "c"}]
        attested = json.dumps(
            {
                "nonce": nonce,
                "evidence": {
                    "quote": base64.b64encode(quote).decode(),
                    "nvtrust_evidence": json.dumps(gpu),
                },
            }
        ).encode()
        signature = (signer or self.tls).sign(attested, padding.PKCS1v15(), hashes.SHA256())
        return {
            "tee_type": "tdx",
            "instance_id": self.id,
            "quote": base64.b64encode(quote).decode(),
            "certificate": base64.b64encode(self.cert.public_bytes(Encoding.DER)).decode(),
            "signature": base64.b64encode(signature).decode(),
            "attested_body": base64.b64encode(attested).decode(),
            "gpu_evidence": gpu,
        }

    def open(self, blob: bytes) -> dict:
        ciphertext, nonce, sealed = blob[:1088], blob[1088:1100], blob[1100:]
        key = derive_key(self.key.decapsulate(ciphertext), ciphertext, INFO_REQUEST)
        return json.loads(gzip.decompress(ChaCha20Poly1305(key).decrypt(nonce, sealed, None)))


def stream_pieces(reply: dict) -> list[str]:
    """`reply` (a chat completion as the model server would send it whole) as
    the pieces of its stream, each one SSE event of the model server's own,
    as Chutes' workload seals them: the reasoning, the text a word or so at a
    time, the finish, the usage, the [DONE], then the blank line after it
    sealed on its own (live, tests/data/chutes_stream.json)."""
    if reply.get("error"):
        return ["data: " + json.dumps({"error": reply["error"]}) + "\n\n"]
    rid = reply.get("id", "chatcmpl-x")
    choice = (reply.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    chunks: list[dict] = []
    if message.get("reasoning_content"):
        chunks.append({"delta": {"reasoning_content": message["reasoning_content"]}})
    words = (message.get("content") or "").split(" ")
    for i, word in enumerate(words):
        if word:
            chunks.append({"delta": {"content": word + (" " if i < len(words) - 1 else "")}})
    if choice.get("finish_reason"):
        chunks.append({"delta": {}, "finish_reason": choice["finish_reason"]})
    events = [{"id": rid, "choices": [{"index": 0, **c}]} for c in chunks]
    if reply.get("usage"):
        events.append({"id": rid, "choices": [], "usage": reply["usage"]})
    return ["data: " + json.dumps(event) + "\n\n" for event in events] + ["data: [DONE]\n", "\n"]


def sealed_stream(pieces: list[str], response_pk: str, *, usage: dict | None = None) -> list[str]:
    """`pieces` sealed as Chutes' stream: the key exchange, then each piece
    under the stream key, its nonce its number from 0; Chutes' unsealed
    copy of the usage and its own [DONE] last, as live."""
    client = mlkem.MLKEM768PublicKey.from_public_bytes(base64.b64decode(response_pk))
    secret, ciphertext = client.encapsulate()
    key = derive_key(secret, ciphertext, INFO_STREAM)
    lines = ["data: " + json.dumps({"e2e_init": base64.b64encode(ciphertext).decode()}), ""]
    for number, piece in enumerate(pieces):
        nonce = stream_nonce(number)
        sealed = nonce + ChaCha20Poly1305(key).encrypt(nonce, piece.encode(), None)
        lines += ["data: " + json.dumps({"e2e": base64.b64encode(sealed).decode()}), ""]
    if usage:
        lines += ["data: " + json.dumps({"usage": usage}), ""]
    return [*lines, "data: [DONE]", ""]


class FakeChutes:
    """api.chutes.ai and llm.chutes.ai as Chutes' code answers (chutes-api
    api/e2e/router.py, api/chute/router.py), every request recorded."""

    def __init__(self, count: int = 3) -> None:
        self.instances = [FakeInstance() for _ in range(count)]
        self.requests: list[httpx.Request] = []
        self.issued: dict[str, str] = {}  # nonce token -> instance id
        self.used: list[str] = []
        self.opened: list[tuple[str, dict]] = []
        self.reply: dict = REPLY
        self.evidence_status: list[int] = []  # statuses to answer before a 200
        self.invoke_status: list[int] = []
        self.invoke_body: bytes | None = None
        self.tamper = False
        # How the stream's sealed lines are spoilt on the way, if at all.
        self.spoil: Callable[[list[str]], list[str]] | None = None
        self.redirect: str | None = None
        self.measured = [MRTD]
        self.nonce_life = 60

    # --- the routes

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = request.url
        if str(url).startswith(NRAS_URL):
            return httpx.Response(200, json=[["JWT", "a.b.c"], {}])
        if url.host == "llm.chutes.ai" and url.path == "/v1/models":
            return httpx.Response(200, json=self.models())
        if url.host != "api.chutes.ai":
            return httpx.Response(404)
        if self.redirect and url.path == self.redirect:
            return httpx.Response(307, headers={"location": "https://elsewhere.example/steal"})
        if url.path == "/servers/tdx/measurements":
            return httpx.Response(
                200,
                json=[
                    {
                        "version": "1.5.0",
                        "name": f"set {i}",
                        "mrtd": m.hex().upper(),
                        **{f"rtmr{j}": r.hex().upper() for j, r in enumerate(RTMRS)},
                    }
                    for i, m in enumerate(self.measured)
                ],
            )
        if url.path == f"/chutes/{CHUTE}/evidence":
            if self.evidence_status:
                status = self.evidence_status.pop(0)
                return httpx.Response(status, headers={"retry-after": "1"}, json={"detail": "no"})
            nonce = url.params["nonce"]
            return httpx.Response(
                200,
                json={
                    "evidence": [i.evidence(nonce) for i in self.instances],
                    "failed_instance_ids": [],
                    "excluded_instance_ids": [],
                },
            )
        if url.path.startswith("/instances/") and url.path.endswith("/evidence"):
            if request.headers.get("authorization") != "Bearer cpk_test":
                return httpx.Response(401, json={"detail": "no key"})
            instance_id = url.path.split("/")[2]
            instance = next(i for i in self.instances if i.id == instance_id)
            return httpx.Response(200, json=instance.evidence(url.params["nonce"]))
        if url.path == f"/e2e/instances/{CHUTE}":
            if request.headers.get("authorization") != "Bearer cpk_test":
                return httpx.Response(401, json={"detail": "Can't find a user with that api key"})
            listed = []
            for instance in self.instances[:5]:
                tokens = [secrets.token_urlsafe(24) for _ in range(10)]
                self.issued.update({t: instance.id for t in tokens})
                listed.append(
                    {"instance_id": instance.id, "e2e_pubkey": instance.pubkey, "nonces": tokens}
                )
            return httpx.Response(
                200, json={"instances": listed, "nonce_expires_in": self.nonce_life}
            )
        if url.path == "/e2e/invoke" and request.method == "POST":
            return self.invoke(request)
        return httpx.Response(404)

    def invoke(self, request: httpx.Request) -> httpx.Response:
        headers = request.headers
        token, instance_id = headers["x-e2e-nonce"], headers["x-instance-id"]
        if self.issued.get(token) != instance_id or token in self.used:
            return httpx.Response(403, json={"detail": "Invalid, expired, or already-used nonce"})
        self.used.append(token)
        if self.invoke_status:
            return httpx.Response(self.invoke_status.pop(0), json={"detail": "Instance\u202e busy\nnow"})
        assert headers["authorization"] == "Bearer cpk_test"
        assert (headers["x-chute-id"], headers["x-e2e-stream"]) == (CHUTE, "true")
        assert headers["x-e2e-path"] == "/v1/chat/completions"
        assert headers["accept"] == "text/event-stream"
        event_stream = {"content-type": "text/event-stream"}
        if self.invoke_body is not None:
            return httpx.Response(200, content=self.invoke_body, headers=event_stream)
        instance = next(i for i in self.instances if i.id == instance_id)
        body = instance.open(request.content)
        self.opened.append((instance_id, body))
        lines = sealed_stream(
            stream_pieces(self.reply), body["e2e_response_pk"], usage=self.reply.get("usage")
        )
        if self.tamper:
            first = next(i for i, line in enumerate(lines) if '"e2e"' in line)
            raw = bytearray(base64.b64decode(json.loads(lines[first][6:])["e2e"]))
            raw[-1] ^= 1
            lines[first] = "data: " + json.dumps({"e2e": base64.b64encode(raw).decode()})
        if self.spoil is not None:
            lines = self.spoil(lines)
        return httpx.Response(200, content="\n".join(lines).encode(), headers=event_stream)

    @staticmethod
    def models() -> dict:
        return {
            "data": [
                {
                    "id": MODEL,
                    "chute_id": CHUTE,
                    "confidential_compute": True,
                    "pricing": {"prompt": 0.2, "completion": 1.0, "input_cache_read": 0.02},
                    "context_length": 131072,
                },
                {"id": "plain/Model", "chute_id": str(uuid.uuid4()), "confidential_compute": False},
            ]
        }

    # --- what was asked

    def paths(self, *, host: str = "api.chutes.ai") -> list[str]:
        return [r.url.path for r in self.requests if r.url.host == host]

    def count(self, path: str) -> int:
        return sum(1 for r in self.requests if r.url.path == path)


BASE = "https://llm.chutes.ai/v1"
MESSAGES = [{"role": "system", "content": "You are a careful technician."},
            {"role": "user", "content": "Open the door."}]


def provider(fake: FakeChutes, clock=None, *, base_url: str = BASE, api_key: str = "cpk_test",
             key_origin: str = "", nvidia=None) -> ChutesE2EEClient:
    client = httpx.Client(transport=httpx.MockTransport(fake.handler))
    return ChutesE2EEClient(
        base_url, api_key, key_origin=key_origin,
        client=client,
        checks_client=client,
        intel=lambda raw, session: UP_TO_DATE,
        nvidia=nvidia or (lambda answer, nonce, session: 1),
        state=ChutesState(clock) if clock is not None else None,
        stream_transport=httpx.MockTransport(fake.handler),
    )


async def events_of(chutes: ChutesE2EEClient, model: str = MODEL, params: dict | None = None,
                    shown: list | None = None) -> list:
    events = [] if shown is None else shown
    async for event in chutes.stream(model, MESSAGES, params=params or {"max_tokens": 300, "temperature": 0.7}):
        events.append(event)
    return events


async def complete(chutes: ChutesE2EEClient, model: str = MODEL):
    events = await events_of(chutes, model)
    text = "".join(v for k, v in events if k == "text")
    return text, events[-1][1]


@pytest.fixture
def fake() -> FakeChutes:
    return FakeChutes()


# --- the whole flow -------------------------------------------------------------------------


async def test_a_request_is_sealed_to_an_attested_instance_and_its_reply_opened(fake):
    chutes = provider(fake)
    text, result = await complete(chutes)
    assert text == "The door opens."
    assert result.finish_reason == "stop" and result.reasoning == "Hm."
    assert result.usage["prompt_tokens"] == 40 and result.usage["completion_tokens"] == 5
    assert result.id == "chatcmpl-7" and result.sent_at is not None
    # What the instance opened: our response key beside the body.
    instance_id, body = fake.opened[0]
    assert instance_id == chutes.last_instance
    response_pk = body.pop("e2e_response_pk")
    assert len(base64.b64decode(response_pk)) == 1184
    assert body == chutes_body(MODEL, MESSAGES, None, {"max_tokens": 300, "temperature": 0.7})
    assert body["model"] == MODEL and body["stream"] is True and body["temperature"] == 0.7
    assert body["stream_options"] == {"include_usage": True}
    assert body["messages"][1] == {"role": "user", "content": "Open the door."}
    # Discovered once, the whole chute's evidence once, then sealed.
    assert fake.paths() == [
        f"/e2e/instances/{CHUTE}",
        "/servers/tdx/measurements",
        f"/chutes/{CHUTE}/evidence",
        "/e2e/invoke",
    ]


def test_the_body_carries_the_tools_and_nothing_vllm_doesnt_take():
    tools = [{"type": "function", "function": {"name": "run", "parameters": {"type": "object"}}}]
    history = [*MESSAGES, {"role": "assistant", "content": "x", "reasoning_content": "secret thoughts",
                           "tool_calls": [{"id": "c1", "type": "function",
                                           "function": {"name": "run", "arguments": "{}"}}]},
               {"role": "tool", "tool_call_id": "c1", "content": "ok"}]
    body = chutes_body(" " + MODEL, history, tools, {"temperature": 0.2, "provider": {"order": ["x"]},
                                                     "prompt_caching": {"enabled": True}})
    assert body["model"] == MODEL and body["tools"] == tools and body["tool_choice"] == "auto"
    assert "provider" not in body and "prompt_caching" not in body, "NanoGPT's fields never go to Chutes"
    assert "reasoning_content" not in body["messages"][2]
    assert set(body) <= module.ALLOWED_FIELDS


def test_the_lowest_reasoning_switches_thinking_off_through_the_chat_template():
    """Chutes' vLLM takes no effort: thinking is the chat template's to switch. Live
    (SealedLore, Nov 15 2026) the Qwen -TEE models sent nothing thought 435-468 tokens over a
    one-line question and wrote none of it within 400."""
    for lowest in ("none", "minimal", "low"):
        assert chutes_body(MODEL, MESSAGES, None, {"reasoning_effort": lowest})["chat_template_kwargs"] == THINKING_OFF
    assert "chat_template_kwargs" not in chutes_body(MODEL, MESSAGES, None, {}), "nothing asked: the model's own"
    assert "chat_template_kwargs" not in chutes_body(MODEL, MESSAGES, None, {"reasoning_effort": "high"})
    own = chutes_body(MODEL, MESSAGES, None, {"reasoning_effort": "none",
                                               "chat_template_kwargs": {"thinking": True}})
    assert own["chat_template_kwargs"] == {"enable_thinking": False, "thinking": True}


def test_the_record_is_partial_always_and_says_what_was_attested(fake):
    chutes = provider(fake)
    attestation = chutes.attest(MODEL)
    assert attestation.verified and attestation.encrypted and attestation.level == "partial"
    assert attestation.attested == "instance" and attestation.instances == 3 and attestation.service == "chutes"
    assert attestation.shortfalls == [WORKLOAD_UNMEASURED, MEASUREMENTS_LISTED]
    assert attestation.gpus == 3 and attestation.tcb_status == "UpToDate"
    assert attestation.hardware == "Intel TDX" and attestation.measurement == "set 0 (1.5.0)"
    assert attestation.headline == "E2EE attested (Chutes)"
    assert "3 of 3 instances" in attestation.detail
    words = what_was_attested(attestation)
    assert words.startswith("Sealed on this computer to the key of one Chutes instance")
    assert "(one of the 3 attested)" in words and "closed binary" in words
    assert "prompt cache is shared" in words
    assert attestation.to_dict()["what"] == words and len(attestation.to_dict()["costs"]) == 2
    assert fake.count("/e2e/invoke") == 0 and not fake.used, "attesting takes no nonce"


def test_every_shortfall_chutes_names_says_what_it_costs():
    """The standard: every shortfall has a tooltip saying what it costs (tee.SHORTFALL_COSTS)."""
    import ast

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    named = {
        getattr(module, node.args[0].id)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "fall_short"
        and node.args
        and isinstance(node.args[0], ast.Name)
    }
    # The keyless check (without a key) names a third.
    assert named == {WORKLOAD_UNMEASURED, MEASUREMENTS_LISTED, KEY_BINDING_UNCHECKED}
    assert all(SHORTFALL_COSTS.get(what) for what in named)


async def test_a_nonce_is_used_once_and_never_again(fake):
    fake.instances = fake.instances[:1]  # ten nonces in all, per discovery
    chutes = provider(fake)
    for _ in range(12):
        await complete(chutes)
    assert len(fake.used) == len(set(fake.used)) == 12
    assert fake.count(f"/e2e/instances/{CHUTE}") == 2, "discovered again when they ran out"
    assert fake.count(f"/chutes/{CHUTE}/evidence") == 1, "the instance attested once"


async def test_a_nonce_is_used_only_while_it_has_time_left(fake):
    now = [1000.0]
    chutes = provider(fake, clock=lambda: now[0])
    await complete(chutes)
    now[0] += 51  # 60 seconds' life, less the margin
    await complete(chutes)
    assert fake.count(f"/e2e/instances/{CHUTE}") == 2
    assert fake.count(f"/chutes/{CHUTE}/evidence") == 1, "still attested"


async def test_an_instance_attested_fifteen_minutes_ago_is_attested_again(fake):
    now = [1000.0]
    chutes = provider(fake, clock=lambda: now[0])
    await complete(chutes)
    now[0] += REATTEST_SECONDS - 1
    await complete(chutes)
    assert fake.count(f"/chutes/{CHUTE}/evidence") == 1
    now[0] += 1
    await complete(chutes)
    assert fake.count(f"/chutes/{CHUTE}/evidence") == 2
    nonces = [r.url.params["nonce"] for r in fake.requests if r.url.path.endswith("/evidence")]
    assert len(set(nonces)) == 2 and all(len(n) == 64 for n in nonces)


async def test_an_instance_first_seen_since_the_chutes_evidence_is_attested_alone(fake):
    now = [1000.0]
    chutes = provider(fake, clock=lambda: now[0])
    await complete(chutes)
    newcomer = FakeInstance()
    fake.instances.append(newcomer)
    now[0] += 120  # the nonces gone: discovered again, the newcomer with them
    await complete(chutes)
    assert fake.count(f"/chutes/{CHUTE}/evidence") == 1
    own = [r for r in fake.requests if r.url.path == f"/instances/{newcomer.id}/evidence"]
    assert len(own) == 1 and own[0].headers["authorization"] == "Bearer cpk_test"
    assert chutes.state.attestations[CHUTE].instances == 4


@pytest.mark.parametrize(
    "spoil, why",
    [
        ({"binds": "another key"}, "doesn't bind the key Chutes lists"),
        ({"mrtd": bytes(48)}, "aren't among the sets Chutes publishes"),
    ],
    ids=["unbound key", "unlisted image"],
)
async def test_an_instance_that_fails_is_left_out_said_and_never_sealed_to(fake, spoil, why):
    bad = FakeInstance(**spoil)
    fake.instances[1] = bad
    chutes = provider(fake)
    for _ in range(10):
        await complete(chutes)
    assert bad.id not in {h.headers.get("x-instance-id") for h in fake.requests}
    attestation = chutes.state.attestations[CHUTE]
    assert attestation.instances == 2 and "2 of 3 instances" in attestation.detail
    assert f"left out, never sealed to: {bad.id[:8]}" in attestation.detail
    assert why in attestation.detail


def test_an_instance_signed_by_another_key_is_left_out(fake):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bad = fake.instances[0]
    original = bad.evidence
    bad.evidence = lambda nonce: original(nonce, signer=other)
    attestation = provider(fake).attest(MODEL)
    assert attestation.instances == 2 and "didn't sign its evidence" in attestation.detail


async def test_with_no_instance_left_the_model_is_refused_and_nothing_sent(fake):
    fake.measured = [bytes(48)]
    with pytest.raises(TeeRefused, match="none of the instances Chutes listed .* could be attested"):
        await complete(provider(fake))
    assert fake.count("/e2e/invoke") == 0 and not fake.used


async def test_chutes_evidence_limit_is_waited_out_within_the_attempt(fake, monkeypatch):
    chutes = provider(fake)
    waits: list[float] = []
    monkeypatch.setattr(chutes._stop, "wait", lambda seconds: waits.append(seconds) or False)
    fake.evidence_status = [429, 429]
    text, _ = await complete(chutes)
    assert text == "The door opens." and waits == [1.0, 1.0]
    nonces = [r.url.params["nonce"] for r in fake.requests if r.url.path.endswith("/evidence")]
    assert len(nonces) == 3 == len(set(nonces)), "a fresh nonce each time"


async def test_chutes_evidence_limit_past_the_attempt_refuses_in_words(fake, monkeypatch):
    monkeypatch.setattr(module, "ATTEMPT_SECONDS", 1.5)
    fake.evidence_status = [429] * 5
    with pytest.raises(TeeRefused) as caught:
        await complete(provider(fake))
    assert EVIDENCE_LIMIT in str(caught.value) and "nothing was sent" in str(caught.value)
    assert fake.count("/e2e/invoke") == 0


async def test_a_close_while_waiting_on_the_limit_stops(fake):
    chutes = provider(fake)
    fake.evidence_status = [429]
    chutes.close()
    with pytest.raises(TeeRefused, match="stopped while waiting"):
        await complete(chutes)
    assert fake.count("/e2e/invoke") == 0


async def test_a_reply_whose_seal_doesnt_hold_is_refused_and_doubts_the_attestation(fake):
    chutes = provider(fake)
    await complete(chutes)
    fake.tamper = True
    with pytest.raises(ProviderError, match="couldn't be opened .* attested again"):
        await complete(chutes)
    fake.tamper = False
    await complete(chutes)
    assert fake.count(f"/chutes/{CHUTE}/evidence") == 2, "attested again at once"
    assert fake.count(f"/e2e/instances/{CHUTE}") == 2


@pytest.mark.parametrize(
    "body",
    [
        b'data: {"choices": [{"delta": {"content": "relay text"}}]}\n\ndata: [DONE]\n\n',
        b'{"choices": [{"message": {"content": "relay text"}}]}',
        b"x" * 4000,
    ],
    ids=["event", "json", "long"],
)
async def test_an_unsealed_reply_is_never_taken_for_the_models(fake, body):
    fake.invoke_body = body
    shown: list = []
    with pytest.raises(ProviderError, match="couldn't be read"):
        await events_of(provider(fake), shown=shown)
    assert shown == [], "nothing of it shown as the model's"


# --- the stream: each piece held to its number ------------------------------------------


def sealed_at(lines: list[str]) -> list[int]:
    return [i for i, line in enumerate(lines) if '"e2e"' in line]


async def test_the_reply_streams_piece_by_piece_as_it_comes(fake):
    """Every -TEE request streams (SealedLore's D6 as changed, Nov 15 2026): the reasoning and the
    text arrive as the pieces open, the usage is the sealed one."""
    events = await events_of(provider(fake))
    assert [v for k, v in events if k == "text"] == ["The ", "door ", "opens."]
    assert "".join(v for k, v in events if k == "reasoning") == "Hm."
    kind, result = events[-1]
    assert kind == "done" and result.finish_reason == "stop"
    assert (result.usage["prompt_tokens"], result.usage["completion_tokens"]) == (40, 5)


async def test_a_caller_may_ask_to_be_told_when_the_sealed_reply_has_begun(fake):
    chutes = provider(fake)
    events = [e async for e in chutes.stream(MODEL, MESSAGES, opened=True)]
    assert events[0] == ("open", None) and events[1] == ("reasoning", "Hm.")


async def test_chutes_unsealed_usage_is_only_a_fallback_for_the_cost(fake):
    """The sealed usage counts; Chutes' unsealed copy only when it is missing."""
    fake.spoil = lambda lines: [
        line.replace('"prompt_tokens": 40', '"prompt_tokens": 4000') if line.startswith('data: {"usage"') else line
        for line in lines
    ]
    _, result = await complete(provider(fake))
    assert result.usage["prompt_tokens"] == 40
    fake.reply = {**REPLY, "usage": None}

    def chutes_count(lines: list[str]) -> list[str]:
        return [*lines[:-2], 'data: {"usage": {"prompt_tokens": 7}}', "", *lines[-2:]]

    fake.spoil = chutes_count
    _, result = await complete(provider(fake))
    assert result.usage["prompt_tokens"] == 7


@pytest.mark.parametrize("change", ["swapped", "dropped", "repeated"])
async def test_a_piece_out_of_its_place_is_refused_in_words_and_never_shown(fake, change):
    """Pieces 1-3 are "The ", "door " and "opens.": whatever the relay did, what was shown is the
    model's text in its order up to there, and nothing of the piece out of its place; the instances
    are attested again."""

    def spoil(lines: list[str]) -> list[str]:
        at = sealed_at(lines)
        if change == "swapped":
            lines[at[1]], lines[at[2]] = lines[at[2]], lines[at[1]]
        elif change == "dropped":
            del lines[at[2]]
        else:
            lines.insert(at[3], lines[at[2]])
        return lines

    chutes = provider(fake)
    await complete(chutes)
    fake.spoil = spoil
    shown: list = []
    with pytest.raises(ProviderError) as caught:
        await events_of(chutes, shown=shown)
    assert str(caught.value).startswith("the encrypted reply couldn't be opened (a piece of the ")
    assert "isn't the one that comes next" in str(caught.value)
    assert "attested again" in str(caught.value)
    text = "".join(v for k, v in shown if k == "text")
    assert text == {"swapped": "", "dropped": "The ", "repeated": "The door "}[change]
    assert not any(k == "done" for k, _v in shown)
    fake.spoil = None
    await complete(chutes)
    assert fake.count(f"/chutes/{CHUTE}/evidence") == 2, "doubted, attested again"


@pytest.mark.parametrize("cut", ["before the finish", "before the sealed done", "after the key exchange"])
async def test_a_stream_cut_short_is_refused_in_words(fake, cut):
    """The connection closing (or the relay ending it) before the sealed [DONE] and a finish
    reason: never passed off as whole; Chutes' own unsealed [DONE] counts for nothing."""

    def spoil(lines: list[str]) -> list[str]:
        at = sealed_at(lines)
        upto = {"before the finish": at[4], "before the sealed done": at[6]}.get(cut, at[0])
        return [*lines[:upto], "data: [DONE]", ""]

    fake.spoil = spoil
    with pytest.raises(ProviderError, match="ended before the model said it was done"):
        await events_of(provider(fake))


async def test_a_refusal_is_said_as_chutes_unauthenticated_words_and_a_500_never_resent(fake):
    fake.invoke_status = [500]
    with pytest.raises(ProviderError) as caught:
        await complete(provider(fake))
    assert str(caught.value) == (
        "Chutes refused the sealed request (HTTP 500); Chutes said (unauthenticated): Instance busy now"
    )
    assert caught.value.status_code == 500 and fake.count("/e2e/invoke") == 1


async def test_a_busy_instance_is_asked_again_with_a_fresh_nonce(fake, monkeypatch):
    slept: list[float] = []

    async def sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr(module.asyncio, "sleep", sleep)
    fake.invoke_status = [429]
    text, _ = await complete(provider(fake))
    assert text == "The door opens." and len(fake.used) == 2 == len(set(fake.used))
    assert slept == [1.0]
    fake.invoke_status = [429, 429]
    with pytest.raises(ProviderError, match="HTTP 429"):
        await complete(provider(fake))


async def test_a_nonce_chutes_refuses_sends_the_next_request_to_discovery(fake):
    chutes = provider(fake)
    await complete(chutes)
    fake.issued.clear()  # every nonce of that discovery now refused
    with pytest.raises(ProviderError, match="HTTP 403"):
        await complete(chutes)
    await complete(chutes)
    assert fake.count(f"/e2e/instances/{CHUTE}") == 2


async def test_the_key_goes_to_api_chutes_ai_alone(fake):
    chutes = provider(fake)
    await complete(chutes)
    chutes.models()
    keyed = {(r.url.scheme, r.url.host) for r in fake.requests if "authorization" in r.headers}
    assert keyed == {("https", "api.chutes.ai")}
    unkeyed = {r.url.path for r in fake.requests if "authorization" not in r.headers}
    assert {"/v1/models", f"/chutes/{CHUTE}/evidence", "/servers/tdx/measurements"} <= unkeyed
    assert all(r.url.host != "llm.chutes.ai" or "authorization" not in r.headers for r in fake.requests)


@pytest.mark.parametrize("where", ["/e2e/invoke", f"/e2e/instances/{CHUTE}"])
async def test_no_redirect_is_followed(fake, where):
    fake.redirect = where
    with pytest.raises(ProviderError, match="redirected"):
        await complete(provider(fake))
    assert all(r.url.host != "elsewhere.example" for r in fake.requests)


@pytest.mark.parametrize(
    "config, why",
    [
        ({"base_url": "https://chutes.example.com"}, "isn't one of Chutes' own addresses"),
        ({"base_url": "https://llm.chutes.ai:8443/v1"}, "isn't one of Chutes' own addresses"),
        ({"base_url": "https://chutes.ai.example"}, "isn't one of Chutes' own addresses"),
        ({"base_url": "http://llm.chutes.ai/v1"}, "isn't one of Chutes' own addresses"),
        ({"api_key": ""}, "need a Chutes API key"),
        ({"key_origin": "https://evil.example:443"}, "was saved for https://evil.example,"),
    ],
    ids=["elsewhere", "another port", "look-alike", "plain http", "no key", "key for elsewhere"],
)
async def test_nothing_is_fetched_or_sent_without_a_key_that_may_go_to_chutes(fake, config, why):
    chutes = provider(fake, **config)
    with pytest.raises(ProviderError, match=why):
        await complete(chutes)
    with pytest.raises(ProviderError, match=why):
        chutes.attest(MODEL)
    assert fake.requests == []


def test_a_key_saved_for_any_of_chutes_own_hosts_may_go_to_its_e2ee_api():
    for saved in ("https://llm.chutes.ai:443", "https://claude.chutes.ai:443", "https://api.chutes.ai:443", ""):
        assert not_chutes("https://claude.chutes.ai", saved) is None
        assert not_chutes(BASE, saved) is None


async def test_a_model_chutes_doesnt_list_as_confidential_is_never_sent(fake):
    chutes = provider(fake)
    with pytest.raises(NotOffered, match="isn't one of Chutes' end-to-end encrypted models") as caught:
        await complete(chutes, "plain/Model")
    assert caught.value.offered == [MODEL]
    assert fake.paths() == [], "not even discovered"
    assert chutes.still_offered(MODEL) is True and chutes.still_offered("plain/Model") is False


async def test_without_ml_kem_nothing_is_sent(fake, monkeypatch):
    monkeypatch.setattr(chutes_e2ee, "_available", False)
    with pytest.raises(ProviderError, match="OpenSSL 3.5"):
        await complete(provider(fake))
    with pytest.raises(ProviderError, match="OpenSSL 3.5"):
        provider(fake).attest(MODEL)
    assert fake.requests == []


async def test_the_models_own_error_inside_the_seal_is_said(fake):
    fake.reply = {"error": {"message": "context too long"}}
    with pytest.raises(ProviderError, match="model's server reported an error: context too long"):
        await complete(provider(fake))


async def test_a_stream_whose_model_never_said_it_was_done_is_refused_in_words(fake):
    """Its sealed [DONE] came, but no finish reason: not taken for a whole reply."""
    fake.reply = {"choices": [{"message": {"content": "Half"}}]}
    with pytest.raises(ProviderError, match="ended before the model said it was done"):
        await complete(provider(fake))


async def test_a_discovered_key_that_isnt_one_is_never_sealed_to(fake):
    raw = base64.b64decode(fake.instances[0].pubkey)
    fake.instances[0].pubkey = base64.b64encode(raw[:-1]).decode()
    chutes = provider(fake)
    for _ in range(5):
        await complete(chutes)
    assert fake.instances[0].id not in {r.headers.get("x-instance-id") for r in fake.requests}
    assert "1183 bytes" in chutes.state.attestations[CHUTE].detail


async def test_clients_sharing_a_state_share_one_attestation_and_one_pool(fake):
    first = provider(fake)
    await complete(first)
    second = provider(fake)
    second.state = first.state
    await complete(second)
    assert fake.count(f"/chutes/{CHUTE}/evidence") == 1
    assert fake.count(f"/e2e/instances/{CHUTE}") == 1
    assert len(set(fake.used)) == 2


async def test_the_model_list_is_chutes_confidential_models_priced(fake):
    chutes = provider(fake)
    ids, listing = await chutes.list_models_detailed()
    assert ids == [MODEL] == await chutes.list_models()
    assert listing[MODEL]["pricing"] == {
        "prompt": 0.2,
        "completion": 1.0,
        "unit": "per_million_tokens",
        "input_cache_read": 0.02,
    }


async def test_an_ordinary_chutes_provider_lists_every_model_keyless(fake):
    http = httpx.AsyncClient(transport=httpx.MockTransport(fake.handler))
    listed = await list_chutes_models(http)
    assert sorted(listed) == ["plain/Model", MODEL]
    assert listed[MODEL]["confidential_compute"] is True and listed["plain/Model"]["confidential_compute"] is False
    assert all("authorization" not in r.headers for r in fake.requests)


# --- GPUs NVIDIA didn't vouch for -----------------------------------------------------------


class NoGpuEvidence(FakeInstance):
    """An instance whose evidence offers nothing for NVIDIA to check."""

    def evidence(self, nonce: str, *, signer=None) -> dict:
        found = super().evidence(nonce, signer=signer)
        attested = json.loads(base64.b64decode(found["attested_body"]))
        attested["evidence"]["nvtrust_evidence"] = "[]"
        body = json.dumps(attested).encode()
        signature = (signer or self.tls).sign(body, padding.PKCS1v15(), hashes.SHA256())
        found.update(
            attested_body=base64.b64encode(body).decode(),
            signature=base64.b64encode(signature).decode(),
            gpu_evidence=[],
        )
        return found


async def test_an_instance_with_no_gpu_evidence_is_left_out_and_never_sealed_to(fake):
    bad = NoGpuEvidence()
    fake.instances[1] = bad
    chutes = provider(fake)
    for _ in range(10):
        await complete(chutes)
    assert bad.id not in {i for i, _ in fake.opened}, "never sealed to"
    attestation = chutes.state.attestations[CHUTE]
    assert attestation.instances == 2
    assert f"instance {bad.id[:8]} offered no GPU evidence for NVIDIA to check" in attestation.detail
    assert "no GPU evidence" not in attestation.shortfalls, "not a partial of the rest"
    # Without a key too: the keyless check leaves it out.
    public = provider(fake).attest_public(MODEL)
    assert public.instances == 2 and KEY_BINDING_UNCHECKED in public.shortfalls


async def test_with_nvidia_out_of_reach_every_instance_is_left_out_and_chutes_refused(fake):
    class NvidiaDown(FakeChutes):
        def handler(self, request: httpx.Request) -> httpx.Response:
            if str(request.url).startswith(NRAS_URL):
                self.requests.append(request)
                return httpx.Response(503)
            return super().handler(request)

    down = NvidiaDown()
    with pytest.raises(TeeRefused, match="NVIDIA's attestation service couldn't be reached"):
        await complete(provider(down))
    assert down.opened == [] and down.count("/e2e/invoke") == 0, "nothing sealed or sent"


async def test_with_nvidias_keys_out_of_reach_every_instance_is_left_out(fake):
    from davibemanager.llm import nras

    def keys_gone(answer, nonce, session):
        raise nras.KeysUnavailable("NVIDIA's signing keys couldn't be fetched")

    with pytest.raises(TeeRefused, match="NVIDIA's signing keys couldn't be fetched"):
        await complete(provider(fake, nvidia=keys_gone))
    assert fake.opened == []


# --- one provider: its -TEE models sealed, the others through the plain client ----------------


class Plain:
    """The app's ordinary client for the provider's address, recording what it was handed."""

    def __init__(self) -> None:
        self.asked: list[str] = []
        self.last_usage = {"prompt_tokens": 1}

    async def stream(self, model, messages, tools=None, params=None):
        self.asked.append(model)
        yield "text", "plain"
        yield "done", None

    async def complete(self, model, messages, params=None):
        self.asked.append(model)
        return "plain"


async def test_a_chutes_provider_seals_its_tee_models_and_hands_the_others_to_the_plain_client(fake):
    plain = Plain()
    chutes = module.ChutesClient(BASE, provider(fake), plain,
                                 http=httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)))
    events = [e async for e in chutes.stream(MODEL, MESSAGES)]
    assert "".join(v for k, v in events if k == "text") == "The door opens." and plain.asked == []
    assert fake.count("/e2e/invoke") == 1
    assert [e async for e in chutes.stream(ORDINARY_ID, MESSAGES)][0] == ("text", "plain")
    assert await chutes.complete(ORDINARY_ID, MESSAGES) == "plain" and chutes.last_usage == {"prompt_tokens": 1}
    assert plain.asked == [ORDINARY_ID, ORDINARY_ID] and fake.count("/e2e/invoke") == 1
    for written in (" test/model-tee", "test/Model-TEE:THINKING"):
        assert chutes.sealed(written), "when in doubt, sealed"
    ids, caps = await chutes.list_models_detailed()
    assert ids == ["plain/Model", MODEL] == await chutes.list_models()
    assert caps[MODEL]["confidential"] is True and caps["plain/Model"]["confidential"] is False
    assert caps[MODEL]["context"] == 131072 and caps[MODEL]["pricing"]["prompt"] == 0.2


ORDINARY_ID = "plain/Model"


async def test_each_attestation_that_checked_an_instance_anew_is_told_and_never_fails_it(fake):
    told = []
    chutes = provider(fake)
    chutes._on_attested = told.append
    await complete(chutes)
    await complete(chutes)
    assert len(told) == 1 and told[0].service == "chutes", "the second found every instance attested"

    def broken(_attestation):
        raise RuntimeError("the log is full")

    again = provider(fake)
    again._on_attested = broken
    text, _ = await complete(again)
    assert text == "The door opens."
