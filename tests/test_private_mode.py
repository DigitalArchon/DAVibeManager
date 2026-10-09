"""NanoGPT Private Mode protocol, against a fake relay and a fake attestation verifier."""

import hashlib
import json

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from davibemanager.llm.client import LLMClient, detect_tier
from davibemanager.llm.private_mode import (
    Attestation, Enclave, PrivateModeClient, PrivateModeError, Verified, _NonEmptyBodyTransport,
    offers_private_mode, relay_url, sealing_transport)

BASE = "https://nano-gpt.com/api/v1"
RELAY = "https://nano-gpt.com/api/v1/private/tinfoil"
# a function tool, as a chat model is given one (the shape is what matters here)
PROPOSE_TOOL = {"type": "function", "function": {"name": "propose_commands", "description": "Queue commands.",
                "parameters": {"type": "object", "properties": {"items": {"type": "array"}}}}}
KEY = "ab" * 32
SCOPE = "c" * 64


def verified(key=KEY):
    return Verified(key, "enclave.tinfoil.example", Attestation(
        enclave="enclave.tinfoil.example", hardware="AMD SEV-SNP", measurement="m", release_digest="d" * 64,
        release_tag="v1.2.3", latest_release="", latest_checked=True,
        hpke_key_sha256=hashlib.sha256(key.encode()).hexdigest(), verified_at=0))


def chunk(delta, finish=None):
    return "data: " + json.dumps({"id": "x", "object": "chat.completion.chunk", "created": 0, "model": "m",
                                  "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}) + "\n\n"


TOOL_REPLY = (chunk({"role": "assistant", "content": "Checking."})
              + chunk({"tool_calls": [{"index": 0, "id": "c1", "type": "function", "function": {
                  "name": "propose_commands",
                  "arguments": json.dumps({"items": [{"session_id": "local", "command": "df -h",
                                                      "purpose": "disk", "risk": "read_only"}]})}}]})
              + chunk({}, "tool_calls") + "data: [DONE]\n\n")


class Relay:
    def __init__(self, replies=None, private_header="tinfoil"):
        self.replies = list(replies or [(200, TOOL_REPLY)])
        self.private_header = private_header
        self.preflights, self.requests, self.keys, self.verifies = [], [], [], 0

    def verifier(self, relay, secret):
        assert relay == RELAY and len(secret) == 64
        self.verifies += 1
        return verified()

    def preflight(self, request):
        assert request.url.path.endswith("/private/tinfoil/preflight")
        self.preflights.append((json.loads(request.content), request.headers["authorization"]))
        return httpx.Response(200, json={"cacheScope": SCOPE, "upstreamModel": "glm-5-3"})

    def transport(self, key):
        self.keys.append(key)

        def handle(request):
            assert request.url.path.endswith("/private/tinfoil/v1/chat/completions")
            self.requests.append((json.loads(request.content), dict(request.headers)))
            status, body = self.replies.pop(0)
            headers = {"content-type": "text/event-stream"}
            if self.private_header:
                headers["x-nanogpt-private-mode"] = self.private_header
            return httpx.Response(status, text=body, headers=headers)
        return httpx.MockTransport(handle)

    def client(self, enclave=None):
        enclave = enclave or Enclave(RELAY, verifier=self.verifier)
        return PrivateModeClient(BASE, "sk-test", enclave, transport_factory=self.transport,
                                 plain_http=httpx.AsyncClient(transport=httpx.MockTransport(self.preflight)))


async def collect(client, model="private/glm-5-3"):
    events = []
    async for kind, val in client.stream(model, [{"role": "user", "content": "disk full?"}], [PROPOSE_TOOL]):
        events.append((kind, val))
    return events


def test_detection():
    assert offers_private_mode(BASE) and offers_private_mode("https://nano-gpt.com/api/v1")
    assert not offers_private_mode("https://api.openai.com/v1")
    assert relay_url(BASE) == RELAY
    assert detect_tier("private/glm-5-3", BASE) == "e2ee"
    assert detect_tier("TEE/glm-5.3", BASE) == "tee"


async def test_sealed_request_protocol():
    relay = Relay()
    client = relay.client()
    events = await collect(client)
    result = events[-1][1]
    assert events[0] == ("text", "Checking.")
    assert result.tool_calls[0].name == "propose_commands"
    assert json.loads(result.tool_calls[0].arguments)["items"][0]["command"] == "df -h"

    assert relay.verifies == 1 and relay.keys == [KEY]           # sealed to the attested key
    pre, auth = relay.preflights[0]
    assert pre["model"] == "private/glm-5-3" and pre["requestBodyBytes"] > 0 and auth == "Bearer sk-test"
    body, headers = relay.requests[0]
    assert body["model"] == "glm-5-3"                            # upstream name from preflight
    assert body["tools"][0]["function"]["name"] == "propose_commands" and body["tool_choice"] == "auto"
    assert body["user_cache_secret"] == client.enclave.cache_secret  # our own secret, inside the seal
    assert body["chat_template_kwargs"] == {"thinking": True}
    assert body["stream_options"] == {"include_usage": True}
    assert headers["x-nanogpt-private-cache-scope"] == hashlib.sha256(SCOPE.encode()).hexdigest()
    assert headers["x-tinfoil-enclave-url"] == "https://enclave.tinfoil.example"
    assert headers["x-nanogpt-private-model"] == "private/glm-5-3"


async def test_refuses_reply_not_marked_private():
    relay = Relay(private_header=None)
    with pytest.raises(PrivateModeError, match="didn't come back through Private Mode"):
        await collect(relay.client())


async def test_refuses_truncated_stream():
    relay = Relay(replies=[(200, chunk({"role": "assistant", "content": "partial"}))])
    with pytest.raises(PrivateModeError, match="ended before it was complete"):
        await collect(relay.client())


async def test_reattests_and_retries_once_on_missing_seal():
    relay = Relay(replies=[(400, '{"error":"missing_encrypted_body_header"}'), (200, TOOL_REPLY)])
    await collect(relay.client())
    assert relay.verifies == 2 and len(relay.requests) == 2


async def test_failed_attestation_sends_nothing():
    relay = Relay()

    def bad_verifier(relay_, secret):
        raise RuntimeError("measurement mismatch")

    with pytest.raises(PrivateModeError, match="couldn't be attested.*nothing was sent"):
        await collect(relay.client(Enclave(RELAY, verifier=bad_verifier)))
    assert relay.preflights == [] and relay.requests == []


async def test_attestation_cached_then_expires():
    relay = Relay(replies=[(200, TOOL_REPLY)] * 3)
    now = [1000.0]
    enclave = Enclave(RELAY, verifier=relay.verifier, clock=lambda: now[0])
    client = relay.client(enclave)
    await collect(client)
    await collect(client)
    assert relay.verifies == 1
    now[0] += 301
    await collect(client)
    assert relay.verifies == 2


async def test_plain_client_refuses_private_models():
    with pytest.raises(RuntimeError, match="only ever sent sealed"):
        async for _ in LLMClient(BASE, "sk").stream("private/glm-5-3", []):
            pass
    with pytest.raises(PrivateModeError):
        await collect(Relay().client(), model="TEE/glm-5.3")


async def test_real_ehbp_seals_body_and_guard_blocks_unsealed():
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    seen = {}

    class Inner(_NonEmptyBodyTransport):
        async def handle_async_request(self, request):
            from ehbp.protocol import ENCAPSULATED_KEY_HEADER
            if ENCAPSULATED_KEY_HEADER not in request.headers:
                raise PrivateModeError("refusing to send an unsealed request to the enclave")
            seen["body"] = await request.aread()
            seen["headers"] = request.headers
            return httpx.Response(500, text="stop here")

    from ehbp import AsyncEHBPTransport
    transport = AsyncEHBPTransport.from_public_key_hex(pub, inner=Inner())
    async with httpx.AsyncClient(transport=transport) as c:
        await c.post(RELAY + "/v1/chat/completions", json={"messages": [{"role": "user", "content": "SECRET-PROMPT"}]})
    assert b"SECRET-PROMPT" not in seen["body"] and len(seen["body"]) > 20
    assert "ehbp-encapsulated-key" in seen["headers"]

    # the production transport's inner layer refuses anything that isn't sealed
    guard = _NonEmptyBodyTransport()
    with pytest.raises(PrivateModeError, match="unsealed"):
        await guard.handle_async_request(httpx.Request("POST", RELAY + "/v1/chat/completions", content=b"{}"))
    assert isinstance(sealing_transport(pub), AsyncEHBPTransport)


REVIEW_REPLY = (chunk({"role": "assistant", "content": "It lists your disks.\nSUMMARY: harmless\nDATA: none\nVERDICT: proceed"})
                + chunk({}, "stop") + "data: [DONE]\n\n")


async def test_second_opinions_from_a_private_reviewer_go_sealed_after_attestation(tmp_path):
    from davibemanager import creds
    from davibemanager.config import Config, Provider
    from davibemanager.engine import Engine
    from davibemanager.hostrun import HostRequest

    relay = Relay(replies=[(200, REVIEW_REPLY)])
    cfg = Config(providers=[Provider("NanoGPT", BASE, builder_url=BASE)])
    cfg.settings.builder_provider, cfg.settings.review_model = "NanoGPT", "NanoGPT|private/glm-5-3"
    engine = Engine(cfg, lambda e: None, tmp_path / "rt", save_config=lambda c: None)
    engine.start_workspace = lambda: None
    creds.set_secret("provider", "NanoGPT", "sk-test")
    enclave = Enclave(RELAY, verifier=relay.verifier)
    engine.models.client_factory = lambda prov, model="": relay.client(enclave)
    await engine.start()
    try:
        engine.requests[1] = HostRequest.create(1, {"command": "lsblk", "purpose": "See your disks", "risk": "read_only"})
        review = await engine.review_request(1)
        assert review["level"] == "ok" and review["tier"] == "e2ee"
        assert relay.verifies == 1 and relay.requests          # attested, then sent sealed
        assert "lsblk" not in json.dumps(relay.preflights)     # the preflight carries no content
    finally:
        await engine.stop()
