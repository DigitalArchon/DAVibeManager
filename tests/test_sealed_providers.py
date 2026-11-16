"""Tinfoil and Chutes wired in (llm/tinfoil_direct.py, llm/chutes_client.py, DA Toolkit's): their public model lists
with each model's privacy and prices, the assistant's helpers and reviewer held to its privacy level, the gateway
never passing a sealed model on as it is, Chutes' proxy given its key as a bearer token, and each attestation logged.
The clients themselves are DA Toolkit's tests (test_tinfoil_direct, test_chutes_*); the routing is test_providers'."""

import json
from pathlib import Path

import httpx
import pytest

from davibemanager import config, creds
from davibemanager.config import Config, Provider
from davibemanager.llm import privacy
from davibemanager.models import Models, OpeningChutesClient, OpeningTinfoilClient, UserError

DATA = Path(__file__).parent / "data"
TINFOIL = Provider("Tinfoil", config.TINFOIL_BASE_URL, chat_api="tinfoil", key_for=[config.TINFOIL_KEY_ORIGIN])
CHUTES = Provider("Chutes", config.CHUTES_BASE_URL, builder_url=config.CHUTES_ANTHROPIC_URL,
                  key_for=["https://claude.chutes.ai:443", "https://llm.chutes.ai:443"])


def listings(request: httpx.Request) -> httpx.Response:
    """Tinfoil's and Chutes' public lists, as recorded (DA Toolkit's tests/data); no key may go with them."""
    assert "authorization" not in request.headers
    if request.url.host == "inference.tinfoil.sh":
        return httpx.Response(200, content=(DATA / "tinfoil" / "models.json").read_bytes())
    if request.url.host == "llm.chutes.ai":
        return httpx.Response(200, content=(DATA / "chutes_models.json").read_bytes())
    return httpx.Response(404)


def _models(cfg):
    events = []
    m = Models(cfg, save_config=lambda c: None, emit=lambda *a, **k: events.append((a, k)),
               log=lambda *a, **k: events.append((a, k)))
    m.listing_http = httpx.AsyncClient(transport=httpx.MockTransport(listings))
    return m, events


@pytest.fixture
def sealed_env(env):
    engine, fake, events = env
    for prov in (TINFOIL, CHUTES):
        engine.cfg.providers.append(Provider(**{**prov.__dict__}))
        creds.set_secret("provider", prov.name, "sk-test-12345678")
    return engine


async def test_tinfoils_and_chutes_lists_are_read_without_the_key_each_model_with_its_privacy_and_prices():
    cfg = Config(providers=[Provider(**TINFOIL.__dict__), Provider(**CHUTES.__dict__)])
    m, _ = _models(cfg)
    tinfoil = {x["id"]: x for x in await m.list_models("Tinfoil")}
    assert tinfoil and all(x["privacy"]["level"] == "highest" and x["tier"] == "e2ee" for x in tinfoil.values())
    assert all(x["privacy"]["service"] == "tinfoil" for x in tinfoil.values())
    chutes = {x["id"]: x for x in await m.list_models("Chutes")}
    tee = [k for k in chutes if privacy.is_tee_id(k)]
    plain = [k for k in chutes if not privacy.is_tee_id(k)]
    assert tee and plain
    assert all(chutes[k]["privacy"]["level"] == "partial" and chutes[k]["tier"] == "e2ee" for k in tee)
    assert all(chutes[k]["privacy"]["level"] == "none" and "Chutes reads" in chutes[k]["privacy"]["note"] for k in plain)
    # prices in this app's shape, so a chat's cost counts them (Engine.spend)
    priced = [c for c in m.known_caps(cfg.provider("Tinfoil")).values() if c["pricing"]]
    assert priced and set(priced[0]["pricing"]) == {"input", "output", "cache_read", "cache_write"}
    assert m.known_caps(cfg.provider("Chutes"))


async def test_the_assistants_helpers_and_reviewer_are_held_to_its_level(sealed_env):
    """A chat moves only to a model at its own level or higher, on any service (llm/privacy.py): a private/ assistant's
    pictures and second opinions go to Tinfoil (highest) but never to Chutes' -TEE models (partial); a Chutes -TEE
    assistant's to a TEE/ or sealed model, never to an ordinary one."""
    engine = sealed_env
    s = engine.cfg.settings
    s.builder_model, s.builder_small_model, s.builder_vision_model = "private/glm-5-3", "", ""
    s.review_model = "Fake|private/glm-5-3"
    with pytest.raises(UserError, match="must be private too, at that level or higher"):
        engine.save_settings({"builder_vision_model": "Chutes|moonshotai/Kimi-K3-TEE"})
    with pytest.raises(UserError, match="reviewer must be private too"):
        engine.save_settings({"review_model": "Chutes|moonshotai/Kimi-K3-TEE"})
    engine.save_settings({"builder_vision_model": "Tinfoil|glm-5-3", "review_model": "Tinfoil|glm-5-3"})
    engine.save_settings({"builder_provider": "Chutes", "builder_model": "moonshotai/Kimi-K3-TEE",
                          "builder_vision_model": "", "review_model": "Fake|TEE/glm-5.3"})
    with pytest.raises(UserError, match="partial privacy"):
        engine.save_settings({"builder_small_model": "zai-org/GLM-5.3"})
    with pytest.raises(UserError, match="reviewer must be private too"):
        engine.save_settings({"review_model": "Fake|reviewer-model"})
    engine.save_settings({"builder_small_model": "zai-org/GLM-5.2-TEE"})
    assert engine.assistant_status()["privacy"]["level"] == "partial"


async def test_a_partial_chat_asks_for_a_reviewer_at_its_level(sealed_env):
    engine = sealed_env
    s = engine.cfg.settings
    s.builder_provider, s.builder_model, s.review_model = "Chutes", "moonshotai/Kimi-K3-TEE", "Fake|reviewer-model"
    with pytest.raises(UserError, match=r"This chat is private \(partial privacy\), and the reviewer \(reviewer-model\)"):
        engine._private_review_check()
    s.review_model = "Tinfoil|glm-5-3"
    engine._private_review_check()


async def test_the_assistants_sealed_models_are_translated_and_sealed_by_their_own_client(sealed_env):
    engine = sealed_env
    engine.models.client_factory = None                     # the app's own routing, not the test fake's
    s = engine.cfg.settings
    s.builder_provider, s.builder_model, s.builder_small_model, s.builder_vision_model = "Tinfoil", "glm-5-3", "", ""
    s.review_model = "Tinfoil|glm-5-3"
    up = engine._builder_upstream()
    assert up.base_url == "" and up.privacy_of("glm-5-3").service == "tinfoil"
    assert isinstance(up.chat("glm-5-3"), OpeningTinfoilClient)
    s.builder_provider, s.builder_model, s.review_model = "Chutes", "moonshotai/Kimi-K3-TEE", "Chutes|moonshotai/Kimi-K3-TEE"
    up = engine._builder_upstream()
    client = up.chat("moonshotai/Kimi-K3-TEE")
    assert isinstance(client, OpeningChutesClient) and client.sealed("moonshotai/Kimi-K3-TEE")
    assert engine.models.builder_target()[3] == "e2ee"


async def test_the_sealed_clients_say_when_their_reply_has_begun(monkeypatch):
    """The gateway answers Claude Code once a reply has begun ("open"), as every client it reads says it."""
    seen = []

    async def stream(self, model, messages, tools=None, params=None, *, opened=False):
        seen.append(opened)
        yield "open", None

    from davibemanager.llm import chutes_client, tinfoil_direct
    monkeypatch.setattr(tinfoil_direct.TinfoilDirectClient, "stream", stream)
    monkeypatch.setattr(chutes_client.ChutesE2EEClient, "stream", stream)
    cfg = Config(providers=[Provider(**TINFOIL.__dict__), Provider(**CHUTES.__dict__)])
    m, _ = _models(cfg)
    for name in ("Tinfoil", "Chutes"):
        creds.set_secret("provider", name, "sk-test-12345678")
    for prov, model in (("Tinfoil", "glm-5-3"), ("Chutes", "moonshotai/Kimi-K3-TEE")):
        assert [e async for e in m.client(cfg.provider(prov), model).stream(model, [])] == [("open", None)]
    assert seen == [True, True]


async def test_chutes_ordinary_models_stream_through_the_apps_own_client_as_it_is_called(monkeypatch):
    """This app's LLMClient takes no `opened` (it always says "open"); Chutes' ordinary models go to it as it is
    called (seen live, Nov 16 2026: they failed on the argument)."""
    from davibemanager.llm.client import LLMClient
    calls = []

    async def plain(self, model, messages, tools=None, params=None):
        calls.append(model)
        yield "open", None
    monkeypatch.setattr(LLMClient, "stream", plain)
    cfg = Config(providers=[Provider(**CHUTES.__dict__)])
    m, _ = _models(cfg)
    creds.set_secret("provider", "Chutes", "sk-test-12345678")
    client = m.client(cfg.provider("Chutes"), "zai-org/GLM-5.3")
    assert [e async for e in client.stream("zai-org/GLM-5.3", [])] == [("open", None)] and calls == ["zai-org/GLM-5.3"]


def _gateway(tmp_path, up, sent):
    from davibemanager.gateway import Gateway
    return Gateway(tmp_path / "gw", lambda: up, http=httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: sent.append(r) or httpx.Response(200, json={"type": "message", "content": []}))))


async def _post(g, model):
    async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(g.model_socket)), base_url="http://gw") as c:
        return await c.post("/v1/messages", headers={"authorization": f"Bearer {g.token}"},
                            json={"model": model, "messages": [{"role": "user", "content": "hi"}]})


async def test_the_gateway_never_passes_a_sealed_model_on_as_it_is(tmp_path):
    """A model sealed by its own client is translated through it, whatever its id says; with no chat client for it,
    refused, never forwarded to the provider's Anthropic address in the clear."""
    from davibemanager.gateway import Upstream
    chutes = Provider(**CHUTES.__dict__)
    sent = []
    up = Upstream(config.CHUTES_ANTHROPIC_URL, "bearer", lambda: "sk-test-12345678", ("claude-x-TEE",),
                  provider="Chutes", privacy=lambda m: config.privacy_of(chutes, m))
    g = _gateway(tmp_path, up, sent)
    await g.start()
    try:
        r = await _post(g, "claude-x-TEE")
    finally:
        await g.stop()
    assert r.status_code == 403 and "end-to-end encrypted" in r.text and sent == []


async def test_chutes_proxy_gets_its_key_as_a_bearer_token(tmp_path):
    from davibemanager.gateway import Upstream
    sent = []
    up = Upstream(config.CHUTES_ANTHROPIC_URL, "x-api-key", lambda: "sk-test-12345678", ("claude-opus-5-5",),
                  provider="Chutes")
    g = _gateway(tmp_path, up, sent)
    await g.start()
    try:
        r = await _post(g, "claude-opus-5-5")
    finally:
        await g.stop()
    assert r.status_code == 200 and sent[0].headers["authorization"] == "Bearer sk-test-12345678"
    assert "x-api-key" not in sent[0].headers


def test_each_sealed_attestation_is_logged_and_chutes_partial_one_said_once():
    cfg = Config(providers=[Provider(**CHUTES.__dict__)])
    m, events = _models(cfg)

    class Att:
        service = "chutes"
        costs = ["the workload isn't measured"]

        def to_dict(self):
            return {"service": "chutes", "level": "partial", "enclave": "instance"}
    m._sealed_attested(cfg.provider("Chutes"), Att())
    m._sealed_attested(cfg.provider("Chutes"), Att())
    logged = [k for a, k in events if a == ("sealed_attested",)]
    toasts = [k for a, k in events if a == ("toast",)]
    assert len(logged) == 2 and logged[0]["provider"] == "Chutes" and logged[0]["level"] == "partial"
    assert len(toasts) == 1 and "partially (preliminary)" in toasts[0]["text"] and json.dumps(toasts[0]["detail"])


# --- every model given what a chat holds is at its level or higher (Toolkit's review, Nov 16 2026) -----------------

TINFOIL_CHAT = {"kind": "sealed", "service": "tinfoil", "origin": "https://inference.tinfoil.sh:443"}


def _on_tinfoil(engine):
    s = engine.cfg.settings
    s.builder_provider, s.builder_model, s.builder_small_model, s.builder_vision_model = "Tinfoil", "glm-5-3", "", ""
    s.review_model = "Tinfoil|glm-5-3"


async def test_the_quick_tasks_model_is_held_to_the_assistants_level(sealed_env, tmp_path):
    """In Settings, named with both levels; and in the gateway, where Claude Code's quick tasks and its compaction
    (summaries of the chat) go: a model less private than the assistant's is never sent the chat."""
    from davibemanager.gateway import Upstream
    engine = sealed_env
    s = engine.cfg.settings
    s.builder_model, s.review_model = "private/glm-5-3", "Fake|private/glm-5-3"
    with pytest.raises(UserError, match=r"The model for quick tasks, z-ai/glm-5.3-flash, has no privacy, and the "
                                        r"assistant's model, private/glm-5-3, has the highest privacy"):
        engine.save_settings({"builder_small_model": "z-ai/glm-5.3-flash"})
    tinfoil = engine.cfg.provider("Tinfoil")
    sent = []
    up = Upstream("", "bearer", lambda: "sk-test-12345678", ("glm-5-3", "plain-small"), provider="Tinfoil",
                  privacy=lambda m: config.privacy_of(tinfoil, m) if m == "glm-5-3" else privacy.NONE)
    g = _gateway(tmp_path, up, sent)
    await g.start()
    try:
        r = await _post(g, "plain-small")
    finally:
        await g.stop()
    assert r.status_code == 403 and "plain-small (no privacy)" in r.text and "the highest privacy" in r.text and sent == []


async def test_the_picture_helper_is_held_to_the_assistants_and_the_chats_level(sealed_env):
    engine = sealed_env
    _on_tinfoil(engine)
    with pytest.raises(UserError, match=r"The model that describes pictures, reviewer-model, has no privacy, and the "
                                        r"assistant's model, glm-5-3, has the highest privacy"):
        engine.save_settings({"builder_vision_model": "Fake|reviewer-model"})
    with pytest.raises(UserError, match="describes pictures, moonshotai/Kimi-K3-TEE, has partial privacy"):
        engine.save_settings({"builder_vision_model": "Chutes|moonshotai/Kimi-K3-TEE"})
    # a chat that ran on Tinfoil, the assistant since set to a plain model (set by hand): its pictures stay at its level
    engine.conv.privacy = TINFOIL_CHAT
    s = engine.cfg.settings
    s.builder_provider, s.builder_model, s.builder_vision_model, s.review_model = "Fake", "plain-model", "fake-vision", ""
    assert engine._builder_upstream().describe is None
    with pytest.raises(UserError, match=r"fake-vision, isn't private enough: it has no privacy, and this chat has the "
                                        r"highest privacy"):
        await engine._describe_image("data:image/png;base64,AAAA", "")


async def test_the_reviewer_is_held_to_the_assistants_and_the_chats_level(sealed_env):
    engine = sealed_env
    _on_tinfoil(engine)
    with pytest.raises(UserError, match=r"The reviewer, reviewer-model, has no privacy, and the assistant's model, "
                                        r"glm-5-3, has the highest privacy.*the reviewer must be private too"):
        engine.save_settings({"review_model": "Fake|reviewer-model"})
    engine.conv.privacy = TINFOIL_CHAT
    s = engine.cfg.settings
    s.builder_provider, s.builder_model, s.review_model = "Fake", "plain-model", "Fake|reviewer-model"
    with pytest.raises(UserError, match=r"This chat is private \(the highest privacy\), and the reviewer "
                                        r"\(reviewer-model\) isn't, at that level \(no privacy\)"):
        engine._private_review_check()
