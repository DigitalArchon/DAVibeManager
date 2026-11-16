"""Providers as Settings → AI providers keeps them: recognised from their addresses whatever added them (a preset, an
address typed by hand, an older config.toml), with the sealing and the key origins that follow; the window's key
questions as the server keeps the answers (key_declined, key_over_http); the presets tables the window builds its
buttons and its model choices from; and model settings that name their provider. The window's side is in
tests/js/providers.test.cjs."""

import httpx
import pytest

from davibemanager import config, creds
from davibemanager.config import Config, Provider
from davibemanager.models import Models, UserError, key_problem_for, sealing_problem

NANO = config.NANOGPT_BASE_URL


def _models(cfg):
    return Models(cfg, save_config=lambda c: None, emit=lambda *a, **k: None, log=lambda *a, **k: None)


# --- recognised from the address -------------------------------------------------------------------------------

@pytest.mark.parametrize(("base_url", "builder_url", "chat_api", "service"), [
    (NANO, NANO, "auto", "nanogpt"),
    ("", "https://api.anthropic.com", "auto", "anthropic"),
    (config.TINFOIL_BASE_URL, "", "auto", "tinfoil"),
    (config.TINFOIL_BASE_URL, "", "openai", "tinfoil"),            # when in doubt, sealed: the host says so
    ("https://inference.tinfoil.sh./v1", "", "openai", "tinfoil"),   # a trailing dot is the same machine
    ("https://router.example/v1", "", "tinfoil", "tinfoil"),         # the field says so
    (config.CHUTES_BASE_URL, config.CHUTES_ANTHROPIC_URL, "auto", "chutes"),
    ("", config.CHUTES_ANTHROPIC_URL, "auto", "chutes"),
    ("https://llm.example/v1", "", "auto", ""),
    ("http://localhost:11434/v1", "", "openai", ""),
])
def test_a_provider_is_recognised_from_its_addresses(base_url, builder_url, chat_api, service):
    assert config.service_of(Provider("X", base_url, builder_url=builder_url, chat_api=chat_api)) == service


def test_which_models_must_be_sealed_follows_the_address_not_the_button():
    tinfoil = Provider("Typed by hand", config.TINFOIL_BASE_URL, chat_api="openai")
    chutes = Provider("Chutes", config.CHUTES_BASE_URL, builder_url=config.CHUTES_ANTHROPIC_URL)
    nano = Provider("NanoGPT", NANO, builder_url=NANO)
    assert config.model_sealing(tinfoil, "glm-5-3") == config.model_sealing(tinfoil, "anything") == "tinfoil"
    assert config.chat_api_of(tinfoil) == "tinfoil"
    for tee in ("moonshotai/Kimi-K3-TEE", "Qwen/Qwen3-32B-TEE:THINKING", " zai-org/GLM-5.3-tee "):
        assert config.model_sealing(chutes, tee) == "chutes", tee
    assert config.model_sealing(chutes, "deepseek-ai/DeepSeek-V4") == ""            # Chutes' ordinary models: plain
    assert config.model_sealing(Provider("Elsewhere", "https://llm.example/v1"), "x/Model-TEE") == ""
    assert config.model_sealing(nano, "private/glm-5-3") == config.model_sealing(nano, " Private/x") == "nanogpt-private"
    assert config.model_sealing(nano, "TEE/glm-5.3") == ""                          # attested, not sealed


def test_an_older_config_with_tinfoils_address_is_sealed_and_a_protocol_without_a_client_is_read_from_the_address(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(f'[[providers]]\nname = "T"\nbase_url = "{config.TINFOIL_BASE_URL}"\nchat_api = "chutes-e2ee"\n')
    prov = config.load(path).provider("T")
    assert prov.chat_api == "auto" and prov.sealed_service() == "tinfoil" and prov.key_declined == []


def test_nothing_that_must_be_sealed_goes_through_a_plain_client():
    """No client seals Tinfoil's or Chutes' TEE models yet: they are refused in words, before anything is sent, for the
    reviewer, the vision helper and the assistant alike. Chutes' other models go as any provider's."""
    cfg = Config(providers=[Provider("Tinfoil", config.TINFOIL_BASE_URL, chat_api="openai", key_for=[config.TINFOIL_KEY_ORIGIN]),
                            Provider("Chutes", config.CHUTES_BASE_URL, builder_url=config.CHUTES_ANTHROPIC_URL,
                                     key_for=["https://llm.chutes.ai:443"])])
    m = _models(cfg)
    creds.set_secret("provider", "Tinfoil", "tk-test-123")
    creds.set_secret("provider", "Chutes", "cpk-test-123")
    with pytest.raises(UserError, match="Tinfoil's end-to-end encrypted API.*nothing is sent"):
        m.client(cfg.provider("Tinfoil"), "glm-5-3")
    with pytest.raises(UserError, match="one of Chutes' TEE models.*nothing is sent"):
        m.client(cfg.provider("Chutes"), "moonshotai/Kimi-K3-TEE")
    assert m.client(cfg.provider("Chutes"), "deepseek-ai/DeepSeek-V4") is not None
    cfg.settings.builder_provider, cfg.settings.builder_model = "Chutes", "moonshotai/Kimi-K3-TEE"
    with pytest.raises(UserError, match="Chutes' TEE models"):
        m.builder_target()
    cfg.settings.builder_model, cfg.settings.builder_small_model = "deepseek-ai/DeepSeek-V4", "zai-org/GLM-5.3-TEE"
    with pytest.raises(UserError, match="GLM-5.3-TEE is one of Chutes' TEE models"):
        m.builder_target()                                   # the quick tasks' model too
    assert sealing_problem(cfg.provider("Chutes"), "deepseek-ai/DeepSeek-V4") is None


async def test_a_chutes_tee_model_isnt_attested_as_nanogpts_tee_models_are():
    """Its name reads as TEE (detect_tier), but NanoGPT's TEE attestation isn't Chutes': the guard every request to a
    model takes (the reviewer's, the vision helper's, the gateway's) refuses it before anything is asked of anyone."""
    cfg = Config(providers=[Provider("Chutes", config.CHUTES_BASE_URL, key_for=["https://llm.chutes.ai:443"])])
    m = _models(cfg)
    asked = []
    m.tee_factory = lambda *a: asked.append(a)
    creds.set_secret("provider", "Chutes", "cpk-test-123")
    with pytest.raises(UserError, match="one of Chutes' TEE models"):
        await m.tee_guard(cfg.provider("Chutes"), "moonshotai/Kimi-K3-TEE")
    assert asked == [] and await m.tee_guard(cfg.provider("Chutes"), "deepseek-ai/DeepSeek-V4") is None


# --- key origins --------------------------------------------------------------------------------------------------

def test_a_chutes_key_goes_to_chutes_own_hosts_and_nowhere_else():
    """The one stated exception to "a key goes only to the origin it was entered for": Chutes takes one key on its
    three hosts, so a key entered for one reaches the others, over https; never another host."""
    chutes = Provider("Chutes", config.CHUTES_BASE_URL, builder_url=config.CHUTES_ANTHROPIC_URL,
                      key_for=["https://llm.chutes.ai:443"])
    assert key_problem_for(chutes) is None
    assert config.key_reaches(["https://claude.chutes.ai:443"], config.CHUTES_E2EE_ORIGIN)
    assert not config.key_reaches(["https://llm.chutes.ai:443"], "https://evil.example:443")
    assert not config.key_reaches(["https://llm.chutes.ai:443"], "http://llm.chutes.ai:80")        # never plain http
    assert not config.key_reaches(["https://llm.example:443"], "https://llm.chutes.ai:443")       # nor another's key
    chutes.builder_url = "https://evil.example"
    assert "isn't sent there" in (key_problem_for(chutes) or "")


def test_a_tinfoil_key_goes_to_tinfoils_own_api_alone():
    prov = Provider("Tinfoil", "https://router.tinfoil.sh/v1", key_for=["https://router.tinfoil.sh:443"])
    assert "goes only to Tinfoil's own API, https://inference.tinfoil.sh/v1" in (key_problem_for(prov) or "")
    prov.base_url, prov.key_for = config.TINFOIL_BASE_URL, [config.TINFOIL_KEY_ORIGIN]
    assert key_problem_for(prov) is None


# --- saving: the window's questions, as the server keeps the answers ---------------------------------------------

def test_a_no_to_using_the_saved_key_at_a_new_address_is_kept_and_a_yes_or_a_new_key_clears_it():
    cfg = Config()
    m = _models(cfg)
    m.save_provider({"name": "Mine", "base_url": "https://llm.example/v1"}, "sk-live-1", is_new=True)
    m.save_provider({"name": "Mine", "base_url": "https://llm2.example/v1", "use_saved_key": False}, original_name="Mine")
    prov = cfg.provider("Mine")
    assert prov.key_for == ["https://llm.example:443"] and prov.key_declined == ["https://llm2.example:443"]
    with pytest.raises(UserError, match="isn't sent there"):
        m.key(prov)
    m.save_provider({"name": "Mine", "base_url": "https://llm2.example/v1", "default_model": "x"}, original_name="Mine")
    assert cfg.provider("Mine").key_declined == ["https://llm2.example:443"]        # no question: the No stands
    m.save_provider({"name": "Mine", "base_url": "https://llm2.example/v1", "use_saved_key": True}, original_name="Mine")
    prov = cfg.provider("Mine")
    assert prov.key_declined == [] and m.key(prov) == "sk-live-1"                  # asked again, and Yes
    m.save_provider({"name": "Mine", "base_url": "https://llm3.example/v1", "use_saved_key": False}, original_name="Mine")
    m.save_provider({"name": "Mine", "base_url": "https://llm3.example/v1"}, "sk-live-3", original_name="Mine")
    assert cfg.provider("Mine").key_declined == [] and m.key(cfg.provider("Mine")) == "sk-live-3"
    m.save_provider({"name": "Mine", "base_url": "https://llm4.example/v1", "use_saved_key": False}, original_name="Mine")
    m.save_provider({"name": "Mine", "base_url": "https://llm3.example/v1"}, original_name="Mine")    # put back
    assert cfg.provider("Mine").key_declined == [] and m.key(cfg.provider("Mine")) == "sk-live-3"


def test_a_provider_added_never_takes_another_ones_place_and_a_name_with_a_bar_is_refused():
    cfg = Config()
    m = _models(cfg)
    m.save_provider({"name": "NanoGPT", "base_url": NANO}, "sk-live-1", is_new=True)
    with pytest.raises(UserError, match="already a provider called NanoGPT"):
        m.save_provider({"name": "NanoGPT", "base_url": "https://evil.example/v1"}, "sk-other", is_new=True)
    m.save_provider({"name": "Other", "base_url": "https://llm.example/v1"}, is_new=True)
    with pytest.raises(UserError, match="already a provider called NanoGPT"):
        m.save_provider({"name": "NanoGPT", "base_url": "https://llm.example/v1"}, original_name="Other")
    assert [(p.name, p.base_url) for p in cfg.providers] == [("NanoGPT", NANO), ("Other", "https://llm.example/v1")]
    assert creds.get_secret("provider", "NanoGPT") == "sk-live-1"
    with pytest.raises(UserError, match=r"can't contain \|"):
        m.save_provider({"name": "A|B", "base_url": "https://llm.example/v1"}, is_new=True)
    with pytest.raises(UserError, match="speaks one of"):
        m.save_provider({"name": "C", "base_url": "https://llm.example/v1", "chat_api": "chutes-e2ee"}, is_new=True)


def test_an_edit_keeps_what_the_form_doesnt_show():
    cfg = Config(providers=[Provider("Local", "http://localhost:11434/v1", vision_overrides={"llava": "yes"},
                                     context_overrides={"llama3": 8192}, tier_overrides={"x": "standard"}, key_for=[])])
    _models(cfg).save_provider({"name": "Local", "base_url": "http://localhost:11434/v1", "default_model": "llama3"},
                               original_name="Local")
    prov = cfg.provider("Local")
    assert (prov.vision_overrides, prov.context_overrides, prov.tier_overrides) == ({"llava": "yes"}, {"llama3": 8192},
                                                                                     {"x": "standard"})


# --- the presets tables ---------------------------------------------------------------------------------------------

def test_every_provider_preset_saves_a_provider_recognised_as_itself():
    """The window's Add buttons are built from config.PROVIDER_PRESETS: each, saved with a key as the window saves it,
    gives a provider the address recognition calls what the button said; the next entries (Tinfoil, Chutes) are
    held to the same test."""
    ids = [p["id"] for p in config.PROVIDER_PRESETS]
    assert ids[:2] == ["nanogpt", "anthropic"] and {"openai", "anthropic-compatible"} <= set(ids)
    assert len(set(ids)) == len(ids)
    for preset in config.PROVIDER_PRESETS:
        assert preset["label"].startswith("Add ") and preset["note"] and preset["chat_api"] in config.CHAT_APIS
        assert preset["builder_auth"] in ("bearer", "x-api-key")
        if not preset["name"]:
            continue                                 # "other": the user types the name and the addresses
        cfg = Config()
        _models(cfg).save_provider({k: preset[k] for k in ("name", "base_url", "builder_url", "builder_auth", "chat_api")},
                                   "sk-live-12345678", is_new=True)
        prov = cfg.provider(preset["name"])
        assert prov.service() == preset["id"] and key_problem_for(prov) is None
        assert cfg.settings.builder_provider == preset["name"]        # the first one is the assistant's
    anthropic = next(p for p in config.PROVIDER_PRESETS if p["id"] == "anthropic")
    assert (anthropic["base_url"], anthropic["builder_url"], anthropic["builder_auth"]) == ("", "https://api.anthropic.com", "x-api-key")


def test_every_model_preset_is_for_a_service_and_its_choices_would_be_saved():
    services = {p["id"] for p in config.PROVIDER_PRESETS} | {"tinfoil", "chutes"}
    assert len({p["id"] for p in config.MODEL_PRESETS}) == len(config.MODEL_PRESETS)
    for preset in config.MODEL_PRESETS:
        assert preset["service"] in services and preset["label"] and preset["note"], preset
        assert set(preset["settings"]) <= {"builder_model", "builder_small_model", "builder_vision_model"}
        assert preset["settings"]["builder_model"]
        if preset.get("sealed"):
            assert all(not m or m.startswith("private/") for m in preset["settings"].values())
            assert preset["review_model"].startswith("private/")
    nano = {p["id"]: p["settings"]["builder_model"] for p in config.MODEL_PRESETS if p["service"] == "nanogpt"}
    assert nano == {"glm": config.DEFAULT_MODEL, "private": config.PRIVATE_MODEL, "claude": config.CLAUDE_MODEL}


def test_chutes_address_brings_its_anthropic_proxy_for_the_assistant():
    cfg = Config()
    _models(cfg).save_provider({"name": "Chutes", "base_url": config.CHUTES_BASE_URL}, "cpk-test-123", is_new=True)
    prov = cfg.provider("Chutes")
    assert (prov.builder_url, prov.builder_auth) == (config.CHUTES_ANTHROPIC_URL, "bearer")
    assert prov.key_for == ["https://claude.chutes.ai:443", "https://llm.chutes.ai:443"]


async def test_the_window_gets_the_presets_and_each_providers_recognition(env):
    engine, _, _ = env
    engine.cfg.providers.append(Provider("Typed", config.TINFOIL_BASE_URL, chat_api="openai", key_for=[]))
    creds.set_secret("provider", "Typed", "tk-test-123")
    state = engine.snapshot()
    assert [p["id"] for p in state["presets"]["providers"]] == [p["id"] for p in config.PROVIDER_PRESETS]
    assert state["presets"]["models"] == list(config.MODEL_PRESETS)
    assert "https://claude.chutes.ai:443" in state["presets"]["chutes_key_origins"]
    typed = next(p for p in state["config"]["providers"] if p["name"] == "Typed")
    assert (typed["service"], typed["speaks"], typed["has_key"]) == ("tinfoil", "tinfoil", True)
    assert "isn't sent" in typed["key_held"]
    fake = next(p for p in state["config"]["providers"] if p["name"] == "Fake")
    assert (fake["service"], fake["speaks"], fake["key_held"]) == ("", "openai", "")


# --- model settings that name their provider -----------------------------------------------------------------------

def test_a_model_setting_names_its_provider_or_means_the_assistants():
    assert config.model_ref("NanoGPT|z-ai/glm-5.3-flash") == ("NanoGPT", "z-ai/glm-5.3-flash")
    assert config.model_ref(" z-ai/glm-5.3-flash ") == ("", "z-ai/glm-5.3-flash")
    assert config.model_ref("") == ("", "")


async def test_the_vision_helper_can_be_on_another_provider(env):
    engine, _, _ = env
    engine.cfg.providers.append(Provider("Seer", "https://seer.example/v1", key_for=["https://seer.example:443"]))
    engine.save_settings({"builder_vision_model": "Seer|qwen-vl"})
    assert engine.cfg.settings.builder_vision_model == "Seer|qwen-vl"
    prov, model = engine.models.vision_target()
    assert (prov.name, model) == ("Seer", "qwen-vl")
    up = engine._builder_upstream()
    assert up.vision_model == "qwen-vl" and up.describe is not None
    with pytest.raises(UserError, match="Nobody isn't one of your providers"):
        engine.save_settings({"builder_vision_model": "Nobody|x"})
    with pytest.raises(UserError, match="on its own provider"):
        engine.save_settings({"builder_small_model": "Seer|qwen"})
    engine.cfg.settings.builder_vision_model = "fake-vision"                 # bare: the assistant's provider
    assert engine.models.vision_target()[0].name == "Fake"


async def test_a_private_assistant_refuses_a_plain_vision_helper_on_any_provider(env):
    engine, _, _ = env
    engine.cfg.providers.append(Provider("Seer", "https://seer.example/v1", key_for=[]))
    engine.cfg.settings.review_model = "Fake|private/glm-5-3"
    with pytest.raises(UserError, match="must be private too"):
        engine.save_settings({"builder_model": "private/glm-5-3", "builder_small_model": "",
                              "builder_vision_model": "Seer|qwen-vl"})
    engine.save_settings({"builder_model": "private/glm-5-3", "builder_small_model": "",
                          "builder_vision_model": "Fake|private/deepseek-v4-1-flash"})


async def test_the_assistants_provider_is_one_of_the_users_own(env):
    engine, _, _ = env
    with pytest.raises(UserError, match="isn't one of your providers"):
        engine.save_settings({"builder_provider": "Elsewhere"})
    engine.cfg.providers.append(Provider("Chat only", "https://llm.example/v1", key_for=["https://llm.example:443"]))
    creds.set_secret("provider", "Chat only", "sk-live-9")
    engine.save_settings({"builder_provider": "Chat only", "builder_model": "llama-4", "builder_small_model": ""})
    prov, model, small, _ = engine.models.builder_target()          # no Anthropic address: translated (gateway.py)
    assert (prov.name, model, small) == ("Chat only", "llama-4", "llama-4")
    assert engine._builder_upstream().base_url == ""
    engine.cfg.settings.builder_model = "anthropic/claude-opus-5.5"
    with pytest.raises(UserError, match="Claude models need Chat only's address for Anthropic's Messages API"):
        engine.models.builder_target()


async def test_the_gateway_passes_nothing_on_for_a_provider_with_no_anthropic_address(tmp_path):
    from davibemanager.gateway import Gateway, Upstream

    sent = []
    g = Gateway(tmp_path / "gw", lambda: Upstream("", "bearer", lambda: "sk-live-1", ("anthropic/claude-opus-5.5",),
                                                  provider="Chat only"),
                http=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200))))
    await g.start()
    try:
        async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(g.model_socket)), base_url="http://gw") as c:
            r = await c.post("/v1/messages", headers={"authorization": f"Bearer {g.token}"}, json={
                "model": "anthropic/claude-opus-5.5", "messages": [{"role": "user", "content": "hi"}]})
    finally:
        await g.stop()
    assert r.status_code == 403 and "Chat only has no address for Anthropic's Messages API" in r.text and sent == []


def test_the_first_provider_of_any_kind_is_the_assistants_and_so_is_the_next_when_it_goes():
    cfg = Config()
    m = _models(cfg)
    m.save_provider({"name": "Chat only", "base_url": "https://llm.example/v1"}, "sk-live-1", is_new=True)
    assert cfg.settings.builder_provider == "Chat only"
    m.save_provider({"name": "Anthropic", "builder_url": "https://api.anthropic.com"}, "sk-ant-test-1", is_new=True)
    m.delete_provider("Chat only")
    assert cfg.settings.builder_provider == "Anthropic"
