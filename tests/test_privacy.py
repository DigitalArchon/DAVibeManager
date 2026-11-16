"""How private a model is, by the endpoint it goes through (llm/privacy.py; ported from SealedLore's
test_privacy, test_privacy_held and test_chutes_mixed, without their config): the three levels, the
move rule, the services' addresses recognised however they are written, the Chutes key's three
origins, and every plain client kept off a sealed host."""

from __future__ import annotations

import pytest

from davibemanager import netpolicy as netguard
from davibemanager.llm.privacy import (
    CHUTES, CHUTES_ANTHROPIC_URL, CHUTES_BASE_URL, CHUTES_E2EE_ORIGIN, CHUTES_KEY_ORIGINS, HIGHEST, NANOGPT_PRIVATE,
    NANOGPT_TEE, NONE, NOT_PRIVATE, PARTIAL, PRIVACY_LEVELS, TINFOIL, TINFOIL_BASE_URL, TINFOIL_ORIGIN, Privacy,
    anthropic_bearer, chat_api, chutes_tee, held, held_back, holds, is_anthropic, is_tee_id, is_tinfoil, key_may_go,
    key_origin, level_of, move_note, move_refusal, on_chutes, plain_refusal, privacy_at, rank, record_of,
    sealed_service, shown_origin)

NANO = "https://nano-gpt.com/api/v1"
MODEL = "Qwen/Qwen3.8-27B-TEE"
ORDINARY = "zai-org/GLM-5.3"
TEE_IDS = [MODEL, "moonshotai/Kimi-K3-TEE", "qwen/qwen3-32b-tee", " Qwen/Qwen3-32B-TEE ", "Qwen/Qwen3-32B-TEE:THINKING"]
CHUTES_HOSTS = [CHUTES_BASE_URL, CHUTES_ANTHROPIC_URL, "https://api.chutes.ai", "https://LLM.Chutes.AI./v1",
                "https://llm.chutes.dev/v1"]


def test_the_constants_are_the_services_own():
    assert TINFOIL_BASE_URL == "https://inference.tinfoil.sh/v1"
    assert netguard.origin(TINFOIL_BASE_URL) == TINFOIL_ORIGIN
    assert (CHUTES_BASE_URL, CHUTES_ANTHROPIC_URL, CHUTES_E2EE_ORIGIN) == (
        "https://llm.chutes.ai/v1", "https://claude.chutes.ai", "https://api.chutes.ai")
    assert CHUTES_KEY_ORIGINS == {netguard.origin(u) for u in (CHUTES_BASE_URL, CHUTES_ANTHROPIC_URL, CHUTES_E2EE_ORIGIN)}


@pytest.mark.parametrize("url", [TINFOIL_BASE_URL, "https://LLM.Chutes.AI/v1", "https://u:p@api.chutes.ai",
                                 "http://192.168.1.5:11434/v1", "https://[fd00::5]:8443/x", "http://localhost",
                                 "ftp://example.com", "not an address", "http://[::1"])
def test_a_key_origin_is_written_as_the_apps_own(url):
    """The form every DA app holds a saved key to (here netguard.origin), so the Chutes key's three
    origins compare with what the app keeps."""
    assert key_origin(url) == netguard.origin(url)
    assert shown_origin(key_origin(url)) == netguard.shown_origin(netguard.origin(url))


def test_nanogpts_models_read_as_they_always_did():
    assert privacy_at("private/glm-5-3", NANO) == Privacy("sealed", NANOGPT_PRIVATE)
    assert privacy_at("TEE/glm-5.3", NANO) == Privacy("tee", NANOGPT_TEE)
    assert privacy_at("z-ai/glm-5.3", NANO) == NONE
    assert privacy_at(" Private/glm-5-3", NANO).sealed, "capitals never make it less private"
    assert privacy_at("TEE/glm-5.3").kind == "tee", "with no address, by the id"


def test_every_model_on_a_sealed_endpoint_is_sealed():
    assert privacy_at("glm-5-3", TINFOIL_BASE_URL) == Privacy("sealed", TINFOIL)
    # The endpoint decides, whatever the id says.
    assert privacy_at("TEE/glm-5.3", TINFOIL_BASE_URL) == Privacy("sealed", TINFOIL)
    assert privacy_at("private/glm-5-3", TINFOIL_BASE_URL) == Privacy("sealed", TINFOIL)


@pytest.mark.parametrize("url, api", [
    (TINFOIL_BASE_URL, ""),
    ("https://router-0.tinfoil.sh/v1", ""),
    ("https://INFERENCE.tinfoil.sh./v1", ""),
    ("https://inference.tinfoil.sh", ""),            # typed without its /v1
    ("https://u:p@inference.tinfoil.sh:443/v1", ""),  # with a password and the port written out
    (TINFOIL_BASE_URL, "openai"),                    # set to plain, still Tinfoil's host
    (TINFOIL_BASE_URL, "anthropic"),
    ("https://proxy.example/v1", "tinfoil"),         # set to Tinfoil's protocol
])
def test_when_in_doubt_sealed(url, api):
    """By the endpoint's `api`, else by its host whatever `api` says: however Tinfoil's address got
    into the settings (a preset, typed, an old config)."""
    assert privacy_at("any/model", url, api) == Privacy("sealed", TINFOIL)
    assert is_tinfoil(url, api) and chat_api(url, api) == "tinfoil" and level_of(url, "any/model", api) == HIGHEST
    assert plain_refusal(url, api=api) is not None


def test_hosts_that_only_look_alike_are_not_sealed():
    for url in ("https://tinfoil.sh.example.com/v1", "https://nottinfoil.sh/v1", NANO, "not an address"):
        assert sealed_service(url) == "", url
        assert not privacy_at("any/model", url).private
        assert plain_refusal(url) is None


def test_the_hosts_are_read_as_their_protocol_from_the_address():
    assert chat_api(TINFOIL_BASE_URL) == "tinfoil"
    assert chat_api(CHUTES_BASE_URL) == "openai"
    assert chat_api(CHUTES_ANTHROPIC_URL) == "anthropic", "Chutes' Anthropic proxy"
    assert chat_api(NANO) == "openai" and chat_api("https://api.anthropic.com") == "anthropic"
    assert chat_api(CHUTES_ANTHROPIC_URL, "openai") == "openai", "an explicit choice is kept"
    assert chat_api("https://example.com/v1", "anthropic") == "anthropic"
    assert is_anthropic("https://api.anthropic.com/v1") and not is_anthropic(CHUTES_ANTHROPIC_URL)
    assert anthropic_bearer(CHUTES_ANTHROPIC_URL) and not anthropic_bearer("https://api.anthropic.com")


@pytest.mark.parametrize("model", TEE_IDS)
@pytest.mark.parametrize("url", CHUTES_HOSTS)
def test_a_tee_id_on_any_of_chutes_hosts_is_sealed_by_chutes(url, model):
    assert chutes_tee(model, url)
    assert privacy_at(model, url) == Privacy("sealed", CHUTES)
    assert privacy_at(model, url, "anthropic") == Privacy("sealed", CHUTES), "whatever it speaks"
    assert level_of(url, model) == PARTIAL
    refusal = plain_refusal(url, "the chat", model=model)
    assert refusal and "only end-to-end encrypted" in refusal and "nothing was sent" in refusal


def test_what_isnt_a_chutes_tee_model():
    assert not is_tee_id(ORDINARY) and not is_tee_id("TEE/glm-5.3") and not is_tee_id("x-TEEx")
    assert is_tee_id("a:b-TEE"), "every colon read as where a variant might begin"
    assert privacy_at(ORDINARY, CHUTES_BASE_URL) == Privacy(plain_on=CHUTES)
    assert not privacy_at(ORDINARY, CHUTES_BASE_URL).private
    assert plain_refusal(CHUTES_BASE_URL, model=ORDINARY) is None, "Chutes' ordinary models go as any provider's"
    for url in ("https://chutes.ai.example", "https://notchutes.ai/v1", NANO):
        assert not on_chutes(url) and not chutes_tee(MODEL, url), url
        assert privacy_at(MODEL, url) == NONE, "another host's -TEE id is nothing of Chutes'"


def test_each_model_has_its_level():
    assert level_of(NANO, "private/glm-5-3") == level_of(TINFOIL_BASE_URL, "glm-5-3") == HIGHEST
    assert level_of(NANO, "TEE/glm-5.3") == level_of(CHUTES_BASE_URL, MODEL) == PARTIAL
    assert level_of(CHUTES_BASE_URL, ORDINARY) == level_of(NANO, "z-ai/glm-5.3") == NOT_PRIVATE == "none"
    assert rank(Privacy("sealed", TINFOIL)) == rank(Privacy("sealed", NANOGPT_PRIVATE)) == 2
    assert rank(Privacy("sealed", CHUTES)) == rank(Privacy("tee", NANOGPT_TEE)) == 1
    assert rank(Privacy(plain_on=CHUTES)) == rank(NONE) == 0
    assert Privacy("sealed", "a-future-service").level == HIGHEST, "unknown: kept highest"
    assert "three levels" in PRIVACY_LEVELS and "DA Vibe Manager" in PRIVACY_LEVELS


def test_each_level_says_what_it_is_in_its_words():
    chutes = Privacy("sealed", CHUTES).to_dict()
    assert chutes["level"] == PARTIAL and chutes["label"] == "🔐 End-to-end encrypted (Chutes, partial)"
    assert chutes["note"].startswith("Partial privacy.") and "closed binary" in chutes["note"]
    assert "aegis" in chutes["note"] and "admitted by Chutes' signature" in chutes["note"]
    assert Privacy("sealed", TINFOIL).to_dict()["note"].startswith("Highest privacy.")
    assert Privacy("tee", NANOGPT_TEE).to_dict()["label"] == "TEE"
    assert Privacy(plain_on=CHUTES).to_dict()["note"].startswith("Not private.")
    assert NONE.to_dict() == {"kind": "", "service": "", "level": "none", "level_words": "Not private",
                              "label": "", "note": ""}


def test_what_holds_by_level():
    tee, chutes, tinfoil = Privacy("tee", NANOGPT_TEE), Privacy("sealed", CHUTES), Privacy("sealed", TINFOIL)
    assert holds(tinfoil, tinfoil) and holds(NONE, NONE)
    assert holds(tee, chutes) and holds(tee, tinfoil), "a TEE conversation at its level or higher"
    assert not holds(chutes, tee), "a sealed record needs its own service's client"
    assert not holds(chutes, tinfoil), "…however private the other is"
    assert not holds(tinfoil, chutes), "lower"
    assert not holds(tinfoil, NONE) and not holds(chutes, Privacy(plain_on=CHUTES))
    said = held_back(tinfoil, NONE, "glm-5-3", origin=TINFOIL_ORIGIN, now="https://openrouter.ai/api/v1")
    assert said == ("This conversation began end-to-end encrypted through Tinfoil (inference.tinfoil.sh), with the "
                    "highest privacy, and its model glm-5-3 now goes to openrouter.ai, not end-to-end encrypted or "
                    "TEE: not private, so nothing was sent.")
    assert held_back(tinfoil, tinfoil, "glm-5-3") is None


def test_a_record_reads_back_as_it_was_kept():
    record = record_of(Privacy("sealed", CHUTES), CHUTES_BASE_URL)
    assert record == {"kind": "sealed", "service": CHUTES, "origin": "https://llm.chutes.ai:443"}
    assert held(record) == Privacy("sealed", CHUTES)
    assert held(None) == held({"kind": "nonsense"}) == held("sealed") == NONE


@pytest.mark.parametrize("current, new, allowed", [
    (("private/glm-5-3", NANO), ("glm-5-3", TINFOIL_BASE_URL), True),
    (("glm-5-3", TINFOIL_BASE_URL), ("private/kimi-k3", NANO), True),
    (("private/glm-5-3", NANO), (MODEL, CHUTES_BASE_URL), False),
    (("glm-5-3", TINFOIL_BASE_URL), (MODEL, CHUTES_BASE_URL), False),
    (("private/glm-5-3", NANO), ("TEE/glm-5.3", NANO), False),
    (("TEE/glm-5.3", NANO), (MODEL, CHUTES_BASE_URL), True),
    ((MODEL, CHUTES_BASE_URL), ("TEE/glm-5.3", NANO), True),
    ((MODEL, CHUTES_BASE_URL), ("other/Model-TEE", CHUTES_ANTHROPIC_URL), True),
    ((MODEL, CHUTES_BASE_URL), ("private/glm-5-3", NANO), True),
    ((MODEL, CHUTES_BASE_URL), ("glm-5-3", TINFOIL_BASE_URL), True),
    (("TEE/glm-5.3", NANO), ("private/glm-5-3", NANO), True),
    ((MODEL, CHUTES_BASE_URL), (ORDINARY, CHUTES_BASE_URL), False),
    (("TEE/glm-5.3", NANO), (ORDINARY, CHUTES_BASE_URL), False),
    (("TEE/glm-5.3", NANO), ("z-ai/glm-5.3", NANO), False),
    (("z-ai/glm-5.3", NANO), (ORDINARY, CHUTES_BASE_URL), True),
])
def test_a_conversation_moves_only_to_its_level_or_higher(current, new, allowed):
    now, then = privacy_at(current[0], current[1]), privacy_at(new[0], new[1])
    refusal = move_refusal(now, then, new[0])
    assert (refusal is None) == allowed, refusal
    if refusal:
        assert "nothing" not in refusal or "kept to" in refusal
        assert "kept to" in refusal and "choose one of" in refusal


def test_every_refusal_names_the_levels():
    """The author, Nov 15 2026: say so in words."""
    private, tee = privacy_at("private/glm-5-3", NANO), privacy_at("TEE/glm-5.3", NANO)
    assert move_refusal(private, tee, "TEE/glm-5.3") == (
        "TEE/glm-5.3 isn't end-to-end encrypted (a TEE model), so it has partial privacy, and this conversation "
        "is kept to the highest privacy: choose one of NanoGPT's private/ models or Tinfoil's, or start a new one.")
    chutes = move_refusal(private, privacy_at(MODEL, CHUTES_BASE_URL), MODEL, what="this case")
    assert chutes == (f"{MODEL} is end-to-end encrypted through Chutes, but has partial privacy, and this case is "
                      "kept to the highest privacy: choose one of NanoGPT's private/ models or Tinfoil's, or start a "
                      "new one.")
    plain = move_refusal(tee, NONE, "z-ai/glm-5.3")
    assert "isn't a TEE or end-to-end encrypted model, so it has no privacy" in plain
    assert "NanoGPT's TEE/ or private/ models, Chutes' -TEE models or Tinfoil's" in plain
    assert move_note(private).startswith("this conversation has the highest privacy")
    assert move_note(tee).startswith("this conversation has partial privacy") and move_note(NONE) == ""


def test_a_chutes_key_goes_to_chutes_three_hosts_alone():
    """The one stated exception to "a key goes only to the origin it was entered for"."""
    for saved in CHUTES_KEY_ORIGINS:
        for url in (CHUTES_BASE_URL, CHUTES_ANTHROPIC_URL, CHUTES_E2EE_ORIGIN + "/e2e/invoke"):
            assert key_may_go(saved, url), (saved, url)
        for url in ("http://llm.chutes.ai/v1", "https://llm.chutes.ai:8443/v1", "https://evil.chutes.ai/v1",
                    "https://chutes.ai.example/v1", TINFOIL_BASE_URL):
            assert not key_may_go(saved, url), (saved, url)
    assert key_may_go(TINFOIL_ORIGIN, TINFOIL_BASE_URL) and key_may_go(TINFOIL_ORIGIN, "https://inference.tinfoil.sh")
    assert not key_may_go(TINFOIL_ORIGIN, "https://router-0.tinfoil.sh/v1")
    assert not key_may_go(TINFOIL_ORIGIN, CHUTES_BASE_URL) and not key_may_go("", TINFOIL_BASE_URL)


def test_a_plain_client_refuses_every_sealed_model_before_sending():
    assert "Tinfoil's end-to-end encrypted endpoint" in plain_refusal(TINFOIL_BASE_URL, "a model list")
    assert "Tinfoil's" in plain_refusal("https://proxy.example/v1", api="tinfoil")
    assert "sent only through its own client" in plain_refusal("https://openrouter.ai/api/v1", model="private/x")
    assert plain_refusal(NANO, model="TEE/glm-5.3") is None, "a TEE model goes in the clear, as always"
    assert plain_refusal(CHUTES_ANTHROPIC_URL, model=ORDINARY) is None
