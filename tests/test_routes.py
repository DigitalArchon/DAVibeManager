"""Which of NanoGPT's hosts runs a model: NanoGPT's own choice (included in a subscription, and
sometimes slow), or a route the user chose in Settings (the fastest, the cheapest, or a host they
trust), which is paid per use. Never for a model sealed to an enclave, attested, or Claude."""

import httpx
import pytest

from davibemanager.config import Config, Provider
from davibemanager.gateway import Gateway, Upstream
from davibemanager.llm import capabilities, routes
from davibemanager.llm.client import _split_params
from davibemanager.models import Models, UserError
from test_anthropic_bridge import events

NANO = "https://nano-gpt.com/api/v1"
LISTING = {
    "canonicalId": "z-ai/glm-5.3", "supportsProviderSelection": True, "autoTps": 137.7, "autoTtftMs": 3300,
    "autoQuantization": "FP8+",
    "providers": [
        {"provider": "parasail", "displayName": "Parasail", "available": True, "quantization": "fp8", "tps": 100,
         "ttftMs": 1061, "supportsPromptCaching": True, "privacy": {"classification": "zdr"},
         "region": {"code": "US", "label": "United States"},
         "pricing": {"inputPer1kTokens": 0.00147, "outputPer1kTokens": 0.00462},
         "effectivePricing": {"effective_price": {"inputPer1kTokens": 0.0012, "outputPer1kTokens": 0.004}}},
        {"provider": "together", "displayName": "Together", "available": True, "quantization": "unknown", "tps": 130,
         "ttftMs": 374.5, "supportsPromptCaching": True, "privacy": {"classification": "no_training"}},
        {"provider": "nebius", "displayName": "Nebius", "available": True, "quantization": "fp4", "tps": 126},
        {"provider": "streamlake", "displayName": "StreamLake", "available": False},
        {"displayName": "no id"},
    ]}


def test_a_route_is_the_provider_field_nanogpt_reads():
    assert routes.body(None) == {} and routes.body({"priority": "subscription"}) == {}
    assert routes.body({"priority": "speed", "fp8": True}) == {
        "provider": {"require_parameters": True, "sort": "speed", "min_quantization": "fp8"}}
    assert routes.body({"priority": "host", "host": "parasail", "fp8": False}) == {
        "provider": {"require_parameters": True, "order": ["parasail"]}}       # preferred, never pinned
    # sent in the request body, whatever the SDK knows about
    assert _split_params({"temperature": 0.2, **routes.body({"priority": "price"})})["extra_body"] == {
        "provider": {"require_parameters": True, "sort": "price", "min_quantization": "fp8"}}
    assert routes.describe({"priority": "host", "host": "parasail", "host_name": "Parasail", "fp8": True}) == \
        "Parasail · FP8 or better"


@pytest.mark.parametrize("model,base,ok", [
    ("z-ai/glm-5.3", NANO, True),
    ("z-ai/glm-5.3", "https://api.nano-gpt.com/api/v1", True),
    ("private/glm-5-3", NANO, False),            # sealed to an attested enclave
    ("TEE/glm-5.3", NANO, False),                # attested before every send
    ("anthropic/claude-opus-5.5", NANO, False),  # only Anthropic runs it
    ("z-ai/glm-5.3", "https://openrouter.example/api/v1", False),
    ("", NANO, False),
])
def test_only_a_model_nanogpt_sends_as_it_is_can_be_routed(model, base, ok):
    assert routes.routable(base, model) is ok


def test_a_route_from_the_window_is_checked():
    assert routes.clean({"priority": "subscription"}) is None
    assert routes.clean({"priority": "latency"}) == {"priority": "latency", "fp8": True}
    for bad in ({"priority": "fastest"}, {"priority": "host"}, {"priority": "host", "host": "a b/../c"}, "speed"):
        with pytest.raises(ValueError):
            routes.clean(bad)


def test_nanogpts_listing_is_read_as_the_window_shows_it():
    d = routes.parse_hosts("z-ai/glm-5.3", LISTING)
    assert d["supported"] and d["auto"] == {"tokens_per_second": 137.7, "first_token_ms": 3300, "precision": "FP8+"}
    assert [x["id"] for x in d["hosts"]] == ["parasail", "together", "nebius", "streamlake"]
    p = d["hosts"][0]
    assert p["input"] == pytest.approx(1.2) and p["output"] == pytest.approx(4.0)      # what it bills, per million
    assert p["fp8"] and p["keeps_nothing"] and p["privacy"] == "Keeps nothing" and p["region"] == "United States"
    assert not d["hosts"][1]["fp8"] and d["hosts"][1]["privacy"] == "Keeps prompts, doesn't train on them"
    assert not d["hosts"][3]["available"] and d["hosts"][2]["privacy"] == "Not known"
    assert routes.hosts_url(NANO, "z-ai/glm-5.3") == "https://nano-gpt.com/api/models/z-ai%2Fglm-5.3/providers"


@pytest.fixture
def models():
    asked = []

    def handler(request):
        asked.append(request)
        return httpx.Response(200, json=LISTING)
    cfg = Config(providers=[Provider("NanoGPT", NANO, builder_url=NANO)])
    saved = []
    m = Models(cfg, save_config=saved.append, emit=lambda *a, **k: None, log=lambda *a, **k: None)
    m.hosts_http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return m, cfg.providers[0], asked, saved


async def test_a_route_is_chosen_per_model_and_kept(models):
    m, prov, asked, saved = models
    out = await m.hosts(prov, "z-ai/glm-5.3")
    assert out["route"] is None and len(out["hosts"]) == 4
    req = asked[0]
    assert str(req.url) == "https://nano-gpt.com/api/models/z-ai%2Fglm-5.3/providers"
    assert "authorization" not in req.headers                        # the listing needs no key: none is sent
    await m.set_route(prov, "z-ai/glm-5.3", {"priority": "speed", "fp8": True})
    assert m.route(prov, "z-ai/glm-5.3") == {"priority": "speed", "fp8": True} and saved
    assert m.params(prov, "z-ai/glm-5.3")["provider"]["sort"] == "speed"   # the vision helper and reviewer too
    assert m.route(prov, "z-ai/glm-5.3-flash") is None                       # each model its own
    await m.set_route(prov, "z-ai/glm-5.3", {"priority": "subscription"})
    assert m.route(prov, "z-ai/glm-5.3") is None and "z-ai/glm-5.3" not in m.cfg.settings.model_routes
    assert len(asked) == 1                                           # the listing is kept a while


async def test_a_host_must_be_one_nanogpt_lists_and_the_floor_never_shuts_it_out(models):
    m, prov, _, _ = models
    with pytest.raises(UserError, match="doesn't list"):
        await m.set_route(prov, "z-ai/glm-5.3", {"priority": "host", "host": "elsewhere"})
    r = await m.set_route(prov, "z-ai/glm-5.3", {"priority": "host", "host": "together", "fp8": True})
    assert r == {"priority": "host", "host": "together", "host_name": "Together", "fp8": False}   # its precision isn't said
    assert routes.body(r)["provider"] == {"require_parameters": True, "order": ["together"]}
    r = await m.set_route(prov, "z-ai/glm-5.3", {"priority": "host", "host": "parasail", "fp8": True})
    assert r["fp8"] and routes.body(r)["provider"]["min_quantization"] == "fp8"


async def test_a_model_that_cant_be_routed_never_is(models):
    m, prov, asked, _ = models
    with pytest.raises(UserError, match="private, TEE or Claude"):
        await m.hosts(prov, "private/glm-5-3")
    m.cfg.settings.model_routes = {"private/glm-5-3": {"priority": "speed", "fp8": True}}   # however it got there
    assert m.route(prov, "private/glm-5-3") is None and "provider" not in m.params(prov, "private/glm-5-3")
    assert not asked


class Recorder:
    def __init__(self, cost):
        self.calls, self.cost = [], cost

    def stream(self, model, messages, tools=None, params=None):
        self.calls.append((model, params))
        return self._events()

    async def _events(self):
        async for kind, val in events("Hi"):
            if kind == "done":
                val.usage = {**val.usage, **({"cost": self.cost} if self.cost is not None else {})}
            yield kind, val


@pytest.mark.parametrize("cost,held", [(0.0021, True), (0, False), (None, None)])
async def test_the_assistants_requests_carry_its_route_and_the_bill_says_if_it_held(tmp_path, cost, held):
    fake, seen = Recorder(cost), []
    chosen = {"z-ai/glm-5.3": {"priority": "host", "host": "parasail", "host_name": "Parasail", "fp8": True}}
    g = Gateway(tmp_path / "gw", lambda: Upstream(NANO, "bearer", lambda: "sk", ("z-ai/glm-5.3", "z-ai/glm-5.3-flash"),
                                                 provider="NanoGPT", chat=lambda m: fake, route=chosen.get),
                on_event=seen.append)
    await g.start()
    try:
        async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(g.model_socket)), base_url="http://gw") as c:
            h = {"authorization": f"Bearer {g.token}"}
            msg = {"stream": True, "messages": [{"role": "user", "content": "hi"}]}
            await c.post("/v1/messages", headers=h, json={"model": "z-ai/glm-5.3", **msg})
            await c.post("/v1/messages", headers=h, json={"model": "z-ai/glm-5.3-flash", **msg})
    finally:
        await g.stop()
    assert fake.calls[0][1]["provider"] == {"require_parameters": True, "order": ["parasail"], "min_quantization": "fp8"}
    assert "provider" not in fake.calls[1][1]                                  # the quick model: NanoGPT's choice
    assert seen[0]["route"] == "Parasail · FP8 or better" and "route" not in seen[1]
    assert seen[0].get("route_held") is held


async def test_routed_tokens_are_paid_even_for_a_model_a_subscription_includes(env):
    engine, _, emitted = env
    engine.models._caps["Fake"] = capabilities.parse([
        {"id": "z-ai/glm-5.3", "subscription": {"included": True}, "pricing": {
            "prompt": 0.7, "completion": 2.2, "currency": "USD", "unit": "per_million_tokens"}}])
    million = {"input": 1_000_000, "output": 0, "cache_read": 0, "cache_write": 0}
    engine._network_event({"kind": "model", "model": "z-ai/glm-5.3", "status": 200, "usage": million})
    assert engine.spend()["included"] == pytest.approx(0.7) and engine.spend()["paid"] == 0
    route = "Fastest overall · FP8 or better"
    engine._network_event({"kind": "model", "model": "z-ai/glm-5.3", "status": 200, "route": route,
                           "usage": {**million, "cost": 1.47}, "route_held": True})
    assert engine.spend()["paid"] == pytest.approx(1.47)              # what NanoGPT billed, at the host's price
    engine._network_event({"kind": "model", "model": "z-ai/glm-5.3", "status": 200, "route": route, "usage": million})
    assert engine.spend()["paid"] == pytest.approx(1.47 + 0.7)         # not billed back: at the listed price
    # NanoGPT billed nothing: it went on its own routing, and the user is told once
    for _ in range(2):
        engine._network_event({"kind": "model", "model": "z-ai/glm-5.3", "status": 200, "route": route,
                               "usage": {**million, "cost": 0.0}, "route_held": False})
    assert engine.spend()["included"] == pytest.approx(3 * 0.7)
    told = [e for e in emitted if e["type"] == "toast" and "didn't use the host" in e["text"]]
    assert len(told) == 1
