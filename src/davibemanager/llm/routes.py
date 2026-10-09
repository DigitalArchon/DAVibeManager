"""Which of NanoGPT's hosts runs a model: a route, chosen per model in Settings.

NanoGPT runs an open model (GLM 5.3) on whichever of its many upstream hosts it chooses; on a
subscription, usually a cheap one at FP8 or better, which may be slow. A route asks for another,
as the request's `provider` object (docs.nano-gpt.com, Provider Selection):

- a priority is a `sort`: "speed" (the fastest estimated completion: the `:fast` suffix),
  "latency" (the first word soonest), "throughput" (the most tokens a second), "price";
- a host is a preference (`order`), never a pin: a host that is down falls back to another,
  so the assistant isn't stopped in the middle of a build;
- "FP8 or better" is `min_quantization` (NanoGPT leaves out a host whose precision it doesn't
  know). FP4 hosts measured less accurate in SealedLore, so it's on by default;
- `require_parameters`: only hosts that take everything the request asks for (its tools).

**Any route is billed pay-as-you-go, even for a model a subscription includes**, at the host's
price plus NanoGPT's markup. Only on NanoGPT, and never for a Private Mode or TEE model, whose
protection is the enclave it was attested on, nor Claude, which only Anthropic runs.

Ported from SealedLore (engine/routing.py, providers/model_hosts.py).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from ..netpolicy import check_url
from .client import detect_tier
from .private_mode import offers_private_mode

PRIORITIES = ("subscription", "speed", "latency", "throughput", "price", "host")
LABELS = {
    "subscription": "NanoGPT's own choice",
    "speed": "Fastest overall",
    "latency": "Fastest to start answering",
    "throughput": "Fastest writing",
    "price": "Cheapest",
    "host": "A host I choose",
}
# bits per weight, for the "FP8 or better" floor; an unknown precision doesn't meet it
BITS = {"int4": 4, "fp4": 4, "nvfp4": 4, "fp6": 6, "int8": 8, "fp8": 8, "fp16": 16, "bf16": 16, "fp32": 32}
PRIVACY = {
    "zdr": "Keeps nothing",
    "no_training": "Keeps prompts, doesn't train on them",
    "logs_training": "Keeps prompts and trains on them",
}


def is_claude(model: str) -> bool:
    return (model or "").lower().startswith(("anthropic/", "claude-", "claude/"))


def routable(base_url: str, model: str) -> bool:
    """Whether a route can be asked for `model` on this endpoint: NanoGPT, and a model sent as it
    is (not sealed to an enclave, not attested, not Claude)."""
    model = (model or "").strip()
    return bool(model) and offers_private_mode(base_url) and not is_claude(model) \
        and detect_tier(model, base_url) == "standard"


def clean(data: Any) -> dict | None:
    """A route from the window, checked; None for NanoGPT's own choice (no route)."""
    if not isinstance(data, Mapping):
        raise ValueError("A route is an object.")
    priority = data.get("priority") or "subscription"
    if priority not in PRIORITIES:
        raise ValueError(f"A route is one of: {', '.join(PRIORITIES)}.")
    if priority == "subscription":
        return None
    out: dict[str, Any] = {"priority": priority, "fp8": bool(data.get("fp8", True))}
    if priority == "host":
        host = str(data.get("host") or "").strip()
        if not host or len(host) > 100 or not all(c.isalnum() or c in "-_." for c in host):
            raise ValueError("Choose the host to use.")
        out["host"] = host
        out["host_name"] = str(data.get("host_name") or host)[:100]
    return out


def body(route: Mapping | None) -> dict[str, Any]:
    """The request field for `route`: {} for NanoGPT's own choice."""
    if not route or route.get("priority") in (None, "subscription"):
        return {}
    provider: dict[str, Any] = {"require_parameters": True}
    if route["priority"] == "host":
        provider["order"] = [route["host"]]
    else:
        provider["sort"] = route["priority"]
    if route.get("fp8", True):
        provider["min_quantization"] = "fp8"
    return {"provider": provider}


def describe(route: Mapping | None) -> str:
    """"Fastest overall · FP8 or better", for the window and the activity log."""
    if not route or route.get("priority") in (None, "subscription"):
        return LABELS["subscription"]
    what = route.get("host_name") or route.get("host") if route["priority"] == "host" else LABELS[route["priority"]]
    return f"{what} · {'FP8 or better' if route.get('fp8', True) else 'any precision'}"


# ---------------------------------------------------------------- the hosts NanoGPT lists for a model

def hosts_url(base_url: str, model: str) -> str:
    """`GET {origin}/api/models/{id}/providers`: outside /api/v1, the model's slash encoded."""
    p = urlparse(base_url.strip())
    return f"{p.scheme}://{p.netloc}/api/models/{quote(model, safe='')}/providers"


def _num(v: Any) -> float | None:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _per_million(pricing: Any, key: str) -> float | None:
    v = _num(pricing.get(key)) if isinstance(pricing, Mapping) else None
    return round(v * 1000, 4) if v is not None else None


def _text(v: Any) -> str | None:
    return v if isinstance(v, str) and v else None


def parse_hosts(model: str, data: Mapping[str, Any]) -> dict:
    """NanoGPT's listing, as the window shows it: each host's precision, privacy, region, price
    (USD per million tokens), whether it caches, and NanoGPT's own measure of its speed; and the
    same measure for NanoGPT's own routing."""
    hosts = []
    for e in data.get("providers") or []:
        if not isinstance(e, Mapping) or not _text(e.get("provider")):
            continue
        quant = (_text(e.get("quantization")) or "").lower() or None
        privacy = (e.get("privacy") or {}).get("classification") if isinstance(e.get("privacy"), Mapping) else None
        region = e.get("region") if isinstance(e.get("region"), Mapping) else {}
        price = (e.get("effectivePricing") or {}).get("effective_price") if isinstance(e.get("effectivePricing"), Mapping) \
            else None
        price = price if isinstance(price, Mapping) else e.get("pricing")
        hosts.append({
            "id": e["provider"], "name": str(e.get("displayName") or e["provider"])[:100],
            "available": e.get("available") is not False,
            "precision": quant, "fp8": BITS.get(quant or "", 0) >= 8,
            "privacy": PRIVACY.get(privacy or "", "Not known"), "keeps_nothing": privacy == "zdr",
            "region": _text(region.get("label")),
            "tokens_per_second": _num(e.get("tps")), "first_token_ms": _num(e.get("ttftMs")),
            "input": _per_million(price, "inputPer1kTokens"), "output": _per_million(price, "outputPer1kTokens"),
            "caches": e.get("supportsPromptCaching") is True,
        })
    return {
        "model": model,
        "supported": data.get("supportsProviderSelection") is True,
        "auto": {"tokens_per_second": _num(data.get("autoTps")), "first_token_ms": _num(data.get("autoTtftMs")),
                 "precision": _text(data.get("autoQuantization"))},
        "hosts": hosts,
    }


async def fetch_hosts(base_url: str, model: str, http: httpx.AsyncClient | None = None) -> dict:
    """NanoGPT's public listing: it needs no key, so none is sent, nor anything but the model's name."""
    url = check_url(hosts_url(base_url, model), "NanoGPT's list of hosts")
    client = http or httpx.AsyncClient(timeout=30)
    try:
        r = await client.get(url)          # never a redirect followed: httpx's default
        r.raise_for_status()
        data = r.json()
    finally:
        if http is None:
            await client.aclose()
    if not isinstance(data, Mapping):
        raise ValueError(f"NanoGPT's list of hosts for {model} wasn't what it should be.")
    return parse_hosts(model, data)
