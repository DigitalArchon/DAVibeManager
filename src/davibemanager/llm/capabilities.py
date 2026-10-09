"""What a model can do: vision, reasoning (and which efforts), tool calls, limits; and what it costs.

NanoGPT reports this in its detailed model list (GET /models?detailed=true). Private Mode
models (private/kimi-k3) are not in that list, so they are matched to their public
counterpart by name (moonshotai/kimi-k3, TEE/kimi-k3). Other OpenAI-compatible providers
report nothing, so their capabilities are unknown unless the technician sets an override."""

from __future__ import annotations

import re

import httpx

EFFORTS = ["none", "minimal", "low", "medium", "high", "xhigh", "max"]


def _norm(model_id: str) -> str:
    return re.sub(r"[._]", "-", model_id.split("/")[-1].lower())


def parse(items: list[dict]) -> dict[str, dict]:
    out = {}
    for m in items:
        caps = m.get("capabilities") or {}
        out[m["id"]] = {
            "vision": bool(caps.get("vision")),
            "reasoning": bool(caps.get("reasoning")),
            "efforts": [e for e in (m.get("reasoning_efforts") or []) if e in EFFORTS],
            "tools": bool(caps.get("tool_calling")),
            "context": m.get("context_length"),
            "max_output": m.get("max_output_tokens"),
            "pricing": _pricing(m.get("pricing")),
            "included": bool((m.get("subscription") or {}).get("included")),
        }
    return out


def _pricing(p) -> dict | None:
    """USD per million tokens: input, output, cache reads and writes (NanoGPT lists the cache's per 1k)."""
    if not isinstance(p, dict) or str(p.get("currency", "USD")).upper() != "USD":
        return None

    def num(v) -> float | None:
        return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0 else None
    inp, out = num(p.get("prompt")), num(p.get("completion"))
    if inp is None or out is None or p.get("unit", "per_million_tokens") != "per_million_tokens":
        return None
    read, write = num(p.get("cacheReadInputPer1kTokens")), num(p.get("cacheWriteInputPer1kTokens"))
    return {"input": inp, "output": out, "cache_read": inp if read is None else read * 1000,
            "cache_write": inp if write is None else write * 1000}


def cost(caps: dict | None, usage: dict) -> float | None:
    """What these tokens cost at the model's listed prices (None: its prices aren't known)."""
    price = (caps or {}).get("pricing")
    if not price:
        return None
    return sum(usage.get(k, 0) * price[k] for k in ("input", "output", "cache_read", "cache_write")) / 1_000_000


async def fetch_nanogpt(base_url: str, api_key: str | None, http: httpx.AsyncClient | None = None) -> dict[str, dict]:
    client = http or httpx.AsyncClient(timeout=30)
    try:
        r = await client.get(base_url.rstrip("/") + "/models", params={"detailed": "true"},
                             headers={"Authorization": f"Bearer {api_key}"} if api_key else {})
        r.raise_for_status()
        return parse(r.json().get("data", []))
    finally:
        if http is None:
            await client.aclose()


def lookup(caps: dict[str, dict], model_id: str) -> dict | None:
    """Capabilities of `model_id`; a private/ model borrows those of its public twin."""
    if model_id in caps:
        return caps[model_id]
    n = _norm(model_id)
    twins = [mid for mid in caps if _norm(mid) == n]
    twins.sort(key=lambda mid: (not mid.startswith("TEE/"), mid))     # the enclave build first
    return caps[twins[0]] if twins else None


# How providers say a request didn't fit (OpenAI/vLLM, Anthropic, Gemini, llama.cpp, generic).
_OVERFLOW = re.compile(r"context[_ ]length[_ ]exceeded|maximum context length|context (?:window|size|length) "
                       r"(?:exceeded|is exceeded|limit)|exceeds? (?:the )?(?:available |model'?s? )?context|prompt is too long|"
                       r"too many (?:input )?tokens|input token count .* exceeds|reduce the length of (?:the )?(?:messages|prompt)",
                       re.I)
_LIMIT = [re.compile(p, re.I) for p in (
    r"maximum context length is (\d+)",                 # OpenAI, vLLM
    r"\d+ tokens > (\d+) maximum",                      # Anthropic
    r"maximum number of tokens allowed \((\d+)\)",      # Gemini
    r"context (?:window|size|length)(?: limit)? (?:of|is) (\d+)",
    r"n_ctx(?:_slot)?\s*[=:]\s*(\d+)",                  # llama.cpp
)]


def overflow(err: Exception | str) -> tuple[bool, int | None]:
    """Whether a provider error says the request was too long for the model's context window,
    and the window size when the message names it."""
    text = str(err)
    if not _OVERFLOW.search(text):
        return False, None
    for pat in _LIMIT:
        m = pat.search(text)
        if m and int(m.group(1)) >= 1024:
            return True, int(m.group(1))
    return True, None
