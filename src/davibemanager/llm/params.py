"""Generation parameters: the technician's settings, validated, and shaped per model.

Settings hold what the technician chose; a missing key means "use the model's default".
Per request, reasoning effort is sent only to models that reason, and moved to the nearest
level the model accepts (Kimi and GLM take low/high/max; Opus takes low..max)."""

from __future__ import annotations

from .capabilities import EFFORTS

DEFAULTS = {"temperature": 0.3, "reasoning_effort": "low"}

_RANGES = {
    "temperature": (float, 0.0, 2.0),
    "top_p": (float, 0.0, 1.0),
    "max_tokens": (int, 1, 1_000_000),
    "frequency_penalty": (float, -2.0, 2.0),
    "presence_penalty": (float, -2.0, 2.0),
    "seed": (int, 0, 2**63 - 1),
}


def validate(data: dict) -> dict:
    """Keep only known keys; blank values mean "model default" and are dropped."""
    out = {}
    for key, (typ, lo, hi) in _RANGES.items():
        v = data.get(key)
        if v is None or v == "":
            continue
        try:
            v = typ(v)
        except (TypeError, ValueError) as e:
            raise ValueError(f"{key} must be a number") from e
        if not lo <= v <= hi:
            raise ValueError(f"{key} must be between {lo} and {hi}")
        out[key] = v
    effort = data.get("reasoning_effort") or ""
    if effort:
        if effort not in EFFORTS:
            raise ValueError(f"reasoning_effort must be one of {', '.join(EFFORTS)}")
        out["reasoning_effort"] = effort
    return out


def nearest_effort(want: str, supported: list[str]) -> str:
    if not supported or want in supported:
        return want
    i = EFFORTS.index(want)
    return min(supported, key=lambda e: (abs(EFFORTS.index(e) - i), EFFORTS.index(e)))


def for_model(settings: dict, caps: dict | None) -> dict:
    """Request parameters for one model. Unknown capabilities: sampling settings only."""
    out = {k: v for k, v in settings.items() if k in _RANGES}
    effort = settings.get("reasoning_effort")
    if effort and caps and caps.get("reasoning"):
        out["reasoning_effort"] = nearest_effort(effort, caps.get("efforts") or [])
    if caps and caps.get("max_output") and out.get("max_tokens", 0) > caps["max_output"]:
        out["max_tokens"] = caps["max_output"]
    return out
