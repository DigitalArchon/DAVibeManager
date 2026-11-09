"""Generation parameters: the technician's settings, validated, and shaped per model.

Settings hold what the technician chose; a missing key means "use the model's default".
Per request, reasoning effort is sent only to models that reason, and moved to the nearest
level the model takes (GLM and Kimi take low/high/max; Opus takes low..max).

Measured live (Nov 8 2026, by DA Private Coder): a private model refuses a level it doesn't take
with HTTP 400 (private Kimi K3 takes only low, high and max; private DeepSeek V4.1 Flash low, high,
xhigh and max), or takes it and ignores it (private GLM-5.3 then reasons at its default, max: medium
thought harder than high). Through NanoGPT's gateway (TEE and standard models) an unlisted level is
taken and ignored the same way, so z-ai/glm-5.3 at medium reasoned at max. NanoGPT's listing holds
for those, not for the private builds (it lists medium for TEE/deepseek-v4.1-flash)."""

from __future__ import annotations

import re

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


# the levels a model may be moved between, least to most: never "none" or "minimal" (GLM with its
# thinking off reasons all the more, in its answer)
LEVELS = ("low", "medium", "high", "xhigh", "max")
# what every private model takes (Kimi K3 only these; GLM-5.3 ignores others; DeepSeek V4.1 Flash also xhigh)
PRIVATE_EFFORTS = ("low", "high", "max")


def nearest_effort(want: str, supported) -> str:
    """The effort a model that takes `supported` (None or empty: not known) is sent for `want`: itself
    if it takes it, else the nearest it does, the higher of two as near (medium as high where there's
    no medium, xhigh as max)."""
    choices = [e for e in (supported or ()) if e in LEVELS]
    if not choices or want in choices or want not in LEVELS:
        return want
    at = LEVELS.index(want)
    return min(choices, key=lambda e: (abs(LEVELS.index(e) - at), -LEVELS.index(e)))


def efforts_named(error: str, sent: str | None) -> tuple[str, ...]:
    """The efforts a model's refusal says it takes ("Kimi K3 supports thinking_effort values: low,
    high, max (… value=medium)"; "reasoning_effort must be low, high, xhigh, max, or …"), or (). A
    list names two or more, as words of their own: "max_tokens", or "effort too high", lists none."""
    low = error.lower()
    if "effort" not in low:
        return ()
    named = set(re.findall(r"(?<![a-z_])(low|medium|high|xhigh|max)(?![a-z_])", low)) - {sent}
    return tuple(e for e in LEVELS if e in named) if len(named) >= 2 else ()


def effort_unsupported(error: str) -> bool:
    """Whether a refusal says the model takes no reasoning effort at all ("Unsupported parameter:
    'reasoning_effort' is not supported with this model.")."""
    low = error.lower()
    return "reasoning_effort" in low and any(w in low for w in (
        "not supported", "unsupported", "unrecognized", "unknown parameter", "not allowed", "extra inputs"))


def with_effort(params: dict, effort: str) -> dict:
    """`params` with the reasoning effort to send ("": none, for a model that takes none)."""
    out = {k: v for k, v in params.items() if k != "reasoning_effort"}
    if effort:
        out["reasoning_effort"] = effort
    return out


def for_model(settings: dict, caps: dict | None) -> dict:
    """Request parameters for one model. Unknown capabilities: sampling settings only."""
    out = {k: v for k, v in settings.items() if k in _RANGES}
    effort = settings.get("reasoning_effort")
    if effort and caps and caps.get("reasoning"):
        out["reasoning_effort"] = nearest_effort(effort, caps.get("efforts") or [])
    if caps and caps.get("max_output") and out.get("max_tokens", 0) > caps["max_output"]:
        out["max_tokens"] = caps["max_output"]
    return out
