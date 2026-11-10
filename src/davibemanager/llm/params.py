"""Generation parameters: the technician's settings, validated, and shaped per model.

Settings hold what the technician chose; a missing key means "use the model's default".
Per request, reasoning effort is sent only to models that reason, and moved to the nearest
level the model takes (GLM and Kimi take low/high/max; Opus takes low..max). The assistant's
one setting (config.BUILDER_EFFORTS) reaches Claude models as Claude's own effort and thinking
(`fit_claude`), from Anthropic's table rather than NanoGPT's listing, which names efforts for
Claude models that take none on Anthropic's endpoint (Sonnet 4.5, Nov 2026).

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


# How hard the assistant thinks (Settings → The assistant, config.BUILDER_EFFORTS) is one setting for
# every model. Each is sent the nearest it takes: a reasoning effort for models other than Claude,
# Claude's own effort and thinking for Claude (`fit_claude`); Claude Code in the sandbox is started
# at it (builder/bridge.py).

# Claude's own levels (output_config.effort), from Anthropic's model table (Nov 2026)
CLAUDE_EFFORTS = ("low", "medium", "high", "xhigh", "max")
# the thinking budget, in tokens, for a Claude model that thinks by one rather than adaptively:
# Claude Code sends 31,999 (its most) whatever the effort
THINKING_BUDGET = {"low": 4096, "medium": 10240, "high": 20480, "max": 31999}
_CLAUDE = re.compile(r"claude-(opus|sonnet|haiku|fable|mythos)-(?:(latest)|(\d+)(?:-(\d{1,2}))?)(?:-\d{8})?$")
_CLAUDE_3 = re.compile(r"claude-(\d)-(\d)-(opus|sonnet|haiku)(?:-\d{8})?$")


def claude_takes(model: str) -> tuple[tuple[str, ...], bool] | None:
    """What a Claude model takes, however NanoGPT or Anthropic writes it ("anthropic/claude-opus-5.5",
    "claude-opus-4-5-20251101", "anthropic/claude-sonnet-5:thinking"): (its efforts, () for none;
    whether it thinks adaptively, else by a budget of tokens). None for one not known here, or that
    doesn't think (Claude 3 but Sonnet 3.7).

    Claude Code reads NanoGPT's names wrongly (2.1.292, measured Nov 10 2026): every 4.x model as one
    of the old ones, sent a budget and no effort (Opus 4.7 and 4.8 refuse a budget), and Haiku 4.5 as
    a new one, sent adaptive thinking and an effort (it takes neither)."""
    name = re.sub(r"[._]", "-", str(model or "").split("/")[-1].split(":")[0].strip().lower())
    if m := _CLAUDE.fullmatch(name):
        family = m.group(1)
        version = (99, 0) if m.group(2) else (int(m.group(3)), int(m.group(4) or 0))
    elif m := _CLAUDE_3.fullmatch(name):
        family, version = m.group(3), (int(m.group(1)), int(m.group(2)))
    else:
        return None
    if family in ("fable", "mythos") or version >= {"opus": (4, 7), "sonnet": (5, 0), "haiku": (5, 0)}[family]:
        return CLAUDE_EFFORTS, True
    if family in ("opus", "sonnet") and version >= (4, 6):
        return ("low", "medium", "high", "max"), True
    if family == "opus" and version == (4, 5):
        return ("low", "medium", "high"), False
    if version >= (4, 0) or (family, version) == ("sonnet", (3, 7)):
        return (), False                      # Opus 4 and 4.1, Sonnet 4 and 4.5, Haiku 4.5, Sonnet 3.7
    return None


def fit_claude(body: dict, model: str, effort: str) -> dict:
    """A request for a Claude model made to take `effort` (config.BUILDER_EFFORTS), as near as the model
    goes (`body` is changed in place): its effort the nearest it takes, or none; its thinking the kind
    it takes, a budget sized to the effort for a model that thinks by one. Only a request that thinks
    or names an effort is fitted (the assistant's own steps); one that doesn't (Claude Code's quick
    tasks) is left as it came, but never with an effort the model doesn't take. A model not known
    here keeps what Claude Code sent, with the effort chosen where it named one.
    Returns what went: {"effort": "low"…, or "" for none; "budget"?: thinking tokens}, or {}."""
    config = body.get("output_config") if isinstance(body.get("output_config"), dict) else None
    thinking = body.get("thinking") if isinstance(body.get("thinking"), dict) else None
    thinks = thinking is not None and thinking.get("type") in ("enabled", "adaptive")
    named = config is not None and "effort" in config
    takes = claude_takes(model)
    if takes is None:
        if not named:
            return {}
        config["effort"] = effort
        return {"effort": effort}
    levels, adaptive = takes
    if not (thinks or named):
        return {}
    sent = nearest_effort(effort, levels) if levels else ""
    if sent:
        body["output_config"] = {**(config or {}), "effort": sent}
    elif config is not None:
        config.pop("effort", None)
        if not config:
            del body["output_config"]
    out = {"effort": sent}
    if thinks:
        shown = {"display": thinking["display"]} if "display" in thinking else {}
        if adaptive:
            body["thinking"] = {"type": "adaptive", **shown}
        else:
            most = body.get("max_tokens")
            budget = THINKING_BUDGET.get(effort, THINKING_BUDGET["medium"])
            if isinstance(most, int) and not isinstance(most, bool):
                budget = min(budget, most - 1)
            if budget >= 1024:                # the least a budget may be
                body["thinking"] = {"type": "enabled", "budget_tokens": budget, **shown}
                out["budget"] = budget
            else:
                del body["thinking"]
    return out


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
