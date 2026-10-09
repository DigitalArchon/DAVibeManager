"""Persistent configuration. Never holds secrets - those live in the OS keyring (see creds.py)."""

from __future__ import annotations

import os
import tomllib
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from urllib.parse import urlparse

import tomli_w

NANOGPT_BASE_URL = "https://nano-gpt.com/api/v1"
ANTHROPIC_BASE_URL = "https://api.anthropic.com"
APP_ID = "davibemanager"
# NanoGPT models. The defaults are GLM 5.3, routed by NanoGPT (included in a NanoGPT subscription);
# GLM 5.3 can't see images, GLM 5.3 Flash can and is fast
DEFAULT_MODEL = "z-ai/glm-5.3"
DEFAULT_FAST_MODEL = "z-ai/glm-5.3-flash"
PRIVATE_MODEL = "private/glm-5-3"          # NanoGPT Private Mode: end-to-end encrypted (paid)
PRIVATE_FAST_MODEL = "private/glm-5-3-flash"
CLAUDE_MODEL = "anthropic/claude-opus-5.5"
# how often an app's official source is asked for new releases (each app can choose its own)
CHECK_EVERY = ("day", "week", "month", "manual")
# when a new release is built with the user's changes: when they say so, at the quiet time, or at once
REBUILD = ("ask", "scheduled", "auto")
# the window's colours; "system" follows the desktop's light or dark preference
THEMES = ("dark", "light", "system")
WINDOW_BACKGROUND = {"dark": "#111418", "light": "#f4f6f9", "system": "#111418"}


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / APP_ID


def data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return Path(base) / APP_ID


@dataclass
class Provider:
    name: str
    # OpenAI-compatible chat endpoint, for the host agent and the reviewer; empty if it has none
    base_url: str
    default_model: str = ""
    # Anthropic Messages endpoint the builder can use through the gateway (gateway.py); empty if
    # none. NanoGPT serves both on the same base; Anthropic itself is api.anthropic.com
    builder_url: str = ""
    # how the gateway presents the key upstream: "bearer" (NanoGPT) or "x-api-key" (Anthropic)
    builder_auth: str = "bearer"
    # model id -> "standard" | "tee" | "e2ee" | "local"; overrides automatic detection, but only
    # ever downwards (llm/client.detect_tier)
    tier_overrides: dict[str, str] = field(default_factory=dict)
    # model id -> "yes" | "no": can it read images (overrides what the provider reports)
    vision_overrides: dict[str, str] = field(default_factory=dict)
    # model id -> context window in tokens (for providers that don't report it, e.g. local models)
    context_overrides: dict[str, int] = field(default_factory=dict)


def provider_defaults(p: Provider) -> Provider:
    """Fill in the builder endpoint for the providers we know."""
    host = (urlparse(p.base_url or p.builder_url).hostname or "").lower()
    if host in ("nano-gpt.com", "api.nano-gpt.com") and not p.builder_url:
        p.builder_url, p.builder_auth = p.base_url, "bearer"
    elif host == "api.anthropic.com" and not p.builder_url:
        p.builder_url, p.builder_auth = ANTHROPIC_BASE_URL, "x-api-key"
    return p


@dataclass
class Settings:
    # what happens to a command's output once it has run on this computer: "review" (the user
    # reads it and sends it, the default) or "auto" (sent redacted at once, unless something in it
    # looks sensitive; the user can still see exactly what was sent)
    output_mode: str = "review"
    # automatic second opinions on commands for this computer: "changes" (anything not plainly
    # read-only), "all", or "off"
    second_opinion: str = "changes"
    # "provider|model" of the reviewer; empty = chosen automatically (a private NanoGPT model)
    review_model: str = ""
    # seconds a command on this computer may run before it is stopped
    command_timeout: int = 120
    # most of a command's output sent to the assistant
    capture_max_lines: int = 400
    capture_max_chars: int = 30000
    # the assistant: provider name (must have builder_url), its main model, and the small model
    # Claude Code uses for quick background tasks; empty small = the main model
    builder_provider: str = ""
    # GLM 5.3 by default (see DEFAULT_MODEL); private GLM and Claude Opus 5.5 are choices in Settings
    builder_model: str = DEFAULT_MODEL
    builder_small_model: str = DEFAULT_FAST_MODEL
    # describes images for a model that can't see them (any but Anthropic's); empty = none
    builder_vision_model: str = DEFAULT_FAST_MODEL
    # how hard a private model reasons before it answers: "low", "medium" or "high". GLM 5.3 at its
    # default reasons for minutes a step, and with thinking off it reasons even more (into its answer)
    builder_reasoning: str = "low"
    # which of NanoGPT's hosts runs a model, by model id (llm/routes.py): {"priority": "speed" |
    # "latency" | "throughput" | "price" | "host", "fp8": bool, "host": id}. None for a model means
    # NanoGPT's own choice (on a subscription, included). Any route is paid per use
    model_routes: dict = field(default_factory=dict)
    # generation parameters for the reviewer; a missing key means "the model's default"
    generation: dict = field(default_factory=lambda: {"temperature": 0.2, "reasoning_effort": "low"})
    # sandbox container limits
    container_memory: str = "8g"
    container_cpus: str = "4"
    container_pids: int = 4096
    # where Install puts delivered apps
    install_dir: str = "~/Applications"
    # how often (from the sandbox) to ask an app's official source for new releases: "day", "week",
    # "month" or "manual" (when the user asks). Each app can choose its own; this is for the others
    check_every: str = "day"
    # when one is out: summarise its change log at once ("auto") or when the user asks ("manual")
    changelog_summary: str = "auto"
    # and build it with the user's changes: "scheduled" (at build_time, when the computer is quiet:
    # building takes its power for a while), "auto" (at once) or "ask" (when the user says so).
    # Each app can choose its own; this is for the others
    rebuild: str = "scheduled"
    # the quiet time for scheduled builds, local "HH:MM"; one is started within two hours after it
    build_time: str = "03:00"
    # whether a scheduled build may start while the computer runs on its battery
    build_on_battery: bool = False
    # where installed apps live: "auto" (Shelly where it is, else Gear Lever, else a menu entry of
    # our own), "shelly", "gearlever" or "menu"
    app_home: str = "auto"
    # the assistant's web searches, through NanoGPT with the user's key; never with anything from
    # the user's computer (safety/outside.py). "answer" searches gather information (Perplexity:
    # substantial extracts with sources), "links" searches find official sites (Kagi: accurate links)
    web_search: bool = True
    search_provider: str = "perplexity"
    search_links_provider: str = "kagi"
    # what the assistant is told about this computer at the start of every chat, so it needn't ask:
    # "system" (distribution, version, desktop) and/or "hardware" (processor, memory, graphics)
    share_about: list = field(default_factory=list)
    # backups (backup.py): the folder they go to, how often one is made by itself ("off", "day",
    # "week", or "change": after a new app, change or build; it needs the password in the keyring),
    # and how many of those automatic ones are kept there
    backup_dir: str = "~/DA Vibe Manager backups"
    backup_auto: str = "week"
    backup_keep: int = 5
    # the window's colours: "dark" (DA Toolkit's), "light" or "system"
    theme: str = "dark"
    # "window" (the app window, needs WebKitGTK) or "browser" (the default web browser); next launch
    ui_mode: str = "window"


@dataclass
class Config:
    providers: list[Provider] = field(default_factory=list)
    settings: Settings = field(default_factory=Settings)

    def provider(self, name: str) -> Provider | None:
        return next((p for p in self.providers if p.name == name), None)

    def to_dict(self) -> dict:
        return _strip_none(asdict(self))


def _strip_none(obj):
    # TOML has no null
    if isinstance(obj, dict):
        return {k: _strip_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_strip_none(v) for v in obj]
    return obj


def _build(cls, data: dict):
    known = {f.name for f in fields(cls)}
    return cls(**{k: v for k, v in data.items() if k in known})


def from_dict(data: dict) -> Config:
    cfg = _build(Config, {k: v for k, v in data.items() if k not in ("providers", "settings")})
    cfg.providers = [_build(Provider, p) for p in data.get("providers", [])]
    settings = dict(data.get("settings", {}))
    if settings.get("check_updates") is False and "check_every" not in settings:
        settings["check_every"] = "manual"      # "don't look for new versions", from before each app chose
    cfg.settings = _build(Settings, settings)
    return cfg


def load(path: Path | None = None) -> Config:
    path = path or config_dir() / "config.toml"
    if not path.exists():
        return Config()
    with path.open("rb") as f:
        return from_dict(tomllib.load(f))


def save(cfg: Config, path: Path | None = None) -> None:
    path = path or config_dir() / "config.toml"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(".tmp")
    with tmp.open("wb") as f:
        tomli_w.dump(cfg.to_dict(), f)
    os.chmod(tmp, 0o600)
    tmp.replace(path)
