"""Persistent configuration. Never holds secrets - those live in the OS keyring (see creds.py).

That goes for a password written into an address too (a provider's endpoint behind one,
https://user:pass@host/v1, or a package mirror's): config.toml has the address without it, and the
keyring the address as typed, under "<setting>_with_password" (address_settings, take_passwords,
keep_password). It is put back together only while the file's address is that one less its password,
so a password goes to no address but the one it was typed for, whatever the file is edited to; taking
the password out in Settings takes it out of the keyring. An address an older version left in the file
with its password is moved to the keyring at the next start, and out of the file once the keyring has
it; with no keyring to take it, it stays in the file and is used, as before. (DA Assistant's rule for
its addresses, 729a415, Nov 2026.)"""

from __future__ import annotations

import os
import tomllib
from contextvars import ContextVar
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from urllib.parse import urlparse

import tomli_w

from .netpolicy import without_password

NANOGPT_BASE_URL = "https://nano-gpt.com/api/v1"
ANTHROPIC_BASE_URL = "https://api.anthropic.com"
APP_ID = "davibemanager"
# NanoGPT models. The defaults are GLM 5.3, routed by NanoGPT (included in a NanoGPT subscription);
# GLM 5.3 can't see images, GLM 5.3 Flash can and is fast
DEFAULT_MODEL = "z-ai/glm-5.3"
DEFAULT_FAST_MODEL = "z-ai/glm-5.3-flash"
PRIVATE_MODEL = "private/glm-5-3"          # NanoGPT Private Mode: end-to-end encrypted (paid)
CLAUDE_MODEL = "anthropic/claude-opus-5.5"
# how often an app's official source is asked for new releases (each app can choose its own)
CHECK_EVERY = ("day", "week", "month", "manual")
# when a new release is built with the user's changes: when they say so, at the quiet time, or at once
REBUILD = ("ask", "scheduled", "auto")
# where the sandbox's image gets its packages if the snapshot server is unavailable (Settings.image_fallback)
IMAGE_FALLBACKS = ("", "archive", "mirror")
# the window's colours; "system" follows the desktop's light or dark preference
THEMES = ("dark", "light", "system")
WINDOW_BACKGROUND = {"dark": "#111418", "light": "#f4f6f9", "system": "#111418"}


# Tests only: a computer of its own, its config and data folders, for the task that sets it and every
# task it starts (sync's tests run two computers in one process). Never set otherwise.
ROOTS: ContextVar[tuple[Path, Path] | None] = ContextVar("dvm_roots", default=None)


def config_dir() -> Path:
    if (roots := ROOTS.get()) is not None:
        return roots[0]
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / APP_ID


def data_dir() -> Path:
    if (roots := ROOTS.get()) is not None:
        return roots[1]
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
    # how hard a model other than Claude reasons before it answers: "low", "medium" or "high", each
    # model sent the nearest it takes (llm/params.py: GLM 5.3 takes no medium, and reasons at its
    # default, max, when sent one). None is called recommended: for building, it's up to the user.
    # Never "none": with thinking off GLM reasons even more (into its answer)
    builder_reasoning: str = "high"
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
    # where the sandbox's image gets its packages when Ubuntu's snapshot server (the pinned, dated archive)
    # is unavailable: "" (nowhere else: the build waits and says why), "archive" (Ubuntu's live archive)
    # or "mirror" (image_mirror: a mirror of the Ubuntu archive, https, or http on the local network).
    # Either way apt checks every package against Ubuntu's key; only the snapshot gives the pinned versions
    image_fallback: str = ""
    image_mirror: str = ""
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
    # whether a build waiting for the quiet time may start while the computer runs on its battery (a build
    # the user starts, or one set to straight away, doesn't wait)
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
    # search with Linkup only, the one provider NanoGPT allows under Zero Data Retention (it keeps
    # nothing), and never with another, whatever the providers above. It finds less. No search is
    # end-to-end encrypted either way: NanoGPT and the provider read every query
    search_zero_retention: bool = False
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
    # the app window's size as the user last left it (app.py); 0: the default
    window_width: int = 0
    window_height: int = 0


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


# ---- passwords written into addresses: in the keyring, never in config.toml

ADDRESS_KIND = "address"          # the keyring's (creds.py) kind for an address kept as typed


def address_settings(cfg: Config) -> list[tuple[str, object, str]]:
    """Every setting that is an address a password can be written into: (its name in the keyring,
    the object holding it, its attribute)."""
    found: list[tuple[str, object, str]] = [("image_mirror", cfg.settings, "image_mirror")]
    for p in cfg.providers:
        found += [(f"provider:{p.name}:base_url", p, "base_url"), (f"provider:{p.name}:builder_url", p, "builder_url")]
    return found


def _secret_name(setting: str) -> str:
    return f"{setting}_with_password"


def _kept(cfg: Config) -> dict[str, str]:
    """The addresses with passwords the keyring is known to hold, by setting: config.toml has each
    without its password (save)."""
    return cfg.__dict__.setdefault("_with_passwords", {})


def take_passwords(cfg: Config) -> bool:
    """Each address as it was typed: the file's, with the password the keyring has for exactly it. One
    the file has a password in (written by an older version, or by hand) is moved to the keyring. A
    keyring that can't be read or written leaves things as they are, to be tried again once it can
    (Engine.retry_keyring). True if a password moved, so the file should be saved again."""
    from . import creds

    kept, moved = _kept(cfg), False
    for setting, holder, attr in address_settings(cfg):
        written = str(getattr(holder, attr) or "")
        if not written:
            continue
        try:
            if without_password(written) != written:
                if kept.get(setting) != written:
                    creds.set_secret(ADDRESS_KIND, _secret_name(setting), written)
                    kept[setting] = written
                    moved = True
            elif setting not in kept:
                stored = creds.get_secret(ADDRESS_KIND, _secret_name(setting)) or ""
                if stored and without_password(stored) == written:
                    setattr(holder, attr, stored)
                    kept[setting] = stored
        except creds.KeyringUnavailable:
            continue
    return moved


def keep_password(cfg: Config, setting: str, address: str) -> None:
    """An address the user has just set: with a password written into it, the address as typed goes to
    the keyring (config.toml will have it without); with none, any kept for this setting is taken out.
    Raises creds.KeyringUnavailable when the keyring can't do that: as with an API key, nothing of it is
    written then."""
    from . import creds

    kept = _kept(cfg)
    if without_password(address) != address:
        creds.set_secret(ADDRESS_KIND, _secret_name(setting), address)
        kept[setting] = address
        return
    kept.pop(setting, None)
    forget_password(setting)


def forget_password(setting: str) -> None:
    """The address kept for `setting` taken out of the keyring (a provider removed or renamed, a
    password taken out of its address). Raises creds.KeyringUnavailable when the keyring can't say."""
    from . import creds

    if creds.get_secret(ADDRESS_KIND, _secret_name(setting)) is not None:
        try:
            creds.delete_secret(ADDRESS_KIND, _secret_name(setting))
        except Exception as e:  # noqa: BLE001 - locked, or gone: said as the keyring's
            raise creds.KeyringUnavailable(f"Your keyring couldn't remove the address's password: {e}") from e


def _on_disk(cfg: Config) -> dict:
    """What config.toml holds of `cfg`: every address whose password the keyring has, without it."""
    data = cfg.to_dict()
    kept = _kept(cfg)
    if data.get("settings", {}).get("image_mirror") and kept.get("image_mirror") == data["settings"]["image_mirror"]:
        data["settings"]["image_mirror"] = without_password(data["settings"]["image_mirror"])
    for p in data.get("providers", []):
        for attr in ("base_url", "builder_url"):
            if p.get(attr) and kept.get(f"provider:{p.get('name')}:{attr}") == p[attr]:
                p[attr] = without_password(p[attr])
    return data


def save(cfg: Config, path: Path | None = None) -> None:
    path = path or config_dir() / "config.toml"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(".tmp")
    with tmp.open("wb") as f:
        tomli_w.dump(_on_disk(cfg), f)
    os.chmod(tmp, 0o600)
    tmp.replace(path)
