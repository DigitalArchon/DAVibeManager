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
import secrets
import stat
import tempfile
import threading
import time
import tomllib
from contextvars import ContextVar
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from urllib.parse import urlparse

import tomli_w

from .llm import privacy
from .netpolicy import origin, without_password

NANOGPT_BASE_URL = "https://nano-gpt.com/api/v1"
ANTHROPIC_BASE_URL = "https://api.anthropic.com"
# The services' addresses, and which hosts and protocols are sealed, are llm/privacy.py's (DA Toolkit's copy): Tinfoil's
# own API, where every request is sealed on this computer to its attested router and its key goes to TINFOIL_KEY_ORIGIN
# alone; Chutes' OpenAI-compatible API, its proxy of Anthropic's Messages API (claude.chutes.ai) and the API its
# end-to-end encryption goes through. A Chutes endpoint offers every model Chutes lists: its -TEE ones are always sent
# end-to-end encrypted, never in the clear (chutes_tee), the others as any provider's
TINFOIL_BASE_URL = privacy.TINFOIL_BASE_URL
TINFOIL_KEY_ORIGIN = privacy.TINFOIL_ORIGIN
CHUTES_BASE_URL = privacy.CHUTES_BASE_URL
CHUTES_ANTHROPIC_URL = privacy.CHUTES_ANTHROPIC_URL
CHUTES_E2EE_ORIGIN = privacy.key_origin(privacy.CHUTES_E2EE_ORIGIN)
# Chutes' own hosts, a fixed list: a key entered for one of them goes to any of them, over https, and nowhere else (the
# one stated exception to "a key goes only to the origin it was entered for": the cross-app standard, Nov 15 2026)
CHUTES_KEY_ORIGINS = privacy.CHUTES_KEY_ORIGINS
# what a provider's chat endpoint speaks (Provider.chat_api): "auto" reads it from the address (chat_api_of). "tinfoil"
# seals every request; an endpoint on one of Tinfoil's hosts speaks it whatever the field says: when in doubt, sealed
# (a plain request there would carry the text in the clear)
CHAT_APIS = ("auto", "openai", "tinfoil")
APP_ID = "davibemanager"
# NanoGPT models. The defaults are GLM 5.3, routed by NanoGPT (included in a NanoGPT subscription);
# GLM 5.3 can't see images, GLM 5.3 Flash can and is fast
DEFAULT_MODEL = "z-ai/glm-5.3"
DEFAULT_FAST_MODEL = "z-ai/glm-5.3-flash"
# where the assistant's Claude Code compacts the conversation (summarises it, and goes on): it's told
# (CLAUDE_CODE_MAX_CONTEXT_TOKENS), as for a model name it doesn't know it assumes 200K. Settings
# offers these; the usual models hold 1M
CONTEXTS = (200_000, 400_000, 1_000_000)
# how hard the assistant thinks (Settings.builder_reasoning): one setting for every model, each sent
# the nearest it takes (llm/params.py)
BUILDER_EFFORTS = ("low", "medium", "high", "max")
BUILDER_EFFORT = "low"
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
    # where the API key stored for it was entered for: the origins (scheme, host, port: netpolicy.origin) of its
    # addresses when it was. The key goes to those alone (models.key_problem_for): an address changed by hand, or
    # through the API, doesn't take the key with it. None until it is known (read from an older config.toml:
    # settle_key_origins gives it the addresses beside it)
    key_for: list[str] | None = None
    # its key may go over plain http to another machine on the local network (netpolicy.in_the_clear), where
    # anyone on that network can read it: set by hand beside the address in config.toml (`key_over_http =
    # true`), there being no field for the address in the window; without it such a key isn't sent
    # (models.key_problem_for). Never set for one already sending its key so before this was asked: it is held back
    # until the line is added (the author, Nov 14 2026: nothing is grandfathered)
    key_over_http: bool = False
    # the origins the user said No to sending the saved key to (Settings asks once for an address changed without a
    # new key, No the default): not asked again at each save, until they ask (the cross-app standard, Nov 2026)
    key_declined: list[str] = field(default_factory=list)
    # what its chat endpoint speaks: "auto" (from the address), "openai" or "tinfoil" (CHAT_APIS). Never less than its
    # address says: a host of Tinfoil's is sealed whatever this is (sealed_service)
    chat_api: str = "auto"

    def origins(self) -> list[str]:
        """The origins its key would go to now: its chat endpoint's and the assistant's."""
        return sorted({origin(url) for url in (self.base_url, self.builder_url) if url} - {""})

    def sealed_service(self) -> str:
        """The end-to-end encrypted protocol every request to its chat endpoint must be sealed in ("tinfoil"), or ""."""
        return sealed_service(self.base_url, self.chat_api)

    def service(self) -> str:
        """Which service it is, as its addresses say (service_of)."""
        return service_of(self)


def _host_of(url: str) -> str:
    """An address's host as a request would reach it: lowercased, a trailing dot gone ("inference.tinfoil.sh." is the
    same machine)."""
    try:
        return (urlparse(str(url or "").strip()).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _under(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def _api(api: str) -> str:
    """Provider.chat_api as llm/privacy.py reads it: "auto" is its "" (from the address)."""
    return "" if api == "auto" else api


def sealed_service(base_url: str, api: str = "auto") -> str:
    """The end-to-end encrypted protocol a chat endpoint must be spoken in ("tinfoil"), or "": the one `api` names, else
    the one its host is known for, whatever `api` says (privacy.sealed_service). When in doubt, sealed."""
    return privacy.sealed_service(base_url, _api(api))


def chat_api_of(p: Provider) -> str:
    """What `p`'s chat endpoint speaks: a sealed protocol where its field or its host says so, else "openai"."""
    return sealed_service(p.base_url, p.chat_api) or "openai"


on_chutes = privacy.on_chutes
is_tee_id = privacy.is_tee_id
chutes_tee = privacy.chutes_tee


def service_of(p: Provider) -> str:
    """Which service a provider is, as its addresses say, whatever button added it (an address typed, or one an
    older config.toml had): "nanogpt", "anthropic", "tinfoil", "chutes", or "" for any other. What its key, its
    sealing and its model presets follow."""
    if p.sealed_service():
        return p.sealed_service()
    hosts = {_host_of(u) for u in (p.base_url, p.builder_url) if u}
    if any(_under(h, "nano-gpt.com") for h in hosts):
        return "nanogpt"
    if any(on_chutes(u) for u in (p.base_url, p.builder_url) if u):
        return "chutes"
    if any(_under(h, "anthropic.com") for h in hosts):
        return "anthropic"
    return ""


def privacy_of(p: Provider | None, model: str) -> privacy.Privacy:
    """How private `model` is on `p` (privacy.privacy_at: kind, service, level), judged at its chat address, else the
    assistant's; with no provider, by the id alone."""
    if p is None:
        return privacy.privacy_at(model)
    return privacy.privacy_at(model, p.base_url or p.builder_url, _api(p.chat_api))


def model_sealing(p: Provider, model: str) -> str:
    """How a request for `model` on `p` must be sealed: "nanogpt-private" (a private/ model: NanoGPT's Private Mode),
    "tinfoil" (any model on a Tinfoil endpoint), "chutes" (a Chutes -TEE model), or "" for one sent as it is. Never
    less than the addresses say: when in doubt, sealed."""
    found = privacy_of(p, model)
    return found.service if found.sealed else ""


def key_reaches(key_for: list[str] | None, where: str) -> bool:
    """Whether a key entered for `key_for` may go to the origin `where`: one of those, or, for a key entered for one of
    Chutes' own hosts, any of them (privacy.key_may_go: CHUTES_KEY_ORIGINS, all https)."""
    if key_for is None:
        return True
    return where in key_for or any(privacy.key_may_go(o, where) for o in key_for)


def model_ref(value: str) -> tuple[str, str]:
    """A setting that holds a model, "provider|model" or a bare model id (the assistant's provider): (the provider
    named, or ""; the model id). Model ids never hold "|", and a provider's name can't (Models.save_provider)."""
    name, bar, model = str(value or "").strip().partition("|")
    return (name.strip(), model.strip()) if bar else ("", name)


# The buttons Settings → AI providers adds one with (the window builds them from this): each fills in the addresses,
# the key's header and the name; the key is then typed beside them. Recognised from its address afterwards, not from
# the button (service_of), so a provider typed by hand is the same as one added here.
PROVIDER_PRESETS: tuple[dict, ...] = (
    {"id": "nanogpt", "label": "Add NanoGPT", "name": "NanoGPT", "base_url": NANOGPT_BASE_URL,
     "builder_url": NANOGPT_BASE_URL, "builder_auth": "bearer", "chat_api": "auto", "primary": True,
     "key_link": "https://nano-gpt.com/api",
     "note": "Every model NanoGPT offers, for the assistant and for second opinions: GLM 5.3 (included in a NanoGPT "
             "subscription), private models sealed end to end, TEE models and Claude."},
    {"id": "anthropic", "label": "Add Anthropic", "name": "Anthropic", "base_url": "",
     "builder_url": ANTHROPIC_BASE_URL, "builder_auth": "x-api-key", "chat_api": "auto",
     "note": "Claude from Anthropic itself, for the assistant (its Claude Code speaks Anthropic's Messages API). It "
             "has no chat endpoint here, so it can't give second opinions: they come from another provider."},
    {"id": "tinfoil", "label": "Add Tinfoil", "name": "Tinfoil", "base_url": TINFOIL_BASE_URL, "builder_url": "",
     "builder_auth": "bearer", "chat_api": "tinfoil",
     "note": "Tinfoil's own API, end-to-end encrypted (preliminary): every request is sealed on this computer to the "
             "key of Tinfoil's attested router, over a connection pinned to its attested TLS key. Highest privacy. "
             "Your Tinfoil key goes to https://inference.tinfoil.sh alone."},
    {"id": "chutes", "label": "Add Chutes", "name": "Chutes", "base_url": CHUTES_BASE_URL,
     "builder_url": CHUTES_ANTHROPIC_URL, "builder_auth": "bearer", "chat_api": "auto",
     "note": "Every model Chutes lists. Its -TEE models are always sent end-to-end encrypted to an attested instance "
             "(partial privacy, preliminary: the program holding the key is Chutes' signed, closed library, not "
             "measured); its others aren't private. Your Chutes key goes to Chutes' own three hosts alone."},
    {"id": "openai", "label": "Add other (OpenAI-compatible)", "name": "", "base_url": "", "builder_url": "",
     "builder_auth": "bearer", "chat_api": "openai",
     "note": "A service that speaks OpenAI's chat completions at its own address (https://, or http:// only on this "
             "computer and your local network). The assistant's requests are translated for it."},
    {"id": "anthropic-compatible", "label": "Add other (Anthropic-compatible)", "name": "", "base_url": "",
     "builder_url": "", "builder_auth": "x-api-key", "chat_api": "auto",
     "note": "A service that speaks Anthropic's Messages API (/v1/messages) at its own address: the assistant's "
             "requests are passed on to it as they are, for any of its models. Give it a chat address too if it has "
             "one, for second opinions and pictures."},
)

# The usual choices for the assistant on each service (Settings → The assistant): each sets the assistant's models,
# and a reviewer on the same provider where it names one. A preset is shown for a provider of its `service`
# (service_of). `sealed`: every model of it is private, and it's only shown as chosen while all of the assistant's are.
MODEL_PRESETS: tuple[dict, ...] = (
    {"id": "glm", "service": "nanogpt", "label": "GLM 5.3",
     "note": "Included with a NanoGPT subscription. Screenshots are described to it by GLM 5.3 Flash.",
     "settings": {"builder_model": DEFAULT_MODEL, "builder_small_model": DEFAULT_FAST_MODEL,
                  "builder_vision_model": DEFAULT_FAST_MODEL}},
    {"id": "private", "service": "nanogpt", "label": "Private GLM 5.3", "sealed": True,
     "note": "End-to-end encrypted: only an attested enclave can read what it sees, its quick tasks and second "
             "opinions too. Screenshots are described to it by private DeepSeek V4.1 Flash, sealed the same way. Paid "
             "per use.",
     "settings": {"builder_model": PRIVATE_MODEL, "builder_small_model": "",
                  "builder_vision_model": "private/deepseek-v4-1-flash"},
     "review_model": PRIVATE_MODEL},
    {"id": "claude", "service": "nanogpt", "label": "Claude Opus 5.5",
     "note": "The strongest, especially for building apps. Paid per use; NanoGPT passes what it sees to Anthropic.",
     "settings": {"builder_model": CLAUDE_MODEL, "builder_small_model": ""}},
    {"id": "tinfoil-glm", "service": "tinfoil", "label": "GLM 5.3, end-to-end encrypted",
     "note": "Highest privacy: sealed to Tinfoil's attested router, its quick tasks and second opinions too. It can't "
             "see screenshots. Paid per use.",
     "settings": {"builder_model": "glm-5-3", "builder_small_model": "", "builder_vision_model": ""},
     "review_model": "glm-5-3"},
    {"id": "chutes-kimi", "service": "chutes", "label": "Kimi K3 (TEE), end-to-end encrypted",
     "note": "Partial privacy: sealed to an attested Chutes instance, its quick tasks and second opinions too, but the "
             "program holding the key is Chutes' own signed library, not measured. Paid per use.",
     "settings": {"builder_model": "moonshotai/Kimi-K3-TEE", "builder_small_model": "", "builder_vision_model": ""},
     "review_model": "moonshotai/Kimi-K3-TEE"},
    {"id": "chutes-glm", "service": "chutes", "label": "GLM 5.3 (not private)",
     "note": "Chutes reads what it is sent, as any provider of an ordinary model does. Paid per use.",
     "settings": {"builder_model": "zai-org/GLM-5.3", "builder_small_model": ""}},
    {"id": "anthropic-opus", "service": "anthropic", "label": "Claude Opus 5.5",
     "note": "The strongest, especially for building apps, from Anthropic itself. Paid per use.",
     "settings": {"builder_model": "claude-opus-5-5", "builder_small_model": "", "builder_vision_model": ""}},
)


def provider_defaults(p: Provider) -> Provider:
    """Fill in the builder endpoint for the providers we know: NanoGPT serves Anthropic's Messages API on its chat
    base, Anthropic itself at api.anthropic.com (its key in x-api-key), and Chutes through its own proxy at
    claude.chutes.ai (its key as a bearer token). A Tinfoil endpoint has none: its every request is sealed, so the
    assistant's go through the app's translation (gateway.py) and are sealed with the rest."""
    host = (urlparse(p.base_url or p.builder_url).hostname or "").lower()
    if host in ("nano-gpt.com", "api.nano-gpt.com") and not p.builder_url:
        p.builder_url, p.builder_auth = p.base_url, "bearer"
    elif host == "api.anthropic.com" and not p.builder_url:
        p.builder_url, p.builder_auth = ANTHROPIC_BASE_URL, "x-api-key"
    elif p.base_url and on_chutes(p.base_url) and not p.builder_url:
        p.builder_url, p.builder_auth = CHUTES_ANTHROPIC_URL, "bearer"
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
    # "provider|model" of the reviewer; empty = none (no second opinions). The first run sets NanoGPT's GLM 5.3
    # (Engine.quick_setup); a private assistant's must be private too (Engine._privacy_settings_check)
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
    # how hard the assistant thinks: "low" (the default), "medium", "high" or "max" (BUILDER_EFFORTS),
    # for every model, each sent the nearest it takes (llm/params.py: GLM 5.3 takes no medium, and
    # reasons at its default, max, when sent one, so it is sent high; Claude its own effort and
    # thinking), and Claude Code in the sandbox started at it. Never "none": with thinking off GLM
    # reasons even more (into its answer). Medium since Nov 10 2026 (was high), low since Nov 17 2026:
    # in DA Private Coder's live test of GLM-5.3 in Claude Code (four coding tasks, each twice at low and
    # at high, scored by tests the model never saw) both passed every test, and high took about four
    # times as long. A saved choice stays
    builder_reasoning: str = BUILDER_EFFORT
    # the conversation's size, in tokens, where the assistant's Claude Code compacts it (CONTEXTS):
    # every request sends the whole conversation, so a bigger one costs more each time
    builder_context: int = CONTEXTS[0]
    # which of NanoGPT's hosts runs a model, by model id (llm/routes.py): {"priority": "speed" |
    # "latency" | "throughput" | "price" | "host", "fp8": bool, "host": id}. None for a model means
    # NanoGPT's own choice (on a subscription, included). Any route is paid per use
    model_routes: dict = field(default_factory=dict)
    # after a TEE reply whose receipt holds, name the provider that ran its model, from RedPill's public
    # record of its gateway's session (llm/tee.py served_by), beside the reply's mark in Sandbox activity.
    # Off by default: it connects to api.redpill.ai directly, not through NanoGPT, so RedPill sees this
    # computer's address (SealedLore's, the author's, Nov 11 2026: a clear choice in Settings)
    tee_name_upstreams: bool = False
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
    # whether the user has chosen between that and the best results (Settings → Web searches): until
    # they have, a private assistant (a private/ model) keeps nothing (apply_search_default)
    search_retention_chosen: bool = False
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


def apply_search_default(settings: Settings) -> None:
    """A private assistant searches with Linkup, which keeps nothing, until the user chooses otherwise:
    its chats are sealed, and its searches are the one thing of them that isn't."""
    if not settings.search_retention_chosen and str(settings.builder_model or "").strip().lower().startswith("private/"):
        settings.search_zero_retention = True


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
    if cfg.settings.builder_context not in CONTEXTS or isinstance(cfg.settings.builder_context, bool):
        cfg.settings.builder_context = CONTEXTS[0]      # a hand-edited size Settings doesn't offer
    for p in cfg.providers:
        if p.chat_api not in CHAT_APIS:
            p.chat_api = "auto"         # a hand-edited protocol there's no client for: read from the address again
    if cfg.settings.builder_reasoning not in BUILDER_EFFORTS:
        cfg.settings.builder_reasoning = BUILDER_EFFORT  # likewise a level ("xhigh", "none")
    apply_search_default(cfg.settings)
    if settle_key_origins(cfg):
        cfg.__dict__["_origins_settled"] = True     # app.main saves it at once: an edit after it can't take the key
    return cfg


def settle_key_origins(cfg: Config) -> bool:
    """A key saved before keys were held to an address takes the origins of the addresses saved beside it, with no
    question (the design every DA app keeps, Nov 2026): from then on a changed address doesn't take it along. True
    if any did, so config.toml should be saved again."""
    settled = False
    for p in cfg.providers:
        if p.key_for is None:
            # a key that went over plain http to another machine before this was asked is not taken as agreed to
            # (nothing is grandfathered, Nov 14 2026): held back until `key_over_http = true` is added beside it
            p.key_for, settled = p.origins(), True
    return settled


def load(path: Path | None = None) -> Config:
    path = path or config_dir() / "config.toml"
    if not path.exists():
        return Config()
    with path.open("rb") as f:
        return from_dict(tomllib.load(f))


def load_or_set_aside(path: Path | None = None) -> tuple[Config, str]:
    """The config, or, when it can't be read, the defaults and why: the file is kept beside itself
    (config.toml.broken-<time>) and never overwritten, and the app still starts, with a banner (Engine.ui_notice).
    Until Nov 2026 a file that couldn't be read (a hand edit's stray quote, a provider without its address) ended
    the app in a traceback before any window: started from its menu, nothing came up at all. (DA Toolkit's.)"""
    path = path or config_dir() / "config.toml"
    try:
        return load(path), ""
    except Exception as e:  # noqa: BLE001 - a hand-edited file can be wrong in any way at all
        kept = path.with_name(f"{path.name}.broken-{time.strftime('%Y%m%d-%H%M%S')}")
        try:
            path.replace(kept)
        except OSError:
            return Config(), f"{path} couldn't be read ({e}). DA Vibe Manager started with default settings."
        return Config(), (f"{path.name} couldn't be read ({e}), so DA Vibe Manager started with default settings. The "
                          f"file is kept as {kept}: fix it, quit, and put it back as {path.name}.")


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
    had = kept.pop(setting, None)
    try:
        forget_password(setting)
    except creds.KeyringUnavailable:
        if had is not None:
            kept[setting] = had             # still the keyring's, and still left out of the file
            raise                           # one the user just took out must go: nothing is saved until it can
        # none known: an address without one is saved as it is, whatever the keyring says now


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


_SAVING = threading.Lock()          # one save at a time: the loop's, and a timer's or a thread's


def write_private(path: Path, data: bytes | str, mode: int = 0o600) -> None:
    """`data` (bytes, or text as UTF-8) as the file `path`, whole or not at all, readable by this user alone. It is
    written to a temporary file of its own in the same folder (two saves never share one, and it is 0600 from the
    start: mkstemp), flushed to the disk, and only then renamed over `path`; then the folder is flushed, so the
    rename outlasts a power cut too. Until Nov 2026 every save wrote one fixed config.tmp under the umask and only
    then made it 0600, flushed nothing (a crash soon after a save could leave the new name on an empty file), and
    two saves at once wrote into the same file (DA Toolkit's config.write_atomic). The one way every file that
    matters is written (the cross-app standard, Nov 2026): settings, chats, apps, builds' records, sync's state,
    the sandbox's wrapper. `mode`: another, for a file that must be run (0700) or read by the desktop (0644), set
    before it is in place."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            if mode != 0o600:
                os.fchmod(f.fileno(), mode)
            os.fsync(f.fileno())
        os.replace(name, path)
    except BaseException:
        try:
            os.unlink(name)
        except OSError:
            pass
        raise
    _flush_folder(path.parent)


def put_in_place(tmp: Path, path: Path) -> None:
    """A file written whole at `tmp` (in `path`'s folder, by a copy or another program), flushed to the disk and
    only then renamed over `path`, the folder flushed after, as write_private does for what it writes itself."""
    fd = os.open(tmp, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    _flush_folder(path.parent)


def spare_name(path: Path) -> Path:
    """A temporary name beside `path` that no other write shares (a fixed ".part" was one for every copy)."""
    return path.with_name(f".{path.name}.{secrets.token_hex(6)}.part")


def _flush_folder(folder_path: Path) -> None:
    try:
        folder = os.open(folder_path, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(folder)
    except OSError:
        pass                            # a file system that can't flush a folder: the file itself is on the disk
    finally:
        os.close(folder)


def private_folder(path: Path) -> Path:
    """`path`, a folder this user alone can open: made 0700, its parents too where they are made here, and made so
    again if it isn't (mkdir's mode is for the last folder it makes, and one made by an older version, by another
    program or by hand, took the umask's). The settings, data and state folders, and sync's."""
    missing = [p for p in (path, *path.parents) if not p.exists()]
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    for made in missing:
        try:
            os.chmod(made, 0o700)
        except OSError:
            pass
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        os.chmod(path, 0o700)
    return path


def private_folders() -> None:
    """The app's own folders (settings, data, state), this user's alone, whatever they were: at every start."""
    for folder in (config_dir(), data_dir(), state_dir()):
        try:
            private_folder(folder)
        except OSError:
            pass


def state_dir() -> Path:
    """$XDG_STATE_HOME/davibemanager: tor's own files for sync (its guards, its consensus)."""
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(base) / APP_ID


def save(cfg: Config, path: Path | None = None) -> None:
    """config.toml, written whole or not at all (write_private), in a folder only this user can open: made 0700,
    and made so again if it isn't (mkdir's mode is for a folder it makes, and one made by an older version, or by
    hand, took the umask's)."""
    path = path or config_dir() / "config.toml"
    private_folder(path.parent)
    data = tomli_w.dumps(_on_disk(cfg)).encode("utf-8")
    with _SAVING:
        write_private(path, data)
