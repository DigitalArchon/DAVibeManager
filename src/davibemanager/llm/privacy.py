"""How private a model is, as a property of the endpoint it is reached through, and the addresses
of the services that make it so: Tinfoil's own API, Chutes' three hosts, NanoGPT's two kinds.

Ported from SealedLore's providers/privacy.py and the provider half of its models/config.py
(3.1.0b13, Nov 2026), without its config: every function here is given the model and the endpoint's
address and protocol, and the app decides what to do with what it says. This copy is the one DA
Vibe Manager's and DA Private Coder's llm/privacy.py are, line for line but their imports and names
(each app's test_shared_code holds them to it): a change is made here first, then copied.

A model is one of three kinds (`Privacy.kind`), the mechanism:

- "sealed": every request is sealed on this computer to an attested enclave's key; the service in
  between relays ciphertext. NanoGPT's `private/` models (its Private Mode, llm/private_mode.py),
  every model on an endpoint that speaks Tinfoil's protocol (`sealed_service`: by the endpoint's
  `api`, else its host, whatever `api` says; llm/tinfoil_direct.py), and Chutes' -TEE models on
  any of Chutes' hosts (`chutes_tee`, llm/chutes_client.py).
- "tee": the model runs in an attested enclave and its replies are signed, but the text passes
  the service in the clear: NanoGPT's `TEE/` models (llm/tee.py).
- "": anything else, Chutes' other models included.

And at one of three levels (`Privacy.level`, `level_of`; the author's ruling, Nov 15 2026), what it
is worth: "highest" (NanoGPT's `private/` models, Tinfoil), "partial" (NanoGPT's `TEE/` models,
Chutes' -TEE ones: `PRIVACY_LEVELS` says why) or "none" (not private; SealedLore's ""). A
conversation keeps to its level: it moves only to a model at its own level or higher, on any
service (`move_refusal`), and nothing of it goes where its model is less private than it was made
(`holds`).

`Privacy.service` names who seals or attests it, and so which client and which checks apply:
"nanogpt-private", "nanogpt-tee", "tinfoil", "chutes", or "" for none.

When in doubt, sealed: a sealed host is sealed whatever the model and whatever its `api` says
(`plain_refusal` keeps every plain client off it), a Chutes id that may end "-TEE" is one, and a
`private/` model on any other endpoint is still NanoGPT's Private Mode, whose client refuses to
send it anywhere but NanoGPT, as it always has. A model whose endpoint isn't known is judged by
its id alone.

Keys (the DA apps' security standard: a key goes only to the origin it was entered for): Tinfoil's
goes only to TINFOIL_ORIGIN; a Chutes key saved for one of Chutes' own hosts goes to the
endpoint's own address for Chutes' ordinary models and to CHUTES_E2EE_ORIGIN for its -TEE ones,
over https, and nowhere else (`CHUTES_KEY_ORIGINS`, `key_may_go`): the one stated exception. And
Chutes' proxy of Anthropic's Messages API (claude.chutes.ai) takes the key only as a bearer token
(`anthropic_bearer`).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlparse

from .. import netpolicy as netguard
from .tee import is_private_mode, is_tee

# --- the services' addresses -----------------------------------------------------------------

# Tinfoil's own API (llm/tinfoil_direct.py): every request sealed to its attested router.
TINFOIL_BASE_URL = "https://inference.tinfoil.sh/v1"
TINFOIL_ORIGIN = "https://inference.tinfoil.sh:443"
# Chutes: its OpenAI-compatible API, its own open-source proxy speaking Anthropic's Messages API
# (github.com/chutesai/claude-proxy, which hands each request on to the OpenAI-compatible one),
# and the API its end-to-end encryption goes through (llm/chutes_client.py).
CHUTES_BASE_URL = "https://llm.chutes.ai/v1"
CHUTES_ANTHROPIC_URL = "https://claude.chutes.ai"
CHUTES_E2EE_ORIGIN = "https://api.chutes.ai"
# Chutes' own hosts, a fixed list, as `key_origin` writes them: a Chutes key saved for one of
# them goes to the endpoint's own address for Chutes' ordinary models and to CHUTES_E2EE_ORIGIN for
# its -TEE ones, over https, and nowhere else. The one stated exception to "a key goes only to the
# origin it was entered for" (`key_may_go`).
CHUTES_KEY_ORIGINS = frozenset(
    {"https://llm.chutes.ai:443", "https://api.chutes.ai:443", "https://claude.chutes.ai:443"}
)
# Chutes' domains: a model on a host under one is judged by Chutes' rule (`chutes_tee`).
CHUTES_DOMAINS = ("chutes.ai", "chutes.dev")
# The hosts whose chat endpoints take only end-to-end encrypted requests, by domain (any host
# under it), and the protocol each speaks: Tinfoil's inference.tinfoil.sh and its routers. Read
# from the address whatever `api` says (`sealed_service`): a plain request to one would carry the
# text in the clear.
SEALED_HOSTS: dict[str, str] = {"tinfoil.sh": "tinfoil"}
# The end-to-end encrypted protocols: an endpoint speaking one seals every request.
SEALED_APIS = frozenset({"tinfoil"})
ANTHROPIC_HOST = "api.anthropic.com"
# The hosts whose chat endpoints speak Anthropic's Messages API (`chat_api`).
_ANTHROPIC_HOSTS = (ANTHROPIC_HOST, "claude.chutes.ai")
# Chutes' proxy of the Messages API says a refusal of the model's server mid-stream as text of its
# own: a text block beginning with this, then the stop reason "error" (one Anthropic's API never
# gives). Live (Nov 15 2026, SealedLore) a wrong header came back so, and was about to be kept as
# the reply.
PROXY_ERROR_TEXT = "⚠️ Backend Error"


def _host_of(base_url: str) -> str:
    """An address's host as a request would reach it: lowercase, a trailing dot gone
    ("inference.tinfoil.sh." is the same machine)."""
    try:
        return (urlparse(str(base_url or "").strip()).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _under(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def key_origin(url: str) -> str:
    """Where an address sends a key: its scheme, host and port ("https://llm.chutes.ai:443"), the port
    said when the address leaves it to its scheme, in lower case; "" for text that isn't an http(s)
    address. The form every DA app holds a saved key to (DA Toolkit's netguard.origin, DA Vibe
    Manager's netpolicy.origin, DA Private Coder's creds.origin), written here so this module needs
    none of them."""
    try:
        parsed = urlparse(str(url or "").strip())
        host, port = parsed.hostname, parsed.port
    except ValueError:
        return ""
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https") or not host:
        return ""
    port = port or (443 if scheme == "https" else 80)
    return f"{scheme}://{f'[{host}]' if ':' in host else host}:{port}"


def shown_origin(kept: str) -> str:
    """An origin as said to the user: without its scheme's own port."""
    for scheme, port in (("https", 443), ("http", 80)):
        if kept.startswith(f"{scheme}://") and kept.endswith(f":{port}"):
            return kept[: -len(f":{port}")]
    return kept


def sealed_service(base_url: str, api: str = "") -> str:
    """The end-to-end encrypted protocol an endpoint must be spoken in ("tinfoil"), or "": the one
    `api` names, else the one its host is known for, whatever `api` says. When in doubt, sealed:
    an endpoint set to "openai" on Tinfoil's host is still Tinfoil's."""
    if api in SEALED_APIS:
        return api
    host = _host_of(base_url)
    for domain, name in SEALED_HOSTS.items():
        if _under(host, domain):
            return name
    return ""


def is_tinfoil(base_url: str, api: str = "") -> bool:
    """Whether the endpoint at `base_url` speaking `api` is Tinfoil's own (`sealed_service`)."""
    return sealed_service(base_url, api) == "tinfoil"


def on_chutes(base_url: str) -> bool:
    """Whether `base_url` is one of Chutes' hosts (chutes.ai, chutes.dev and any host under them;
    a trailing dot is the same machine)."""
    host = _host_of(base_url)
    return any(_under(host, domain) for domain in CHUTES_DOMAINS)


def is_tee_id(model: str) -> bool:
    """Whether a model id names one of Chutes' TEE models: it ends "-TEE", in any case, whatever
    stray spaces, less a ":variant" after it ("Qwen/Qwen3-32B-TEE:THINKING"). Read generously,
    every ":" taken as where a variant might begin: a TEE model judged ordinary would be sent in
    the clear."""
    bare = str(model or "").strip()
    pieces = [bare] + [bare[:at] for at, char in enumerate(bare) if char == ":"]
    return any(piece.strip().upper().endswith("-TEE") for piece in pieces)


def chutes_tee(model: str, base_url: str) -> bool:
    """Whether `model` on the endpoint at `base_url` is one of Chutes' TEE models (`is_tee_id` on
    one of Chutes' hosts): always sent end-to-end encrypted to an attested Chutes instance
    (llm/chutes_client.py), never in the clear, whatever the endpoint speaks. Chutes lists exactly
    these as confidential compute (11 of its 19 models, Nov 15 2026); its other models are
    ordinary."""
    return on_chutes(base_url) and is_tee_id(model)


def chat_api(base_url: str, api: str = "") -> str:
    """The protocol a chat endpoint speaks: `api` when it names one ("openai", "anthropic",
    "tinfoil"), otherwise a sealed service's for its host (`sealed_service`), Anthropic's for its
    own host and Chutes' proxy of it, and OpenAI's for anything else. A sealed host is spoken in its
    protocol whatever `api` says."""
    sealed = sealed_service(base_url, api)
    if sealed:
        return sealed
    if api in ("openai", "anthropic"):
        return api
    host = _host_of(base_url)
    if any(_under(host, known) for known in _ANTHROPIC_HOSTS):
        return "anthropic"
    return "openai"


def is_anthropic(base_url: str) -> bool:
    """Whether `base_url` is Anthropic's own API (api.anthropic.com), as opposed to another that
    speaks its Messages API (Chutes' proxy, a compatible server)."""
    return _under(_host_of(base_url), ANTHROPIC_HOST)


def anthropic_bearer(base_url: str) -> bool:
    """Whether the Messages API at `base_url` takes the key as a bearer token
    (`Authorization: Bearer`) rather than Anthropic's `x-api-key`: Chutes' proxy (claude.chutes.ai)
    does, and only so: live (Nov 15 2026, SealedLore) an x-api-key reached its backend as nothing
    ("Authentication required")."""
    return on_chutes(base_url)


def key_may_go(saved_for: str, url: str) -> bool:
    """Whether a key saved for `saved_for` (a `key_origin`) may be sent to `url`: the origin it was
    saved for, or, for a Chutes key, any of Chutes' own hosts, over https (`CHUTES_KEY_ORIGINS`, the
    one stated exception). A key saved for no origin yet goes nowhere by this."""
    now = key_origin(url)
    if not saved_for or not now:
        return False
    if now == saved_for:
        return True
    return saved_for in CHUTES_KEY_ORIGINS and now in CHUTES_KEY_ORIGINS


# --- kinds and levels ------------------------------------------------------------------------

HIGHEST = "highest"
PARTIAL = "partial"
NOT_PRIVATE = "none"

NANOGPT_PRIVATE = "nanogpt-private"
NANOGPT_TEE = "nanogpt-tee"
TINFOIL = "tinfoil"
CHUTES = "chutes"
# The service behind each sealed protocol an endpoint may speak.
_SEALED_SERVICES = {"tinfoil": TINFOIL}
SERVICE_NAMES = {
    NANOGPT_PRIVATE: "NanoGPT's Private Mode",
    NANOGPT_TEE: "NanoGPT's TEE models",
    TINFOIL: "Tinfoil",
    CHUTES: "Chutes",
}
# Each sealed service's level: one not named here is taken as the highest, so a conversation
# recorded on it moves to nothing less.
_SEALED_LEVELS = {NANOGPT_PRIVATE: HIGHEST, TINFOIL: HIGHEST, CHUTES: PARTIAL}
_RANK = {HIGHEST: 2, PARTIAL: 1, NOT_PRIVATE: 0}
# The level's own words, leading every note that says how private a model is.
LEVEL_WORDS = {HIGHEST: "Highest privacy", PARTIAL: "Partial privacy", NOT_PRIVATE: "Not private"}
# The three levels in one sentence (the author's ruling, Nov 15 2026): in the notes and the manual.
PRIVACY_LEVELS = (
    "DA Vibe Manager names three levels of privacy: highest, end-to-end encrypted to an attested "
    "enclave whose software is measured (NanoGPT's private/ models, and Tinfoil's); partial, "
    "attested but with a gap in what is proved (NanoGPT's TEE/ models, whose text passes NanoGPT's "
    "gateway in the clear, and Chutes' -TEE models, encrypted all the way to a key that rests on "
    "software Chutes signs); and not private, every other model, whose provider can read your text."
)

E2EE_NOTE = (
    "Highest privacy. End-to-end encrypted: every message is sealed on this machine to a key only "
    "the model's attested enclave holds. NanoGPT relays ciphertext; it sees your account, the "
    "model, timing, sizes and cost, never the text."
)
TINFOIL_NOTE = (
    "Highest privacy. End-to-end encrypted, straight to Tinfoil (preliminary): every message is "
    "sealed on this machine to a key only Tinfoil's attested router enclave holds, over a "
    "connection pinned to the enclave's attested TLS key. Tinfoil sees your account, the model, "
    "timing, sizes and cost, never the text."
)
CHUTES_NOTE = (
    "Partial privacy. End-to-end encrypted to one Chutes instance (preliminary): each message is "
    "sealed on this machine to the key of an instance whose Intel TDX quote, for our nonce, binds "
    "that key, whose GPUs NVIDIA vouches for, and whose VM image is one Chutes publishes. Why "
    "partial: that only the model can read your text rests on software Chutes signs. The program "
    "that makes and holds the key (Chutes' aegis library, a closed binary) is admitted by Chutes' "
    "signature, not measured, and the list of measured images is Chutes' own. Beside NanoGPT's TEE "
    "models: your text is encrypted all the way here, where theirs passes NanoGPT's gateway in the "
    "clear; but what they attest is the enclave as measured, where here the program holding the "
    "key is outside the measurement. Replies stream, each piece held to its number, which Chutes' "
    "closed library writes: a piece dropped, repeated or out of its place is refused. Chutes sees "
    "your account, the model, timing, sizes and cost; the instance's operator, ciphertext."
)
TEE_NOTE = (
    "Partial privacy. TEE: the model runs in an attested enclave and its replies are signed, but "
    "the text passes NanoGPT's gateway in the clear."
)
# The note for one of Chutes' ordinary models (`Privacy.plain_on`).
CHUTES_PLAIN_NOTE = (
    "Not private. Chutes reads this model's text, as any provider of an ordinary model does. "
    "Chutes' -TEE models are the ones sent end-to-end encrypted (partial privacy)."
)


@dataclass(frozen=True)
class Privacy:
    kind: str = ""          # "", "tee" or "sealed"
    service: str = ""
    # A model that isn't private on a service that also has private ones (CHUTES, for its
    # ordinary models): for the note alone, never deciding anything (`service` stays "").
    plain_on: str = ""

    @property
    def sealed(self) -> bool:
        """End-to-end encrypted: never sent in the clear."""
        return self.kind == "sealed"

    @property
    def private(self) -> bool:
        """A TEE or end-to-end encrypted model: kept to its enclave, attested, its calls never
        routed or handed to another host."""
        return self.kind != ""

    @property
    def level(self) -> str:
        """How private (the author's ruling, Nov 15 2026): "highest" for NanoGPT's `private/`
        models and Tinfoil's, "partial" for NanoGPT's `TEE/` models and Chutes' -TEE ones, "none"
        for every other."""
        if self.kind == "sealed":
            return _SEALED_LEVELS.get(self.service, HIGHEST)
        if self.kind == "tee":
            return PARTIAL
        return NOT_PRIVATE

    def label(self) -> tuple[str, str]:
        """(short label, what it protects, its level's words first) for a picker or a model's
        mark, or ("", "") (a Chutes ordinary model: ("", its note))."""
        if self.service == NANOGPT_PRIVATE:
            return "🔐 End-to-end encrypted", E2EE_NOTE
        if self.service == TINFOIL:
            return "🔐 End-to-end encrypted (Tinfoil)", TINFOIL_NOTE
        if self.service == CHUTES:
            return "🔐 End-to-end encrypted (Chutes, partial)", CHUTES_NOTE
        if self.kind == "tee":
            return "TEE", TEE_NOTE
        if self.plain_on == CHUTES:
            return "", CHUTES_PLAIN_NOTE
        return "", ""

    def to_dict(self) -> dict:
        """For a page: the kind, service, level, its words, and the label and note."""
        short, note = self.label()
        return {"kind": self.kind, "service": self.service, "level": self.level,
                "level_words": LEVEL_WORDS[self.level], "label": short, "note": note}


NONE = Privacy()


def privacy_at(model: str, base_url: str = "", api: str = "") -> Privacy:
    """`model`'s privacy on the endpoint at `base_url` speaking `api`: a sealed endpoint's service
    for every model on it, Chutes' for a -TEE model on one of its hosts whatever it speaks
    (`chutes_tee`), else NanoGPT's kinds by the id (its capitals and stray spaces never make it
    less private, tee.is_tee). With no address, by the id alone."""
    sealed = sealed_service(base_url, api)
    if sealed:
        return Privacy("sealed", _SEALED_SERVICES[sealed])
    if chutes_tee(model, base_url):
        return Privacy("sealed", CHUTES)
    if is_private_mode(model):
        return Privacy("sealed", NANOGPT_PRIVATE)
    if is_tee(model):
        return Privacy("tee", NANOGPT_TEE)
    if on_chutes(base_url):
        return Privacy(plain_on=CHUTES)
    return NONE


def level_of(base_url: str, model: str, api: str = "") -> str:
    """How private `model` is on the endpoint at `base_url` speaking `api`: "highest", "partial" or
    "none" (`privacy_at`)."""
    return privacy_at(model, base_url, api).level


def level_line(privacy: Privacy) -> str:
    """The one sentence leading what a note says of `privacy`'s level."""
    if privacy.level == HIGHEST:
        return "Highest privacy: end-to-end encrypted to an attested enclave."
    if privacy.service == CHUTES:
        return ("Partial privacy: end-to-end encrypted, but to a key that rests on software Chutes "
                "signs, not on what is measured.")
    if privacy.level == PARTIAL:
        return "Partial privacy: an attested enclave, but your text passes NanoGPT's gateway in the clear."
    return "Not private: the model's provider can read your text."


# --- what a conversation was made, and must stay ---------------------------------------------

Judge = Callable[[str], Privacy]


def rank(privacy: Privacy) -> int:
    """How private, by level: 2 the highest, 1 partial, 0 not private."""
    return _RANK.get(privacy.level, 0)


def more_private(one: Privacy, other: Privacy) -> Privacy:
    """The more private of two, by level; `one` when they are as private."""
    return one if rank(one) >= rank(other) else other


def record_of(privacy: Privacy, base_url: str = "") -> dict:
    """`privacy` as a conversation keeps it (JSON), with the origin its calls go to."""
    return {"kind": privacy.kind, "service": privacy.service, "origin": key_origin(base_url)}


def held(record: object) -> Privacy:
    """The privacy a conversation was recorded with (`record_of`), or NONE for anything else."""
    if not isinstance(record, dict) or record.get("kind") not in ("", "tee", "sealed"):
        return NONE
    service = record.get("service")
    return Privacy(record["kind"], service if isinstance(service, str) else "")


def holds(kept: Privacy, found: Privacy) -> bool:
    """Whether `found`, where a call would go now, keeps what `kept` promised: at its level or
    higher, and an end-to-end encrypted one sealed by the same service, whose own client alone
    seals to it. An explicit move to another service's model (its level or higher: `move_refusal`)
    records the new one first."""
    if rank(found) < rank(kept):
        return False
    return not (kept.sealed and found.service != kept.service)


def level_phrase(privacy: Privacy) -> str:
    """Its level as a sentence says it: "the highest privacy", "partial privacy", "no privacy"."""
    return {HIGHEST: "the highest privacy", PARTIAL: "partial privacy"}.get(privacy.level, "no privacy")


def service_words(privacy: Privacy) -> str:
    """Who a model's messages go through, and its level, as a note says it."""
    if not privacy.private:
        return "not end-to-end encrypted or TEE: not private"
    name = SERVICE_NAMES.get(privacy.service, privacy.service)
    level = LEVEL_WORDS[privacy.level].lower()
    return f"{name}, end-to-end encrypted: {level}" if privacy.sealed else f"{name}: {level}"


def held_back(kept: Privacy, found: Privacy, model: str, *, origin: str = "", now: str = "",
              what: str = "This conversation", way_out: str = "") -> str | None:
    """Why nothing of a conversation recorded as `kept` goes where its `model` would go now
    (`found`, at the address `now`, "" for an endpoint that isn't set up), or None when that keeps
    its privacy (`holds`)."""
    if holds(kept, found):
        return None
    name = SERVICE_NAMES.get(kept.service, kept.service)
    began = f"end-to-end encrypted through {name}" if kept.sealed else f"on {name}"
    if origin:
        began += f" ({urlparse(origin).hostname or origin})"
    began += f", with {level_phrase(kept)}"
    if now:
        host = urlparse(netguard.shown(now)).hostname or netguard.shown(now)
        goes = f"its model {model} now goes to {host}, {service_words(found)}"
    else:
        goes = f"its model {model} names a provider that isn't set up any more"
    return f"{what} began {began}, and {goes}, so nothing was sent. {way_out}".rstrip()


# What a conversation at each level may move to, as the refusals say it.
LEVEL_CHOICES = {
    HIGHEST: "NanoGPT's private/ models or Tinfoil's",
    PARTIAL: "NanoGPT's TEE/ or private/ models, Chutes' -TEE models or Tinfoil's",
}


def move_refusal(now: Privacy, then: Privacy, new: str, *, what: str = "this conversation",
                 way_out: str = "or start a new one") -> str | None:
    """Why a conversation whose model is `now` may not move to the model `new`, which is `then`,
    or None: only to a model at its own level or higher, on any service (the author's ruling, Nov
    15 2026): one with the highest privacy to NanoGPT's private/ models or Tinfoil's, one with
    partial privacy to those, NanoGPT's TEE/ models or Chutes' -TEE ones. So a private/ one never
    moves to Chutes, nor a TEE/ one to an ordinary model."""
    if rank(then) >= rank(now):
        return None
    if then.sealed:
        name = SERVICE_NAMES.get(then.service, then.service)
        said = f"{new} is end-to-end encrypted through {name}, but has {level_phrase(then)}"
    elif then.private:
        said = f"{new} isn't end-to-end encrypted (a TEE model), so it has {level_phrase(then)}"
    elif now.level == HIGHEST:
        said = f"{new} isn't end-to-end encrypted, so it has {level_phrase(then)}"
    else:
        said = f"{new} isn't a TEE or end-to-end encrypted model, so it has {level_phrase(then)}"
    return (f"{said}, and {what} is kept to {level_phrase(now)}: choose one of "
            f"{LEVEL_CHOICES[now.level]}, {way_out}.")


def move_note(privacy: Privacy, what: str = "this conversation") -> str:
    """What a conversation at `privacy`'s level may move to, for a model list's note ("" when it
    may move to any)."""
    if privacy.level == HIGHEST:
        return (f"{what} has the highest privacy: NanoGPT's private/ and Tinfoil's end-to-end "
                "encrypted models only")
    if privacy.level == PARTIAL:
        return f"{what} has partial privacy: TEE and end-to-end encrypted models only"
    return ""


# --- the plain clients ---------------------------------------------------------------------

WAY_OUT = "Choose a model on another provider (Settings → AI providers)."


def plain_refusal(url: str, what: str = "this request", *, api: str = "", model: str = "",
                  way_out: str = WAY_OUT) -> str | None:
    """Why a client that sends in the clear must not send `what` to `url`, or None: `url`'s host
    takes only end-to-end encrypted requests, or `api` names a sealed protocol (`sealed_service`);
    or `model`, the request's own, is end-to-end encrypted on that endpoint (one of Chutes' TEE
    models on one of Chutes' hosts, `chutes_tee`, or NanoGPT's private/ ones), sent only by its own
    client. For every plain client (chat, a model list with the key, research, vision), before
    anything is sent."""
    sealed = sealed_service(url, api)
    host = urlparse(netguard.shown(url)).hostname or netguard.shown(url)
    if sealed:
        name = SERVICE_NAMES[_SEALED_SERVICES[sealed]]
        return (f"{host} is {name}'s end-to-end encrypted endpoint, and {what} would go to it in the "
                f"clear, so nothing was sent. {way_out}")
    if model and chutes_tee(model, url):
        return (f"{model.strip()} is one of Chutes' TEE models, which DA Vibe Manager sends only end-to-end "
                f"encrypted (partial privacy), through its own client: {what} would go to {host} in "
                "the clear, so nothing was sent. Choose one of Chutes' other models for this, or a "
                "model on another provider.")
    if model and is_private_mode(model):
        return (f"{model.strip()} is end-to-end encrypted and is sent only through its own client: "
                f"{what} would go to {host} in the clear, so nothing was sent.")
    return None
