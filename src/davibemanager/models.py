"""Providers and models: the assistant's (Claude Code in the sandbox, through the gateway) and
the reviewer's (outside it, for second opinions).

The reviewer reads the commands proposed for this computer and the patches of delivered apps. It is
the one the user chooses (Settings → Second opinions, or a model preset that names one); the first
run's NanoGPT key sets GLM 5.3 (Engine.quick_setup), and a private assistant's must be private too
(Engine._privacy_settings_check). TEE models are attested before anything is sent to them, and a
failed attestation means nothing is sent.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from typing import Callable

from . import config as config_mod
from . import creds
from .config import Config, Provider, provider_defaults
from .llm import capabilities
from .llm import privacy as privacy_mod
from .llm import dcap
from .llm import params as params_mod
from .llm import routes as routes_mod
from .llm import tee as tee_mod
from .llm.chutes_client import ChutesClient, ChutesE2EEClient, ChutesState, list_chutes_models
from .llm.chutes_client import listing_capabilities as chutes_capabilities
from .llm.client import LLMClient, detect_tier, is_private_mode
from .llm.errors import error_words, shown_error
from .llm.private_mode import (Enclave, PrivateModeClient, PrivateModeError, list_private_models, offers_private_mode,
                               relay_said, relay_url)
from .llm.tinfoil_direct import TinfoilDirectClient, TinfoilState
from .llm.tinfoil_direct import listing_capabilities as tinfoil_capabilities
from .netpolicy import InsecureURL, UnusableKey, check_url, in_the_clear, key_problem, origin, scrubbed, shown

# A TEE model's attestation is made again, with a fresh nonce, before a send once it is this old: on a
# clock that runs on while the computer sleeps (dcap.since_boot), so one made before a night's suspend
# isn't taken for minutes old in the morning.
TEE_REATTEST_SECONDS = 900
# a provider's model list that couldn't be read is asked for again after this long, no sooner
CAPS_RETRY_SECONDS = 30
# choose_reviewer's choice: the first private model matching one of these, in order
REVIEWER_PREFERENCE = (r"glm", r"deepseek", r"kimi", r"qwen", r"gpt-oss", r"llama", r".")


def upstream_view(upstream: tee_mod.TeeUpstream) -> dict:
    """Who ran a TEE reply's model (llm/tee.py served_by), as its check's event carries it: RedPill's record
    as read, the provider's name as the mark shows it ("Phala"), and what it means for the mark's tooltip
    (TeeUpstream.to_dict: the session it was, and whether api.redpill.ai was asked, too)."""
    return upstream.to_dict()


class OpeningPrivateModeClient(PrivateModeClient):
    """The Private Mode client as this app uses it: every stream says ("open", None) once the enclave's
    sealed reply has begun, as LLMClient's streams do once a provider has taken a request, so the gateway
    answers Claude Code then (gateway.answered) and not only at the reply's first word. The shared client
    (llm/private_mode.py, one copy with DA Toolkit's) says it when asked (`opened`); this is where it is
    asked, outside that copy."""

    def stream(self, model: str, messages: list[dict], tools: list[dict] | None = None,
               params: dict | None = None, *, opened: bool = True):
        return super().stream(model, messages, tools, params, opened=opened)


class OpeningTinfoilClient(TinfoilDirectClient):
    """Tinfoil's direct client as this app uses it: ("open", None) once the enclave's sealed reply has begun, as every
    stream the gateway reads says it (OpeningPrivateModeClient)."""

    def stream(self, model: str, messages: list[dict], tools: list[dict] | None = None,
               params: dict | None = None, *, opened: bool = True):
        return super().stream(model, messages, tools, params, opened=opened)


class OpeningChutesClient(ChutesClient):
    """One Chutes provider's chat as this app uses it: its -TEE models sealed (ChutesE2EEClient), the others through
    the plain client, and ("open", None) once a reply has begun, either way: the sealed one says it when asked, this
    app's LLMClient always does, and takes no `opened` (live, Nov 16 2026: ChutesClient's opened=True reached it as an
    argument it doesn't know, and Chutes' ordinary models failed)."""

    def stream(self, model: str, messages: list[dict], tools: list[dict] | None = None,
               params: dict | None = None, *, opened: bool = True):
        if self.sealed(model):
            return self.e2ee.stream(model, messages, tools, params, opened=opened)
        if self.plain is None:
            raise UserError(f"{model} isn't one of Chutes' TEE models, and this provider has no chat address to send "
                            "it to (Settings → AI providers).")
        return self.plain.stream(model, messages, tools, params)


def listed_caps(caps: dict[str, dict]) -> dict[str, dict]:
    """Tinfoil's or Chutes' listing (their listing_capabilities) in this app's shape (capabilities.parse): each price
    per million tokens as input, output and cache reads and writes, as NanoGPT's are kept."""
    out = {}
    for model_id, entry in caps.items():
        p = entry.get("pricing") or {}
        price = None
        if isinstance(p.get("prompt"), (int, float)) and isinstance(p.get("completion"), (int, float)):
            read = p.get("input_cache_read")
            price = {"input": float(p["prompt"]), "output": float(p["completion"]),
                     "cache_read": float(read) if isinstance(read, (int, float)) else float(p["prompt"]),
                     "cache_write": float(p["prompt"])}
        out[model_id] = {**entry, "efforts": [e for e in entry.get("efforts") or [] if e in capabilities.EFFORTS],
                         "pricing": price, "included": False}
    return out


class UserError(Exception):
    """An error to show the user as-is."""


class KeyringWait(UserError):
    """The key may well be stored, but the keyring can't be read yet (e.g. just after login)."""


class KeyHeldBack(UserError):
    """The key is stored, but isn't sent (key_problem_for): its words say why and the way out."""


def key_problem_for(prov: Provider) -> str | None:
    """Why the key stored for `prov` isn't sent with its requests, or None: it was entered for other addresses
    than the provider has now (Provider.key_for). An address changed in Settings without the key, in config.toml by
    hand, or through the API, never takes the key with it: the key would go, with everything sent, to whatever the
    new address is. Nothing is deleted; entering the key again for the new address, saying Yes to using it there
    (Settings asks), or putting the address back, sends it again (the design every DA app keeps, Nov 2026; DA
    Private Coder's creds.account keys it by host and port). One stated exception: a key entered for one of Chutes'
    own hosts goes to any of them (config.key_reaches). And Tinfoil's key goes to Tinfoil's own API alone."""
    clear = [url for url in (prov.base_url, prov.builder_url) if url and in_the_clear(url)]
    if clear and not prov.key_over_http:
        # plain http to another machine on the network: anyone on it reads the key (SealedLore's keys_in_the_clear):
        # Settings asks before it is saved so, No the default; one already going so is held back until asked
        return (f"{prov.name}'s address {shown(clear[0])} is plain http to another machine on your network, so its API "
                "key would cross the network unencrypted, readable by anyone on it (a café's or a hotel's Wi-Fi too): "
                "it isn't sent. Use the server's https:// address, or, if the network is yours alone, say so in "
                f"Settings → AI providers → {prov.name} (Send it unencrypted…).")
    if prov.sealed_service() == "tinfoil" and prov.base_url and origin(prov.base_url) != config_mod.TINFOIL_KEY_ORIGIN:
        # its key opens the account at Tinfoil's own API: never to another of its hosts, nor one typed beside it
        return (f"{prov.name} is a Tinfoil endpoint at {shown(prov.base_url)}, and a Tinfoil API key goes only to "
                f"Tinfoil's own API, {shown(config_mod.TINFOIL_BASE_URL)}: it isn't sent. Set its address to that "
                "in Settings → AI providers.")
    unread = [url for url in (prov.base_url, prov.builder_url) if url and not origin(url)]
    if unread:
        # an address origin() can't read (config.toml edited by hand; Settings refuses one) is held to nothing by
        # the check below, so nothing says where its key would go: not sent
        return (f"{prov.name}'s address {shown(unread[0])[:80]!r} isn't one the app can read, so its API key isn't "
                "sent. Correct it in Settings → AI providers.")
    if prov.key_for is None:
        return None
    elsewhere = [o for o in prov.origins() if not config_mod.key_reaches(prov.key_for, o)]
    if not elsewhere:
        return None
    was = ", ".join(shown(o) for o in prov.key_for) or "no address"
    now = ", ".join(shown(o) for o in elsewhere)
    # the ways out as they work: Settings → AI providers → Edit takes the key typed again for the address in its form,
    # or asks whether to use the saved one there (Ask again: models.save_provider's use_saved_key)
    return (f"The API key saved for {prov.name} was entered for {was}, and {prov.name}'s address is now {now}: the key "
            "isn't sent there, so a changed address can't take it anywhere else. In Settings → AI providers, edit "
            f"{prov.name}: type the key again for {now}, choose Ask again to use the saved one there, or put its address "
            "back.")


def sealing_problem(prov: Provider, model: str) -> str | None:
    """Why `model` on `prov` can't be sent at all, or None: its requests must be sealed end to end (config.model_sealing)
    by a client this provider's addresses can't take. Chutes' -TEE models are sealed only through Chutes' own hosts
    (llm/chutes_client.py not_chutes). Sent any other way, the text would be read in the clear on its way, so nothing is
    sent (when in doubt, sealed)."""
    if config_mod.model_sealing(prov, model) == "chutes":
        base = prov.base_url if config_mod.on_chutes(prov.base_url) else prov.builder_url
        if origin(base) not in config_mod.CHUTES_KEY_ORIGINS:
            return (f"{model} is one of Chutes' TEE models, sent only end-to-end encrypted through Chutes' own "
                    f"addresses ({privacy_mod.CHUTES_BASE_URL} or {privacy_mod.CHUTES_ANTHROPIC_URL}), and "
                    f"{prov.name}'s isn't one: nothing was sent. Set its address in Settings → AI providers.")
    return None


class Models:
    def __init__(self, cfg: Config, *, save_config: Callable[[Config], None], emit: Callable[..., None],
                 log: Callable[..., None]):
        self.cfg = cfg
        self._save_config = save_config
        self._emit = emit                       # emit(type, **data) to the UI
        self._told_release: set[tuple[str, str]] = set()      # older router releases the user was told of
        self._told_partial: set[tuple[str, tuple]] = set()    # TEE models attested in part, the user told of
        self._log = log                         # log(event, **data) to the conversation's audit log
        self._models: dict[str, list[str]] = {}
        self._enclaves: dict[str, Enclave] = {}      # provider name -> attested enclave (Private Mode)
        self._caps: dict[str, dict[str, dict]] = {}   # provider -> model id -> capabilities
        self._caps_failed: dict[str, float] = {}      # provider -> when its list last couldn't be read
        self.caps_http = None                         # httpx client override (tests)
        self._unsupported: dict[tuple[str, str], set[str]] = {}   # generation settings a model's route refused
        self._tee: dict[tuple[str, str, str], tuple[tee_mod.TeeClient, float, dict]] = {}
        self._doubted: set[tuple[str, str, str]] = set()   # TEE models a reply of failed its check: attested again
        self._told_failed: set[tuple[str, str, str]] = set()  # ...and the user told, until one of its replies holds
        self.tee_factory: Callable | None = None      # tests: (base_url, key, model) -> TeeClient
        self.client_factory: Callable | None = None   # tests: (provider, model) -> client
        self.private_lister: Callable | None = None   # tests: base_url -> private model ids
        self._attest_lock = asyncio.Lock()
        self._hosts: dict[tuple[str, str], tuple[float, dict]] = {}   # (base, model) -> (when, NanoGPT's listing)
        self.hosts_http = None                        # httpx client override (tests)
        # per provider: Tinfoil's attested router and listing (TinfoilState), Chutes' attested instances and nonces
        # (ChutesState) and its sealing client: (what they were made for, the object), in memory only
        self._sealed: dict[str, tuple[tuple, object]] = {}
        self.listing_http = None                      # httpx client override for the keyless listings (tests)
        self._told_chutes: set[str] = set()          # Chutes models whose partial attestation the user was told of

    def _changed(self) -> None:
        self._emit("config_changed")

    # ---------------------------------------------------------------- providers

    def save_provider(self, data: dict, api_key: str | None = None, original_name: str | None = None,
                      is_new: bool = False) -> None:
        """Save a provider (Settings → AI providers, or the API). Its key is held to the addresses it is entered for
        (Provider.key_for, key_problem_for): a new key is for the addresses as saved; a saved one stays for its own,
        so an address changed without a new key doesn't take it along, unless `use_saved_key` (a JSON true) says the
        user chose to use it there (Settings asks, No the default). Their No (`use_saved_key` false) is kept for those
        addresses (Provider.key_declined), so Settings doesn't ask again at each save. A key over plain http to another
        machine is sent only with `key_over_http` (a JSON true: Settings asks first, No the default), or where it
        already went at these same addresses. `is_new`: a provider added, never one saved over another of its name."""
        name = str(data.get("name", "")).strip()
        base_url = str(data.get("base_url", "")).strip().rstrip("/")
        builder_url = str(data.get("builder_url", "")).strip().rstrip("/")
        if not name or not (base_url or builder_url):
            raise UserError("A provider needs a name and an address: a chat address (OpenAI-compatible), an address "
                            "for the assistant (Anthropic's Messages API), or both.")
        old = self.cfg.provider(original_name or name)
        if is_new and old is not None:
            raise UserError(f"There is already a provider called {name}. Give this one a name of its own (such as "
                            f"\"{name} 2\"), or edit that one.")
        if original_name and original_name != name and self.cfg.provider(name) is not None:
            raise UserError(f"There is already a provider called {name}: choose another name.")
        if "|" in name and not (old and old.name == name):
            # "provider|model" is how a setting names a model (the reviewer, the vision helper), split at the first "|"
            raise UserError("A provider's name can't contain | (it separates the provider from the model where a "
                            "setting names both).")
        chat_api = str(data.get("chat_api") or (old.chat_api if old else "auto")).strip().lower()
        if chat_api not in config_mod.CHAT_APIS:
            raise UserError(f"A chat endpoint speaks one of: {', '.join(config_mod.CHAT_APIS)}.")
        try:
            if base_url:
                check_url(base_url, "The provider's base URL")
            if builder_url:
                check_url(builder_url, "The assistant's endpoint")
        except InsecureURL as e:
            raise UserError(str(e)) from None
        api_key = (api_key or "").strip() or None        # what a paste brings around it
        if api_key and (problem := key_problem(api_key, name)):
            raise UserError(problem)                        # never stored: no request could carry it
        builder_auth = str(data.get("builder_auth", "bearer")).strip() or "bearer"
        if builder_auth not in ("bearer", "x-api-key"):
            raise UserError("The key goes in a bearer header or x-api-key.")
        overrides = {k.strip(): v.strip() for k, v in (data.get("tier_overrides") or {}).items() if k.strip()} \
            if "tier_overrides" in data or not old else dict(old.tier_overrides)
        prov = provider_defaults(Provider(
            name=name, base_url=base_url, default_model=str(data.get("default_model", "")).strip(),
            builder_url=builder_url, builder_auth=builder_auth, tier_overrides=overrides, chat_api=chat_api,
            # what the window's form doesn't show stays as it was
            vision_overrides=dict(old.vision_overrides) if old else {},
            context_overrides=dict(old.context_overrides) if old else {}))
        # a key over plain http to another machine (netpolicy.in_the_clear): only where the caller says the user
        # chose it (a JSON true), or the provider had it at these same addresses (key_problem_for)
        prov.key_over_http = data.get("key_over_http") is True or bool(
            old and old.key_over_http and old.origins() == prov.origins())
        # the key goes only where it was entered for: a new one is for these addresses; an older one stays for its
        # own, so an address changed here without it doesn't take it along (key_problem_for), unless the caller
        # says the user chose to use it there (`use_saved_key`). A provider new here has none until one is given
        use_saved = data.get("use_saved_key")
        if api_key or (old and use_saved is True):
            prov.key_for = prov.origins()
        elif old:
            prov.key_for = list(old.key_for) if old.key_for is not None else old.origins()
        else:
            prov.key_for = []
        # a No for these addresses is kept, and Settings asks no more at each save; asked again and Yes, a key typed, or
        # the address put back, it goes
        away = [o for o in prov.origins() if not config_mod.key_reaches(prov.key_for, o)]
        if old and not api_key and away and use_saved is not True:
            prov.key_declined = sorted(set(old.key_declined) | set(away)) if use_saved is False else list(old.key_declined)
        # a password written into an address goes to the keyring, as the API key does (config.py)
        renamed = bool(original_name and original_name != name and old)
        try:
            for attr in ("base_url", "builder_url"):
                address = getattr(prov, attr)
                if renamed or not old or getattr(old, attr) != address:
                    config_mod.keep_password(self.cfg, f"provider:{name}:{attr}", address)
                if renamed:
                    config_mod.forget_password(f"provider:{original_name}:{attr}")
        except creds.KeyringUnavailable as e:
            raise UserError(f"{e}. Unlock your keyring (GNOME Keyring or KWallet) and try again: a password in an "
                            "address is kept there, never in the settings file.") from None
        if original_name and original_name != name and old:
            try:
                key = creds.get_secret("provider", original_name)
                if key and not api_key:
                    creds.set_secret("provider", name, key)
            except creds.KeyringUnavailable as e:
                raise UserError(f"{e}. Unlock your keyring (GNOME Keyring or KWallet) and try again.") from None
            try:
                creds.delete_secret("provider", original_name)
            except creds.KeyringUnavailable as e:
                # the key stays under the old name, with the provider: the copy made above is taken back, so the
                # keyring doesn't hold it twice (until Nov 2026 the keyring's own error went up from here, the
                # copy left behind)
                if key and not api_key:
                    try:
                        creds.delete_secret("provider", name)
                    except creds.KeyringUnavailable:
                        pass
                raise UserError(f"{e}. Unlock your keyring (GNOME Keyring or KWallet) and try again.") from None
            s = self.cfg.settings
            if s.builder_provider == original_name:
                s.builder_provider = name
            # the settings that name a provider beside a model ("provider|model") follow it
            for setting in ("review_model", "builder_vision_model"):
                value = getattr(s, setting)
                if value.startswith(original_name + "|"):
                    setattr(s, setting, name + value[len(original_name):])
        if api_key:
            try:
                creds.set_secret("provider", name, api_key)
            except creds.KeyringUnavailable as e:
                raise UserError(f"{e}. Unlock your keyring (GNOME Keyring or KWallet) and try again.") from None
        if old and (renamed or api_key or old.base_url != prov.base_url):
            # its TEE models' attestations were made with the key and at the address it had: their clients look
            # up each reply's signature with that key, there. Attested again at the next request instead
            self._forget_tee(old.name)
        if old and (renamed or old.base_url != prov.base_url):
            self._forget_learned(old.name)      # what its models can do was read at the address it had
        if old:
            self.cfg.providers[self.cfg.providers.index(old)] = prov
        else:
            self.cfg.providers.append(prov)
        if not self.cfg.settings.builder_provider and (prov.builder_url or prov.base_url):
            self.cfg.settings.builder_provider = name       # the first provider is the assistant's
        self._models.pop(name, None)
        self._save_config(self.cfg)
        self._changed()

    def delete_provider(self, name: str) -> None:
        # the keyring first: one that can't be asked (locked, its prompt dismissed) changes nothing, and says so.
        # Until Nov 2026 its own exception went up after the provider had left memory, the settings unsaved and
        # the key still kept (DA Toolkit's Engine.delete_provider)
        try:
            creds.delete_secret("provider", name)
        except creds.KeyringUnavailable as e:
            raise UserError(f"{e}. Unlock your keyring (GNOME Keyring or KWallet) and try again.") from None
        self._forget_tee(name)
        self._forget_learned(name)
        self.cfg.providers = [p for p in self.cfg.providers if p.name != name]
        for attr in ("base_url", "builder_url"):
            try:
                config_mod.forget_password(f"provider:{name}:{attr}")
            except creds.KeyringUnavailable:
                pass                    # only what an address with its name kept: nothing uses it now
        s = self.cfg.settings
        if s.builder_provider == name:
            s.builder_provider = next((p.name for p in self.cfg.providers if p.builder_url or p.base_url), "")
        # a setting that named it beside a model is cleared: a provider added under the name later isn't the
        # reviewer's or the vision helper's for having it
        for setting in ("review_model", "builder_vision_model"):
            if getattr(s, setting).startswith(name + "|"):
                setattr(s, setting, "")
        self._save_config(self.cfg)
        self._changed()

    def _forget_learned(self, name: str) -> None:
        """Drop what was learned of provider `name`'s models at the address it had: what each can do (its
        listing), the generation settings its routes refused and its model list. Read again where it is now: a
        provider moved to another server, or another added under a deleted one's name, kept the old one's."""
        self._models.pop(name, None)
        self._caps.pop(name, None)
        self._caps_failed.pop(name, None)
        self._enclaves.pop(name, None)
        for key in [k for k in self._unsupported if k[0] == name]:
            del self._unsupported[key]

    def _forget_tee(self, name: str) -> None:
        """Drop, and close, the attested TEE clients kept for provider `name`: they were made with its key and
        at its address as they were (DA Toolkit's review, Nov 2026: a new key went unused by the checks until
        the attestation aged out). Its models are attested again before anything more is sent to them."""
        held = self._sealed.pop(name, None)
        if held is not None and callable(getattr(held[1], "close", None)):
            try:
                held[1].close()
            except Exception:  # noqa: BLE001 - it is forgotten all the same
                pass
        for key in [k for k in self._tee if k[0] == name]:
            client = self._tee.pop(key)[0]
            self._doubted.discard(key)
            self._told_failed.discard(key)
            try:
                client.close()
            except Exception:  # noqa: BLE001 - it is forgotten all the same
                pass

    def provider(self, name: str) -> Provider:
        prov = self.cfg.provider(name)
        if not prov:
            raise UserError(f"Unknown provider {name}")
        return prov

    def key(self, prov: Provider) -> str | None:
        """The provider's key, for its requests; None when none can be read. A key entered for another address
        than the provider has now is never given out: UserError, saying why and what to do (key_problem_for)."""
        try:
            key = creds.get_secret("provider", prov.name)
        except Exception:  # noqa: BLE001 - keyring locked/unavailable
            return None
        if key and (problem := key_problem_for(prov)):
            raise UserError(problem)
        return key

    def client(self, prov: Provider, model: str = ""):
        """The client for `model` on `prov`, by how private it is there (config.privacy_of, llm/privacy.py): every model
        on a Tinfoil endpoint through Tinfoil's direct client, sealed to its attested router; on a Chutes provider, its
        -TEE models sealed to an attested instance and its others plain (ChutesClient); a private/ model through
        NanoGPT's Private Mode; anything else through the plain client, which is never given a sealed host or model
        (privacy.plain_refusal)."""
        if self.client_factory:
            return self.client_factory(prov, model)
        found = config_mod.privacy_of(prov, model)
        chutes = config_mod.on_chutes(prov.base_url or prov.builder_url)
        if not prov.base_url and not (chutes and found.sealed):
            raise UserError(f"{prov.name} has no chat address, so {model or 'its models'} can't be sent through it "
                            "(Settings → AI providers).")
        if problem := sealing_problem(prov, model):
            raise UserError(problem)
        key = self.key(prov)
        try:
            if found.service == privacy_mod.TINFOIL:
                return OpeningTinfoilClient(prov.base_url, key, self._tinfoil_state(prov))
            if chutes:
                base = prov.base_url if config_mod.on_chutes(prov.base_url) else prov.builder_url
                plain = LLMClient(prov.base_url, key) if prov.base_url and not found.sealed else None
                return OpeningChutesClient(base, self._chutes_e2ee(prov, base, key), plain, http=self.listing_http)
            if is_private_mode(model):
                enclave = self._enclaves.get(prov.name)
                if enclave is None or enclave.relay != relay_url(prov.base_url):
                    enclave = self._enclaves[prov.name] = Enclave(
                        relay_url(prov.base_url), on_attested=lambda att: self._private_attested(prov, att))
                return OpeningPrivateModeClient(prov.base_url, key, enclave)
            refusal = privacy_mod.plain_refusal(prov.base_url, f"the request for {model or 'its models'}",
                                                api=config_mod._api(prov.chat_api), model=model)
            if refusal:
                raise UserError(refusal)
            return LLMClient(prov.base_url, key)
        except (InsecureURL, UnusableKey, PrivateModeError) as e:
            raise UserError(str(e)) from None

    def _held_state(self, prov: Provider, made_for: tuple, make: Callable[[], object]):
        """The object kept for `prov`'s sealed requests, made again (the old one closed) when what it was made for
        changed: its address, or its key."""
        held = self._sealed.get(prov.name)
        if held is None or held[0] != made_for:
            if held is not None and callable(getattr(held[1], "close", None)):
                try:
                    held[1].close()
                except Exception:  # noqa: BLE001
                    pass
            held = self._sealed[prov.name] = (made_for, make())
        return held[1]

    def _tinfoil_state(self, prov: Provider) -> TinfoilState:
        """One provider's attested router and listing, shared by its clients: the router attested again when old, our
        prompt cache's secret kept in memory only, per provider."""
        return self._held_state(prov, ("tinfoil", prov.base_url), lambda: TinfoilState(
            prov.base_url, plain_http=self.listing_http, on_attested=lambda att: self._sealed_attested(prov, att)))

    def _chutes_e2ee(self, prov: Provider, base: str, key: str | None) -> ChutesE2EEClient:
        """One Chutes provider's sealing client (its instances' attestations and nonces), made again for a new key or
        address. The key goes to Chutes' own hosts alone (privacy.key_may_go): its origin is the one of Chutes' hosts
        it was entered for."""
        saved_for = next((o for o in prov.key_for or [] if o in config_mod.CHUTES_KEY_ORIGINS), "")
        made_for = ("chutes", base, saved_for, hashlib.sha256((key or "").encode()).hexdigest())
        return self._held_state(prov, made_for, lambda: ChutesE2EEClient(
            base, key, key_origin=saved_for, state=ChutesState(), on_attested=lambda att: self._sealed_attested(prov, att)))

    def _sealed_attested(self, prov: Provider, att) -> None:
        """A new attestation of Tinfoil's router or of a Chutes instance: in the log; and for Chutes, once a model,
        what its partial attestation means (privacy.CHUTES_NOTE)."""
        record = att.to_dict() if callable(getattr(att, "to_dict", None)) else {"attestation": str(att)}
        self._log("sealed_attested", provider=prov.name, **{k: v for k, v in record.items() if k != "provider"})
        if getattr(att, "service", "") == "chutes" and prov.name not in self._told_chutes:
            self._told_chutes.add(prov.name)
            self._emit("toast", level="info", text=(
                f"{prov.name}: a Chutes instance was attested, partially (preliminary). " + privacy_mod.CHUTES_NOTE),
                detail="\n\n".join(getattr(att, "costs", []) or []))

    def _private_attested(self, prov: Provider, att) -> None:
        """A new attestation of the Private Mode enclave: in the log, and said once if it runs an older
        release of Tinfoil's router than the newest (still verified; NanoGPT may simply be catching up)."""
        self._log("private_enclave_attested", provider=prov.name, enclave=att.enclave, hardware=att.hardware,
                  release=att.release_tag, digest=att.release_digest, latest=att.latest_release,
                  latest_checked=att.latest_checked, key_sha256=att.hpke_key_sha256)
        if att.latest_release and (prov.name, att.release_digest) not in self._told_release:
            self._told_release.add((prov.name, att.release_digest))
            self._emit("toast", level="info", text=(
                f"Private Mode's enclave runs an older release of Tinfoil's router ({att.release_tag or att.release_digest[:12]}) "
                f"than the newest ({att.latest_release}). It's verified all the same, so what you send stays sealed; "
                "NanoGPT may not have updated it yet."))

    async def _private_ids(self, base_url: str) -> list[str]:
        if self.private_lister:
            return await self.private_lister(base_url)
        return await list_private_models(base_url)

    async def _listed(self, prov: Provider) -> dict[str, dict] | None:
        """Tinfoil's or Chutes' own public list of models, with what each can do and its prices (this app's shape:
        listed_caps), read without the key; None for any other provider."""
        service = prov.service()
        if service == "tinfoil":
            entries = await self._tinfoil_state(prov).listing.fetch()
            return listed_caps(tinfoil_capabilities(entries))
        if service == "chutes":
            return listed_caps(chutes_capabilities(await list_chutes_models(self.listing_http)))
        return None

    def tier(self, prov: Provider, model: str) -> str:
        """The model's tier as this app's checks read it: "e2ee" for any sealed one (NanoGPT's private/, Tinfoil's, a
        Chutes -TEE one), else llm/client.detect_tier's."""
        found = config_mod.privacy_of(prov, model)
        if found.sealed:
            return "e2ee"
        if found.service in ("tinfoil", "chutes"):
            return "standard"
        return detect_tier(model, prov.base_url or prov.builder_url, prov.tier_overrides)

    async def list_models(self, provider_name: str, refresh: bool = False) -> list[dict]:
        prov = self.provider(provider_name)
        if refresh or provider_name not in self._models:
            try:
                listed = await self._listed(prov)
                if listed is not None:
                    ids = sorted(listed)
                    self._caps[prov.name] = listed
                    self._caps_failed.pop(prov.name, None)
                else:
                    ids = await self.client(prov).list_models()
            except UserError:
                raise
            except Exception as e:  # noqa: BLE001
                raise UserError(f"Could not list models from {shown(prov.base_url or prov.builder_url)}: "
                                f"{scrubbed(e)}") from e
            if offers_private_mode(prov.base_url):
                try:
                    ids = sorted(set(ids) | set(await self._private_ids(prov.base_url)))
                except Exception as e:  # noqa: BLE001 - the plain models are still usable
                    self._emit("toast", level="error", text=f"Could not list Private Mode models: {scrubbed(e)}")
            self._models[provider_name] = ids
            await self._load_caps(prov)
        out = []
        for m in self._models[provider_name]:
            caps = capabilities.lookup(self._caps.get(prov.name, {}), m) or {}
            # how private each is leads its note wherever a model is chosen (the cross-app standard)
            out.append({"id": m, "tier": self.tier(prov, m), "privacy": config_mod.privacy_of(prov, m).to_dict(),
                        "reasoning": caps.get("reasoning", False), "context": caps.get("context")})
        return out

    async def _load_caps(self, prov: Provider) -> bool:
        """Read the provider's model list; whether there's one now. Tinfoil and Chutes list theirs publicly, NanoGPT
        with the key; any other provider lists nothing of what its models do: known as that. One that can't be read
        now isn't taken for an empty list: it's asked for again, CAPS_RETRY_SECONDS later at the soonest."""
        service = prov.service()
        if not offers_private_mode(prov.base_url) and service not in ("tinfoil", "chutes"):
            self._caps.setdefault(prov.name, {})
            return True
        if time.monotonic() - self._caps_failed.get(prov.name, float("-inf")) < CAPS_RETRY_SECONDS:
            return prov.name in self._caps
        try:
            listed = await self._listed(prov)
            caps = listed if listed is not None else \
                await capabilities.fetch_nanogpt(prov.base_url, self.key(prov), http=self.caps_http)
        except Exception:  # noqa: BLE001 - models still work; their limits are just unknown for now
            caps = {}
        if not caps:
            self._caps_failed[prov.name] = time.monotonic()
            return prov.name in self._caps               # an earlier list is kept
        self._caps[prov.name] = caps
        self._caps_failed.pop(prov.name, None)
        return True

    async def sees(self, prov: Provider, model: str) -> bool | None:
        """Whether `model` reads images itself: the provider's vision_overrides, else what the
        provider reports (its list loaded first if it hasn't been); a model it doesn't list, no. None
        while the list can't be read: never guessed, since a model that sees would be given
        descriptions in place of the images, and one that doesn't images it can't read."""
        override = (prov.vision_overrides or {}).get(model)
        if override in ("yes", "no"):
            return override == "yes"
        if self.known_caps(prov) is None:
            await self.load_caps(prov)
        caps = self.known_caps(prov)
        if caps is None:
            return None
        return bool((capabilities.lookup(caps, model) or {}).get("vision"))

    async def efforts(self, prov: Provider, model: str) -> tuple[str, ...] | None:
        """The reasoning efforts `model` takes: for a private model those every private model takes
        (NanoGPT's listing of its TEE twin doesn't hold for it); else what the provider lists, its list
        loaded first if it hasn't been. None when that isn't known: the effort is sent as it is."""
        if is_private_mode(model):
            return params_mod.PRIVATE_EFFORTS
        if self.known_caps(prov) is None:
            await self.load_caps(prov)
        listed = (capabilities.lookup(self.known_caps(prov) or {}, model) or {}).get("efforts")
        return tuple(listed) if listed else None

    def known_caps(self, prov: Provider) -> dict[str, dict] | None:
        """The provider's model list with capabilities and prices, once loaded (None: not yet)."""
        return self._caps.get(prov.name)

    async def load_caps(self, prov: Provider) -> None:
        if await self._load_caps(prov):
            self._changed()

    async def choose_reviewer(self) -> str:
        """Pick a private (end-to-end encrypted) NanoGPT model as the reviewer when none is set.
        Returns the setting ("provider|model"), or "" when there is no such model. Nothing in the app calls it
        now: the reviewer is the user's choice, GLM 5.3 after the first run (Engine.quick_setup)."""
        s = self.cfg.settings
        if s.review_model:
            return s.review_model
        for prov in self.cfg.providers:
            if not (prov.base_url and offers_private_mode(prov.base_url)) or key_problem_for(prov) or not self.key(prov):
                continue
            try:
                ids = [m for m in await self._private_ids(prov.base_url) if is_private_mode(m)]
            except Exception:  # noqa: BLE001 - try the next provider
                continue
            for pattern in REVIEWER_PREFERENCE:
                hit = next((m for m in sorted(ids) if re.search(pattern, m, re.I)), None)
                if hit:
                    s.review_model = f"{prov.name}|{hit}"
                    self._save_config(self.cfg)
                    self._changed()
                    return s.review_model
        return ""

    # ---------------------------------------------------------------- generation

    def params(self, prov: Provider, model: str) -> dict:
        caps = capabilities.lookup(self._caps.get(prov.name, {}), model)
        if caps and is_private_mode(model):
            caps = {**caps, "efforts": list(params_mod.PRIVATE_EFFORTS)}    # not its TEE twin's
        out = params_mod.for_model(self.cfg.settings.generation or {}, caps)
        out.update(routes_mod.body(self.route(prov, model)))
        for key in self._unsupported.get((prov.name, model), ()):
            out.pop(key, None)
        return out

    # ---------------------------------------------------------------- routes (llm/routes.py)

    def route(self, prov: Provider, model: str) -> dict | None:
        """Which of NanoGPT's hosts runs `model`, as the user chose; None for NanoGPT's own choice."""
        if not routes_mod.routable(prov.base_url, model):
            return None
        return (self.cfg.settings.model_routes or {}).get(model) or None

    HOSTS_FRESH = 600

    async def hosts(self, prov: Provider, model: str, refresh: bool = False) -> dict:
        """The hosts NanoGPT runs `model` on, with its figures for each, and the route chosen."""
        if not routes_mod.routable(prov.base_url, model):
            raise UserError(f"{model} runs where it runs: only models NanoGPT sends as they are can be given a host "
                            "(not a private, TEE or Claude model).")
        hit = self._hosts.get((prov.base_url, model))
        if refresh or not hit or time.monotonic() - hit[0] > self.HOSTS_FRESH:
            try:
                listing = await routes_mod.fetch_hosts(prov.base_url, model, http=self.hosts_http)
            except Exception as e:  # noqa: BLE001 - the reason is the user's to see
                raise UserError(f"Couldn't get NanoGPT's list of hosts for {model}: {scrubbed(e)}") from e
            hit = self._hosts[(prov.base_url, model)] = (time.monotonic(), listing)
        return {**hit[1], "route": self.route(prov, model)}

    async def set_route(self, prov: Provider, model: str, data: dict) -> dict | None:
        """Choose which host runs `model` (None: NanoGPT's own choice). A host must be one NanoGPT
        lists for it; the FP8 floor is off for a host below it, or the host would never be used."""
        try:
            route = routes_mod.clean(data)
        except ValueError as e:
            raise UserError(str(e)) from None
        if route is not None:
            listing = await self.hosts(prov, model)
            if not listing["supported"]:
                raise UserError(f"NanoGPT doesn't let you choose the host for {model}.")
            if route["priority"] == "host":
                host = next((h for h in listing["hosts"] if h["id"] == route["host"]), None)
                if host is None:
                    raise UserError(f"NanoGPT doesn't list {route['host']} as a host for {model}.")
                route["host_name"] = host["name"]
                route["fp8"] = route["fp8"] and host["fp8"]
        routes = dict(self.cfg.settings.model_routes or {})
        if route is None:
            routes.pop(model, None)
        else:
            routes[model] = route
        self.cfg.settings.model_routes = routes
        self._save_config(self.cfg)
        self._log("model_route", model=model, route=routes_mod.describe(route))
        self._changed()
        return route

    def learn_unsupported(self, prov: Provider, model: str, params: dict, err: Exception) -> str | None:
        # the body too: openai 3.38 and later leave it out of str(err)
        m = re.search(r"(?:does not|doesn't|do not) support (?:the )?[`'\"]?([a-z_]+)", error_words(err), re.I)
        key = m.group(1).lower() if m else ""
        if key not in params:
            return None
        self._unsupported.setdefault((prov.name, model), set()).add(key)
        self._log("setting_unsupported", model=model, setting=key, error=shown_error(err))
        return key

    def is_tee(self, prov: Provider, model: str) -> bool:
        """A model attested through NanoGPT's TEE checks before anything is sent to it (tee_guard), whose replies are
        checked against the record its enclave signs (reply_check). Never one Tinfoil's or Chutes' own client attests
        and seals (a Chutes -TEE id reads as TEE by its name)."""
        if config_mod.privacy_of(prov, model).service in ("tinfoil", "chutes"):
            return False
        return detect_tier(model, prov.base_url, prov.tier_overrides) == "tee"

    async def complete(self, client, prov: Provider, model: str, messages: list[dict]) -> str:
        """A one-off completion, dropping a generation setting the provider refuses. A TEE model's reply is
        read as a stream, every byte hashed (LLMClient.complete, exact), to be checked as the gateway checks
        the assistant's: its id, receipt and hash are then on the client's `last_reply` (Engine._check_reply).
        A private model's needs none: it is sealed by the attested enclave's key."""
        params = self.params(prov, model)
        exact = {"exact": True} if isinstance(client, LLMClient) and self.is_tee(prov, model) else {}
        try:
            return await client.complete(model, messages, params, **exact)
        except Exception as e:  # noqa: BLE001
            if not self.learn_unsupported(prov, model, params, e):
                raise
            return await client.complete(model, messages, self.params(prov, model), **exact)

    # ---------------------------------------------------------------- the two roles

    def privacy(self, prov: Provider | None, model: str) -> privacy_mod.Privacy:
        """How private `model` is on `prov` (config.privacy_of): its kind, service and level."""
        return config_mod.privacy_of(prov, model)

    def assistant_privacy(self) -> privacy_mod.Privacy:
        """How private the assistant's model is on its provider, now."""
        s = self.cfg.settings
        return self.privacy(self.cfg.provider(s.builder_provider), s.builder_model)

    def vision_target(self) -> tuple[Provider | None, str]:
        """The vision helper's provider and model: the one its setting names ("provider|model"), else the assistant's
        provider; (None, "") for none, or for a provider that no longer exists."""
        named, model = config_mod.model_ref(self.cfg.settings.builder_vision_model)
        if not model:
            return None, ""
        return self.cfg.provider(named or self.cfg.settings.builder_provider), model

    def builder_target(self) -> tuple[Provider, str, str, str]:
        """(provider, model, small model, tier) the assistant uses. Its provider needs an address for Anthropic's
        Messages API (builder_url) for Claude models, which are passed on as they are, and a chat address (base_url)
        for any other, whose requests are translated (gateway.py); one of the two at least."""
        s = self.cfg.settings
        prov = self.cfg.provider(s.builder_provider)
        if not prov or not (prov.builder_url or prov.base_url):
            raise UserError("Set up the assistant first: add your NanoGPT key, or another provider (Settings).")
        try:
            stored = creds.get_secret("provider", prov.name)
        except creds.KeyringUnavailable as e:
            raise KeyringWait(f"Your keyring isn't open yet, so your {prov.name} key can't be read ({e}).") from None
        if not stored:
            raise UserError(f"No API key is stored for {prov.name}; add it in Settings.")
        if problem := key_problem_for(prov):
            raise KeyHeldBack(problem)          # another address, or plain http to another machine: not sent
        if not s.builder_model:
            raise UserError("Choose the assistant's model in Settings.")
        small = s.builder_small_model or s.builder_model
        order = ("standard", "tee", "e2ee", "local")
        # the lower of the models' tiers; private/ models are sealed by the gateway (e2ee), but it doesn't attest TEE
        # models, so on the wire those are like any standard model. The vision helper's on its own provider
        vprov, vision = self.vision_target()
        seen = [(prov, m) for m in (s.builder_model, small) if m] + ([(vprov, vision)] if vprov and vision else [])
        tiers = [self.tier(p, m) for p, m in seen]
        tier = min(("standard" if t == "tee" else t for t in tiers), key=order.index)
        if config_mod.privacy_of(prov, s.builder_model).sealed:
            # the gateway seals the chat's every request (NanoGPT's Private Mode, Tinfoil's or Chutes' own client),
            # or refuses it, and no image helper less private than it is given anything (Engine._builder_upstream)
            tier = "e2ee"
        claude = [m.lower().startswith(("anthropic/", "claude")) for m in (s.builder_model, small)]
        # with no chat address, every model goes to the provider's Messages API as it is (an Anthropic-compatible
        # server, Chutes' proxy: their own models, not only Claude), but for one sealed by its own client, which a
        # chat address alone takes (a Chutes -TEE one needs none: it is sealed to api.chutes.ai whatever the provider
        # speaks)
        chat_less = [m for m in (s.builder_model, small)
                     if self.privacy(prov, m).sealed and config_mod.model_sealing(prov, m) != "chutes"]
        if not prov.base_url and chat_less:
            raise UserError(f"{chat_less[0]} is end-to-end encrypted, sent only through its own client to a chat "
                            f"address, and {prov.name} has none (Settings → AI providers).")
        if not prov.builder_url and any(claude):
            raise UserError(f"Claude models need {prov.name}'s address for Anthropic's Messages API (Settings → AI "
                            "providers), or a provider that has one.")
        for model in (s.builder_model, small):
            if problem := sealing_problem(prov, model):
                raise UserError(problem)
        return prov, s.builder_model, small, tier

    def review_target(self) -> tuple[Provider, str, str]:
        want = (self.cfg.settings.review_model or "").strip()
        if not want or "|" not in want:
            raise UserError("No reviewer is set up yet (Settings → Second opinions).")
        pname, model = (x.strip() for x in want.split("|", 1))
        prov = self.cfg.provider(pname)
        if not prov:
            raise UserError(f"The reviewer's provider {pname} no longer exists; choose a reviewer in Settings.")
        return prov, model, detect_tier(model, prov.base_url, prov.tier_overrides)

    # ---------------------------------------------------------------- attestation

    async def tee_guard(self, prov: Provider, model: str) -> dict | None:
        """Nothing goes to a TEE model whose enclave hasn't attested; an attestation older than
        TEE_REATTEST_SECONDS, or one a reply of failed its check against (reply_check), is made again
        first. None for a model that isn't TEE."""
        if problem := sealing_problem(prov, model):
            # a Chutes -TEE model on an address that isn't Chutes' own: nothing is asked of anyone, nothing sent
            raise UserError(problem)
        if not self.is_tee(prov, model):
            return None
        key = (prov.name, prov.base_url, model)     # another address: attested again
        async with self._attest_lock:
            hit = self._tee.get(key)
            if hit and key not in self._doubted and dcap.since_boot() - hit[1] < TEE_REATTEST_SECONDS:
                return hit[2]
            make = self.tee_factory or tee_mod.TeeClient
            try:
                client = make(prov.base_url, self.key(prov) or "", model)
            except (InsecureURL, UnusableKey) as e:
                raise UserError(f"{model}'s enclave wasn't asked to attest, so nothing was sent to it: {e}") from None
            # the client gives the whole attempt tee.ATTEMPT_SECONDS; one request's timeout after that it is
            # given up here whatever it is doing (Intel's or NVIDIA's service answering a byte at a time), as a
            # refusal: nothing waits on "attesting" longer (DA Toolkit's review, Nov 2026)
            limit = tee_mod.ATTEMPT_SECONDS + tee_mod.TIMEOUT_SECONDS
            try:
                try:
                    att = await asyncio.wait_for(asyncio.to_thread(client.attest), limit)
                except TimeoutError:
                    raise tee_mod.TeeRefused(f"the attestation wasn't done within {limit / 60:g} minutes, and was "
                                             "given up; this may pass if tried again") from None
            except Exception as e:  # noqa: BLE001
                client.close()
                # shown on the card, logged and told the assistant: on one line, short, without what can't be
                # seen (relay_said), whoever wrote it (DA Toolkit's review, Nov 2026)
                said = relay_said(scrubbed(e), 700)
                self._log("enclave_attestation_failed", model=model, error=said)
                raise UserError(f"{model}'s TEE attestation didn't hold, so nothing was sent to it: {said}") from e
            self._tee[key] = (client, dcap.since_boot(), att.to_dict())
            self._doubted.discard(key)
            self._log("enclave_attested", model=model, **att.to_dict())
            told = (model, tuple(att.shortfalls))
            if att.level == "partial" and told not in self._told_partial:
                # sent all the same, as before; but the user knows how far the attestation goes, and what was
                # attested: RedPill's gateway is not the machine that runs the model (llm/tee.py what_was_attested)
                self._told_partial.add(told)
                what = "TEE gateway attested" if att.attested == "gateway" else "TEE attested"
                self._emit("toast", level="info", text=(
                    f"{model}: {what}, only in part ({', '.join(att.shortfalls)}). "
                    + (tee_mod.what_was_attested(att)
                       or "What goes to it isn't sealed end to end: for that, choose a private model.")),
                    # what each shortfall costs, as the toast's tooltip (llm/tee.py SHORTFALL_COSTS: the standard every
                    # DA app keeps, Nov 14 2026)
                    detail="\n\n".join(att.costs))
            return att.to_dict()

    def reply_check(self, prov: Provider, model: str):
        """How a reply of TEE `model` is checked, against the attestation in force now (tee_guard made it
        just before the request): an async (reply's TurnResult) -> {"tee": "verified" | "signed" | "failed"
        | "unchecked", "detail"?, "upstream"?} that never raises (llm/tee.py check_reply), or None when none is
        kept. "upstream" (upstream_view) is who ran the model, by RedPill's record, when Settings asks for it.

        With a "verified" or "signed" mark, "receipt": whether the reply's receipt was read under the attested
        keys and held. A model attested itself is verified by its own key's signature without one, so the mark's
        tooltip says which (DA Toolkit's review, Nov 2026).

        The outcome goes in the log; a reply that failed (not signed by the attested key, or not the text it
        signed) is said to the user, and its model attested again before its next request. One that couldn't
        be checked ("unchecked": a provider that signs no replies, a record not found) is no reason to
        attest again (DA Assistant's rule, Nov 2026)."""
        key = (prov.name, prov.base_url, model)
        hit = self._tee.get(key)
        if hit is None:
            return None
        client = hit[0]

        async def check(reply) -> dict:
            # and when its request went: a receipt served before that is another request's, handed back
            record = {"receipt_id": getattr(reply, "receipt_id", None), "body_hash": getattr(reply, "body_hash", None),
                      "route": getattr(reply, "tee_route", None), "sent_at": getattr(reply, "sent_at", None)}
            # who ran its model too, where the user asked for it (Settings, off by default: it asks api.redpill.ai,
            # llm/tee.py served_by); never the mark's concern
            named = self.cfg.settings.tee_name_upstreams and callable(getattr(client, "check", None))
            try:
                if named:
                    done = await asyncio.to_thread(client.check, getattr(reply, "id", None), **record, name_upstream=True)
                    found = {"tee": done.mark, **({"upstream": upstream_view(done.upstream)} if done.upstream else {})}
                    receipt = getattr(done, "receipt", None)
                else:
                    mark = await asyncio.to_thread(client.check_reply, getattr(reply, "id", None), **record)
                    found, receipt = {"tee": str(mark)}, getattr(mark, "receipt", None)
                if found["tee"] in ("verified", "signed") and isinstance(receipt, bool):
                    found["receipt"] = receipt
            except Exception as e:  # noqa: BLE001 - an unreachable check is not a failed one
                found = {"tee": "unchecked", "detail": str(e)[:300]}
            self._log("tee_reply_checked", model=model, **found)
            if found["tee"] == "failed":
                self._doubted.add(key)
                if key not in self._told_failed:     # once, not at each of a turn's many requests: each is marked
                    self._told_failed.add(key)
                    self._emit("toast", level="error", text=(
                        f"{model}'s reply didn't match the record its attested enclave signed: it wasn't signed by "
                        "that enclave's key, or it isn't the text that was signed. Its enclave is attested again "
                        "before anything more is sent to it, and Sandbox activity marks each reply so."))
            elif found["tee"] in ("verified", "signed"):
                self._told_failed.discard(key)
            return found
        return check
