"""Providers and models: the assistant's (Claude Code in the sandbox, through the gateway) and
the reviewer's (outside it, for second opinions).

The reviewer reads the commands proposed for this computer and the patches of delivered apps,
so by default it is a NanoGPT Private Mode model: end-to-end encrypted to an attested enclave
(llm/private_mode.py). TEE models are attested before anything is sent to them, and a failed
attestation means nothing is sent.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import asdict
from typing import Callable

from . import config as config_mod
from . import creds
from .config import Config, Provider, provider_defaults
from .llm import capabilities
from .llm import dcap
from .llm import params as params_mod
from .llm import routes as routes_mod
from .llm import tee as tee_mod
from .llm.client import LLMClient, detect_tier, is_private_mode
from .llm.private_mode import Enclave, PrivateModeClient, list_private_models, offers_private_mode, relay_url
from .netpolicy import InsecureURL, UnusableKey, check_url, key_problem, scrubbed, shown

# A TEE model's attestation is made again, with a fresh nonce, before a send once it is this old: on a
# clock that runs on while the computer sleeps (dcap.since_boot), so one made before a night's suspend
# isn't taken for minutes old in the morning.
TEE_REATTEST_SECONDS = 900
# a provider's model list that couldn't be read is asked for again after this long, no sooner
CAPS_RETRY_SECONDS = 30
# the reviewer chosen automatically: the first private model matching one of these, in order
REVIEWER_PREFERENCE = (r"glm", r"deepseek", r"kimi", r"qwen", r"gpt-oss", r"llama", r".")


def upstream_view(upstream: tee_mod.TeeUpstream) -> dict:
    """Who ran a TEE reply's model (llm/tee.py served_by), as its check's event carries it: RedPill's record
    as read, the provider's name as the mark shows it ("Phala"), and what it means for the mark's tooltip."""
    return {**asdict(upstream), "label": tee_mod.upstream_label(upstream) if upstream.name else "",
            "words": tee_mod.upstream_words(upstream)}


class UserError(Exception):
    """An error to show the user as-is."""


class KeyringWait(UserError):
    """The key may well be stored, but the keyring can't be read yet (e.g. just after login)."""


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

    def _changed(self) -> None:
        self._emit("config_changed")

    # ---------------------------------------------------------------- providers

    def save_provider(self, data: dict, api_key: str | None = None, original_name: str | None = None) -> None:
        name = str(data.get("name", "")).strip()
        base_url = str(data.get("base_url", "")).strip().rstrip("/")
        builder_url = str(data.get("builder_url", "")).strip().rstrip("/")
        if not name or not (base_url or builder_url):
            raise UserError("A provider needs a name and a base URL.")
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
        overrides = {k.strip(): v.strip() for k, v in (data.get("tier_overrides") or {}).items() if k.strip()}
        prov = provider_defaults(Provider(
            name=name, base_url=base_url, default_model=str(data.get("default_model", "")).strip(),
            builder_url=builder_url, builder_auth=builder_auth, tier_overrides=overrides))
        old = self.cfg.provider(original_name or name)
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
            creds.delete_secret("provider", original_name)
            s = self.cfg.settings
            if s.builder_provider == original_name:
                s.builder_provider = name
            if s.review_model.startswith(original_name + "|"):
                s.review_model = name + s.review_model[len(original_name):]
        if api_key:
            try:
                creds.set_secret("provider", name, api_key)
            except creds.KeyringUnavailable as e:
                raise UserError(f"{e}. Unlock your keyring (GNOME Keyring or KWallet) and try again.") from None
        if old:
            self.cfg.providers[self.cfg.providers.index(old)] = prov
        else:
            self.cfg.providers.append(prov)
        if not self.cfg.settings.builder_provider and prov.builder_url:
            self.cfg.settings.builder_provider = name
        self._models.pop(name, None)
        self._save_config(self.cfg)
        self._changed()

    def delete_provider(self, name: str) -> None:
        self.cfg.providers = [p for p in self.cfg.providers if p.name != name]
        creds.delete_secret("provider", name)
        for attr in ("base_url", "builder_url"):
            try:
                config_mod.forget_password(f"provider:{name}:{attr}")
            except creds.KeyringUnavailable:
                pass                    # only what an address with its name kept: nothing uses it now
        s = self.cfg.settings
        if s.builder_provider == name:
            s.builder_provider = next((p.name for p in self.cfg.providers if p.builder_url), "")
        if s.review_model.startswith(name + "|"):
            s.review_model = ""
        self._save_config(self.cfg)
        self._changed()

    def provider(self, name: str) -> Provider:
        prov = self.cfg.provider(name)
        if not prov:
            raise UserError(f"Unknown provider {name}")
        return prov

    def key(self, prov: Provider) -> str | None:
        try:
            return creds.get_secret("provider", prov.name)
        except Exception:  # noqa: BLE001 - keyring locked/unavailable
            return None

    def client(self, prov: Provider, model: str = "") -> LLMClient | PrivateModeClient:
        if self.client_factory:
            return self.client_factory(prov, model)
        if not prov.base_url:
            raise UserError(f"{prov.name} has no chat endpoint, so it can't be the reviewer.")
        key = self.key(prov)
        enclave = None
        if is_private_mode(model):
            enclave = self._enclaves.get(prov.name)
            if enclave is None or enclave.relay != relay_url(prov.base_url):
                enclave = self._enclaves[prov.name] = Enclave(relay_url(prov.base_url),
                                                              on_attested=lambda att: self._private_attested(prov, att))
        try:
            return PrivateModeClient(prov.base_url, key, enclave) if is_private_mode(model) else LLMClient(prov.base_url, key)
        except (InsecureURL, UnusableKey) as e:
            raise UserError(str(e)) from None

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

    async def list_models(self, provider_name: str, refresh: bool = False) -> list[dict]:
        prov = self.provider(provider_name)
        if refresh or provider_name not in self._models:
            try:
                ids = await self.client(prov).list_models()
            except UserError:
                raise
            except Exception as e:  # noqa: BLE001
                raise UserError(f"Could not list models from {shown(prov.base_url)}: {scrubbed(e)}") from e
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
            out.append({"id": m, "tier": detect_tier(m, prov.base_url, prov.tier_overrides),
                        "reasoning": caps.get("reasoning", False), "context": caps.get("context")})
        return out

    async def _load_caps(self, prov: Provider) -> bool:
        """Read the provider's model list; whether there's one now. A provider other than NanoGPT lists
        nothing of what its models do: known as that. One that can't be read now isn't taken for an
        empty list: it's asked for again, CAPS_RETRY_SECONDS later at the soonest."""
        if not offers_private_mode(prov.base_url):
            self._caps.setdefault(prov.name, {})
            return True
        if time.monotonic() - self._caps_failed.get(prov.name, float("-inf")) < CAPS_RETRY_SECONDS:
            return prov.name in self._caps
        try:
            caps = await capabilities.fetch_nanogpt(prov.base_url, self.key(prov), http=self.caps_http)
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
        Returns the setting ("provider|model"), or "" when there is no such model."""
        s = self.cfg.settings
        if s.review_model:
            return s.review_model
        for prov in self.cfg.providers:
            if not (prov.base_url and offers_private_mode(prov.base_url) and self.key(prov)):
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
        m = re.search(r"(?:does not|doesn't|do not) support (?:the )?[`'\"]?([a-z_]+)", str(err), re.I)
        key = m.group(1).lower() if m else ""
        if key not in params:
            return None
        self._unsupported.setdefault((prov.name, model), set()).add(key)
        self._log("setting_unsupported", model=model, setting=key, error=str(err)[:300])
        return key

    def is_tee(self, prov: Provider, model: str) -> bool:
        """A model attested before anything is sent to it (tee_guard), whose replies are checked against the
        record its enclave signs (reply_check)."""
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

    def builder_target(self) -> tuple[Provider, str, str, str]:
        """(provider, model, small model, tier) the assistant uses."""
        s = self.cfg.settings
        prov = self.cfg.provider(s.builder_provider)
        if not prov or not prov.builder_url:
            raise UserError("Set up the assistant first: add your NanoGPT key (Settings).")
        try:
            stored = creds.get_secret("provider", prov.name)
        except creds.KeyringUnavailable as e:
            raise KeyringWait(f"Your keyring isn't open yet, so your {prov.name} key can't be read ({e}).") from None
        if not stored:
            raise UserError(f"No API key is stored for {prov.name}; add it in Settings.")
        if not s.builder_model:
            raise UserError("Choose the assistant's model in Settings.")
        small = s.builder_small_model or s.builder_model
        order = ("standard", "tee", "e2ee", "local")
        # the lower of the two models' tiers; private/ models are sealed by the gateway (e2ee), but it
        # doesn't attest TEE models, so on the wire those are like any standard model
        seen = [m for m in (s.builder_model, small, s.builder_vision_model.strip()) if m]
        tiers = [detect_tier(m, prov.builder_url, prov.tier_overrides) for m in seen]
        tier = min(("standard" if t == "tee" else t for t in tiers), key=order.index)
        if is_private_mode(s.builder_model):
            tier = "e2ee"       # the gateway seals the chat's every request, or refuses it (and no clear image helper)
        if not prov.base_url and not all(m.lower().startswith(("anthropic/", "claude")) for m in (s.builder_model, small)):
            raise UserError(f"Models other than Claude need {prov.name}'s chat endpoint (Settings).")
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
            try:
                att = await asyncio.to_thread(client.attest)
            except Exception as e:  # noqa: BLE001
                client.close()
                self._log("enclave_attestation_failed", model=model, error=scrubbed(e))
                raise UserError(f"{model}'s TEE attestation didn't hold, so nothing was sent to it: {scrubbed(e)}") from e
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
                       or "What goes to it isn't sealed end to end: for that, choose a private model.")))
            return att.to_dict()

    def reply_check(self, prov: Provider, model: str):
        """How a reply of TEE `model` is checked, against the attestation in force now (tee_guard made it
        just before the request): an async (reply's TurnResult) -> {"tee": "verified" | "signed" | "failed"
        | "unchecked", "detail"?, "upstream"?} that never raises (llm/tee.py check_reply), or None when none is
        kept. "upstream" (upstream_view) is who ran the model, by RedPill's record, when Settings asks for it.

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
            record = {"receipt_id": getattr(reply, "receipt_id", None), "body_hash": getattr(reply, "body_hash", None),
                      "route": getattr(reply, "tee_route", None)}
            # who ran its model too, where the user asked for it (Settings, off by default: it asks api.redpill.ai,
            # llm/tee.py served_by); never the mark's concern
            named = self.cfg.settings.tee_name_upstreams and callable(getattr(client, "check", None))
            try:
                if named:
                    done = await asyncio.to_thread(client.check, getattr(reply, "id", None), **record, name_upstream=True)
                    found = {"tee": done.mark, **({"upstream": upstream_view(done.upstream)} if done.upstream else {})}
                else:
                    found = {"tee": await asyncio.to_thread(client.check_reply, getattr(reply, "id", None), **record)}
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
