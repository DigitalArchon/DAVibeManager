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
from typing import Callable

from . import creds
from .config import Config, Provider, provider_defaults
from .llm import capabilities
from .llm import params as params_mod
from .llm import routes as routes_mod
from .llm import tee as tee_mod
from .llm.client import LLMClient, detect_tier, is_private_mode
from .llm.private_mode import Enclave, PrivateModeClient, list_private_models, offers_private_mode, relay_url
from .netpolicy import InsecureURL, check_url

# A TEE model's attestation is made again, with a fresh nonce, before a send once it is this old.
TEE_REATTEST_SECONDS = 900
# the reviewer chosen automatically: the first private model matching one of these, in order
REVIEWER_PREFERENCE = (r"glm", r"deepseek", r"kimi", r"qwen", r"gpt-oss", r"llama", r".")


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
        self._log = log                         # log(event, **data) to the conversation's audit log
        self._models: dict[str, list[str]] = {}
        self._enclaves: dict[str, Enclave] = {}      # provider name -> attested enclave (Private Mode)
        self._caps: dict[str, dict[str, dict]] = {}   # provider -> model id -> capabilities
        self.caps_http = None                         # httpx client override (tests)
        self._unsupported: dict[tuple[str, str], set[str]] = {}   # generation settings a model's route refused
        self._tee: dict[tuple[str, str], tuple[tee_mod.TeeClient, float, dict]] = {}
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
        builder_auth = str(data.get("builder_auth", "bearer")).strip() or "bearer"
        if builder_auth not in ("bearer", "x-api-key"):
            raise UserError("The key goes in a bearer header or x-api-key.")
        overrides = {k.strip(): v.strip() for k, v in (data.get("tier_overrides") or {}).items() if k.strip()}
        prov = provider_defaults(Provider(
            name=name, base_url=base_url, default_model=str(data.get("default_model", "")).strip(),
            builder_url=builder_url, builder_auth=builder_auth, tier_overrides=overrides))
        old = self.cfg.provider(original_name or name)
        if original_name and original_name != name and old:
            key = creds.get_secret("provider", original_name)
            if key and not api_key:
                creds.set_secret("provider", name, key)
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
        if is_private_mode(model):
            enclave = self._enclaves.get(prov.name)
            if enclave is None or enclave.relay != relay_url(prov.base_url):
                enclave = self._enclaves[prov.name] = Enclave(relay_url(prov.base_url))
            return PrivateModeClient(prov.base_url, key, enclave)
        try:
            return LLMClient(prov.base_url, key)
        except InsecureURL as e:
            raise UserError(str(e)) from None

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
                raise UserError(f"Could not list models from {prov.base_url}: {e}") from e
            if offers_private_mode(prov.base_url):
                try:
                    ids = sorted(set(ids) | set(await self._private_ids(prov.base_url)))
                except Exception as e:  # noqa: BLE001 - the plain models are still usable
                    self._emit("toast", level="error", text=f"Could not list Private Mode models: {e}")
            self._models[provider_name] = ids
            await self._load_caps(prov)
        out = []
        for m in self._models[provider_name]:
            caps = capabilities.lookup(self._caps.get(prov.name, {}), m) or {}
            out.append({"id": m, "tier": detect_tier(m, prov.base_url, prov.tier_overrides),
                        "reasoning": caps.get("reasoning", False)})
        return out

    async def _load_caps(self, prov: Provider) -> None:
        if not offers_private_mode(prov.base_url):
            self._caps.setdefault(prov.name, {})
            return
        try:
            self._caps[prov.name] = await capabilities.fetch_nanogpt(prov.base_url, self.key(prov), http=self.caps_http)
        except Exception:  # noqa: BLE001 - models still work; their limits are just unknown
            self._caps.setdefault(prov.name, {})

    def known_caps(self, prov: Provider) -> dict[str, dict] | None:
        """The provider's model list with capabilities and prices, once loaded (None: not yet)."""
        return self._caps.get(prov.name)

    async def load_caps(self, prov: Provider) -> None:
        await self._load_caps(prov)
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
                raise UserError(f"Couldn't get NanoGPT's list of hosts for {model}: {e}") from e
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

    async def complete(self, client, prov: Provider, model: str, messages: list[dict]) -> str:
        """A one-off completion, dropping a generation setting the provider refuses."""
        params = self.params(prov, model)
        try:
            return await client.complete(model, messages, params)
        except Exception as e:  # noqa: BLE001
            if not self.learn_unsupported(prov, model, params, e):
                raise
            return await client.complete(model, messages, self.params(prov, model))

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
        tiers = [detect_tier(m, prov.builder_url, prov.tier_overrides) for m in (s.builder_model, small)]
        tier = min(("standard" if t == "tee" else t for t in tiers), key=order.index)
        if not prov.base_url and not all(m.lower().startswith(("anthropic/", "claude")) for m in (s.builder_model, small)):
            raise UserError(f"Models other than Claude need {prov.name}'s chat endpoint (Settings).")
        return prov, s.builder_model, small, tier

    def review_target(self) -> tuple[Provider, str, str]:
        want = (self.cfg.settings.review_model or "").strip()
        if not want or "|" not in want:
            raise UserError("No reviewer is set up yet (Settings → Second opinions).")
        pname, model = want.split("|", 1)
        prov = self.cfg.provider(pname)
        if not prov:
            raise UserError(f"The reviewer's provider {pname} no longer exists; choose a reviewer in Settings.")
        return prov, model, detect_tier(model, prov.base_url, prov.tier_overrides)

    # ---------------------------------------------------------------- attestation

    async def tee_guard(self, prov: Provider, model: str) -> dict | None:
        """Nothing goes to a TEE model whose enclave hasn't attested; an attestation older than
        TEE_REATTEST_SECONDS is made again first. None for a model that isn't TEE."""
        if detect_tier(model, prov.base_url, prov.tier_overrides) != "tee":
            return None
        async with self._attest_lock:
            hit = self._tee.get((prov.name, model))
            if hit and time.monotonic() - hit[1] < TEE_REATTEST_SECONDS:
                return hit[2]
            make = self.tee_factory or tee_mod.TeeClient
            client = make(prov.base_url, self.key(prov) or "", model)
            try:
                att = await asyncio.to_thread(client.attest)
            except Exception as e:  # noqa: BLE001
                client.close()
                self._log("enclave_attestation_failed", model=model, error=str(e))
                raise UserError(f"{model}'s TEE attestation didn't hold, so nothing was sent to it: {e}") from e
            self._tee[(prov.name, model)] = (client, time.monotonic(), att.to_dict())
            self._log("enclave_attested", model=model, **att.to_dict())
            return att.to_dict()
