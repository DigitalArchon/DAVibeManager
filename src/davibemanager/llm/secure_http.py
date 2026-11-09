"""The httpx client the TEE verifier uses (llm/tee.py, dcap.py, nras.py).

Ported from SealedLore (providers/http.py), where the verifier comes from:

- **A local server stays local.** A loopback endpoint is built with `trust_env=False`, so
  proxy variables never route it elsewhere; anything else keeps the environment's proxies
  and certificate settings.
- **A redirect never downgrades.** The response hook refuses a redirect whose target isn't
  https (or http to a local address, netpolicy.py), whether or not the client follows redirects,
  and one from a server on the internet into this computer or the local network. A relative one
  is judged where it leads (SealedLore's providers/http.py, Nov 2026).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from ..netpolicy import is_local_host, is_secure, shown

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


class ProviderError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None, body: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


def is_loopback(url: str) -> bool:
    return (urlparse(url).hostname or "").lower() in LOOPBACK_HOSTS


def is_local(url: str) -> bool:
    """A server on this computer or the local network (netpolicy.is_local_host)."""
    try:
        return is_local_host(urlparse(url).hostname or "")
    except ValueError:
        return False


def refuse_insecure_redirect(response: httpx.Response) -> None:
    """A response hook: a redirect to anywhere the app wouldn't send to directly, or from a server
    out on the internet into this computer or the local network (a router's admin page)."""
    if not response.is_redirect:
        return
    location = response.headers.get("location")
    if location is None:
        return
    # httpx runs the hooks before it builds the next request, so `Location` is read here as
    # written: a relative one ("/c/2") was refused for having no scheme, and one to a local
    # address passed for https. It is resolved the way the client will resolve it.
    try:
        target = str(response.request.url.join(location))
    except httpx.InvalidURL:
        target = location
    source = str(response.request.url)
    if not is_secure(target):
        raise ProviderError(
            f"{response.request.url.host} redirected to {shown(target)[:120]!r}; refusing to "
            "send over an insecure connection"
        )
    if is_local(target) and not is_local(source):
        raise ProviderError(
            f"{response.request.url.host} redirected to {shown(target)[:120]!r}, a server on this "
            "computer or your local network; refused"
        )


def make_client(base_url: str, **kwargs: Any) -> httpx.Client:
    """An httpx client for `base_url`: no proxies for a loopback endpoint, and the redirect
    guard. `kwargs` go to `httpx.Client` as they are."""
    kwargs.setdefault("trust_env", not is_loopback(base_url))
    hooks = dict(kwargs.pop("event_hooks", None) or {})
    hooks["response"] = [*hooks.get("response", ()), refuse_insecure_redirect]
    return httpx.Client(event_hooks=hooks, **kwargs)
