"""The httpx client the TEE verifier uses (llm/tee.py, dcap.py, nras.py).

Ported from SealedLore (providers/http.py), where the verifier comes from:

- **A local server stays local.** A loopback endpoint is built with `trust_env=False`, so
  proxy variables never route it elsewhere; anything else keeps the environment's proxies
  and certificate settings.
- **A redirect never downgrades.** The response hook refuses a redirect whose target isn't
  https (or http to a local address, netpolicy.py), whether or not the client follows redirects.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from ..netpolicy import is_secure

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


class ProviderError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None, body: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


def is_loopback(url: str) -> bool:
    return (urlparse(url).hostname or "").lower() in LOOPBACK_HOSTS


def refuse_insecure_redirect(response: httpx.Response) -> None:
    """A response hook: a redirect to anywhere the app wouldn't send to directly."""
    if not response.is_redirect:
        return
    target = response.next_request.url if response.next_request is not None else None
    if target is None:
        target = response.headers.get("location")
    if target is not None and not is_secure(str(target)):
        raise ProviderError(
            f"{response.request.url.host} redirected to {str(target)[:120]!r}; refusing to "
            "send over an insecure connection"
        )


def make_client(base_url: str, **kwargs: Any) -> httpx.Client:
    """An httpx client for `base_url`: no proxies for a loopback endpoint, and the redirect
    guard. `kwargs` go to `httpx.Client` as they are."""
    kwargs.setdefault("trust_env", not is_loopback(base_url))
    hooks = dict(kwargs.pop("event_hooks", None) or {})
    hooks["response"] = [*hooks.get("response", ()), refuse_insecure_redirect]
    return httpx.Client(event_hooks=hooks, **kwargs)
