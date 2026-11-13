"""The httpx client the TEE verifier uses (llm/tee.py, dcap.py, nras.py).

Ported from SealedLore (providers/http.py), where the verifier comes from:

- **A local server stays local.** An endpoint on this computer or the local network is built
  with `trust_env=False` (local_http_options), so proxy variables never route it elsewhere;
  anything else keeps the environment's proxies and certificate settings.
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


def local_http_options(base_url: str) -> dict:
    """Arguments for the HTTP client (httpx's, or an SDK's) that will talk to `base_url`.

    A local address stays local. For one of this computer or its network (netpolicy.is_local_host:
    what the Local tier counts) the client is built with `trust_env=False`, so a proxy named in the
    environment (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY) is never handed the request. httpx exempts no
    address of its own accord: until Nov 2026 only loopback was kept off it, and a provider at
    192.168.x or a .local name sent its key and the conversation to whatever proxy the desktop
    session had set (DA Toolkit's c6de017). Certificates are still read as the environment names
    them (SSL_CERT_FILE, SSL_CERT_DIR: the AppImage points the first at the system's bundle, so a
    company's own CA stands), which `trust_env=False` alone would stop. And every scheme is mounted
    on the client's own transport (None), because an SDK may build its default client's proxies
    from the environment itself, whatever `trust_env` says, and lets only a mount stand over them.

    Any other address gets nothing here, and keeps the environment's proxy as before."""
    if not is_local(base_url):
        return {}
    return {"trust_env": False, "verify": httpx.create_ssl_context(),
            "mounts": {"all://": None, "http://": None, "https://": None}}


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
    """An httpx client for `base_url`: no proxies for a local endpoint (local_http_options), and
    the redirect guard. `kwargs` go to `httpx.Client` as they are."""
    for k, v in local_http_options(base_url).items():
        kwargs.setdefault(k, v)
    hooks = dict(kwargs.pop("event_hooks", None) or {})
    hooks["response"] = [*hooks.get("response", ()), refuse_insecure_redirect]
    return httpx.Client(event_hooks=hooks, **kwargs)
