"""Tinfoil's SDK fetches over https only: a redirect off https, or from the internet into this computer
or its network, is not followed.

The SDK makes bare requests.get and requests.post calls (GitHub's release and Sigstore bundle, AMD's and
Intel's certificates, the enclave's attestation), and requests follows a redirect anywhere, https to plain
http included. llm/sdk_guard.py hands each of its modules a stand-in for requests whose every fetch judges
a redirect first, without changing the SDK on disk. Here the SDK is a fake one, written to a folder of the
test's own, in the shapes the real one takes requests in; nothing reaches the network. Ported from DA
Assistant's tests/test_sdk_redirects.py (Nov 2026)."""

import importlib
import io
import pkgutil
import sys
import textwrap
import types

import pytest
import requests
import urllib3

from davibemanager.llm import private_mode, sdk_guard
from davibemanager.netpolicy import is_local_host

FILES = {
    "__init__.py": "from .client import SecureClient\n",
    "client.py": """
        from .github import fetch_latest_release

        class SecureClient:
            def __init__(self, **kwargs):
                self.enclave = "enclave.example"

            def verify(self):
                return fetch_latest_release("owner/repo")
        """,
    # as tinfoil.github and tinfoil.attestation.* take it
    "github.py": """
        import requests

        def fetch_latest_release(repo):
            response = requests.get(f"https://github-proxy.example/repos/{repo}", timeout=5)
            response.raise_for_status()
            return response.text
        """,
    # a function taken by name, and Session in an annotation made at import
    "byname.py": """
        from typing import Optional

        import requests
        from requests import post

        HttpSession = Optional[requests.Session]

        def send(url, session: HttpSession = None):
            if session is not None:
                return session.get(url, timeout=5).text
            return post(url, json={}, timeout=5).text
        """,
    # a module the package doesn't import until it is wanted
    "later/__init__.py": "",
    "later/collateral.py": """
        import requests

        def fetch(url):
            return requests.get(url, timeout=5).text
        """,
}
URL = "https://github-proxy.example/repos/owner/repo"


class Network:
    """Each URL answered as `answers` says (a redirect to another, or 200), every request that reached
    it recorded."""

    def __init__(self):
        self.sent, self.answers = [], {}

    def send(self, adapter, request, **kwargs):
        self.sent.append(request.url)
        response = requests.Response()
        response.url, response.request = request.url, request
        target = self.answers.get(request.url)
        response.status_code = 302 if target else 200
        if target:
            response.headers["Location"] = target
        response._content = b"" if target else b"fine"
        return response


@pytest.fixture
def sigstore_unguarded(tmp_path, monkeypatch):
    """sigstore-python as it is before guard(), and put back as it was after the test (the guard changes it for
    the rest of the process, as the app wants it to); its TUF cache in the test's own folder."""
    import sigstore
    from tuf.ngclient import Updater

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))      # XDG_DATA_HOME is the test's already
    for found in pkgutil.walk_packages(sigstore.__path__, "sigstore.", onerror=lambda _name: None):
        if found.name not in sys.modules and found.name not in ("sigstore.__main__", "sigstore._cli"):
            importlib.import_module(found.name)
    for name, mod in list(sys.modules.items()):
        if mod is not None and (name == "sigstore" or name.startswith("sigstore.")) \
                and isinstance(getattr(mod, "requests", None), types.ModuleType):
            monkeypatch.setattr(mod, "requests", requests)
    monkeypatch.setattr(importlib.import_module("sigstore._internal.tuf"), "Updater", Updater)


@pytest.fixture
def sdk(tmp_path, monkeypatch, sigstore_unguarded):
    """The fake SDK in place of the real one (put back afterwards), and the network it reaches."""
    for name, text in FILES.items():
        path = tmp_path / "tinfoil" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text))
    for name in [name for name in sys.modules if name == "tinfoil" or name.startswith("tinfoil.")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.invalidate_caches()
    importlib.import_module("tinfoil")
    net = Network()
    monkeypatch.setattr("requests.adapters.HTTPAdapter.send",
                        lambda adapter, request, **kwargs: net.send(adapter, request, **kwargs))
    yield net
    for name in [name for name in sys.modules if name == "tinfoil" or name.startswith("tinfoil.")]:
        del sys.modules[name]                       # the fake's modules go; monkeypatch brings the real ones back


def module(name):
    return importlib.import_module(f"tinfoil.{name}")


def test_unguarded_the_sdk_follows_one_into_the_clear(sdk):
    sdk.answers[URL] = "http://evil.example/release"
    assert module("github").fetch_latest_release("owner/repo") == "fine"
    assert sdk.sent == [URL, "http://evil.example/release"]       # what the SDK does by itself, and why


def test_guarded_one_off_https_is_refused_and_nothing_is_sent_there(sdk):
    sdk_guard.guard(is_local_host)
    sdk.answers[URL] = "http://evil.example/release"
    with pytest.raises(requests.exceptions.InvalidURL, match="isn't https") as refused:
        module("github").fetch_latest_release("owner/repo")
    assert isinstance(refused.value, requests.RequestException)    # a failed fetch, as the SDK handles one
    assert sdk.sent == [URL]


def test_one_from_the_internet_into_this_network_is_refused(sdk):
    sdk_guard.guard(is_local_host)
    sdk.answers[URL] = "https://192.168.1.1/admin"
    with pytest.raises(requests.exceptions.InvalidURL, match="this computer or its network"):
        module("github").fetch_latest_release("owner/repo")
    assert sdk.sent == [URL]


def test_one_that_stays_on_https_is_followed_and_a_relative_one_too(sdk):
    sdk_guard.guard(is_local_host)
    sdk.answers[URL] = "https://objects.example/release"
    assert module("github").fetch_latest_release("owner/repo") == "fine"
    assert sdk.sent == [URL, "https://objects.example/release"]
    sdk.sent.clear()
    sdk.answers[URL] = "/elsewhere"
    assert module("github").fetch_latest_release("owner/repo") == "fine"
    assert sdk.sent == [URL, "https://github-proxy.example/elsewhere"]


def test_a_function_taken_by_name_and_a_module_loaded_later_are_guarded(sdk):
    given = sdk_guard.guard(is_local_host)
    assert {"tinfoil.byname", "tinfoil.later.collateral"} <= set(given)
    for send in (module("byname").send, module("later.collateral").fetch):
        sdk.sent.clear()
        sdk.answers["https://kds.example/vcek"] = "http://kds.example/vcek"
        with pytest.raises(requests.exceptions.InvalidURL):
            send("https://kds.example/vcek")
        assert sdk.sent == ["https://kds.example/vcek"]


def test_a_session_of_its_own_is_guarded_too(sdk):
    sdk_guard.guard(is_local_host)
    session = module("byname").requests.Session()
    assert isinstance(session, requests.Session)
    sdk.answers["https://pcs.example/tcb"] = "http://pcs.example/tcb"
    with pytest.raises(requests.exceptions.InvalidURL):
        module("byname").send("https://pcs.example/tcb", session)


def test_the_rest_of_requests_is_requests_own_and_twice_is_once(sdk):
    sdk_guard.guard(is_local_host)
    stand_in = module("github").requests
    assert stand_in.RequestException is requests.RequestException and stand_in.Response is requests.Response
    assert sdk_guard.guard(is_local_host) == []
    assert module("github").requests is stand_in
    assert sys.modules["requests"] is requests                     # the app's own untouched


def test_attesting_guards_the_sdk_first(sdk):
    sdk.answers[URL] = "http://evil.example/release"
    with pytest.raises(requests.exceptions.InvalidURL):
        private_mode.tinfoil_verify("https://nano-gpt.com/api/v1/private/tinfoil", "s" * 64)
    assert sdk.sent == [URL]


def test_without_the_sdk_there_is_nothing_to_guard(sdk, monkeypatch):
    monkeypatch.delitem(sys.modules, "tinfoil")
    assert sdk_guard.guard(is_local_host) == []



# --- sigstore-python, which the SDK verifies with (Nov 2026) --------------------------------------------------------
#
# Its trust root comes from Sigstore's TUF repository through TUF's own client, whose fetcher asks urllib3, which
# follows a redirect anywhere, https to plain http included. Here urllib3's connection pools are answered by a fake,
# so that urllib3's own redirect handling runs above it as it would for real; nothing reaches the network.

TUF_URL = "https://tuf.example/14.root.json"


class Wire:
    """urllib3's connection pools: each URL answered as `answers` says (a redirect to another, or 200), a host in
    `everywhere` redirected wherever it is asked, every request that reached a pool recorded."""

    def __init__(self):
        self.sent, self.answers, self.everywhere, self.agents = [], {}, {}, []

    def urlopen(self, pool, method, url, **kw):
        whole = url if "://" in url else f"{pool.scheme}://{pool.host}{url}"
        self.sent.append(whole)
        self.agents.append((kw.get("headers") or {}).get("User-Agent", ""))
        target = self.answers.get(whole) or self.everywhere.get(pool.host)
        if target:
            return urllib3.HTTPResponse(body=io.BytesIO(b""), status=302, headers={"Location": target},
                                        preload_content=False, request_url=whole)
        return urllib3.HTTPResponse(body=io.BytesIO(b"fine"), status=200, preload_content=False, request_url=whole)


@pytest.fixture
def wire(monkeypatch):
    for name in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.upper(), raising=False)
    fake = Wire()
    monkeypatch.setattr(urllib3.connectionpool.HTTPConnectionPool, "urlopen",
                        lambda pool, method, url, **kw: fake.urlopen(pool, method, url, **kw))
    return fake


def fetched(fetcher, url=TUF_URL) -> bytes:
    return b"".join(fetcher.fetch(url))


def guarded_fetcher():
    return sdk_guard._fetcher_class(is_local_host)(app_user_agent="sigstore-python/4.5.0")


def test_unguarded_tufs_own_fetcher_follows_one_into_the_clear(wire):
    """What TUF's client does by itself, and why: urllib3 follows the redirect to plain http."""
    from tuf.ngclient import Urllib3Fetcher

    wire.answers[TUF_URL] = "http://evil.example/14.root.json"
    assert fetched(Urllib3Fetcher()) == b"fine"
    assert wire.sent == [TUF_URL, "http://evil.example/14.root.json"]


def test_the_guarded_fetcher_refuses_one_off_https_or_into_this_network_and_nothing_is_sent_there(wire):
    from tuf.api import exceptions

    for target, said in (("http://evil.example/14.root.json", "isn't https"),
                         ("https://192.168.1.1/admin", "this computer or its network")):
        wire.sent.clear()
        wire.answers[TUF_URL] = target
        with pytest.raises(exceptions.DownloadError, match=said):       # a failed fetch, as TUF handles one
            fetched(guarded_fetcher())
        assert wire.sent == [TUF_URL]


def test_the_guarded_fetcher_follows_one_that_stays_on_https_and_a_relative_one_too(wire):
    wire.answers[TUF_URL] = "https://cdn.example/14.root.json"
    assert fetched(guarded_fetcher()) == b"fine"
    assert wire.sent == [TUF_URL, "https://cdn.example/14.root.json"]
    wire.sent.clear()
    wire.answers[TUF_URL] = "/elsewhere/14.root.json"
    assert fetched(guarded_fetcher()) == b"fine"
    assert wire.sent == [TUF_URL, "https://tuf.example/elsewhere/14.root.json"]
    # TUF's own User-Agent, sigstore's before it, as its fetcher sends them
    assert set(wire.agents) == {f"sigstore-python/4.5.0 python-tuf/{__import__('tuf').__version__}"}


def test_the_guarded_fetcher_follows_only_a_few(wire):
    from tuf.api import exceptions

    hops = [TUF_URL] + [f"https://hop{n}.example/14.root.json" for n in range(10)]
    wire.answers.update(zip(hops, hops[1:]))
    with pytest.raises(exceptions.DownloadError, match=f"more than {sdk_guard.TUF_MAX_REDIRECTS} times"):
        fetched(guarded_fetcher())
    assert wire.sent == hops[:sdk_guard.TUF_MAX_REDIRECTS + 1]


def test_sigstores_trust_root_is_refreshed_through_the_guarded_fetcher(wire, sigstore_unguarded, tmp_path):
    """sigstore's TrustUpdater builds TUF's Updater with no fetcher: unguarded, a refresh sent on into the clear
    went there; guarded, the refresh fails, and the attestation with it, and nothing is fetched there."""
    from sigstore._internal import tuf as sigstore_tuf
    from sigstore._utils import read_embedded
    from sigstore.errors import TUFError
    from tuf.ngclient import UpdaterConfig

    repo = "https://tuf-repo-cdn.sigstore.dev"
    wire.everywhere["tuf-repo-cdn.sigstore.dev"] = "http://evil.example/root.json"
    with pytest.raises(TUFError):
        sigstore_tuf.TrustUpdater(repo)
    assert "http://evil.example/root.json" in wire.sent                  # what it does by itself
    wire.sent.clear()
    assert "sigstore._internal.tuf" in sdk_guard.guard_sigstore(is_local_host)
    with pytest.raises(TUFError):
        sigstore_tuf.TrustUpdater(repo)
    assert wire.sent and all(url.startswith(repo + "/") for url in wire.sent)
    # the Updater it builds has the guarded fetcher, and keeps a fetcher it is given
    made = sigstore_tuf.Updater(metadata_dir=str(tmp_path / "m"), metadata_base_url=repo,
                                target_dir=str(tmp_path / "t"), target_base_url=repo + "/targets/",
                                config=UpdaterConfig(app_user_agent="sigstore-python/4.5.0"),
                                bootstrap=read_embedded("root.json", repo))
    assert type(made._fetcher).__name__ == "GuardedFetcher" and isinstance(made, __import__("tuf").ngclient.Updater)
    mine = guarded_fetcher()
    given = sigstore_tuf.Updater(str(tmp_path / "m"), repo, fetcher=mine, bootstrap=read_embedded("root.json", repo))
    assert given._fetcher is mine
    assert sdk_guard.guard_sigstore(is_local_host) == []                  # twice is once


SIGSTORE_REQUESTS = ("sigstore.oidc", "sigstore._internal.rekor", "sigstore._internal.rekor.client",
                     "sigstore._internal.rekor.client_v2", "sigstore._internal.fulcio.client", "sigstore._internal.timestamp")


def test_sigstores_own_requests_users_are_guarded_as_the_sdks_are(sdk):
    """Rekor's, Fulcio's, a timestamp authority's and OIDC's clients: none fetches while an attestation is
    verified, all of them while signing; each is given the stand-in, one loaded only later (Rekor's v2) too."""
    given = sdk_guard.guard(is_local_host)                                # the SDK, and what it verifies with
    assert set(SIGSTORE_REQUESTS) <= set(given)
    for name in SIGSTORE_REQUESTS:
        assert isinstance(sys.modules[name].requests, sdk_guard._GuardedRequests), name
    assert "sigstore._cli" not in given                                   # its command line: never run, never loaded
    sdk.answers["https://rekor.example/api/v1/log"] = "http://rekor.example/api/v1/log"
    with pytest.raises(requests.exceptions.InvalidURL, match="isn't https"):
        sys.modules["sigstore._internal.rekor.client"].requests.Session().get("https://rekor.example/api/v1/log")
    assert sdk.sent == ["https://rekor.example/api/v1/log"]


def test_with_sigstores_internals_elsewhere_nothing_is_attested(sdk, monkeypatch):
    """Another sigstore or TUF, its TUF client not where this expects: the attestation is refused, saying why,
    rather than its trust root fetched unguarded; and nothing is fetched."""
    import asyncio

    from sigstore._internal import tuf as sigstore_tuf

    monkeypatch.setattr(sigstore_tuf, "Updater", object)
    with pytest.raises(sdk_guard.Unguarded, match="isn't tuf.ngclient.Updater"):
        sdk_guard.guard(is_local_host)
    relay = "https://nano-gpt.com/api/v1/private/tinfoil"
    with pytest.raises(private_mode.PrivateModeError, match="couldn't be attested: Sigstore's trust root can't be"):
        asyncio.run(private_mode.Enclave(relay).current())
    assert sdk.sent == []


def test_what_the_guard_rests_on_is_where_it_expects(sigstore_unguarded):
    """sigstore 4.5 and tuf 7.0, as pinned: a version that moves these fails here first (and in the app,
    refuses to attest: Unguarded); a new user of requests in sigstore is named here, to be looked at."""
    import inspect

    from sigstore._internal import tuf as sigstore_tuf
    from tuf.api import exceptions
    from tuf.ngclient import Updater, Urllib3Fetcher
    from tuf.ngclient._internal.proxy import ProxyEnvironment

    assert sigstore_tuf.Updater is Updater and callable(sigstore_tuf.TrustUpdater)
    made = inspect.getsource(sigstore_tuf.TrustUpdater.__init__)
    assert "Updater(" in made and "fetcher" not in made                   # it gives none: the guard's is used
    assert list(inspect.signature(Updater.__init__).parameters)[1:7] == [
        "metadata_dir", "metadata_base_url", "target_dir", "target_base_url", "fetcher", "config"]
    assert isinstance(Urllib3Fetcher()._proxy_env, ProxyEnvironment) and callable(Urllib3Fetcher._chunks)
    assert issubclass(exceptions.DownloadHTTPError, exceptions.DownloadError)
    users = sorted(name for name, mod in sys.modules.items() if mod is not None
                   and (name == "sigstore" or name.startswith("sigstore.")) and getattr(mod, "requests", None) is requests)
    assert users == sorted(SIGSTORE_REQUESTS)
