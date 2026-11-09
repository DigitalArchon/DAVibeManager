"""Tinfoil's SDK fetches over https only: a redirect off https, or from the internet into this computer
or its network, is not followed.

The SDK makes bare requests.get and requests.post calls (GitHub's release and Sigstore bundle, AMD's and
Intel's certificates, the enclave's attestation), and requests follows a redirect anywhere, https to plain
http included. llm/sdk_guard.py hands each of its modules a stand-in for requests whose every fetch judges
a redirect first, without changing the SDK on disk. Here the SDK is a fake one, written to a folder of the
test's own, in the shapes the real one takes requests in; nothing reaches the network. Ported from DA
Assistant's tests/test_sdk_redirects.py (Nov 2026)."""

import importlib
import sys
import textwrap

import pytest
import requests

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
def sdk(tmp_path, monkeypatch):
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
