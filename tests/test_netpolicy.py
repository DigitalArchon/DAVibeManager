"""Which addresses the app may use (https anywhere, http only locally), and which the workspace may reach."""

import pytest

from davibemanager.config import Provider
from davibemanager.llm.client import LLMClient, detect_tier, is_local_url
from davibemanager.models import Models, UserError
from davibemanager import netpolicy
from davibemanager.netpolicy import InsecureURL, check_url, is_global_ip, is_local_host, is_secure


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "127.8.9.1", "::1", "[::1]", "10.1.2.3", "172.16.0.1",
                                  "172.31.255.255", "192.168.1.5", "fd12::1", "fe80::1", "169.254.10.1", "nas.local",
                                  "app.localhost"])
def test_local_hosts_are_exactly_the_local_set(host):
    assert is_local_host(host)


@pytest.mark.parametrize("host", ["", "example.com", "172.32.0.1", "8.8.8.8", "nas.lan", "10.0.0.1.evil.com",
                                  "localhost.evil.com", "2001:db8::1", "100.64.0.1"])
def test_anything_else_is_not_local(host):
    assert not is_local_host(host)


def test_https_is_accepted_anywhere_and_http_only_locally():
    assert is_secure("https://nano-gpt.com/api/v1")
    assert is_secure("http://localhost:11434/v1")
    assert is_secure("http://192.168.1.20:8000/v1")
    assert not is_secure("http://nano-gpt.com/api/v1")
    assert not is_secure("http://example.lan/v1")
    assert not is_secure("ftp://localhost/")
    assert not is_secure("https:///nohost")


def test_a_plain_http_cloud_url_is_refused_with_a_reason_not_rewritten():
    with pytest.raises(InsecureURL, match="plain http to nano-gpt.com"):
        check_url("http://nano-gpt.com/api/v1")
    with pytest.raises(InsecureURL, match="full https"):
        check_url("nano-gpt.com/api/v1")
    assert check_url(" https://x.example/v1 ") == "https://x.example/v1"


def test_the_chat_client_refuses_an_insecure_base_url():
    with pytest.raises(InsecureURL):
        LLMClient("http://api.example.com/v1", "k")
    LLMClient("http://127.0.0.1:1234/v1", None)          # a local server is fine


async def test_the_chat_client_never_follows_a_redirect_the_request_would_go_anywhere():
    """A provider's 307 to plain http (one has pointed at 0.0.0.0): the request, the user's words in it,
    isn't sent again there, in the clear."""
    import httpx2                                       # the OpenAI SDK's own http library
    import openai
    c = LLMClient("https://nano-gpt.com/api/v1", "sk-test")
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx2.Response(307, headers={"location": "http://0.0.0.0:3000/api/v1/chat/completions"})
    inner = c._client._client
    inner._transport, inner._mounts = httpx2.MockTransport(handler), {}
    with pytest.raises(openai.APIStatusError, match="307"):
        await c.complete("z-ai/glm-5.3", [{"role": "user", "content": "the output of ip a"}])
    assert seen == ["https://nano-gpt.com/api/v1/chat/completions"]


async def test_every_client_that_carries_the_key_refuses_plain_http_to_the_cloud():
    """A base URL from a config file edited by hand, or from a backup, isn't checked when it's read:
    each client that sends the key (or a prompt) holds it to the rule itself, before sending anything."""
    from davibemanager.llm import capabilities, websearch
    from davibemanager.llm.private_mode import Enclave, PrivateModeClient, list_private_models, relay_url
    from davibemanager.llm.tee import TeeClient
    base = "http://nano-gpt.com/api/v1"
    with pytest.raises(InsecureURL):
        TeeClient(base, "sk-test", "TEE/glm-5.3")
    with pytest.raises(InsecureURL):
        PrivateModeClient(base, "sk-test", Enclave(relay_url(base)))
    with pytest.raises(InsecureURL):
        await list_private_models(base)
    with pytest.raises(InsecureURL):
        await capabilities.fetch_nanogpt(base, "sk-test")
    with pytest.raises(websearch.SearchError, match="plain http"):
        await websearch.web_search(base, "sk-test", "gtk drag to zoom")


def test_saving_a_provider_with_a_plain_http_cloud_url_is_refused(tmp_path):
    from davibemanager.config import Config
    models = Models(Config(), save_config=lambda c: None, emit=lambda *a, **k: None, log=lambda *a, **k: None)
    with pytest.raises(UserError, match="plain http"):
        models.save_provider({"name": "Bad", "base_url": "http://api.example.com/v1"})
    with pytest.raises(UserError, match="assistant's endpoint"):
        models.save_provider({"name": "Bad", "base_url": "https://ok.example/v1", "builder_url": "http://api.example.com"})
    models.save_provider({"name": "Ollama", "base_url": "http://localhost:11434/v1"})
    models.save_provider({"name": "NanoGPT", "base_url": "https://nano-gpt.com/api/v1"})
    nano = models.cfg.provider("NanoGPT")
    assert (nano.builder_url, nano.builder_auth) == ("https://nano-gpt.com/api/v1", "bearer")   # filled in


@pytest.mark.parametrize("ip,ok", [("140.82.112.3", True), ("2606:4700::1111", True), ("192.168.1.1", False),
                                   ("10.0.2.2", False), ("127.0.0.1", False), ("::1", False), ("169.254.169.254", False),
                                   ("100.64.0.1", False), ("fd00::1", False), ("::ffff:127.0.0.1", False),
                                   ("0.0.0.0", False), ("224.0.0.1", False), ("not-an-ip", False)])
def test_the_workspace_may_only_reach_globally_routable_addresses(ip, ok):
    assert is_global_ip(ip) is ok


def test_an_override_can_lower_a_tier_but_never_claim_encryption_or_locality():
    cloud = "https://nano-gpt.com/api/v1"
    assert detect_tier("anthropic/claude-opus-5.5", cloud, {"anthropic/claude-opus-5.5": "e2ee"}) == "standard"
    assert detect_tier("anthropic/claude-opus-5.5", cloud, {"anthropic/claude-opus-5.5": "local"}) == "standard"
    assert detect_tier("TEE/glm-5.3", cloud, {"TEE/glm-5.3": "local"}) == "tee"
    assert detect_tier("TEE/glm-5.3", cloud, {"TEE/glm-5.3": "standard"}) == "standard"       # lowering is fine
    assert detect_tier("odd-tee-model", cloud, {"odd-tee-model": "tee"}) == "tee"            # attested before use
    assert detect_tier("private/glm-5-3", cloud, {"private/glm-5-3": "standard"}) == "standard"
    assert detect_tier("qwen3", "http://localhost:11434/v1", {"qwen3": "standard"}) == "standard"
    assert detect_tier("qwen3", "http://localhost:11434/v1") == "local"


def test_an_empty_host_is_not_the_local_tier():
    assert not is_local_url("http:///v1")
    assert is_local_url("training://disk-full")
    assert not is_local_url("https://ollama.lan/v1")
    assert Provider("x", "https://a").builder_url == ""


def test_this_computers_own_networks_are_never_public_for_the_workspace():
    import ipaddress
    own = netpolicy.own_networks()
    assert any(n.version == 4 and ipaddress.ip_address("127.0.0.1") in n for n in own)
    lan = (ipaddress.ip_network("2a02:8108:1:2::/64"),)
    assert not netpolicy.is_global_ip("2a02:8108:1:2::abcd", lan) and netpolicy.is_global_ip("2a02:8108:9:9::1", lan)
    for carried in ("64:ff9b::7f00:1", "2002:7f00:1::1", "::ffff:10.0.0.1"):
        assert not netpolicy.is_global_ip(carried)
