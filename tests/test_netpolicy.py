"""Which addresses the app may use (https anywhere, http only locally), and which the workspace may reach."""

import httpx
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


def test_an_address_urlparse_cant_take_or_an_ip_with_a_dot_after_it_is_refused():
    with pytest.raises(InsecureURL, match="isn't an address the app can use"):
        check_url("http://[::1]@evil.example/v1")
    assert not is_secure("http://[::1]@evil.example/v1")
    with pytest.raises(InsecureURL):
        check_url("http://192.168.1.50.:8080/v1")      # a name to the resolver: DNS says where it goes
    assert check_url("http://192.168.1.50:8080/v1")


def test_this_computers_networks_include_its_second_addresses_and_its_sites_other_ipv6_networks(tmp_path, monkeypatch):
    import ipaddress
    fib = tmp_path / "fib_trie"
    fib.write_text("Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 0.0.0.0\n        /0 universe UNICAST\n"
                   "     +-- 192.168.1.0/24 2 0 2\n        |-- 192.168.1.0\n           /24 link UNICAST\n"
                   "        |-- 192.168.1.20\n           /32 host LOCAL\n        |-- 192.168.1.21\n           /32 host LOCAL\n")
    nets = netpolicy._fib_ipv4(str(fib))
    assert ipaddress.ip_network("192.168.1.21/32") in nets and ipaddress.ip_network("192.168.1.0/24") in nets
    assert ipaddress.ip_network("0.0.0.0/0") not in nets
    v6 = tmp_path / "if_inet6"
    v6.write_text("2a0200aa00bb00010000000000000005 02 40 00 80 eth0\n")      # 2a02:aa:bb:1::5/64
    real_open = open
    monkeypatch.setattr("builtins.open", lambda path, *a, **k: real_open(v6 if path == "/proc/net/if_inet6" else path, *a, **k))
    own = netpolicy.own_networks()
    assert not is_global_ip("2a02:aa:bb:7::9", own)           # another /64 of the same site (a guest network)
    assert is_global_ip("2a02:aa:cc::1", own)


def test_the_router_is_asked_for_the_public_address_on_this_network_only(monkeypatch):
    """NAT-PMP to the default gateway, else UPnP from its description: never anyone outside."""
    import socket
    import threading
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))

    def answer():
        data, addr = srv.recvfrom(16)
        if data == b"\x00\x00":
            srv.sendto(b"\x00\x80\x00\x00" + b"\x00\x00\x00\x01" + socket.inet_aton("203.0.113.9"), addr)
    threading.Thread(target=answer, daemon=True).start()
    port = srv.getsockname()[1]
    monkeypatch.setattr(netpolicy, "_default_gateway", lambda: "127.0.0.1")
    real_sendto = socket.socket.sendto
    monkeypatch.setattr(socket.socket, "sendto", lambda self, data, addr: real_sendto(self, data, ("127.0.0.1", port))
                        if addr[1] == 5351 else real_sendto(self, data, addr))
    assert netpolicy._natpmp_external(1.0) == "203.0.113.9"
    srv.close()
    monkeypatch.setattr(netpolicy, "_default_gateway", lambda: "8.8.8.8")    # not a local address: not asked
    assert netpolicy._natpmp_external(0.2) is None
    with pytest.raises(ValueError, match="isn't on this network"):
        netpolicy._local_http("http://example.org/desc.xml")


def test_upnp_gives_the_routers_public_address_from_its_description():
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    desc = ("<root><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1"
            "</serviceType><controlURL>/ctl/IPConn</controlURL></service></serviceList></device></root>")

    class Router(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(desc.encode())

        def do_POST(self):
            assert "GetExternalIPAddress" in self.headers["SOAPAction"]
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200); self.end_headers()
            self.wfile.write(b"<s:Envelope><s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>198.51.100.4"
                             b"</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>")
    server = HTTPServer(("127.0.0.1", 0), Router)
    threading.Thread(target=server.handle_request, daemon=True).start()
    threading.Thread(target=lambda: (server.handle_request(), server.server_close()), daemon=True).start()
    assert netpolicy._upnp_ask([f"http://127.0.0.1:{server.server_port}/rootDesc.xml"]) == "198.51.100.4"
    assert netpolicy._upnp_ask(["http://router.example.org/rootDesc.xml"]) is None     # not this network's


# --- the TEE verifier's client: where a redirect may lead (llm/secure_http.py) ---------------------

def _verifier_client(base, handler):
    from davibemanager.llm.secure_http import make_client
    return make_client(base, transport=httpx.MockTransport(handler), follow_redirects=True)


def test_a_redirect_off_https_is_refused_before_anything_is_sent_there():
    from davibemanager.llm.secure_http import ProviderError
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(307, headers={"location": "http://elsewhere.example/collect"})
    with pytest.raises(ProviderError, match="insecure"):
        _verifier_client("https://api.example/v1", handler).get("https://api.example/v1/tee/attestation")
    assert seen == ["https://api.example/v1/tee/attestation"]


def test_a_relative_redirect_and_one_that_stays_on_https_are_followed():
    """httpx runs response hooks before it resolves Location: read raw, a relative one ("/v2/x") had no
    scheme, and every one was refused (SealedLore's test, b829e91)."""
    for location, lands in (("/v2/x", "https://api.example/v2/x"), ("https://cdn.example/x", "https://cdn.example/x")):
        seen = []

        def handler(request, location=location):
            seen.append(str(request.url))
            return httpx.Response(308, headers={"location": location}) if len(seen) == 1 else httpx.Response(200)
        assert _verifier_client("https://api.example/v1", handler).get("https://api.example/v1/a").status_code == 200
        assert seen == ["https://api.example/v1/a", lands]


@pytest.mark.parametrize("location", ["https://192.168.1.1/admin", "http://192.168.1.1/admin", "http://localhost:8080/x",
                                      "https://[fd00::1]/"])
def test_a_server_on_the_internet_cannot_redirect_into_the_local_network(location):
    from davibemanager.llm.secure_http import ProviderError
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": location})
    with pytest.raises(ProviderError, match="local network"):
        _verifier_client("https://api.example/v1", handler).get("https://api.example/v1/a")
    assert len(seen) == 1, "the redirect was not followed"


def test_a_local_server_may_redirect_on_the_local_network():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(307, headers={"location": "http://192.168.1.20:7860/v1/x"}) if len(seen) == 1 \
            else httpx.Response(200)
    _verifier_client("http://192.168.1.10:7860/v1", handler).get("http://192.168.1.10:7860/v1/a")
    assert seen[-1] == "http://192.168.1.20:7860/v1/x"
