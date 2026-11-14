"""The keyring: only a secure one is ever used. Nothing here reaches the real keyring (conftest's is in
memory, and these stand in for the backends the keyring library falls back to)."""

import keyring
import pytest

from davibemanager import creds
from davibemanager.config import Config
from davibemanager.models import Models, UserError
from conftest import MemoryKeyring


class Plaintext(MemoryKeyring):
    """What keyrings.alt's PlaintextKeyring is to the keyring library: there, and writing secrets to a
    file anyone with the disk can read (its priority is 0.5)."""
    priority = 0.5


@pytest.fixture
def plaintext(monkeypatch):
    backend = Plaintext()
    keyring.set_keyring(backend)
    monkeypatch.setattr(keyring.core, "init_backend", lambda *a: None)      # looking again finds the same
    creds.forget()
    return backend


def test_a_backend_that_isnt_secure_is_never_written_to(plaintext):
    with pytest.raises(creds.KeyringUnavailable, match="No secure keyring"):
        creds.set_secret("provider", "NanoGPT", "sk-live-123")
    assert plaintext.store == {}
    assert "No secure keyring" in creds.backend_error()


def test_nor_read_from(plaintext):
    plaintext.store[(creds.SERVICE, "provider:NanoGPT")] = "sk-left-there"
    with pytest.raises(creds.KeyringUnavailable):
        creds.get_secret("provider", "NanoGPT")
    creds.delete_secret("provider", "NanoGPT")                # nothing to do there, and no error
    assert plaintext.store                                     # left as it was: not the app's to touch


def test_settings_say_so_and_keep_nothing(plaintext, tmp_path):
    saved = []
    cfg = Config()
    m = Models(cfg, save_config=saved.append, emit=lambda *a, **k: None, log=lambda *a, **k: None)
    with pytest.raises(UserError, match="Unlock your keyring"):
        m.save_provider({"name": "NanoGPT", "base_url": "https://nano-gpt.com/api/v1"}, "sk-live-123")
    assert plaintext.store == {}


def test_the_backups_password_is_refused_the_same_way(plaintext, tmp_path):
    from davibemanager.backup import BackupError, Backups
    from davibemanager.engine import Engine
    engine = Engine(Config(), lambda e: None, tmp_path, save_config=lambda c: None)
    with pytest.raises(BackupError, match="unlock your keyring"):
        Backups(engine).set_password("a long enough password 1")
    assert plaintext.store == {}


def test_a_secure_one_is_used_as_ever(memory_keyring):
    creds.set_secret("provider", "NanoGPT", "sk-live-123")
    assert memory_keyring.store[(creds.SERVICE, "provider:NanoGPT")] == "sk-live-123"
    assert creds.backend_error() is None


# --- a key goes only to the address it was entered for (the design every DA app keeps, Nov 2026) ------------

def _models(cfg):
    return Models(cfg, save_config=lambda c: None, emit=lambda *a, **k: None, log=lambda *a, **k: None)


NANO = "https://nano-gpt.com/api/v1"


def test_a_key_doesnt_follow_an_address_changed_without_it():
    """The key was kept by the provider's name alone: an address changed through the API (or by hand) took it, and
    everything sent with it, to wherever it now pointed. Nothing is deleted: the address put back, it goes again."""
    cfg = Config()
    m = _models(cfg)
    m.save_provider({"name": "NanoGPT", "base_url": NANO}, "sk-live-1")
    assert cfg.provider("NanoGPT").key_for == ["https://nano-gpt.com:443"]
    assert m.key(cfg.provider("NanoGPT")) == "sk-live-1"
    m.save_provider({"name": "NanoGPT", "base_url": "https://evil.example/api/v1"})       # no key given with it
    prov = cfg.provider("NanoGPT")
    with pytest.raises(UserError, match=r"entered for https://nano-gpt.com:443, and NanoGPT's address is now "
                                        r"https://evil.example:443: the key isn't sent there"):
        m.key(prov)
    with pytest.raises(UserError, match="isn't sent there"):
        m.client(prov, "zai-org/glm-5.3")
    assert creds.get_secret("provider", "NanoGPT") == "sk-live-1"                         # never deleted
    m.save_provider({"name": "NanoGPT", "base_url": NANO})                                # put back
    assert m.key(cfg.provider("NanoGPT")) == "sk-live-1"


def test_a_key_follows_a_new_address_only_when_the_user_says_so_or_enters_it_again():
    cfg = Config()
    m = _models(cfg)
    m.save_provider({"name": "Mine", "base_url": "https://llm.example/v1"}, "sk-live-1")
    m.save_provider({"name": "Mine", "base_url": "https://llm2.example/v1", "use_saved_key": True})
    assert m.key(cfg.provider("Mine")) == "sk-live-1" and cfg.provider("Mine").key_for == ["https://llm2.example:443"]
    m.save_provider({"name": "Mine", "base_url": "http://localhost:11434/v1"}, "sk-local")
    assert m.key(cfg.provider("Mine")) == "sk-local" and cfg.provider("Mine").key_for == ["http://localhost:11434"]
    m.save_provider({"name": "Mine", "base_url": "http://localhost:8080/v1"})              # another port: elsewhere
    with pytest.raises(UserError, match="isn't sent there"):
        m.key(cfg.provider("Mine"))
    # renamed, the key keeps its address
    m.save_provider({"name": "Theirs", "base_url": "http://localhost:11434/v1"}, original_name="Mine")
    assert m.key(cfg.provider("Theirs")) == "sk-local"
    # a provider new here, with a key left under its name from before, sends it nowhere until one is entered
    creds.set_secret("provider", "Stale", "sk-left-behind")
    m.save_provider({"name": "Stale", "base_url": "https://new.example/v1"})
    with pytest.raises(UserError, match="entered for no address"):
        m.key(cfg.provider("Stale"))


def test_a_hand_edited_address_doesnt_take_the_key_and_an_older_config_gives_it_the_addresses_beside_it(tmp_path):
    from davibemanager import config

    path = tmp_path / "config.toml"
    path.write_text(f'[[providers]]\nname = "NanoGPT"\nbase_url = "{NANO}"\nbuilder_url = "{NANO}"\n\n'
                    '[settings]\nbuilder_provider = "NanoGPT"\nbuilder_model = "zai-org/glm-5.3"\n')
    cfg = config.load(path)                                  # from before keys were held to their address
    assert cfg.provider("NanoGPT").key_for == ["https://nano-gpt.com:443"] and cfg.__dict__["_origins_settled"]
    config.save(cfg, path)
    import tomllib
    assert tomllib.loads(path.read_text())["providers"][0]["key_for"] == ["https://nano-gpt.com:443"]
    path.write_text(path.read_text().replace(NANO, "https://evil.example/v1"))           # edited by hand
    cfg = config.load(path)
    assert "_origins_settled" not in cfg.__dict__
    creds.set_secret("provider", "NanoGPT", "sk-live-2")
    m = _models(cfg)
    with pytest.raises(UserError, match="entered for https://nano-gpt.com:443.*Settings"):
        m.builder_target()                                  # the assistant doesn't start with it
    with pytest.raises(UserError, match="isn't sent there"):
        m.key(cfg.provider("NanoGPT"))


async def test_the_gateway_refuses_a_request_whose_key_was_entered_for_another_address(tmp_path):
    import httpx

    from davibemanager.gateway import Gateway, Upstream

    forwarded = []

    def key():
        raise UserError("The API key saved for NanoGPT was entered for https://nano-gpt.com:443 …")

    g = Gateway(tmp_path / "gw", lambda: Upstream(
        "https://evil.example/api/v1", "bearer", key, ("anthropic/claude-opus-5.5",), provider="NanoGPT"),
        http=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: forwarded.append(r) or httpx.Response(200))))
    await g.start()
    try:
        async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(g.model_socket)), base_url="http://gw") as c:
            r = await c.post("/v1/messages", headers={"authorization": f"Bearer {g.token}"}, json={
                "model": "anthropic/claude-opus-5.5", "messages": [{"role": "user", "content": "hi"}]})
    finally:
        await g.stop()
    assert r.status_code == 403 and "entered for https://nano-gpt.com:443" in r.text and forwarded == []


# --- a key over plain http to another machine (the cross-app standard, Nov 2026) ----------------------------

def test_a_key_never_crosses_the_network_unencrypted_unless_the_config_says_so(tmp_path):
    """Plain http is allowed to this computer and the local network, but to another machine the key crosses that
    network unencrypted. With no field for the address in the window, nothing asks: it isn't sent, in words naming
    the address and the ways out, until config.toml says `key_over_http = true` beside it."""
    from davibemanager import netpolicy
    assert netpolicy.in_the_clear("http://192.168.1.5:11434/v1") and netpolicy.in_the_clear("http://nas.local/v1")
    for here in ("http://localhost:11434/v1", "http://127.0.0.2/v1", "http://[::1]:8080/v1", "https://192.168.1.5/v1"):
        assert not netpolicy.in_the_clear(here), here
    assert not netpolicy.is_loopback_host("127.0.0.1.") and netpolicy.is_loopback_host("api.localhost")
    cfg = Config()
    m = _models(cfg)
    m.save_provider({"name": "Mine", "base_url": "http://192.168.1.5:11434/v1"}, "sk-lan")
    with pytest.raises(UserError, match=r"http://192.168.1.5:11434/v1 is plain http to another machine.*https://.*"
                                        r"`key_over_http = true` under Mine in config.toml"):
        m.key(cfg.provider("Mine"))
    with pytest.raises(UserError, match="plain http to another machine"):
        m.client(cfg.provider("Mine"), "llama3")
    cfg.provider("Mine").key_over_http = True                                         # as a hand edit sets it
    assert m.key(cfg.provider("Mine")) == "sk-lan"
    m.save_provider({"name": "Mine", "base_url": "http://192.168.1.5:11434/v1", "default_model": "x"})
    assert m.key(cfg.provider("Mine")) == "sk-lan"                                    # kept at the same address
    m.save_provider({"name": "Mine", "base_url": "http://192.168.1.6:11434/v1"}, "sk-other")
    with pytest.raises(UserError, match="plain http"):
        m.key(cfg.provider("Mine"))                                                   # not to another machine
    m.save_provider({"name": "Mine", "base_url": "http://192.168.1.6:11434/v1", "key_over_http": "yes"})
    assert cfg.provider("Mine").key_over_http is False                                # only a JSON true
    m.save_provider({"name": "Mine", "base_url": "http://192.168.1.6:11434/v1", "key_over_http": True})
    assert m.key(cfg.provider("Mine")) == "sk-other"
    m.save_provider({"name": "Local", "base_url": "http://localhost:11434/v1"}, "sk-here")
    assert m.key(cfg.provider("Local")) == "sk-here"                                  # this computer: never leaves it


def test_a_provider_already_sending_its_key_over_plain_http_keeps_doing_so_once_settled(tmp_path):
    """The first load by this version of a config.toml from before keys were held to their address sets the flag
    for a provider whose key already went so, with no question; a hand edit after it sets nothing."""
    import tomllib

    from davibemanager import config
    path = tmp_path / "config.toml"
    path.write_text('[[providers]]\nname = "Lan"\nbase_url = "http://192.168.1.5:11434/v1"\n\n'
                    '[[providers]]\nname = "NanoGPT"\nbase_url = "https://nano-gpt.com/api/v1"\n')
    cfg = config.load(path)
    assert cfg.provider("Lan").key_over_http is True and cfg.provider("NanoGPT").key_over_http is False
    config.save(cfg, path)
    assert tomllib.loads(path.read_text())["providers"][0]["key_over_http"] is True
    path.write_text(path.read_text().replace("http://192.168.1.5:11434/v1", "http://192.168.1.9:11434/v1")
                    .replace("key_over_http = true", "key_over_http = false"))
    cfg = config.load(path)
    assert cfg.provider("Lan").key_over_http is False                                  # settled once, never again
