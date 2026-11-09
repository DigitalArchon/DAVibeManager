"""A password written into an address (a provider's endpoint, the package mirror's) is kept in the keyring,
as an API key is, never in config.toml, and never said in a message or a log. Ported from DA Assistant's
tests/test_address_passwords.py (729a415, Nov 2026). The keyring is conftest's, in memory."""

import pytest

from davibemanager import config, creds, netpolicy
from davibemanager.config import Config, Provider
from davibemanager.models import Models, UserError

ENDPOINT = "https://bob:hunter2@llm.example/v1"
BUILDER = "https://bob:hunter2@llm.example/anthropic"
MIRROR = "https://carol:pw0rd@mirror.example/ubuntu/"


@pytest.fixture
def setup(tmp_path):
    path = tmp_path / "config.toml"
    cfg = Config()
    models = Models(cfg, save_config=lambda c: config.save(c, path), emit=lambda *a, **k: None, log=lambda *a, **k: None)
    return cfg, models, path


def secret(setting):
    return creds.get_secret(config.ADDRESS_KIND, f"{setting}_with_password")


def fresh(path) -> Config:
    """The app started again: config.toml read, and its addresses put together with the keyring's."""
    creds.forget()
    cfg = config.load(path)
    config.take_passwords(cfg)
    return cfg


def test_the_user_name_and_password_go_and_the_address_stays():
    for url, plain in (("https://alice:s3cret@proxy.example:3128", "https://proxy.example:3128"),
                       ("https://token@host.example/v1?a=b#c", "https://host.example/v1?a=b#c"),
                       ("https://u:p@ss@host.example/", "https://host.example/"),
                       ("http://u:p@[fd00::5]:11434", "http://[fd00::5]:11434"),
                       ("u:p@proxy:3128", "proxy:3128"),
                       ("https://u:p@host:port/", "https://host:port/")):
        assert netpolicy.without_password(url) == plain, url
        assert "p@" not in netpolicy.shown(url) and "…@" in netpolicy.shown(url), url
    for url in ("", "http://localhost:11434", "HTTPS://Host.Example:3128/", "https://host.example/a@b",
                "https://host.example/?to=a@b"):
        assert netpolicy.without_password(url) == url and netpolicy.shown(url) == url, url


def test_an_address_typed_with_a_password_is_written_without_it(setup):
    cfg, models, path = setup
    models.save_provider({"name": "Mine", "base_url": ENDPOINT, "builder_url": BUILDER}, "sk-mine")
    text = path.read_text()
    assert "hunter2" not in text and "bob" not in text
    assert 'base_url = "https://llm.example/v1"' in text and 'builder_url = "https://llm.example/anthropic"' in text
    assert secret("provider:Mine:base_url") == ENDPOINT and secret("provider:Mine:builder_url") == BUILDER
    assert (cfg.providers[0].base_url, cfg.providers[0].builder_url) == (ENDPOINT, BUILDER)    # in use as typed
    again = fresh(path)
    assert (again.providers[0].base_url, again.providers[0].builder_url) == (ENDPOINT, BUILDER)   # and next time


def test_one_left_in_the_file_moves_to_the_keyring(setup):
    _, _, path = setup
    old = Config(providers=[Provider("Mine", ENDPOINT)])
    config.save(old, path)                                   # as an older version wrote it, password and all
    assert "hunter2" in path.read_text()
    cfg = config.load(path)
    assert config.take_passwords(cfg) is True                # moved: the file is to be saved again
    config.save(cfg, path)
    assert "hunter2" not in path.read_text() and cfg.providers[0].base_url == ENDPOINT
    assert secret("provider:Mine:base_url") == ENDPOINT
    assert fresh(path).providers[0].base_url == ENDPOINT
    assert path.stat().st_mode & 0o777 == 0o600


def test_the_password_goes_only_to_the_address_it_was_typed_for(setup):
    cfg, models, path = setup
    models.save_provider({"name": "Mine", "base_url": ENDPOINT}, "sk-mine")
    path.write_text(path.read_text().replace("llm.example", "other.example"))      # edited by hand
    assert fresh(path).providers[0].base_url == "https://other.example/v1"


def test_taking_the_password_out_takes_it_out_of_the_keyring(setup):
    cfg, models, path = setup
    models.save_provider({"name": "Mine", "base_url": ENDPOINT}, "sk-mine")
    models.save_provider({"name": "Mine", "base_url": "https://llm.example/v1"}, None, "Mine")
    assert secret("provider:Mine:base_url") is None
    assert fresh(path).providers[0].base_url == "https://llm.example/v1"


def test_renaming_or_removing_the_provider_takes_its_password_along(setup):
    cfg, models, path = setup
    models.save_provider({"name": "Mine", "base_url": ENDPOINT}, "sk-mine")
    models.save_provider({"name": "Ours", "base_url": ENDPOINT}, None, "Mine")
    assert secret("provider:Mine:base_url") is None and secret("provider:Ours:base_url") == ENDPOINT
    assert fresh(path).providers[0].base_url == ENDPOINT
    models.delete_provider("Ours")
    assert secret("provider:Ours:base_url") is None


def test_saving_other_settings_does_not_touch_the_keyring(setup, memory_keyring, monkeypatch):
    cfg, models, path = setup
    models.save_provider({"name": "Mine", "base_url": ENDPOINT}, "sk-mine")
    writes = []
    real = memory_keyring.set_password
    monkeypatch.setattr(memory_keyring, "set_password", lambda *a: writes.append(a) or real(*a))
    models.save_provider({"name": "Mine", "base_url": ENDPOINT}, None, "Mine")      # as Settings sends it all
    cfg.settings.window_width = 900
    config.save(cfg, path)
    assert writes == [] and "hunter2" not in path.read_text() and cfg.providers[0].base_url == ENDPOINT


def test_an_address_without_a_password_is_written_as_it_is_and_the_keyring_left_alone(setup, memory_keyring, monkeypatch):
    cfg, models, path = setup
    writes = []
    monkeypatch.setattr(memory_keyring, "set_password", lambda *a: writes.append(a))
    cfg.providers.append(Provider("Ollama", "http://192.168.1.201:11434/v1"))
    config.save(cfg, path)
    assert 'base_url = "http://192.168.1.201:11434/v1"' in path.read_text() and writes == []


def test_the_mirrors_password_is_kept_the_same_way(env, tmp_path):
    engine, _, _ = env
    path = tmp_path / "mirror.toml"
    engine._save_config = lambda c: config.save(c, path)
    engine.save_settings({"image_mirror": MIRROR})
    assert engine.cfg.settings.image_mirror == MIRROR and "pw0rd" not in path.read_text()
    assert secret("image_mirror") == MIRROR
    assert fresh(path).settings.image_mirror == MIRROR
    engine.save_settings({"image_mirror": "https://mirror.example/ubuntu/"})
    assert secret("image_mirror") is None


def test_never_said_in_a_message(setup):
    cfg, models, path = setup
    with pytest.raises(UserError) as e:
        models.save_provider({"name": "Mine", "base_url": "ftp://bob:hunter2@llm.example/v1"}, "sk")
    assert "hunter2" not in str(e.value) and "…@llm.example" in str(e.value)
    with pytest.raises(netpolicy.InsecureURL) as e:
        netpolicy.check_url("http://bob:hunter2@llm.example/v1")
    assert "hunter2" not in str(e.value)
    assert netpolicy.scrubbed("Client error '404' for url 'https://bob:hunter2@llm.example/v1/models'") == \
        "Client error '404' for url 'https://…@llm.example/v1/models'"


async def test_nor_in_the_tee_checks_words():
    import httpx

    from davibemanager.llm.tee import TeeClient, TeeRefused
    client = TeeClient("https://bob:hunter2@nano-gpt.example/api/v1", "k", "TEE/x",
                       client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404))))
    with pytest.raises(TeeRefused) as e:
        client.attest()
    assert "hunter2" not in str(e.value) and "…@nano-gpt.example" in str(e.value)


class Locked:
    """A keyring that is there but refuses: locked, or its unlock prompt dismissed."""

    def __init__(self, keyring, monkeypatch):
        def refuse(*a):
            raise RuntimeError("the keyring is locked")
        for name in ("get_password", "set_password", "delete_password"):
            monkeypatch.setattr(keyring, name, refuse)
        creds.forget()


def test_with_the_keyring_locked_one_in_the_file_is_used_and_kept_there(setup, memory_keyring, monkeypatch):
    cfg, models, path = setup
    config.save(Config(providers=[Provider("Mine", ENDPOINT)]), path)         # an older version's file
    with monkeypatch.context() as m:
        Locked(memory_keyring, m)
        cfg = config.load(path)
        assert config.take_passwords(cfg) is False and cfg.providers[0].base_url == ENDPOINT     # used
        cfg.settings.window_width = 800
        config.save(cfg, path)
        assert "hunter2" in path.read_text()                  # kept, not lost
        # and one typed meanwhile isn't taken, nor written anywhere
        models = Models(cfg, save_config=lambda c: config.save(c, path), emit=lambda *a, **k: None,
                        log=lambda *a, **k: None)
        with pytest.raises(UserError, match="Unlock your keyring"):
            models.save_provider({"name": "Other", "base_url": "https://dan:letmein@other.example/v1"}, None)
        assert "letmein" not in path.read_text() and not cfg.provider("Other")
    creds.forget()
    assert config.take_passwords(cfg) is True                 # the keyring is back (Engine.retry_keyring)
    config.save(cfg, path)
    assert "hunter2" not in path.read_text() and fresh(path).providers[0].base_url == ENDPOINT
