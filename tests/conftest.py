import keyring
import pytest
from keyring.backend import KeyringBackend


class MemoryKeyring(KeyringBackend):
    priority = 1

    def __init__(self):
        super().__init__()
        self.store = {}

    def get_password(self, service, username):
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        from keyring.errors import PasswordDeleteError

        if (service, username) not in self.store:
            raise PasswordDeleteError(username)
        del self.store[(service, username)]


@pytest.fixture(autouse=True)
def memory_keyring(tmp_path, monkeypatch):
    """Never touch the real keyring or real config/data dirs in tests."""
    backend = MemoryKeyring()
    old = keyring.get_keyring()
    keyring.set_keyring(backend)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    yield backend
    keyring.set_keyring(old)


@pytest.fixture
async def env(tmp_path):
    """An engine with one fake provider ("Fake", serving the assistant and the reviewer) and an
    open conversation; no sandbox. Yields (engine, fake API, emitted events)."""
    import httpx

    from davibemanager import creds
    from davibemanager.config import Config, Provider
    from davibemanager.engine import Engine
    from davibemanager.llm.client import LLMClient
    from davibemanager.llm.tee import TeeClient
    from helpers import BASE, FakeAPI

    fake = FakeAPI()
    events = []
    cfg = Config(providers=[Provider("Fake", BASE, builder_url=BASE)])
    cfg.settings.builder_provider = "Fake"
    cfg.settings.review_model = "Fake|reviewer-model"
    engine = Engine(cfg, events.append, tmp_path / "rt", save_config=lambda c: None)
    http = httpx.AsyncClient(transport=httpx.MockTransport(fake.handler))
    engine.models.client_factory = lambda prov, model="": LLMClient(prov.base_url, creds.get_secret("provider", prov.name), http)
    engine.models.tee_factory = lambda base, key, model: TeeClient(
        base, key, model, client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404))))
    creds.set_secret("provider", "Fake", "sk-test")
    engine.start_workspace = lambda: None          # no sandbox in unit tests
    await engine.start()
    # most tests build something: an app chat, about an app not built before (computer chats set their own)
    engine.conv.mode, engine.conv.app_name = "app", "an app"
    yield engine, fake, events
    await engine.stop()


@pytest.fixture(autouse=True)
def no_real_app_homes(monkeypatch, tmp_path):
    """Tests never reach this computer's Gear Lever, Shelly or Flatpak: only fakes a test puts in
    tmp_path/bin are found."""
    from davibemanager import integrate

    def which(name):
        fake = tmp_path / "bin" / name
        return str(fake) if fake.exists() else None
    monkeypatch.setattr(integrate, "_which", which)


@pytest.fixture(autouse=True)
def no_real_podman(request, monkeypatch):
    """Unit tests never run podman on this computer (its real sandbox is there): a test that makes the
    engine think the sandbox runs would otherwise stop it when it ends. Only -m podman tests may."""
    if request.node.get_closest_marker("podman"):
        return
    from davibemanager.workspace import podman
    calls, real = [], podman.run

    async def run(argv, **kw):
        if argv and argv[0] != podman.podman():
            return await real(argv, **kw)       # the runner itself, tested with other commands
        calls.append(argv)
        return 0, ""
    monkeypatch.setattr(podman, "run", run)
    return calls
