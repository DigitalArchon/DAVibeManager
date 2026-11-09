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
