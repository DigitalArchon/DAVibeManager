"""Secret storage in the OS keyring (Secret Service on Linux).

Right after login the keyring may not be there yet: started with the session, the app can ask
before the Secret Service runs or before the user's keyring is unlocked. A key that can't be read
then is not a key that isn't there: reading raises KeyringUnavailable, and a key that isn't stored
reads as None. The keyring library picks its backend once per process; if it settled on none (no
Secret Service yet), it is asked to look again before each use. A backend that isn't a secure one
(priority below 1: none at all, or one that keeps secrets in a plain file) is never used: nothing
is stored in it, or read from it, and KeyringUnavailable says so. Until Nov 2026 it was only
reported (backend_error) and written to all the same (DA Private Coder's creds._backend).

What has been read is kept in memory for the rest of the run (and what is stored or deleted here
with it): every model request and every redraw of the window needs the key, and a keyring that
locked itself again (KWallet's timeout) would otherwise stop the whole app on its password prompt."""

from __future__ import annotations

import keyring
import keyring.core
from keyring.errors import PasswordDeleteError

SERVICE = "davibemanager"


class KeyringUnavailable(Exception):
    """The keyring couldn't be read or written: not running yet, locked, or none at all."""


def _backend():
    """The keyring's backend, if it is a secure one; else KeyringUnavailable, saying what to do."""
    backend = keyring.get_keyring()
    if getattr(backend, "priority", 0) < 1:
        keyring.core.init_backend()          # the Secret Service may have started since
        backend = keyring.get_keyring()
    if getattr(backend, "priority", 0) < 1:
        raise KeyringUnavailable(
            f"No secure keyring backend available ({type(backend).__name__}). "
            "Install and unlock a Secret Service provider such as gnome-keyring or KWallet.")
    return backend


def backend_error() -> str | None:
    """Return a human-readable problem if no usable keyring backend exists."""
    try:
        _backend()
    except KeyringUnavailable as e:
        return str(e)
    except Exception as e:  # noqa: BLE001 - any backend failure is reportable
        return f"Keyring unavailable: {e}"
    return None


_known: dict[tuple[str, str], str | None] = {}


def forget() -> None:
    """Read everything from the keyring again (a restore brought other keys; tests)."""
    _known.clear()


def _user(kind: str, name: str) -> str:
    return f"{kind}:{name}"


def set_secret(kind: str, name: str, value: str) -> None:
    try:
        _backend().set_password(SERVICE, _user(kind, name), value)
    except KeyringUnavailable:
        raise
    except Exception as e:  # noqa: BLE001 - said to the user as it is
        raise KeyringUnavailable(f"Your keyring couldn't store the key: {e}") from e
    _known[(kind, name)] = value


def get_secret(kind: str, name: str) -> str | None:
    if (kind, name) in _known:
        return _known[(kind, name)]
    try:
        value = _backend().get_password(SERVICE, _user(kind, name))
    except KeyringUnavailable:
        raise
    except Exception as e:  # noqa: BLE001 - locked, not running yet, or none (never kept: asked again)
        raise KeyringUnavailable(str(e) or type(e).__name__) from e
    _known[(kind, name)] = value
    return value


def delete_secret(kind: str, name: str) -> None:
    try:
        _backend().delete_password(SERVICE, _user(kind, name))
    except (PasswordDeleteError, KeyringUnavailable):
        pass                                 # nothing there, or nothing secure to have it in
    _known[(kind, name)] = None


def has_secret(kind: str, name: str) -> bool:
    return get_secret(kind, name) is not None
