"""Secret storage in the OS keyring (Secret Service on Linux).

Right after login the keyring may not be there yet: started with the session, the app can ask
before the Secret Service runs or before the user's keyring is unlocked. A key that can't be read
then is not a key that isn't there: reading raises KeyringUnavailable, and a key that isn't stored
reads as None. The keyring library picks its backend once per process; if it settled on none (no
Secret Service yet), it is asked to look again before each use."""

from __future__ import annotations

import keyring
import keyring.core
from keyring.errors import PasswordDeleteError

SERVICE = "davibemanager"
OLD_SERVICE = "dalinuxagent"             # before the app was renamed (DA Linux Agent)


class KeyringUnavailable(Exception):
    """The keyring couldn't be read or written: not running yet, locked, or none at all."""


def _backend():
    backend = keyring.get_keyring()
    if getattr(backend, "priority", 0) < 1:
        keyring.core.init_backend()          # the Secret Service may have started since
        backend = keyring.get_keyring()
    return backend


def backend_error() -> str | None:
    """Return a human-readable problem if no usable keyring backend exists."""
    try:
        backend = _backend()
    except Exception as e:  # noqa: BLE001 - any backend failure is reportable
        return f"Keyring unavailable: {e}"
    if getattr(backend, "priority", 0) < 1:
        return (
            f"No secure keyring backend available ({type(backend).__name__}). "
            "Install and unlock a Secret Service provider such as gnome-keyring or KWallet."
        )
    return None


def _user(kind: str, name: str) -> str:
    return f"{kind}:{name}"


def set_secret(kind: str, name: str, value: str) -> None:
    try:
        _backend().set_password(SERVICE, _user(kind, name), value)
    except Exception as e:  # noqa: BLE001 - said to the user as it is
        raise KeyringUnavailable(f"Your keyring couldn't store the key: {e}") from e


def get_secret(kind: str, name: str) -> str | None:
    try:
        backend = _backend()
        value = backend.get_password(SERVICE, _user(kind, name))
        if value is None:
            value = _moved(backend, _user(kind, name))
        return value
    except Exception as e:  # noqa: BLE001 - locked, not running yet, or none
        raise KeyringUnavailable(str(e) or type(e).__name__) from e


def _moved(backend, user: str) -> str | None:
    """A secret stored under the app's old name, moved to its new one (here, not at startup: the
    keyring may still be locked then). The old one is deleted only once the new one reads back."""
    value = backend.get_password(OLD_SERVICE, user)
    if value is not None:
        backend.set_password(SERVICE, user, value)
        if backend.get_password(SERVICE, user) == value:
            try:
                backend.delete_password(OLD_SERVICE, user)
            except PasswordDeleteError:
                pass
    return value


def delete_secret(kind: str, name: str) -> None:
    for service in (SERVICE, OLD_SERVICE):
        try:
            _backend().delete_password(service, _user(kind, name))
        except PasswordDeleteError:
            pass


def has_secret(kind: str, name: str) -> bool:
    return get_secret(kind, name) is not None
