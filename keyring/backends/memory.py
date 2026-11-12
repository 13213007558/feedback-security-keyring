"""
In-memory keyring backend.

A backend that keeps credentials in a process-local dictionary. It is not
persistent and never leaves the process, so it is well suited to tests and to
composing restricted views without touching a real credential store.
"""

from __future__ import annotations

from .. import credentials, errors
from ..backend import KeyringBackend
from ..compat import properties


class MemoryKeyring(KeyringBackend):
    """
    Store credentials in memory only.

    >>> kr = MemoryKeyring()
    >>> kr.set_password('svc', 'alice', 'secret')
    >>> kr.get_password('svc', 'alice')
    'secret'
    >>> kr.get_password('svc', 'bob') is None
    True
    >>> kr.delete_password('svc', 'alice')
    >>> kr.get_password('svc', 'alice') is None
    True
    """

    def __init__(self) -> None:
        super().__init__()
        self._entries: dict[tuple[str, str], str] = {}

    @properties.classproperty
    def priority(cls) -> float:
        return 1

    def get_password(self, service: str, username: str) -> str | None:
        return self._entries.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self._entries[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        try:
            del self._entries[(service, username)]
        except KeyError:
            msg = f"No password for {username!r} in {service!r}"
            raise errors.PasswordDeleteError(msg) from None

    def get_credential(
        self,
        service: str,
        username: str | None,
    ) -> credentials.SimpleCredential | None:
        if username is not None:
            password = self.get_password(service, username)
            if password is None:
                return None
            return credentials.SimpleCredential(username, password)

        for (stored_service, stored_username), password in self._entries.items():
            if stored_service == service:
                return credentials.SimpleCredential(stored_username, password)
        return None
