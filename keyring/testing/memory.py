"""
An in-memory backend for demonstrating chaining and stale-copy behavior.

This module is a test aid, not a production backend.  It lets tests and
documentation model independent stores (for example, an authoritative
source and a lagging replica) without touching an OS keychain.
"""

from __future__ import annotations

from .. import backend, credentials, errors


class MemoryBackend(backend.KeyringBackend):
    """A dict-backed backend.

    Subclasses choose an identity and priority at class definition time::

        class Vault(MemoryBackend):
            source_id = 'vault'
            priority = 5

    ``source_id`` is the stable identity used by source-bound policies.
    When omitted, the backend's module-qualified name is used instead.

    The class is marked non-viable so importing this test aid does not
    make it a participant in automatic backend discovery.
    """

    viable = False
    priority = 1
    source_id: str | None = None

    def __init__(self, store: dict[tuple[str, str], str] | None = None):
        super().__init__()
        self.store = store if store is not None else {}
        self.reads = 0

    def get_password(self, service, username):
        self.reads += 1
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        try:
            del self.store[(service, username)]
        except KeyError:
            raise errors.PasswordDeleteError('No such password!') from None

    def get_credential(self, service, username):
        if username is None:
            for (svc, user), password in self.store.items():
                if svc == service:
                    return credentials.SimpleCredential(user, password)
            return None
        password = self.get_password(service, username)
        if password is None:
            return None
        return credentials.SimpleCredential(username, password)


class StaleReplica(MemoryBackend):
    """A replica whose copy can lag behind the source.

    ``snapshot_from`` copies the source's entries once, modeling
    replication that stops after a write is redirected elsewhere.  The
    replica keeps serving the old copy indefinitely.
    """

    viable = False

    def snapshot_from(self, source: MemoryBackend) -> None:
        self.store.update(source.store)
