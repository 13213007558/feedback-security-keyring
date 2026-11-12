"""
Tests for the optional scoped-credential interface.

The fake backends below count every backend read so the tests can assert
when (and whether) credential material is dereferenced.
"""

from __future__ import annotations

import logging
import threading

import pytest

import keyring
from keyring import credentials
from keyring.backend import KeyringBackend
from keyring.compat import properties
from keyring.errors import CredentialScopeError, KeyringError

SECRET = 's3cret-value'


class CountingKeyring(KeyringBackend):
    """In-memory backend that counts reads of credential material."""

    def __init__(self):
        super().__init__()
        self._store: dict[tuple[str, str], str] = {}
        self.credential_reads = 0
        self.password_reads = 0

    @properties.classproperty
    def priority(cls) -> float:
        return 1

    def set_password(self, service, username, password):
        self._store[(service, username)] = password

    def delete_password(self, service, username):
        self._store.pop((service, username))

    def get_password(self, service, username):
        self.password_reads += 1
        return self._store.get((service, username))

    def get_credential(self, service, username):
        self.credential_reads += 1
        for (stored_service, stored_username), password in self._store.items():
            if stored_service == service and (
                username is None or stored_username == username
            ):
                return credentials.SimpleCredential(stored_username, password)
        return None


class FailingKeyring(CountingKeyring):
    """Backend whose dereference always fails."""

    def get_credential(self, service, username):
        self.credential_reads += 1
        raise KeyringError('backend unavailable')


class CustomScopedKeyring(CountingKeyring):
    """Backend that overrides the scoped interface with its own loader."""

    def get_scoped_credential(self, service, username, scope):
        def load():
            return self.get_credential(service, username)

        return credentials.ScopedCredential(service, username, load)


@pytest.fixture
def keyring_backend(monkeypatch):
    backend = CountingKeyring()
    backend.set_password('service', 'alice', SECRET)
    monkeypatch.setattr(keyring.core, '_keyring_backend', backend)
    return backend


def test_handle_does_not_read_backend_on_issue(keyring_backend):
    with keyring.scoped_credential() as scope:
        handle = scope.get('service', 'alice')
        assert keyring_backend.credential_reads == 0
        assert keyring_backend.password_reads == 0
        assert isinstance(handle, credentials.ScopedCredential)


def test_resolve_reads_backend_each_time(keyring_backend):
    with keyring.scoped_credential() as scope:
        handle = scope.get('service', 'alice')
        first = handle.resolve()
        second = handle.resolve()
        assert first is not None and second is not None
        assert (first.username, first.password) == ('alice', SECRET)
        assert (second.username, second.password) == ('alice', SECRET)
        assert keyring_backend.credential_reads == 2


def test_repr_and_str_never_contain_secret(keyring_backend, caplog):
    with keyring.scoped_credential() as scope:
        handle = scope.get('service', 'alice')
        rendered = [repr(handle), str(handle)]
        handle.resolve()
        rendered += [repr(handle), str(handle)]
    rendered += [repr(handle), str(handle)]

    caplog.set_level(logging.DEBUG)
    logging.getLogger(__name__).info('handle in flight: %s', handle)

    for text in rendered + [r.getMessage() for r in caplog.records]:
        assert SECRET not in text
    assert all('service' in text for text in rendered)


def test_handle_is_invalid_after_scope_exit(keyring_backend):
    with keyring.scoped_credential() as scope:
        handle = scope.get('service', 'alice')
        assert handle.active
        assert handle.resolve().password == SECRET

    assert not handle.active
    reads_at_exit = keyring_backend.credential_reads
    with pytest.raises(CredentialScopeError):
        handle.resolve()
    # no further backend access once invalidated
    assert keyring_backend.credential_reads == reads_at_exit


def test_scope_cannot_be_reentered_after_exit(keyring_backend):
    scope = keyring.scoped_credential()
    with scope:
        scope.get('service', 'alice')
    with pytest.raises(CredentialScopeError):
        scope.__enter__()
    with pytest.raises(CredentialScopeError):
        scope.get('service', 'alice')


def test_resolve_without_entering_scope_fails(keyring_backend):
    scope = credentials.credential_scope(keyring_backend)
    handle = scope.get('service', 'alice')
    assert not handle.active
    with pytest.raises(CredentialScopeError):
        handle.resolve()
    assert keyring_backend.credential_reads == 0


def test_resolve_across_threads(keyring_backend):
    errors: list[BaseException] = []

    def worker(handle, barrier, results):
        barrier.wait()
        try:
            credential = handle.resolve()
            assert credential is not None
            results.append(credential.password)
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    with keyring.scoped_credential() as scope:
        handle = scope.get('service', 'alice')
        barrier = threading.Barrier(4)
        results: list[str] = []
        threads = [
            threading.Thread(target=worker, args=(handle, barrier, results))
            for _ in range(4)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    assert errors == []
    assert results == [SECRET] * 4
    assert keyring_backend.credential_reads == 4

    with pytest.raises(CredentialScopeError):
        handle.resolve()


def test_thread_after_scope_exit_is_denied(keyring_backend):
    handle_holder: dict[str, credentials.ScopedCredential] = {}
    entered = threading.Event()
    release = threading.Event()

    def worker():
        entered.set()
        release.wait()
        with pytest.raises(CredentialScopeError):
            handle_holder['handle'].resolve()

    thread = threading.Thread(target=worker)
    with keyring.scoped_credential() as scope:
        handle_holder['handle'] = scope.get('service', 'alice')
        thread.start()
        entered.wait()
    release.set()
    thread.join()
    assert keyring_backend.credential_reads == 0


def test_backend_failure_propagates_and_handle_remains_usable(monkeypatch):
    backend = FailingKeyring()
    backend.set_password('service', 'alice', SECRET)
    monkeypatch.setattr(keyring.core, '_keyring_backend', backend)

    with keyring.scoped_credential() as scope:
        handle = scope.get('service', 'alice')
        with pytest.raises(KeyringError):
            handle.resolve()
        assert handle.active
        # the scope is still open, so retrying hits the backend again
        with pytest.raises(KeyringError):
            handle.resolve()
        assert backend.credential_reads == 2

    with pytest.raises(CredentialScopeError):
        handle.resolve()
    # after exit the scope error wins and the backend is not consulted
    assert backend.credential_reads == 2


def test_missing_credential_resolves_to_none(keyring_backend):
    with keyring.scoped_credential() as scope:
        handle = scope.get('service', 'nobody')
        assert handle.resolve() is None
        assert keyring_backend.credential_reads == 1


def test_default_bridge_falls_back_to_get_password(monkeypatch):
    backend = CountingKeyring()
    backend.set_password('service', 'alice', SECRET)

    def no_credential(self, service, username):
        self.credential_reads += 1
        return None

    monkeypatch.setattr(CountingKeyring, 'get_credential', no_credential)
    monkeypatch.setattr(keyring.core, '_keyring_backend', backend)

    with keyring.scoped_credential() as scope:
        handle = scope.get('service', 'alice')
        credential = handle.resolve()
        assert credential is not None
        assert credential.password == SECRET
        assert backend.credential_reads == 1
        assert backend.password_reads == 1


def test_backend_override_of_scoped_interface(monkeypatch):
    backend = CustomScopedKeyring()
    backend.set_password('service', 'alice', SECRET)
    monkeypatch.setattr(keyring.core, '_keyring_backend', backend)

    with keyring.scoped_credential() as scope:
        handle = scope.get('service', 'alice')
        assert isinstance(handle, credentials.ScopedCredential)
        assert handle.resolve().password == SECRET
        assert backend.credential_reads == 1


def test_string_api_remains_available_alongside_scopes(keyring_backend):
    assert keyring.get_password('service', 'alice') == SECRET
    credential = keyring.get_credential('service', 'alice')
    assert credential is not None and credential.password == SECRET
