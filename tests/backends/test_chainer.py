import pytest

import keyring.backends.chainer
from keyring import backend, errors


@pytest.fixture
def two_keyrings(monkeypatch):
    def get_two():
        class Keyring1(backend.KeyringBackend):
            priority = 1

            def get_password(self, system, user):
                return f'ring1-{system}-{user}'

            def set_password(self, system, user, password):
                pass

        class Keyring2(backend.KeyringBackend):
            priority = 2

            def get_password(self, system, user):
                return f'ring2-{system}-{user}'

            def set_password(self, system, user, password):
                raise NotImplementedError()

        return Keyring1(), Keyring2()

    monkeypatch.setattr('keyring.backend.get_all_keyring', get_two)


class TestChainer:
    def test_chainer_gets_from_highest_priority(self, two_keyrings):
        chainer = keyring.backends.chainer.ChainerBackend()
        pw = chainer.get_password('alpha', 'bravo')
        assert pw == 'ring2-alpha-bravo'

    def test_chainer_defers_to_fail(self, monkeypatch):
        """
        The Chainer backend should defer to the Fail backend when there are
        no backends to be chained.
        """
        monkeypatch.setattr('keyring.backend.get_all_keyring', tuple)
        assert keyring.backend.by_priority(
            keyring.backends.chainer.ChainerBackend
        ) < keyring.backend.by_priority(keyring.backends.fail.Keyring)


class MemoryBackend(backend.KeyringBackend):
    """In-memory backend with optional read-only and failure flags."""

    priority = 1

    def __init__(self, name, store=None, writable=True, delete_error=None):
        super().__init__()
        self._name = name
        self.store = dict(store or {})
        self.writable = writable
        self.delete_error = delete_error
        self.delete_calls = []

    @property
    def name(self):
        return self._name

    def get_password(self, service, username):
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        if not self.writable:
            raise NotImplementedError('read-only backend')
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        self.delete_calls.append((service, username))
        if self.delete_error is not None:
            raise self.delete_error
        if (service, username) not in self.store:
            raise errors.PasswordDeleteError('missing')
        del self.store[(service, username)]


@pytest.fixture
def memory_chain(monkeypatch):
    """Install the supplied backends as the only approved chain."""

    def install(*backends):
        monkeypatch.setattr(
            'keyring.backend.get_all_keyring', lambda: list(backends)
        )
        return keyring.backends.chainer.ChainerBackend()

    return install


def test_source_binding_survives_a_lower_priority_write(memory_chain):
    """A rotation follows the reader, not the first writable backend."""
    sloppy = MemoryBackend('sloppy-low-priority', writable=True)
    real = MemoryBackend('real-source', {('svc', 'alice'): 'OLD'})
    # real wins the read; the old chainer wrote to the first writable
    # backend instead, leaving the stale value in place.
    chainer = memory_chain(sloppy, real)

    source = chainer.get_password_source('svc', 'alice')
    assert source.backend is real
    assert chainer.get_password('svc', 'alice') == 'OLD'

    report = chainer.rotate_password(source, 'NEW')

    assert report.status is keyring.backends.chainer.RotationStatus.ROTATED
    assert report.ok
    assert chainer.get_password('svc', 'alice') == 'NEW'
    assert chainer.get_credential('svc', 'alice').password == 'NEW'
    # the new value was not copied into the backend that never held it
    assert sloppy.store == {}


def test_duplicate_entries_are_removed_from_every_backend(memory_chain):
    """Duplicate copies of the old value are all deleted, not just the first."""
    upper = MemoryBackend('upper', {('svc', 'alice'): 'OLD'})
    lower = MemoryBackend('lower', {('svc', 'alice'): 'OLD'})
    other = MemoryBackend('other-user', {('svc', 'bob'): 'OLD'})

    chainer = memory_chain(upper, lower, other)
    source = chainer.get_password_source('svc', 'alice')
    report = chainer.rotate_password(source, 'NEW')

    assert report.status is keyring.backends.chainer.RotationStatus.ROTATED
    assert upper.store[('svc', 'alice')] == 'NEW'
    assert lower.store == {}
    # the same value stored under a different user is not this credential
    assert other.store == {('svc', 'bob'): 'OLD'}
    assert chainer.get_password('svc', 'alice') == 'NEW'


def test_stale_read_after_rotation_is_never_successful(memory_chain):
    """A stale value still ahead in the chain must not be reported as done."""
    stale_first = MemoryBackend(
        'stale-first',
        {('svc', 'alice'): 'OLD'},
        delete_error=RuntimeError('cannot remove stale copy'),
    )
    source_backend = MemoryBackend('source', {('svc', 'alice'): 'OLD'})

    # A source captured when the backend order differed, or bound
    # explicitly, must not be assumed to be the chain's first reader.
    chainer = memory_chain(stale_first, source_backend)
    source = keyring.backends.chainer.CredentialSource(
        source_backend, 'svc', 'alice'
    )
    report = chainer.rotate_password(source, 'NEW')

    assert source_backend.store[('svc', 'alice')] == 'NEW'
    assert stale_first.store[('svc', 'alice')] == 'OLD'
    assert report.status is keyring.backends.chainer.RotationStatus.STALE_VISIBLE
    assert not report.ok
    assert report.delete_failures
    # the visible old value proves the claim: the chain still answers OLD
    assert chainer.get_password('svc', 'alice') == 'OLD'


def test_read_only_source_is_reported_and_not_copied_elsewhere(memory_chain):
    """A read-only source cannot be rotated; no other backend is chosen."""
    readonly = MemoryBackend(
        'readonly-source', {('svc', 'alice'): 'OLD'}, writable=False
    )
    writable = MemoryBackend('writable-other')

    chainer = memory_chain(readonly, writable)
    source = chainer.get_password_source('svc', 'alice')
    report = chainer.rotate_password(source, 'NEW')

    assert report.status is keyring.backends.chainer.RotationStatus.SOURCE_NOT_WRITABLE
    assert not report.rotated
    assert readonly.store == {('svc', 'alice'): 'OLD'}
    assert writable.store == {}
    assert chainer.get_password('svc', 'alice') == 'OLD'


def test_delete_failure_is_reported_but_new_value_still_served(memory_chain):
    """An undeletable duplicate is reported, never silently ignored."""
    failing = MemoryBackend(
        'failing-delete',
        {('svc', 'alice'): 'OLD'},
        delete_error=RuntimeError('backend refused to delete'),
    )
    source_backend = MemoryBackend('source', {('svc', 'alice'): 'OLD'})
    chainer = memory_chain(source_backend, failing)
    # Bind explicitly to the second backend so the duplicate is still
    # visible through the pair, but not through the chain.
    chainer_source = keyring.backends.chainer.CredentialSource(
        source_backend, 'svc', 'alice'
    )
    report = chainer.rotate_password(chainer_source, 'NEW')

    assert report.rotated
    assert not report.ok
    assert report.status is keyring.backends.chainer.RotationStatus.ROTATED_INCOMPLETE
    assert [failure.backend for failure in report.delete_failures] == [failing]
    assert chainer.get_password('svc', 'alice') == 'NEW'


def test_detached_source_is_rejected(memory_chain):
    """A backend outside the approved chain cannot be used as a target."""
    approved = MemoryBackend('approved', {('svc', 'alice'): 'OLD'})
    detached = MemoryBackend('detached', {('svc', 'alice'): 'OLD'})

    chainer = memory_chain(approved)
    source = keyring.backends.chainer.CredentialSource(
        detached, 'svc', 'alice'
    )
    report = chainer.rotate_password(source, 'NEW')

    assert report.status is keyring.backends.chainer.RotationStatus.SOURCE_NOT_FOUND
    assert not report.rotated
    assert detached.store == {('svc', 'alice'): 'OLD'}
    assert approved.store == {('svc', 'alice'): 'OLD'}


def test_same_value_rotation_changes_nothing(memory_chain):
    backend_a = MemoryBackend('a', {('svc', 'alice'): 'SAME'})
    backend_b = MemoryBackend('b', {('svc', 'alice'): 'SAME'})
    chainer = memory_chain(backend_a, backend_b)
    source = chainer.get_password_source('svc', 'alice')
    report = chainer.rotate_password(source, 'SAME')

    assert report.status is keyring.backends.chainer.RotationStatus.SAME_VALUE
    assert chainer.get_password('svc', 'alice') == 'SAME'
    assert backend_b.delete_calls == []


def test_report_never_echoes_secrets(memory_chain):
    class EchoError(MemoryBackend):
        def delete_password(self, service, username):
            value = self.store.get((service, username))
            raise RuntimeError(f'tried to delete {value}')

    failing = EchoError('failing', {('svc-private', 'alice-private'): 'SECRET-OLD'})
    source_backend = MemoryBackend(
        'source', {('svc-private', 'alice-private'): 'SECRET-OLD'}
    )
    chainer = memory_chain(source_backend, failing)
    source = keyring.backends.chainer.CredentialSource(
        source_backend, 'svc-private', 'alice-private'
    )
    report = chainer.rotate_password(source, 'SECRET-NEW')

    rendered = report.render()
    assert 'SECRET-OLD' not in rendered
    assert 'SECRET-NEW' not in rendered
    assert 'delete failed (RuntimeError)' in rendered


def test_sourced_credential_rotates_the_serving_backend(memory_chain):
    """The credential handle itself carries the source binding."""
    first = MemoryBackend('first', {('svc', 'alice'): 'OLD'})
    second = MemoryBackend('second', {('svc', 'alice'): 'OLD'})
    chainer = memory_chain(first, second)

    sourced = chainer.get_credential_with_source('svc', 'alice')
    assert (sourced.username, sourced.password) == ('alice', 'OLD')
    assert sourced.source.backend is first

    report = sourced.rotate(chainer, 'NEW')

    assert report.status is keyring.backends.chainer.RotationStatus.ROTATED
    assert first.store[('svc', 'alice')] == 'NEW'
    assert second.store == {}
    assert chainer.get_password('svc', 'alice') == 'NEW'


def test_partial_write_is_reported_before_any_delete(memory_chain):
    """A backend that only partly applies the write must not look rotated."""

    class PartialWrite(MemoryBackend):
        def set_password(self, service, username, password):
            # Keep serving the old value while claiming success.
            self.store[(service, username)] = password
            self.store[(service, username)] = 'OLD'

    partial = PartialWrite('partial', {('svc', 'alice'): 'OLD'})
    duplicate = MemoryBackend('duplicate', {('svc', 'alice'): 'OLD'})
    chainer = memory_chain(partial, duplicate)
    source = chainer.get_password_source('svc', 'alice')
    report = chainer.rotate_password(source, 'NEW')

    assert report.status is keyring.backends.chainer.RotationStatus.VERIFY_FAILED
    assert not report.rotated
    # Verification happened before deletion, so the only copy is intact.
    assert duplicate.store == {('svc', 'alice'): 'OLD'}
    assert duplicate.delete_calls == []
    assert chainer.get_password('svc', 'alice') == 'OLD'


def test_missing_source_is_reported_without_writing(memory_chain):
    """A credential that no longer exists at the source is not recreated."""
    emptied = MemoryBackend('emptied')
    reader = MemoryBackend('reader', {('svc', 'alice'): 'OLD'})
    chainer = memory_chain(emptied, reader)
    source = keyring.backends.chainer.CredentialSource(emptied, 'svc', 'alice')
    report = chainer.rotate_password(source, 'NEW')

    assert report.status is keyring.backends.chainer.RotationStatus.SOURCE_NOT_FOUND
    assert not report.rotated
    assert emptied.store == {}
    assert reader.store == {('svc', 'alice'): 'OLD'}
    assert reader.delete_calls == []
