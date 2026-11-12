"""
Executable decision table for ChainerBackend.

Each test states one row of the table: an observed outcome, the action a
policy must take, and the security-relevant evidence (backend writes or
reads that did or did not happen, and what the caller can observe).
"""

from __future__ import annotations

import logging
from unittest import mock

import pytest

import keyring.backends.chainer
from keyring import errors
from keyring.backends import chainer_policy
from keyring.backends.chainer_policy import Action, Outcome, classify
from keyring.testing.memory import MemoryBackend, StaleReplica


class _Named(MemoryBackend):
    """Memory backend whose identity and failure mode are fixed per class."""

    priority = 5
    failure: BaseException | None = None

    def get_password(self, service, username):
        if self.failure is not None:
            self.reads += 1
            raise self.failure
        return super().get_password(service, username)


class Missing(_Named):
    source_id = 'missing'
    priority = 5


class Denied(_Named):
    source_id = 'denied'
    priority = 4
    failure = PermissionError('backend says alice is not a real account')


class Locked(_Named):
    source_id = 'locked'
    priority = 3
    failure = errors.KeyringLocked('failed to unlock')


class Unknown(_Named):
    source_id = 'unknown'
    priority = 2
    failure = RuntimeError('transport error mentioning alice')


class Replica(MemoryBackend):
    source_id = 'replica'
    priority = 1


@pytest.fixture
def chained(monkeypatch):
    """Install a source backend plus an able replica and return a factory."""

    source_classes = {'missing': Missing, 'denied': Denied, 'locked': Locked}
    source_classes['unknown'] = Unknown

    def install(name: str, *, replica_password: str | None = 'old-copy'):
        primary = source_classes[name]()
        replica = Replica()
        if replica_password is not None:
            replica.set_password('svc', 'alice', replica_password)
        monkeypatch.setattr(
            'keyring.backend.get_all_keyring', lambda: [primary, replica]
        )
        return primary, replica

    return install


def _chainer(policy, source=None):
    backend = keyring.backends.chainer.ChainerBackend(policy)
    return backend.with_properties(source=source) if source else backend


def test_public_denial_does_not_reveal_existence():
    """A distrusting caller must not distinguish "denied" from "missing"."""
    assert chainer_policy.DECISION_TABLES['concealed-source'][
        Outcome.DENIED
    ].action is (Action.NOT_FOUND)
    assert chainer_policy.CONCEALED_SOURCE.conceal_denial is True
    assert chainer_policy.STRICT_SOURCE.conceal_denial is False


def test_concealed_source_is_indistinguishable_from_missing(chained):
    chained('denied')
    denied = _chainer('concealed-source', source='denied')
    assert denied.get_password('svc', 'alice') is None

    chained('missing')
    missing = _chainer('concealed-source', source='missing')
    assert missing.get_password('svc', 'alice') is None


def test_concealed_source_still_audits_the_real_reason(chained, caplog):
    chained('denied')
    backend = _chainer('concealed-source', source='denied')
    with caplog.at_level(logging.WARNING, logger=chainer_policy.__name__):
        assert backend.get_password('svc', 'alice') is None
    record = next(r for r in caplog.records if 'credential resolution' in r.message)
    assert 'permission-denied' in record.getMessage()
    assert 'alice' not in record.getMessage()


def test_table_is_total_over_outcomes():
    """Every policy has a decision for every observable outcome."""

    for name, table in chainer_policy.DECISION_TABLES.items():
        assert set(table) == set(Outcome), name
        assert all(decision.action in Action for decision in table.values())


def test_legacy_table_matches_existing_chainer_behavior():
    assert chainer_policy.LEGACY_TABLE[Outcome.MISSING].action is Action.CONTINUE
    for outcome in (Outcome.DENIED, Outcome.LOCKED, Outcome.ERROR):
        assert chainer_policy.LEGACY_TABLE[outcome].action is Action.PROPAGATE


def test_strict_table_fails_closed():
    assert chainer_policy.STRICT_SOURCE_TABLE[Outcome.MISSING].action is (
        Action.NOT_FOUND
    )
    for outcome in (Outcome.DENIED, Outcome.LOCKED, Outcome.ERROR):
        assert chainer_policy.STRICT_SOURCE_TABLE[outcome].action is Action.DENY


def test_redundant_table_never_falls_through_denial():
    table = chainer_policy.REDUNDANT_FALLBACK_TABLE
    assert table[Outcome.DENIED].action is Action.DENY
    assert table[Outcome.LOCKED].action is Action.CONTINUE
    assert table[Outcome.ERROR].action is Action.CONTINUE


@pytest.mark.parametrize(
    ('err', 'expected'),
    [
        (PermissionError('secret context'), Outcome.DENIED),
        (errors.AccessDenied('ref'), Outcome.DENIED),
        (errors.KeyringLocked('locked'), Outcome.LOCKED),
        (RuntimeError('anything'), Outcome.ERROR),
        (errors.PasswordSetError('set failed'), Outcome.ERROR),
    ],
)
def test_classify(err, expected):
    assert classify(err) is expected


def test_unrecognized_error_is_not_missing():
    """A bug or transport failure must never look like an absent entry."""

    assert classify(KeyError('svc')) is Outcome.ERROR
    assert classify(ValueError('bad data')) is Outcome.ERROR


@pytest.mark.parametrize('policy', ['chainer-default', chainer_policy.LEGACY])
def test_missing_continues_in_default_policy(chained, policy):
    primary, replica = chained('missing')
    assert _chainer(policy).get_password('svc', 'alice') == 'old-copy'
    assert primary.reads == 1
    assert replica.reads == 1


@pytest.mark.parametrize('policy', ['chainer-default', chainer_policy.LEGACY])
def test_denied_stops_in_default_policy(chained, policy):
    primary, replica = chained('denied')
    with pytest.raises(PermissionError):
        _chainer(policy).get_password('svc', 'alice')
    assert replica.reads == 0


@pytest.mark.parametrize('policy', ['chainer-default', chainer_policy.LEGACY])
@pytest.mark.parametrize('source_name', ['locked', 'unknown'])
def test_locked_and_unknown_stop_in_default_policy(chained, policy, source_name):
    primary, replica = chained(source_name)
    with pytest.raises(Exception):  # noqa: B017, PT011 - exact type is asserted
        _chainer(policy).get_password('svc', 'alice')
    assert replica.reads == 0


def test_strict_source_missing_is_final_even_with_stale_replica(chained):
    primary, replica = chained('missing')
    backend = _chainer('strict-source', source='missing')
    assert backend.get_password('svc', 'alice') is None
    assert replica.reads == 0


def test_strict_source_denied_is_opaque(chained):
    primary, replica = chained('denied')
    backend = _chainer('strict-source', source='denied')
    with pytest.raises(errors.AccessDenied) as excinfo:
        backend.get_password('svc', 'alice')
    assert replica.reads == 0
    assert_public_denial_is_opaque(excinfo.value)


@pytest.mark.parametrize('source_name', ['locked', 'unknown'])
def test_strict_source_unavailable_is_opaque(chained, source_name):
    primary, replica = chained(source_name)
    backend = _chainer('strict-source', source=source_name)
    with pytest.raises(errors.AccessDenied):
        backend.get_password('svc', 'alice')
    assert replica.reads == 0


def test_strict_source_requires_binding(chained):
    chained('missing')
    backend = _chainer('strict-source')
    with pytest.raises(errors.AccessDenied):
        backend.get_password('svc', 'alice')


def test_strict_source_denies_when_named_source_is_absent(chained):
    chained('missing')
    backend = _chainer('strict-source', source='vault')
    with pytest.raises(errors.AccessDenied):
        backend.get_password('svc', 'alice')


def test_redundant_fallback_serves_replica_on_lock(chained):
    primary, replica = chained('locked')
    backend = _chainer('redundant-fallback')
    assert backend.get_password('svc', 'alice') == 'old-copy'
    assert primary.reads == 1
    assert replica.reads == 1


def test_redundant_fallback_serves_replica_on_unknown_error(chained):
    primary, replica = chained('unknown')
    backend = _chainer('redundant-fallback')
    assert backend.get_password('svc', 'alice') == 'old-copy'


def test_redundant_fallback_does_not_serve_replica_on_denial(chained):
    primary, replica = chained('denied')
    backend = _chainer('redundant-fallback')
    with pytest.raises(errors.AccessDenied):
        backend.get_password('svc', 'alice')
    assert replica.reads == 0


def test_redundant_fallback_reports_not_found_when_replica_empty(chained):
    chained('locked', replica_password=None)
    backend = _chainer('redundant-fallback')
    assert backend.get_password('svc', 'alice') is None


def test_redundant_fallback_denies_denial_before_missing(chained):
    """A denial from the source outranks an entry that exists on a replica."""

    chained('denied', replica_password='old-copy')
    backend = _chainer('redundant-fallback')
    with pytest.raises(errors.AccessDenied):
        backend.get_password('svc', 'alice')


def test_denial_is_logged_without_identity(chained, caplog):
    primary, replica = chained('denied')
    with caplog.at_level(logging.WARNING, logger=chainer_policy.__name__):
        with pytest.raises(errors.AccessDenied):
            _chainer('strict-source', source='denied').get_password('svc', 'alice')
    records = [r for r in caplog.records if 'credential resolution' in r.message]
    assert records, 'a denial must produce a diagnostic record'
    logged = records[0].getMessage()
    assert 'svc' not in logged
    assert 'alice' not in logged
    assert 'not a real account' not in logged
    assert 'permission-denied' in logged


def test_public_denial_has_only_a_reference(chained):
    chained('denied')
    backend = _chainer('strict-source', source='denied')
    with pytest.raises(errors.AccessDenied) as excinfo:
        backend.get_password('svc', 'alice')
    err = excinfo.value
    assert_public_denial_is_opaque(err)
    assert err.__context__ is None
    assert err.__cause__ is None
    assert 'alice' not in str(err)
    assert 'not a real account' not in str(err)


def assert_public_denial_is_opaque(err):
    assert isinstance(err, errors.AccessDenied)
    assert isinstance(err, errors.KeyringError)
    assert err.correlation_id
    assert err.correlation_id in str(err)
    assert vars(err) == {'correlation_id': err.correlation_id}


def test_credential_lookup_obeys_the_same_policy(chained):
    primary, replica = chained('denied')
    backend = _chainer('redundant-fallback')
    with pytest.raises(errors.AccessDenied):
        backend.get_credential('svc', 'alice')
    assert replica.reads == 0


def test_stale_copy_demo():
    """The scenario the decision table is meant to make visible.

    A write lands on the authoritative source and is never replicated.
    The replica still answers with the previous password.  The default
    chainer returns the source's fresh value because both entries exist;
    the danger is when the source's entry disappears or becomes
    unreadable while the replica keeps serving the old secret.
    """

    class Vault(MemoryBackend):
        source_id = 'vault'
        priority = 5

    class OldReplica(StaleReplica):
        source_id = 'replica'
        priority = 1

    vault, replica = Vault(), OldReplica()
    vault.set_password('svc', 'alice', 'old-password')
    replica.snapshot_from(vault)
    vault.set_password('svc', 'alice', 'rotated-password')
    assert replica.store[('svc', 'alice')] == 'old-password'
    assert vault.store[('svc', 'alice')] == 'rotated-password'

    with mock.patch('keyring.backend.get_all_keyring', lambda: [vault, replica]):
        assert _chainer('chainer-default').get_password('svc', 'alice') == (
            'rotated-password'
        )
        # After the source entry is removed (or becomes unreadable), the
        # replica silently serves the stale secret to a permissive policy.
        vault.delete_password('svc', 'alice')
        assert _chainer('chainer-default').get_password('svc', 'alice') == (
            'old-password'
        )
        # A source-binding policy reports the entry as absent rather than
        # silently serving the replica's old copy.
        assert (
            _chainer('strict-source', source='vault').get_password('svc', 'alice')
            is None
        )
        assert replica.reads == 1
