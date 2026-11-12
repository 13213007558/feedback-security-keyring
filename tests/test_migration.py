import pytest

from keyring.backend import KeyringBackend
from keyring.migration import (
    MigrationEntry,
    Migrator,
    NamespacedKeyring,
    Status,
    redact,
)


class FakeBackend(KeyringBackend):
    """
    In-memory backend with fault injection to simulate a real backend's
    failure modes: pre-existing targets, writes that succeed but fail
    verification, and interruptions mid-migration.
    """

    priority = 1

    def __init__(self):
        super().__init__()
        self.store = {}
        # keys whose reads return a corrupted value (verify failure)
        self.corrupt_reads = set()
        # keys that raise on set/delete (interruption)
        self.fail_sets = set()
        self.fail_deletes = set()

    def get_password(self, service, username):
        value = self.store.get((service, username))
        if value is not None and (service, username) in self.corrupt_reads:
            return 'corrupted-value'
        return value

    def set_password(self, service, username, password):
        if (service, username) in self.fail_sets:
            raise RuntimeError('backend unavailable')
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        if (service, username) in self.fail_deletes:
            raise RuntimeError('backend unavailable')
        self.store.pop((service, username), None)


@pytest.fixture
def backend():
    return FakeBackend()


def entry(username, source='shared-service', target=None):
    target = target or f'{username}-ns::{source}'
    return MigrationEntry(source, username, target)


class TestMigrator:
    def test_migrates_entries(self, backend):
        backend.store[('shared-service', 'alice')] = 'secret-a'
        report = Migrator(backend).migrate([entry('alice')])

        assert [r.status for r in report.results] == [Status.MIGRATED]
        assert backend.store == {('alice-ns::shared-service', 'alice'): 'secret-a'}
        assert not report.rolled_back

    def test_repeatable_run_is_idempotent(self, backend):
        backend.store[('shared-service', 'alice')] = 'secret-a'
        migrator = Migrator(backend)
        migrator.migrate([entry('alice')])

        report = migrator.migrate([entry('alice')])

        assert [r.status for r in report.results] == [Status.ALREADY_MIGRATED]
        assert backend.store == {('alice-ns::shared-service', 'alice'): 'secret-a'}

    def test_target_exists_with_same_value_cleans_up_source(self, backend):
        backend.store[('shared-service', 'alice')] = 'secret-a'
        backend.store[('alice-ns::shared-service', 'alice')] = 'secret-a'

        report = Migrator(backend).migrate([entry('alice')])

        assert [r.status for r in report.results] == [Status.ALREADY_MIGRATED]
        assert ('shared-service', 'alice') not in backend.store

    def test_conflict_stops_and_preserves_originals(self, backend):
        backend.store[('shared-service', 'alice')] = 'secret-a'
        backend.store[('alice-ns::shared-service', 'alice')] = 'other-tenant-secret'

        report = Migrator(backend).migrate([entry('alice')])

        assert [r.status for r in report.results] == [Status.CONFLICT]
        assert backend.store[('shared-service', 'alice')] == 'secret-a'
        assert (
            backend.store[('alice-ns::shared-service', 'alice')]
            == 'other-tenant-secret'
        )
        assert report.stopped_early

    def test_conflict_rolls_back_entries_migrated_earlier_in_run(self, backend):
        backend.store[('shared-service', 'alice')] = 'secret-a'
        backend.store[('shared-service', 'bob')] = 'secret-b'
        backend.store[('bob-ns::shared-service', 'bob')] = 'conflicting'

        report = Migrator(backend).migrate([entry('alice'), entry('bob')])

        statuses = [r.status for r in report.results]
        assert statuses == [Status.ROLLED_BACK, Status.CONFLICT]
        assert report.rolled_back
        # alice's move was undone: source restored, target removed
        assert backend.store[('shared-service', 'alice')] == 'secret-a'
        assert ('alice-ns::shared-service', 'alice') not in backend.store
        # bob's originals untouched
        assert backend.store[('shared-service', 'bob')] == 'secret-b'
        assert backend.store[('bob-ns::shared-service', 'bob')] == 'conflicting'

    def test_remaining_entries_are_skipped_after_stop(self, backend):
        backend.store[('shared-service', 'alice')] = 'secret-a'
        backend.store[('alice-ns::shared-service', 'alice')] = 'conflicting'
        backend.store[('shared-service', 'bob')] = 'secret-b'

        report = Migrator(backend).migrate([entry('alice'), entry('bob')])

        assert [r.status for r in report.results] == [Status.CONFLICT, Status.SKIPPED]
        assert backend.store[('shared-service', 'bob')] == 'secret-b'

    def test_write_succeeds_but_verification_fails(self, backend):
        backend.store[('shared-service', 'alice')] = 'secret-a'
        backend.corrupt_reads.add(('alice-ns::shared-service', 'alice'))

        report = Migrator(backend).migrate([entry('alice')])

        assert [r.status for r in report.results] == [Status.VERIFY_FAILED]
        assert report.rolled_back
        # unverifiable target removed, source preserved
        assert ('alice-ns::shared-service', 'alice') not in backend.store
        assert backend.store[('shared-service', 'alice')] == 'secret-a'

    def test_interrupted_migration_rolls_back(self, backend):
        backend.store[('shared-service', 'alice')] = 'secret-a'
        backend.store[('shared-service', 'bob')] = 'secret-b'
        backend.fail_sets.add(('bob-ns::shared-service', 'bob'))

        report = Migrator(backend).migrate([entry('alice'), entry('bob')])

        statuses = [r.status for r in report.results]
        assert statuses == [Status.ROLLED_BACK, Status.WRITE_FAILED]
        assert report.rolled_back
        assert backend.store == {
            ('shared-service', 'alice'): 'secret-a',
            ('shared-service', 'bob'): 'secret-b',
        }

    def test_failed_source_delete_rolls_back(self, backend):
        backend.store[('shared-service', 'alice')] = 'secret-a'
        backend.fail_deletes.add(('shared-service', 'alice'))

        report = Migrator(backend).migrate([entry('alice')])

        assert [r.status for r in report.results] == [Status.DELETE_FAILED]
        assert report.rolled_back
        assert backend.store == {('shared-service', 'alice'): 'secret-a'}

    def test_missing_source_is_not_fatal(self, backend):
        report = Migrator(backend).migrate([entry('alice')])
        assert [r.status for r in report.results] == [Status.SOURCE_MISSING]
        assert not report.rolled_back

    def test_report_contains_only_redacted_keys(self, backend):
        backend.store[('shared-service', 'alice')] = 'secret-a'
        backend.store[('shared-service', 'bob')] = 'secret-b'
        backend.fail_sets.add(('bob-ns::shared-service', 'bob'))

        report = Migrator(backend).migrate([entry('alice'), entry('bob')])
        rendered = report.render()

        for sensitive in ('secret-a', 'secret-b', 'alice', 'bob', 'shared-service'):
            assert sensitive not in rendered
        assert Status.ROLLED_BACK.value in rendered
        assert Status.WRITE_FAILED.value in rendered


class TestRedact:
    def test_hides_value_but_is_stable_and_distinct(self):
        assert redact('alice') == redact('alice')
        assert redact('alice') != redact('bob')
        assert 'alice' not in redact('alice')


class TestNamespacedKeyring:
    ownership = {
        ('shared-service', 'alice'): 'tenant-a',
        ('shared-service', 'carol'): 'tenant-b',
    }

    def facade(self, backend, namespace='tenant-a'):
        return NamespacedKeyring(backend, namespace, ownership=self.ownership)

    def test_reads_namespaced_key_first(self, backend):
        backend.store[('tenant-a::payments', 'alice')] = 'new-secret'
        backend.store[('shared-service', 'alice')] = 'legacy-secret'

        assert self.facade(backend).get_password('payments', 'alice') == 'new-secret'

    def test_falls_back_to_owned_legacy_key(self, backend):
        backend.store[('shared-service', 'alice')] = 'legacy-secret'

        password = self.facade(backend).get_password(
            'payments', 'alice', legacy_service='shared-service'
        )

        assert password == 'legacy-secret'

    def test_never_returns_another_tenants_legacy_credential(self, backend):
        backend.store[('shared-service', 'carol')] = 'carol-secret'

        password = self.facade(backend, namespace='tenant-a').get_password(
            'payments', 'carol', legacy_service='shared-service'
        )

        assert password is None

    def test_unclaimed_legacy_key_is_invisible(self, backend):
        backend.store[('shared-service', 'mallory')] = 'unclaimed-secret'

        password = self.facade(backend).get_password(
            'payments', 'mallory', legacy_service='shared-service'
        )

        assert password is None

    def test_no_fallback_without_legacy_service(self, backend):
        backend.store[('shared-service', 'alice')] = 'legacy-secret'

        assert self.facade(backend).get_password('payments', 'alice') is None

    def test_writes_go_to_namespaced_service(self, backend):
        self.facade(backend).set_password('payments', 'alice', 'fresh-secret')

        assert backend.store == {('tenant-a::payments', 'alice'): 'fresh-secret'}
