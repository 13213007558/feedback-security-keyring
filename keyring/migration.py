"""
Migrate credentials from a shared service name to explicitly
isolated per-tenant namespaces, and read safely during the transition.

The migration tool is re-runnable: entries already migrated are
detected and skipped, and a caller-supplied mapping describes which
credential belongs to which tenant namespace. Whenever a target key
already holds a different value (an ownership conflict), the run stops
immediately, rolls back anything it changed, and preserves the
original values.

Reports only ever expose redacted keys and statuses -- never secret
values.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import typing

from .backend import KeyringBackend


def redact(value: str) -> str:
    """
    Render a key component safe for display: a one-character hint plus
    a short stable digest. Never reveals the full value.

    >>> redact('tenant-a::payments')
    't…(2475e56a)'
    """
    digest = hashlib.sha256(value.encode('utf-8')).hexdigest()[:8]
    return f'{value[:1]}…({digest})'


class Status(enum.Enum):
    """Outcome of a single migration entry."""

    MIGRATED = 'migrated'
    ALREADY_MIGRATED = 'already-migrated'
    SOURCE_MISSING = 'source-missing'
    CONFLICT = 'conflict'
    WRITE_FAILED = 'write-failed'
    VERIFY_FAILED = 'verify-failed'
    DELETE_FAILED = 'delete-failed'
    ROLLED_BACK = 'rolled-back'
    SKIPPED = 'skipped'


@dataclasses.dataclass(frozen=True)
class MigrationEntry:
    """
    One planned move, supplied by the caller's mapping.

    ``source_service`` is the shared legacy service name and
    ``target_service`` the explicitly isolated (namespaced) one.
    """

    source_service: str
    username: str
    target_service: str


@dataclasses.dataclass
class EntryResult:
    """The redacted, reportable outcome of one entry."""

    entry: MigrationEntry
    status: Status
    detail: str = ''

    def render(self) -> str:
        """
        A single report line with redacted keys only.

        >>> result = EntryResult(
        ...     MigrationEntry('shared', 'alice', 'tenant-a::shared'),
        ...     Status.MIGRATED,
        ... )
        >>> line = result.render()
        >>> 'alice' in line or 'shared' in line
        False
        >>> 'migrated' in line
        True
        """
        keys = (
            f'{redact(self.entry.source_service)}/'
            f'{redact(self.entry.username)} -> '
            f'{redact(self.entry.target_service)}'
        )
        line = f'{keys}: {self.status.value}'
        if self.detail:
            line += f' ({self.detail})'
        return line


@dataclasses.dataclass
class MigrationReport:
    """Aggregate result of a migration run."""

    results: list[EntryResult] = dataclasses.field(default_factory=list)
    rolled_back: bool = False
    rollback_errors: list[str] = dataclasses.field(default_factory=list)

    @property
    def stopped_early(self) -> bool:
        return any(
            result.status
            in {
                Status.CONFLICT,
                Status.WRITE_FAILED,
                Status.VERIFY_FAILED,
                Status.DELETE_FAILED,
            }
            for result in self.results
        )

    def render(self) -> str:
        lines = [result.render() for result in self.results]
        if self.rolled_back:
            lines.append('run rolled back: original values preserved')
        lines += [f'rollback error: {error}' for error in self.rollback_errors]
        return '\n'.join(lines)


class MigrationHalted(Exception):
    """Internal control flow: the run must stop and roll back."""


class Migrator:
    """
    Re-runnable migration of credentials to namespaced services.

    For each entry the migrator reads the source, checks the target,
    writes the target, verifies the write by reading it back, and only
    then deletes the source. Any conflict or failure stops the run and
    rolls back every change made during it, preserving original values.
    """

    def __init__(self, backend: KeyringBackend):
        self.backend = backend
        self._written: list[tuple[str, str]] = []
        self._deleted_sources: list[tuple[str, str, str]] = []

    def migrate(self, entries: typing.Iterable[MigrationEntry]) -> MigrationReport:
        entries = list(entries)
        report = MigrationReport()
        for index, entry in enumerate(entries):
            try:
                result = self._migrate_entry(entry)
            except MigrationHalted as halted:
                result = EntryResult(entry, halted.args[0], halted.args[1])
                report.results.append(result)
                self._rollback(report)
                report.results.extend(
                    EntryResult(rest, Status.SKIPPED, 'run stopped')
                    for rest in entries[index + 1 :]
                )
                break
            report.results.append(result)
        return report

    def _migrate_entry(self, entry: MigrationEntry) -> EntryResult:
        source_value = self.backend.get_password(entry.source_service, entry.username)
        target_value = self.backend.get_password(entry.target_service, entry.username)

        if source_value is None:
            if target_value is not None:
                return EntryResult(entry, Status.ALREADY_MIGRATED)
            return EntryResult(entry, Status.SOURCE_MISSING)

        if target_value is not None:
            if target_value == source_value:
                self._delete_source(entry, source_value)
                return EntryResult(entry, Status.ALREADY_MIGRATED)
            raise MigrationHalted(
                Status.CONFLICT,
                'target already exists with a different value; '
                'original values preserved',
            )

        self._write_target(entry, source_value)
        self._verify_target(entry, source_value)
        self._delete_source(entry, source_value)
        return EntryResult(entry, Status.MIGRATED)

    def _write_target(self, entry: MigrationEntry, value: str) -> None:
        try:
            self.backend.set_password(entry.target_service, entry.username, value)
        except Exception as exc:
            raise MigrationHalted(
                Status.WRITE_FAILED, f'target write failed: {exc!r}'
            ) from exc
        self._written.append((entry.target_service, entry.username))

    def _verify_target(self, entry: MigrationEntry, value: str) -> None:
        read_back = self.backend.get_password(entry.target_service, entry.username)
        if read_back != value:
            raise MigrationHalted(
                Status.VERIFY_FAILED,
                'target write could not be verified; rolled back',
            )

    def _delete_source(self, entry: MigrationEntry, value: str) -> None:
        try:
            self.backend.delete_password(entry.source_service, entry.username)
        except Exception as exc:
            raise MigrationHalted(
                Status.DELETE_FAILED, f'source delete failed: {exc!r}'
            ) from exc
        self._deleted_sources.append((entry.source_service, entry.username, value))

    def _rollback(self, report: MigrationReport) -> None:
        report.rolled_back = True
        for result in report.results:
            if result.status is Status.MIGRATED:
                result.status = Status.ROLLED_BACK
        for service, username in reversed(self._written):
            try:
                self.backend.delete_password(service, username)
            except Exception as exc:
                report.rollback_errors.append(
                    f'could not remove target {redact(service)}/{redact(username)}: {exc!r}'
                )
        for service, username, value in reversed(self._deleted_sources):
            try:
                self.backend.set_password(service, username, value)
            except Exception as exc:
                report.rollback_errors.append(
                    f'could not restore source {redact(service)}/{redact(username)}: {exc!r}'
                )
        self._written.clear()
        self._deleted_sources.clear()


class NamespacedKeyring:
    """
    Runtime compatibility facade for the migration window.

    Reads always prefer the explicitly namespaced service. The shared
    legacy service is consulted only when the caller-supplied
    ``ownership`` mapping attributes that exact (service, username)
    pair to *this* namespace -- so a read for one tenant can never
    fall back to a legacy key and receive another tenant's credential.
    Unclaimed legacy keys are invisible to every tenant.
    """

    def __init__(
        self,
        backend: KeyringBackend,
        namespace: str,
        ownership: typing.Mapping[tuple[str, str], str] | None = None,
        separator: str = '::',
    ):
        self.backend = backend
        self.namespace = namespace
        self.ownership = dict(ownership or {})
        self.separator = separator

    def namespaced_service(self, service: str) -> str:
        return f'{self.namespace}{self.separator}{service}'

    def get_password(
        self, service: str, username: str, legacy_service: str | None = None
    ) -> str | None:
        password = self.backend.get_password(self.namespaced_service(service), username)
        if password is not None:
            return password
        if legacy_service is None:
            return None
        owner = self.ownership.get((legacy_service, username))
        if owner != self.namespace:
            # Unclaimed or owned by another tenant: never fall back.
            return None
        return self.backend.get_password(legacy_service, username)

    def set_password(self, service: str, username: str, password: str) -> None:
        """New writes always go to the namespaced service."""
        self.backend.set_password(self.namespaced_service(service), username, password)

    def delete_password(self, service: str, username: str) -> None:
        self.backend.delete_password(self.namespaced_service(service), username)
