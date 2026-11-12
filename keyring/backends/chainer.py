"""
Keyring Chainer - iterates over other viable backends to
discover passwords in each.
"""

from __future__ import annotations

import dataclasses
import enum

from .. import backend, credentials
from ..compat import properties
from . import fail

Keyring = backend.KeyringBackend


@dataclasses.dataclass(frozen=True)
class CredentialSource:
    """
    An explicit binding to the backend that served a credential read.

    The bound backend, service and username identify one concrete
    read. Bindings are produced by :meth:`ChainerBackend.get_password_source`
    or :meth:`ChainerBackend.get_credential_with_source` and can be
    supplied to :meth:`ChainerBackend.rotate_password` so the rotation
    targets the exact backend that served the read, not whichever
    backend happens to be first in priority order.

    A source is only usable while its backend remains part of the
    approved chain; a backend removed by the chain limit is not an
    authorized target.
    """

    backend: Keyring
    service: str
    username: str

    def __str__(self) -> str:
        return f'{self.backend.name} ({self.service}/{self.username})'


@dataclasses.dataclass(frozen=True)
class SourcedCredential:
    """A credential together with the backend that served it."""

    credential: credentials.Credential
    source: CredentialSource

    @property
    def username(self) -> str:
        return self.credential.username

    @property
    def password(self) -> str:
        return self.credential.password

    def rotate(
        self, chainer: ChainerBackend, new_password: str
    ) -> RotationReport:
        """Rotate this credential at the backend that served it."""
        return chainer.rotate_password(self.source, new_password)


class RotationStatus(enum.Enum):
    """Outcome of an attempted source-bound rotation."""

    ROTATED = 'rotated'
    ROTATED_INCOMPLETE = 'rotated-incomplete'
    STALE_VISIBLE = 'stale-visible'
    SAME_VALUE = 'same-value'
    SOURCE_NOT_FOUND = 'source-not-found'
    SOURCE_NOT_WRITABLE = 'source-not-writable'
    WRITE_FAILED = 'write-failed'
    VERIFY_FAILED = 'verify-failed'


@dataclasses.dataclass(frozen=True)
class DeleteFailure:
    """
    A stale copy that could not be removed from a chained backend.

    ``reason`` intentionally carries no stored value, so reports can
    be logged without exposing credentials.
    """

    backend: Keyring
    reason: str

    def __str__(self) -> str:
        return f'{self.backend.name}: {self.reason}'


@dataclasses.dataclass
class RotationReport:
    """
    The outcome of :meth:`ChainerBackend.rotate_password`.

    ``ROTATED`` when the new value is served by the bound source and no
    stale copies remain, ``ROTATED_INCOMPLETE`` when the new value is
    served but some stale copies remain, and ``STALE_VISIBLE`` when the
    chain still returns the old value through a read entry point.
    ``rotated`` is true for the first two (and for ``SAME_VALUE``, where
    no change was needed); inspect ``delete_failures`` for remaining
    copies. ``SAME_VALUE`` means the requested value already equals the
    stored one, so nothing was rewritten or deleted.

    """

    status: RotationStatus
    source: CredentialSource | None = None
    deleted: list[CredentialSource] = dataclasses.field(default_factory=list)
    delete_failures: list[DeleteFailure] = dataclasses.field(default_factory=list)
    detail: str = ''

    @property
    def rotated(self) -> bool:
        """
        True when a subsequent read cannot observe the old value.

        ``STALE_VISIBLE`` deliberately fails this check: the bound source
        holds the new value, but the chain still answers with the old one,
        so the rotation has not taken effect from a reader's perspective.
        """
        return self.status in {
            RotationStatus.ROTATED,
            RotationStatus.ROTATED_INCOMPLETE,
            RotationStatus.SAME_VALUE,
        }

    @property
    def complete(self) -> bool:
        return self.status is RotationStatus.ROTATED

    @property
    def ok(self) -> bool:
        """Alias for :attr:`complete`: the rotation fully finished."""
        return self.complete

    def render(self) -> str:
        """
        A human-readable summary with no stored secrets. Backends are
        identified by their public ``name``; service, usernames and
        values are not included in failure detail.
        """
        lines = [f'status: {self.status.value}']
        lines.extend(f'deleted: {item.backend.name}' for item in self.deleted)
        lines.extend(f'delete-failed: {item}' for item in self.delete_failures)
        if self.detail:
            lines.append(f'note: {self.detail}')
        return '\n'.join(lines)


class ChainerBackend(backend.KeyringBackend):
    """
    >>> ChainerBackend()
    <keyring.backends.chainer.ChainerBackend object at ...>
    """

    # override viability as 'priority' cannot be determined
    # until other backends have been constructed
    viable = True

    @properties.classproperty
    def priority(cls) -> float:
        """
        If there are backends to chain, high priority
        Otherwise very low priority since our operation when empty
        is the same as null.
        """
        return 10 if len(cls.backends) > 1 else (fail.Keyring.priority - 1)

    @properties.classproperty
    def backends(cls):
        """
        Discover all keyrings for chaining.
        """

        def allow(keyring):
            limit = backend._limit or bool
            return (
                not isinstance(keyring, ChainerBackend)
                and limit(keyring)
                and keyring.priority > 0
            )

        allowed = filter(allow, backend.get_all_keyring())
        return sorted(allowed, key=backend.by_priority, reverse=True)

    def get_password(self, service, username):
        for keyring in self.backends:
            password = keyring.get_password(service, username)
            if password is not None:
                return password

    def get_password_source(
        self, service, username
    ) -> CredentialSource | None:
        """
        Like :meth:`get_password`, but also report the backend that
        served the value. Returns None when no backend has it.
        """
        for keyring in self.backends:
            password = keyring.get_password(service, username)
            if password is not None:
                return CredentialSource(keyring, service, username)
        return None

    def get_credential_with_source(
        self, service, username
    ) -> SourcedCredential | None:
        """
        Like :meth:`get_credential`, but report the backend that served
        the credential as well. ``source.username`` is the username the
        backend actually returned (or the requested one for an anonymous
        credential), and is what a later rotation addresses.
        """
        for keyring in self.backends:
            credential = keyring.get_credential(service, username)
            if credential is not None:
                try:
                    bound_username = credential.username
                except ValueError:
                    # Anonymous credentials carry no username; the bind
                    # still addresses the pair the caller requested.
                    bound_username = username
                source = CredentialSource(keyring, service, bound_username)
                return SourcedCredential(credential, source)
        return None

    def set_password(self, service, username, password):
        for keyring in self.backends:
            try:
                return keyring.set_password(service, username, password)
            except NotImplementedError:
                pass

    def delete_password(self, service, username):
        for keyring in self.backends:
            try:
                return keyring.delete_password(service, username)
            except NotImplementedError:
                pass

    def get_credential(self, service, username):
        for keyring in self.backends:
            credential = keyring.get_credential(service, username)
            if credential is not None:
                return credential

    def _read(
        self,
        keyring: Keyring,
        service: str,
        username: str,
    ) -> str | None:
        """
        Read exactly the requested pair from one backend.

        Some backends serve credentials through ``get_credential`` even
        when a username is supplied, so both routes are consulted. A
        credential for a different username is not this credential.
        """
        password = keyring.get_password(service, username)
        if password is not None:
            return password
        credential = keyring.get_credential(service, username)
        if credential is None:
            return None
        try:
            bound_username = credential.username
        except ValueError:
            return None
        if bound_username != username:
            return None
        return credential.password

    def _stale_copies(
        self,
        chain: list[Keyring],
        service: str,
        username: str,
        password: str,
    ) -> list[Keyring]:
        """
        Return every backend in ``chain`` that still serves exactly the
        old ``password`` for the requested pair.

        A credential for a different username, or a different password
        for the same username, is someone else's state and is left
        alone.
        """
        return [
            keyring
            for keyring in chain
            if self._read(keyring, service, username) == password
        ]

    def _first_password(self, chain, service, username) -> str | None:
        for keyring in chain:
            password = keyring.get_password(service, username)
            if password is not None:
                return password
        return None

    def _first_credential_password(self, chain, service, username) -> str | None:
        for keyring in chain:
            credential = keyring.get_credential(service, username)
            if credential is not None:
                return credential.password
        return None

    def _serves_old(
        self, chain, service: str, username: str, old: str
    ) -> bool:
        """Return True if a chain read entry point still serves ``old``.

        This mirrors what callers see: the rotation has not taken effect
        if ``get_password`` or ``get_credential`` can still return the old
        value. A different credential is not the old one and does not make
        the rotation stale.
        """
        return old in (
            self._first_password(chain, service, username),
            self._first_credential_password(chain, service, username),
        )

    def rotate_password(
        self,
        source: CredentialSource,
        new_password: str,
    ) -> RotationReport:
        """
        Replace a credential at the backend that actually served it.

        The rotation is bound to ``source`` and never picks a different
        backend by priority and never copies the credential into a
        backend that did not previously hold it:

        * the new value is written to the bound backend;
        * it is read back from the bound backend before any deletion,
          so a write that does not survive is reported instead of
          silently shadowing the old value;
        * the old value is removed from every backend that still serves
          it, and any backend that refuses or otherwise fails to delete
          is reported in ``delete_failures``;
        * deletion is not attempted on backends holding a different
          value or a credential for a different username.

        Returns a :class:`RotationReport`. Success is based on what the
        chain actually serves after the change, not only on the write:
        ``ROTATED``/``ROTATED_INCOMPLETE`` mean a subsequent read no
        longer returns the old value, and ``delete_failures`` lists the
        copies that remain. When a copy cannot be deleted and is still
        visible through a read entry point, the report is instead
        ``STALE_VISIBLE`` and is not successful, even though the bound
        backend itself holds the new value.
        """
        chain = self.backends
        bound = source.backend
        if not any(keyring is bound for keyring in chain):
            return RotationReport(
                RotationStatus.SOURCE_NOT_FOUND,
                source,
                detail='source backend is not part of this chain',
            )

        if source.username is None:
            return RotationReport(
                RotationStatus.SOURCE_NOT_FOUND,
                source,
                detail='source has no username to address',
            )

        old = self._read(bound, source.service, source.username)
        if old is None:
            return RotationReport(
                RotationStatus.SOURCE_NOT_FOUND,
                source,
                detail='source backend no longer holds this credential',
            )

        if old == new_password:
            return RotationReport(
                RotationStatus.SAME_VALUE,
                source,
                detail='the stored value is already the requested value',
            )

        try:
            bound.set_password(source.service, source.username, new_password)
        except NotImplementedError as exc:
            return RotationReport(
                RotationStatus.SOURCE_NOT_WRITABLE,
                source,
                detail=(
                    'source backend does not support writes '
                    f'({type(exc).__name__})'
                ),
            )
        except Exception as exc:  # noqa: BLE001 - reported to the caller
            return RotationReport(
                RotationStatus.WRITE_FAILED,
                source,
                detail=f'write failed ({type(exc).__name__})',
            )

        if self._read(bound, source.service, source.username) != new_password:
            return RotationReport(
                RotationStatus.VERIFY_FAILED,
                source,
                detail='new value is not served by the source backend',
            )

        report = RotationReport(RotationStatus.ROTATED, source)
        stale = [
            keyring
            for keyring in self._stale_copies(
                chain, source.service, source.username, old
            )
            if keyring is not bound
        ]
        for keyring in stale:
            try:
                keyring.delete_password(source.service, source.username)
            except Exception as exc:  # noqa: BLE001 - report, never retry blindly
                # A delete may still have taken effect before reporting
                # an error, so verify instead of trusting the exception.
                if self._read(keyring, source.service, source.username) != old:
                    report.deleted.append(self._source_for(keyring, source))
                    continue
                reason = (
                    'delete not supported'
                    if isinstance(exc, NotImplementedError)
                    else f'delete failed ({type(exc).__name__})'
                )
                report.delete_failures.append(DeleteFailure(keyring, reason))
                continue
            if self._read(keyring, source.service, source.username) == old:
                report.delete_failures.append(
                    DeleteFailure(
                        keyring, 'old value is still served after delete'
                    )
                )
            else:
                report.deleted.append(self._source_for(keyring, source))

        if self._serves_old(chain, source.service, source.username, old):
            report.status = RotationStatus.STALE_VISIBLE
            report.detail = (
                'the bound source was updated, but a read entry point still '
                'serves the old value'
            )
        elif report.delete_failures:
            report.status = RotationStatus.ROTATED_INCOMPLETE
            report.detail = 'the new value is served, but stale copies remain'
        return report

    @staticmethod
    def _source_for(keyring, source: CredentialSource) -> CredentialSource:
        return CredentialSource(keyring, source.service, source.username)
