"""
Credential-resolution policy for :class:`keyring.backends.chainer.ChainerBackend`.

The chainer walks backends in priority order.  What it does when a backend
is unavailable is a security decision, not just an availability decision:
falling through a permission error can turn a revoked identity into a
credential read, and falling through a transient lock can turn a rotated
secret into a silently served stale copy.

The decision table in this module is executable: each policy maps the
observed outcome of a backend lookup to an action.  The default table
mirrors the historical ``ChainerBackend`` behavior exactly.  The strict
and redundant tables are opt-in alternatives for callers that have made
an explicit availability/security trade-off.

Diagnostics are deliberately split from public failures.  A denial raises
:class:`keyring.errors.AccessDenied`, which contains only a correlation
id.  The matching :class:`DecisionEvent` records the policy, backend,
outcome, action, and reason for an operator or local audit sink.  Neither
the public error nor the audit event contains a username, password, or a
backend-supplied error message; a backend's message can be attacker
controlled and can mention an account that does not exist.

This module is a prototype of the policy interface.  It is not wired
into automatic backend selection unless a caller explicitly assigns a
policy to a chainer instance.
"""

from __future__ import annotations

import dataclasses
import enum
import logging
import secrets
import typing

from .. import errors

log = logging.getLogger(__name__)


class Outcome(enum.Enum):
    """The observed result of querying one backend."""

    MISSING = 'missing'
    DENIED = 'denied'
    LOCKED = 'locked'
    ERROR = 'error'


class Action(enum.Enum):
    """What the chainer should do after observing an outcome."""

    CONTINUE = 'continue'
    """Try the next backend."""

    NOT_FOUND = 'not_found'
    """Stop and report that no credential was found."""

    PROPAGATE = 'propagate'
    """Stop and re-raise the original exception (legacy behavior)."""

    DENY = 'deny'
    """Stop and raise an opaque, non-diagnostic AccessDenied."""


@dataclasses.dataclass(frozen=True)
class Decision:
    action: Action
    reason: str
    """A stable diagnostic label, safe to write to an internal audit log."""


@dataclasses.dataclass(frozen=True)
class DecisionEvent:
    """A diagnostic record for one policy decision.

    The event intentionally has no username, service, password, or
    exception-message field.  Use ``correlation_id`` to join a public
    error to this record.
    """

    correlation_id: str
    policy: str
    outcome: Outcome
    action: Action
    reason: str
    backend: str | None = None

    def as_log_fields(self) -> dict[str, str]:
        return {
            'ref': self.correlation_id,
            'policy': self.policy,
            'outcome': self.outcome.value,
            'action': self.action.value,
            'reason': self.reason,
            'backend': self.backend or '-',
        }


def _decision(action: Action, reason: str) -> Decision:
    return Decision(action, reason)


LEGACY_TABLE: dict[Outcome, Decision] = {
    # Historical ChainerBackend behavior: only a missing entry continues.
    Outcome.MISSING: _decision(Action.CONTINUE, 'entry-not-found'),
    Outcome.DENIED: _decision(Action.PROPAGATE, 'permission-denied'),
    Outcome.LOCKED: _decision(Action.PROPAGATE, 'backend-locked'),
    Outcome.ERROR: _decision(Action.PROPAGATE, 'unknown-error'),
}

STRICT_SOURCE_TABLE: dict[Outcome, Decision] = {
    # A source-bound read never falls through to a replica.  A missing
    # entry is final, even if a lower-priority backend still has a copy.
    Outcome.MISSING: _decision(Action.NOT_FOUND, 'entry-not-found'),
    Outcome.DENIED: _decision(Action.DENY, 'permission-denied'),
    Outcome.LOCKED: _decision(Action.DENY, 'backend-locked'),
    Outcome.ERROR: _decision(Action.DENY, 'unknown-error'),
}

CONCEALED_SOURCE_TABLE: dict[Outcome, Decision] = {
    # For callers that must not learn whether an account exists.  Every
    # failure looks the same as an absent entry.  The audit event still
    # records the true outcome, so an operator can diagnose it.
    Outcome.MISSING: _decision(Action.NOT_FOUND, 'entry-not-found'),
    Outcome.DENIED: _decision(Action.NOT_FOUND, 'permission-denied'),
    Outcome.LOCKED: _decision(Action.NOT_FOUND, 'backend-locked'),
    Outcome.ERROR: _decision(Action.NOT_FOUND, 'unknown-error'),
}

REDUNDANT_FALLBACK_TABLE: dict[Outcome, Decision] = {
    # Availability-first table.  Missing, locked, and unknown failures
    # may consult a replica.  A permission denial never may.
    Outcome.MISSING: _decision(Action.CONTINUE, 'entry-not-found'),
    Outcome.DENIED: _decision(Action.DENY, 'permission-denied'),
    Outcome.LOCKED: _decision(Action.CONTINUE, 'backend-locked'),
    Outcome.ERROR: _decision(Action.CONTINUE, 'unknown-error'),
}

DECISION_TABLES: dict[str, dict[Outcome, Decision]] = {
    'chainer-default': LEGACY_TABLE,
    'strict-source': STRICT_SOURCE_TABLE,
    'concealed-source': CONCEALED_SOURCE_TABLE,
    'redundant-fallback': REDUNDANT_FALLBACK_TABLE,
}

# Where a fixed string is not enough, callers may inspect the exception.
# Classification is intentionally narrow: an unrecognized exception is an
# error, never a "missing entry" and never a permission denial.
_DENIED_TYPES = (errors.AccessDenied, PermissionError)
_LOCKED_TYPES = (errors.KeyringLocked,)


def classify(err: BaseException) -> Outcome:
    """Map a backend exception to one of the four decision-table rows."""

    if isinstance(err, _DENIED_TYPES):
        return Outcome.DENIED
    if isinstance(err, _LOCKED_TYPES):
        return Outcome.LOCKED
    return Outcome.ERROR


class ChainerPolicy(typing.Protocol):
    """The policy interface consumed by ``ChainerBackend``.

    Implementations decide what an outcome means, whether a credential
    from a particular backend is acceptable for a source-bound read, and
    where diagnostic events are delivered.
    """

    name: str
    requires_source: bool

    def decide(self, outcome: Outcome) -> Decision: ...

    def accepts_source(self, source: str | None, backend: str) -> bool: ...

    conceal_denial: bool
    """When true, ``DENY`` is reported as a not-found result."""

    def audit(self, event: DecisionEvent) -> None: ...


class _TablePolicy:
    def __init__(
        self,
        name: str,
        table: dict[Outcome, Decision],
        *,
        requires_source: bool = False,
        conceal_denial: bool = False,
    ):
        self.name = name
        self.table = table
        self.requires_source = requires_source
        self.conceal_denial = conceal_denial

    def decide(self, outcome: Outcome) -> Decision:
        try:
            return self.table[outcome]
        except KeyError:
            return Decision(Action.DENY, 'unclassified-outcome')

    def accepts_source(self, source: str | None, backend: str) -> bool:
        if self.requires_source:
            return source is not None and secrets.compare_digest(source, backend)
        return True

    def audit(self, event: DecisionEvent) -> None:
        noteworthy = event.action in (Action.DENY, Action.PROPAGATE) or (
            event.outcome in (Outcome.DENIED, Outcome.LOCKED, Outcome.ERROR)
        )
        if noteworthy:
            log.warning('credential resolution %s', event.as_log_fields())
        else:
            log.debug('credential resolution %s', event.as_log_fields())


LEGACY = _TablePolicy('chainer-default', LEGACY_TABLE)
"""Preserve the historical chainer behavior; use for compatibility."""

STRICT_SOURCE = _TablePolicy('strict-source', STRICT_SOURCE_TABLE, requires_source=True)
"""Fail closed and bind every read to one authoritative backend."""

CONCEALED_SOURCE = _TablePolicy(
    'concealed-source',
    CONCEALED_SOURCE_TABLE,
    requires_source=True,
    conceal_denial=True,
)
"""Source-bound and indistinguishable from a missing entry on every failure."""

REDUNDANT_FALLBACK = _TablePolicy('redundant-fallback', REDUNDANT_FALLBACK_TABLE)
"""Consult replicas on transient failures, but never on a denial."""

DEFAULT_POLICY = LEGACY

POLICIES: dict[str, _TablePolicy] = {
    policy.name: policy
    for policy in (LEGACY, STRICT_SOURCE, CONCEALED_SOURCE, REDUNDANT_FALLBACK)
}


def get_policy(name_or_policy: str | ChainerPolicy) -> ChainerPolicy:
    """Resolve a policy by name, or validate and return a policy object."""

    if isinstance(name_or_policy, str):
        return POLICIES[name_or_policy]
    required = (
        'name',
        'requires_source',
        'conceal_denial',
        'decide',
        'accepts_source',
        'audit',
    )
    if not all(hasattr(name_or_policy, attr) for attr in required):
        raise TypeError('object does not implement the ChainerPolicy interface')
    return name_or_policy


def identify(backend: typing.Any) -> str:
    """Return a stable source identity for a backend.

    A backend may set ``source_id`` (preferred) or ``label``.  Otherwise
    its module-qualified class name is used.  Source binding is only
    meaningful when the identity is stable across processes and releases.
    """

    for attr in ('source_id', 'label'):
        value = getattr(backend, attr, None)
        if value:
            return str(value)
    return backend.name


def new_correlation_id() -> str:
    """Generate a non-reversible id suitable for a public error message."""

    return secrets.token_hex(8)


def table_rows() -> list[tuple[str, Outcome, Action, str]]:
    """Render the complete table for tests, docs, and ``keyring diagnose``."""

    return [
        (policy_name, outcome, decision.action, decision.reason)
        for policy_name, table in DECISION_TABLES.items()
        for outcome, decision in table.items()
    ]
