"""
Service admission policy.

A long-running (resident/daemon) service cannot rely on an interactive
session: it must never pop up an unlock prompt and it must not silently fall
back to a backend that cannot satisfy its security requirements when the
preferred secure backend is unavailable.

This module expresses the two concerns independently:

* **availability** -- can the backend be constructed and used in this
  process at all (its ``priority`` resolves without raising)?
* **security capability** -- can the backend serve the caller without an
  interactive unlock, and is it permitted by the active policy?

The :class:`ServiceAdmissionPolicy` evaluates both for every candidate and
records a human-readable :class:`AdmissionDecision` explaining the result.
Diagnostics never include credential material; they only name backends and
the reason for acceptance or rejection.
"""

from __future__ import annotations

import dataclasses
import enum
import logging
import os
import typing

from jaraco.context import ExceptionTrap

from . import backend
from .errors import KeyringError

log = logging.getLogger(__name__)


class Capability(enum.Enum):
    """
    The security posture a backend advertises for the current process.

    The capability describes *how* a backend can serve a request, kept
    separate from whether the backend is merely available.
    """

    #: The backend is known to serve requests without an interactive prompt.
    NON_INTERACTIVE = 'non-interactive'
    #: The backend may raise an interactive unlock prompt before serving.
    INTERACTIVE = 'interactive'
    #: The backend does not (or cannot) declare its unlock behavior.
    UNKNOWN = 'unknown'


class Outcome(enum.Enum):
    """The result of admitting a single backend."""

    ACCEPTED = 'accepted'
    REJECTED_LOCKED = 'rejected: locked at runtime'
    REJECTED_INTERACTIVE = 'rejected: interactive unlock required'
    REJECTED_UNKNOWN = 'rejected: security capability unknown'
    REJECTED_UNAVAILABLE = 'rejected: unavailable'
    REJECTED_POLICY = 'rejected: denied by policy'


class PolicyError(KeyringError):
    """
    Raised when no backend can be admitted under the active policy.

    The message explains *why* each candidate was rejected but never
    contains credential material.
    """


@dataclasses.dataclass(frozen=True)
class AdmissionDecision:
    """
    The outcome of evaluating one backend against a policy.

    ``reason`` is safe for logging: it references backend names and
    capability states only, never secrets.
    """

    backend: backend.KeyringBackend
    available: bool
    capability: Capability
    outcome: Outcome
    reason: str

    @property
    def accepted(self) -> bool:
        return self.outcome is Outcome.ACCEPTED

    def describe(self) -> str:
        keyring = type(self.backend)
        return (
            f"{keyring.__module__}.{keyring.__name__}: "
            f"available={self.available} capability={self.capability.value} "
            f"-> {self.outcome.value} ({self.reason})"
        )


def _env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ('1', 'true', 'yes', 'on')


class ServiceAdmissionPolicy:
    """
    Decide which backends a non-interactive service may use.

    The policy is explicit: construct it with the security requirements of
    the service rather than relying on implicit priority ordering.

    Parameters
    ----------
    interactive:
        Whether the process is allowed to present an interactive unlock
        prompt. A resident service passes ``False``.
    require_known_capability:
        When ``True`` (the default for a service), backends whose security
        capability is :data:`Capability.UNKNOWN` are rejected instead of
        being optimistically trusted.
    predicate:
        Optional extra allow-list applied *after* the built-in checks. It
        receives a backend instance and returns ``True`` to permit it.
    """

    #: Backends that are never acceptable for storing real secrets, even
    #: when they are the only available option.
    _insecure_class_names: typing.ClassVar[frozenset[str]] = frozenset(
        {
            'keyring.backends.null.Keyring',
            'keyring.backends.fail.Keyring',
        }
    )

    def __init__(
        self,
        *,
        interactive: bool = False,
        require_known_capability: bool = True,
        predicate: typing.Callable[[backend.KeyringBackend], bool] | None = None,
    ) -> None:
        self.interactive = interactive
        self.require_known_capability = require_known_capability
        self.predicate = predicate

    @classmethod
    def for_service(
        cls,
        *,
        predicate: typing.Callable[[backend.KeyringBackend], bool] | None = None,
    ) -> 'ServiceAdmissionPolicy':
        """
        Build the policy appropriate for a resident/daemon service.

        Unlock prompts are forbidden and backends with an unknown security
        capability are not trusted.
        """
        return cls(
            interactive=False,
            require_known_capability=True,
            predicate=predicate,
        )

    @classmethod
    def from_env(
        cls,
        *,
        predicate: typing.Callable[[backend.KeyringBackend], bool] | None = None,
    ) -> 'ServiceAdmissionPolicy':
        """
        Build a policy from the environment.

        ``KEYRING_INTERACTIVE`` permits unlock prompts (default off for a
        service); ``KEYRING_ALLOW_UNKNOWN_CAPABILITY`` relaxes the
        requirement that capability be known (default off).
        """
        return cls(
            interactive=_env_flag('KEYRING_INTERACTIVE', False),
            require_known_capability=not _env_flag(
                'KEYRING_ALLOW_UNKNOWN_CAPABILITY', False
            ),
            predicate=predicate,
        )

    @staticmethod
    def _qualified_name(candidate: backend.KeyringBackend | type) -> str:
        keyring = candidate if isinstance(candidate, type) else type(candidate)
        return f'{keyring.__module__}.{keyring.__name__}'

    def availability(self, candidate: backend.KeyringBackend) -> bool:
        """
        Return whether the backend is usable in this process.

        Availability only reflects constructability/priority; it says
        nothing about security capability.
        """
        with ExceptionTrap(Exception) as trap:
            priority = candidate.priority
            if priority is None:
                raise RuntimeError('backend reported no priority')
        if trap:
            log.debug("Backend unavailable: %s", trap.value)
            return False
        return True

    def capability(self, candidate: backend.KeyringBackend) -> Capability:
        """
        Determine the advertised security capability of a backend.

        A backend may declare ``service_capability`` (a :class:`Capability`
        or its value) or, for runtime state, implement
        :meth:`KeyringBackend.service_capability` to return one. Anything
        unrecognized is treated as :data:`Capability.UNKNOWN` rather than
        guessed.
        """
        try:
            declared = candidate.service_capability()
        except Exception as exc:  # noqa: BLE001 - capability must never raise
            log.debug("Capability probe failed for %s: %s", type(candidate), exc)
            return Capability.UNKNOWN
        if isinstance(declared, Capability):
            return declared
        try:
            return Capability(declared)
        except (ValueError, TypeError):
            return Capability.UNKNOWN

    def evaluate(self, candidate: backend.KeyringBackend) -> AdmissionDecision:
        """Apply availability and security checks to one backend."""
        name = self._qualified_name(candidate)

        if not self.availability(candidate):
            return AdmissionDecision(
                candidate,
                available=False,
                capability=Capability.UNKNOWN,
                outcome=Outcome.REJECTED_UNAVAILABLE,
                reason='priority could not be resolved in this environment',
            )

        capability = self.capability(candidate)

        if name in self._insecure_class_names:
            return AdmissionDecision(
                candidate,
                available=True,
                capability=capability,
                outcome=Outcome.REJECTED_POLICY,
                reason='backend does not provide protected storage',
            )

        if self.predicate is not None and not self.predicate(candidate):
            return AdmissionDecision(
                candidate,
                available=True,
                capability=capability,
                outcome=Outcome.REJECTED_POLICY,
                reason='rejected by the supplied policy predicate',
            )

        if capability is Capability.INTERACTIVE and not self.interactive:
            return AdmissionDecision(
                candidate,
                available=True,
                capability=capability,
                outcome=Outcome.REJECTED_INTERACTIVE,
                reason='backend may prompt for an interactive unlock',
            )

        if capability is Capability.UNKNOWN and self.require_known_capability:
            return AdmissionDecision(
                candidate,
                available=True,
                capability=capability,
                outcome=Outcome.REJECTED_UNKNOWN,
                reason='backend does not declare a service-safe capability',
            )

        return AdmissionDecision(
            candidate,
            available=True,
            capability=capability,
            outcome=Outcome.ACCEPTED,
            reason='satisfies availability and security requirements',
        )

    def admit(
        self, candidates: typing.Iterable[backend.KeyringBackend]
    ) -> tuple[backend.KeyringBackend, list[AdmissionDecision]]:
        """
        Select the highest-priority admissible backend.

        Returns the chosen backend and the decision for every candidate.
        Raises :class:`PolicyError` if nothing can be admitted. The error
        message lists the rejection reasons without any secret material.
        """
        decisions = [self.evaluate(candidate) for candidate in candidates]
        accepted = [decision for decision in decisions if decision.accepted]
        if not accepted:
            summary = '; '.join(decision.describe() for decision in decisions)
            raise PolicyError(
                'No keyring backend satisfies the service admission policy. '
                f'Evaluated {len(decisions)} backend(s): {summary or "(none)"}'
            )
        selected = max(accepted, key=lambda decision: decision.backend.priority)
        log.debug(
            "Admitted %s from %d candidate(s)",
            self._qualified_name(selected.backend),
            len(decisions),
        )
        return selected.backend, decisions
