"""
Policy-aware entry points for resident (non-interactive) services.

The functions in :mod:`keyring.core` select a backend purely by priority and
configuration. A long-running service has stricter needs:

* it must never trigger an interactive unlock prompt;
* it must not fall back to a non-compliant backend (null/fail/plaintext)
  when the secure backend becomes unavailable;
* a backend that was available at startup may become locked at runtime, so
  admission must be re-checked *before* reading any credential.

This module layers an explicit :class:`~keyring.policy.ServiceAdmissionPolicy`
over backend selection (both automatic and explicitly named) and over the
:class:`~keyring.backends.chainer.ChainerBackend`. Every read performs a
preflight first, so rejection happens before any secret is touched. Error and
log messages describe the selection decision without exposing credentials.
"""

from __future__ import annotations

import logging
import typing

from . import backend, core, credentials, policy
from .backends import chainer

log = logging.getLogger(__name__)

_policy: policy.ServiceAdmissionPolicy | None = None


def configure(
    admission_policy: policy.ServiceAdmissionPolicy | None = None,
) -> policy.ServiceAdmissionPolicy:
    """
    Install (and return) the admission policy used by the service entry
    points. Pass ``None`` to reset to the default service policy.
    """
    global _policy
    _policy = admission_policy or policy.ServiceAdmissionPolicy.for_service()
    backend._limit = _limit_for(_policy)
    return _policy


def get_policy() -> policy.ServiceAdmissionPolicy:
    """Return the active service policy, installing the default on first use."""
    if _policy is None:
        configure()
    return typing.cast(policy.ServiceAdmissionPolicy, _policy)


def _limit_for(
    admission_policy: policy.ServiceAdmissionPolicy,
) -> typing.Callable[[backend.KeyringBackend], bool]:
    """
    Adapt the policy to the legacy ``limit`` predicate used by automatic
    selection and the chainer, so both honor the same security rules.
    """

    def limit(candidate: backend.KeyringBackend) -> bool:
        return admission_policy.evaluate(candidate).accepted

    return limit


def _candidates() -> list[backend.KeyringBackend]:
    """All constructible backends, including ones the policy will reject."""
    return list(backend.get_all_keyring())


def select_backend(
    admission_policy: policy.ServiceAdmissionPolicy | None = None,
) -> backend.KeyringBackend:
    """
    Select a backend automatically under the admission policy.

    Fails closed with :class:`~keyring.errors.PolicyError` (surfaced via
    :class:`keyring.policy.PolicyError`) when no backend qualifies; it never
    substitutes the null/fail backend.
    """
    admission_policy = admission_policy or get_policy()
    chosen, decisions = admission_policy.admit(_candidates())
    for decision in decisions:
        log.debug("admission: %s", decision.describe())
    return chosen


def select_named_backend(
    keyring_name: str,
    admission_policy: policy.ServiceAdmissionPolicy | None = None,
) -> backend.KeyringBackend:
    """
    Load an explicitly requested backend and require it to pass the policy.

    An explicit choice is honored, but never exempted from the security
    checks: a locked, interactive, or unknown-capability backend is rejected
    before it can read a credential rather than silently downgrading.
    """
    admission_policy = admission_policy or get_policy()
    candidate = core.load_keyring(keyring_name)
    decision = admission_policy.evaluate(candidate)
    log.debug("explicit admission: %s", decision.describe())
    if not decision.accepted:
        raise policy.PolicyError(
            "Explicitly requested backend rejected by the service "
            f"admission policy: {decision.describe()}"
        )
    return candidate


def get_backend(
    keyring_name: str | None = None,
    admission_policy: policy.ServiceAdmissionPolicy | None = None,
) -> backend.KeyringBackend:
    """
    Return an admitted backend, honoring an explicit name when supplied.
    """
    if keyring_name:
        return select_named_backend(keyring_name, admission_policy)
    return select_backend(admission_policy)


def _preflight(candidate: backend.KeyringBackend, service: str, username) -> None:
    """
    Reject a backend that cannot serve the read without prompting.

    The chainer is checked as a whole; every member it would consult must
    currently be admissible. Other backends run their own preflight hook.
    Runs before any credential is read.
    """
    admission_policy = get_policy()
    if isinstance(candidate, chainer.ChainerBackend):
        _preflight_chain(candidate, admission_policy, service, username)
        return

    decision = admission_policy.evaluate(candidate)
    if not decision.accepted:
        raise policy.PolicyError(
            "Backend no longer admissible at runtime: "
            f"{decision.describe()}"
        )
    candidate.preflight(service, username)


def _preflight_chain(
    candidate: chainer.ChainerBackend,
    admission_policy: policy.ServiceAdmissionPolicy,
    service: str,
    username,
) -> None:
    members = candidate.backends
    if not members:
        raise policy.PolicyError(
            "Chainer has no admissible member backends; refusing to read."
        )
    for member in members:
        decision = admission_policy.evaluate(member)
        if not decision.accepted:
            raise policy.PolicyError(
                "Chainer member rejected before reading any credential: "
                f"{decision.describe()}"
            )
        member.preflight(service, username)


def get_password(service_name: str, username: str) -> str | None:
    """Read a password only after the backend passes the runtime preflight."""
    candidate = get_backend()
    _preflight(candidate, service_name, username)
    return candidate.get_password(service_name, username)


def get_credential(
    service_name: str, username: str | None
) -> credentials.Credential | None:
    """Read a credential only after the backend passes the runtime preflight."""
    candidate = get_backend()
    _preflight(candidate, service_name, username)
    return candidate.get_credential(service_name, username)


def set_password(service_name: str, username: str, password: str) -> None:
    """Write through an admitted backend after the runtime preflight."""
    candidate = get_backend()
    _preflight(candidate, service_name, username)
    candidate.set_password(service_name, username, password)


def delete_password(service_name: str, username: str) -> None:
    """Delete through an admitted backend after the runtime preflight."""
    candidate = get_backend()
    _preflight(candidate, service_name, username)
    candidate.delete_password(service_name, username)


__all__ = [
    'configure',
    'get_policy',
    'select_backend',
    'select_named_backend',
    'get_backend',
    'get_password',
    'get_credential',
    'set_password',
    'delete_password',
]
