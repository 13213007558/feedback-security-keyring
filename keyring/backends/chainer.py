"""
Keyring Chainer - iterates over other viable backends to
discover passwords in each.
"""

from __future__ import annotations

import typing

from .. import backend, errors
from ..compat import properties
from . import fail
from .chainer_policy import (
    DEFAULT_POLICY,
    Action,
    ChainerPolicy,
    Decision,
    DecisionEvent,
    Outcome,
    classify,
    get_policy,
    identify,
    new_correlation_id,
)


class ChainerBackend(backend.KeyringBackend):
    """
    >>> ChainerBackend()
    <keyring.backends.chainer.ChainerBackend object at ...>
    """

    # override viability as 'priority' cannot be determined
    # until other backends have been constructed
    viable = True

    policy: typing.ClassVar[ChainerPolicy | str] = DEFAULT_POLICY
    """
    Credential-resolution policy.  Defaults to the historical chainer
    behavior.  May be a policy object or one of the names in
    :data:`keyring.backends.chainer_policy.POLICIES`.
    """

    source: typing.ClassVar[str | None] = None
    """
    Identity of the authoritative backend for source-bound policies.

    Set via ``with_properties(source='vault')``.  Policies that do not
    require a source ignore this value.
    """

    def __init__(self, policy: ChainerPolicy | str | None = None):
        super().__init__()
        if policy is not None:
            self.policy = policy

    @property
    def _active_policy(self) -> ChainerPolicy:
        return get_policy(self.policy)

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

    def _record(
        self,
        policy: ChainerPolicy,
        outcome: Outcome,
        decision: Decision,
        keyring: backend.KeyringBackend | None = None,
    ) -> DecisionEvent:
        event = DecisionEvent(
            correlation_id=new_correlation_id(),
            policy=policy.name,
            outcome=outcome,
            action=decision.action,
            reason=decision.reason,
            backend=identify(keyring) if keyring is not None else None,
        )
        try:
            policy.audit(event)
        except Exception:
            # A broken audit sink must not change the authorization result.
            pass
        return event

    def _deny(
        self,
        policy: ChainerPolicy,
        outcome: Outcome,
        reason: str,
        keyring: backend.KeyringBackend | None = None,
    ) -> typing.NoReturn:
        event = self._record(policy, outcome, Decision(Action.DENY, reason), keyring)
        raise errors.AccessDenied(event.correlation_id) from None

    def _candidates(self, policy: ChainerPolicy) -> list[backend.KeyringBackend]:
        candidates = list(self.backends)
        if not policy.requires_source:
            return candidates
        if not self.source:
            self._deny(policy, Outcome.DENIED, 'source-unbound')
        selected = [
            keyring
            for keyring in candidates
            if policy.accepts_source(self.source, identify(keyring))
        ]
        if not selected:
            self._deny(policy, Outcome.DENIED, 'source-unavailable')
        return selected

    def _resolve(
        self,
        service: str,
        username: str | None,
        fetch: typing.Callable[[backend.KeyringBackend], typing.Any],
    ) -> typing.Any:
        policy = self._active_policy
        for keyring in self._candidates(policy):
            err: BaseException | None = None
            try:
                value = fetch(keyring)
            except Exception as exc:
                err = exc
                outcome = classify(exc)
            else:
                if value is not None:
                    return value
                outcome = Outcome.MISSING

            decision = policy.decide(outcome)
            event = self._record(policy, outcome, decision, keyring)
            if decision.action is Action.CONTINUE:
                continue
            if decision.action is Action.NOT_FOUND:
                return None
            if decision.action is Action.PROPAGATE:
                if err is None:
                    return None
                # Raising outside the except suite keeps the original
                # traceback without attaching a credential value as context.
                raise err
            if policy.conceal_denial:
                # Indistinguishable from an absent entry to the caller; the
                # audit event above still records why the read was denied.
                return None
            # Raise outside the except suite so no backend message (which
            # may contain the username or confirm account existence) ends up
            # in the exception context.
            raise errors.AccessDenied(event.correlation_id) from None
        return None

    def get_password(self, service, username):
        return self._resolve(
            service, username, lambda keyring: keyring.get_password(service, username)
        )

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
        return self._resolve(
            service,
            username,
            lambda keyring: keyring.get_credential(service, username),
        )
