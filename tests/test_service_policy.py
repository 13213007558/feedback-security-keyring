"""
Tests for the explicit service admission policy.

The backends here are in-memory fakes. They model the situations a resident
service actually faces -- a store that was available at startup but locks at
runtime, a backend that cannot declare its capability, priority changes, and
an explicitly requested backend -- without touching a real keychain.

Assertions verify that rejection happens before any credential is read and
that diagnostics explain the decision without leaking secret material.
"""

from __future__ import annotations

import logging

import pytest

from keyring import backend, policy, service
from keyring.backends import chainer
from keyring.compat import properties
from keyring.errors import KeyringLocked


class FakeBackend(backend.KeyringBackend):
    """Base fake with controllable availability, capability and lock state."""

    #: subclasses override these class-level controls
    priority_value: float = 2
    capability_value: str = policy.Capability.NON_INTERACTIVE.value
    locked: bool = False

    #: per-class count of credential reads that actually executed
    reads: int = 0
    secret: str = 'super-secret-value'

    @properties.classproperty
    def priority(cls):  # type: ignore[override]
        if cls.priority_value is None:
            raise RuntimeError('backend not suitable in this environment')
        return cls.priority_value

    def service_capability(self) -> str:
        return type(self).capability_value

    def preflight(self, service, username):
        if type(self).locked:
            raise KeyringLocked('keyring is locked at runtime')

    def get_password(self, service, username):
        type(self).reads += 1
        return self.secret

    def set_password(self, service, username, password):
        type(self).reads += 1
        self.secret = password

    def delete_password(self, service, username):
        type(self).reads += 1


class SecureBackend(FakeBackend):
    priority_value = 3


class InteractiveBackend(FakeBackend):
    priority_value = 4
    capability_value = policy.Capability.INTERACTIVE.value


class UnknownBackend(FakeBackend):
    priority_value = 5
    capability_value = policy.Capability.UNKNOWN.value


class UnavailableBackend(FakeBackend):
    priority_value = None


def _reset(*classes):
    for cls in classes:
        cls.priority_value = cls._default_priority
        cls.capability_value = cls._default_capability
        cls.locked = False
        cls.reads = 0


SecureBackend._default_priority = 3
SecureBackend._default_capability = policy.Capability.NON_INTERACTIVE.value
InteractiveBackend._default_priority = 4
InteractiveBackend._default_capability = policy.Capability.INTERACTIVE.value
UnknownBackend._default_priority = 5
UnknownBackend._default_capability = policy.Capability.UNKNOWN.value
UnavailableBackend._default_priority = None
UnavailableBackend._default_capability = policy.Capability.NON_INTERACTIVE.value


@pytest.fixture(autouse=True)
def isolate_global_state(monkeypatch):
    """Ensure service policy changes never leak to other test modules."""
    monkeypatch.setattr(service, '_policy', None)
    monkeypatch.setattr(backend, '_limit', None)
    yield


@pytest.fixture
def fake_registry(monkeypatch):
    """Register a fresh set of fake backends for selection."""
    classes = [SecureBackend, InteractiveBackend, UnknownBackend, UnavailableBackend]
    _reset(*classes)
    instances = [cls() for cls in classes]
    monkeypatch.setattr(backend, 'get_all_keyring', lambda: instances)
    return instances


@pytest.fixture
def strict_policy(monkeypatch):
    admission = policy.ServiceAdmissionPolicy.for_service()
    service.configure(admission)
    return admission


# --- availability vs. security capability are independent -----------------


def test_availability_does_not_imply_security(fake_registry):
    admission = policy.ServiceAdmissionPolicy.for_service()
    interactive = next(b for b in fake_registry if isinstance(b, InteractiveBackend))
    decision = admission.evaluate(interactive)
    assert decision.available is True
    assert decision.capability is policy.Capability.INTERACTIVE
    assert decision.outcome is policy.Outcome.REJECTED_INTERACTIVE
    assert not decision.accepted


def test_unavailable_is_rejected_separately(fake_registry):
    admission = policy.ServiceAdmissionPolicy.for_service()
    unavailable = next(
        b for b in fake_registry if isinstance(b, UnavailableBackend)
    )
    decision = admission.evaluate(unavailable)
    assert decision.available is False
    assert decision.outcome is policy.Outcome.REJECTED_UNAVAILABLE


def test_unknown_capability_rejected_for_service(fake_registry):
    admission = policy.ServiceAdmissionPolicy.for_service()
    unknown = next(b for b in fake_registry if isinstance(b, UnknownBackend))
    decision = admission.evaluate(unknown)
    assert decision.available is True
    assert decision.outcome is policy.Outcome.REJECTED_UNKNOWN


def test_interactive_allowed_only_when_policy_permits(fake_registry):
    relaxed = policy.ServiceAdmissionPolicy(interactive=True)
    interactive = next(
        b for b in fake_registry if isinstance(b, InteractiveBackend)
    )
    assert relaxed.evaluate(interactive).accepted


# --- automatic selection fails closed --------------------------------------


def test_auto_select_prefers_secure_backend(fake_registry, strict_policy):
    chosen = service.select_backend()
    assert isinstance(chosen, SecureBackend)


def test_auto_select_rejects_when_only_interactive_available(
    fake_registry, strict_policy
):
    SecureBackend.priority_value = None
    UnknownBackend.capability_value = policy.Capability.UNKNOWN.value
    with pytest.raises(policy.PolicyError) as excinfo:
        service.select_backend()
    # never silently downgrade to fail/null
    assert 'service admission policy' in str(excinfo.value)


def test_no_backend_at_all_fails_closed(monkeypatch, strict_policy):
    monkeypatch.setattr(backend, 'get_all_keyring', lambda: [])
    with pytest.raises(policy.PolicyError):
        service.select_backend()


# --- runtime lock after a successful initialization ------------------------


def test_runtime_lock_rejected_before_reading_credential(
    fake_registry, strict_policy
):
    chosen = service.select_backend()
    assert isinstance(chosen, SecureBackend)
    SecureBackend.locked = True

    SecureBackend.reads = 0
    with pytest.raises(KeyringLocked):
        service.get_password('svc', 'alice')
    # the rejection happened in preflight, before get_password ran
    assert SecureBackend.reads == 0


def test_runtime_lock_blocks_credential_and_set(
    fake_registry, strict_policy
):
    SecureBackend.locked = True
    SecureBackend.reads = 0
    with pytest.raises(KeyringLocked):
        service.get_credential('svc', None)
    with pytest.raises(KeyringLocked):
        service.set_password('svc', 'alice', 'pw')
    assert SecureBackend.reads == 0


# --- priority change after startup -----------------------------------------


def test_priority_change_reevaluated_at_selection(
    fake_registry, strict_policy
):
    first = service.select_backend()
    assert isinstance(first, SecureBackend)

    # a higher priority backend appears but is interactive -> must not win
    InteractiveBackend.capability_value = policy.Capability.INTERACTIVE.value
    InteractiveBackend.priority_value = 99
    chosen = service.select_backend()
    assert isinstance(chosen, SecureBackend)

    # when the secure backend drops out, selection fails closed rather than
    # downgrading
    SecureBackend.priority_value = None
    with pytest.raises(policy.PolicyError):
        service.select_backend()


# --- explicitly specified backend is not exempt ----------------------------


def test_explicit_interactive_backend_rejected(fake_registry, strict_policy):
    name = f'{InteractiveBackend.__module__}.{InteractiveBackend.__name__}'
    with pytest.raises(policy.PolicyError):
        service.select_named_backend(name)


def test_explicit_secure_backend_accepted(fake_registry, strict_policy, monkeypatch):
    monkeypatch.setattr(
        service.core,
        'load_keyring',
        lambda keyring_name: SecureBackend(),
    )
    chosen = service.select_named_backend('some.explicit.Name')
    assert isinstance(chosen, SecureBackend)


def test_explicit_backend_still_preflighted(fake_registry, strict_policy, monkeypatch):
    SecureBackend.locked = True
    SecureBackend.reads = 0
    monkeypatch.setattr(
        service.core,
        'load_keyring',
        lambda keyring_name: SecureBackend(),
    )
    # admission succeeds (the named backend is otherwise compliant)...
    chosen = service.get_backend('explicit.Name')
    assert isinstance(chosen, SecureBackend)
    # ...but the read preflights and rejects before touching a credential.
    with pytest.raises(KeyringLocked):
        service.get_password('svc', 'alice')
    assert SecureBackend.reads == 0


# --- chainer honors the same policy ----------------------------------------


class ChainA(FakeBackend):
    priority_value = 2
    capability_value = policy.Capability.NON_INTERACTIVE.value


class ChainB(FakeBackend):
    priority_value = 3
    capability_value = policy.Capability.NON_INTERACTIVE.value


ChainA._default_priority = 2
ChainA._default_capability = policy.Capability.NON_INTERACTIVE.value
ChainB._default_priority = 3
ChainB._default_capability = policy.Capability.NON_INTERACTIVE.value


@pytest.fixture
def chain_registry(monkeypatch):
    _reset(ChainA, ChainB)
    members = [ChainA(), ChainB()]
    monkeypatch.setattr(backend, 'get_all_keyring', lambda: members)
    service.configure(policy.ServiceAdmissionPolicy.for_service())
    return members


def test_chainer_only_contains_admitted_members(chain_registry):
    chain = chainer.ChainerBackend()
    names = {type(m).__name__ for m in chain.backends}
    assert names == {'ChainA', 'ChainB'}


def test_chainer_excludes_member_that_becomes_locked(chain_registry):
    ChainB.locked = True
    chain = chainer.ChainerBackend()
    # preflight must reject before reading when a member is unusable
    with pytest.raises((policy.PolicyError, KeyringLocked)):
        service._preflight(chain, 'svc', 'alice')
    assert ChainA.reads == 0 and ChainB.reads == 0


def test_chainer_empty_fails_closed(monkeypatch):
    monkeypatch.setattr(backend, 'get_all_keyring', lambda: [])
    service.configure(policy.ServiceAdmissionPolicy.for_service())
    chain = chainer.ChainerBackend()
    with pytest.raises(policy.PolicyError):
        service._preflight(chain, 'svc', 'alice')


# --- diagnostics explain the decision without leaking secrets --------------


def test_decision_describe_names_backend_not_secret(fake_registry, strict_policy):
    secure = next(b for b in fake_registry if isinstance(b, SecureBackend))
    decision = strict_policy.evaluate(secure)
    text = decision.describe()
    assert 'SecureBackend' in text
    assert 'accepted' in text
    assert secure.secret not in text


def test_policy_error_lists_reasons_without_secrets(
    fake_registry, strict_policy, caplog
):
    caplog.set_level(logging.DEBUG)
    SecureBackend.priority_value = None
    with pytest.raises(policy.PolicyError) as excinfo:
        service.select_backend()
    message = str(excinfo.value)
    assert SecureBackend.secret not in message
    # every candidate's disposition is explained
    assert 'REJECTED' in message or 'rejected' in message
    assert all(log_record.getMessage().find(SecureBackend.secret) == -1
               for log_record in caplog.records)


def test_default_base_capability_is_unknown():
    class Bare(backend.KeyringBackend):
        priority = 1

        def get_password(self, service, username):
            raise NotImplementedError

        def set_password(self, service, username, password):
            raise NotImplementedError

    assert Bare().service_capability() == policy.Capability.UNKNOWN.value


# --- never fall back to non-protecting backends ----------------------------


class InsecureLike(FakeBackend):
    """Mimics the qualified name of the built-in null backend."""

    priority_value = 1
    capability_value = policy.Capability.NON_INTERACTIVE.value


InsecureLike.__module__ = 'keyring.backends.null'
InsecureLike.__name__ = 'Keyring'
InsecureLike._default_priority = 1
InsecureLike._default_capability = policy.Capability.NON_INTERACTIVE.value
InsecureLike.__qualname__ = 'Keyring'


def test_null_like_backend_rejected_even_when_only_option(
    monkeypatch, strict_policy
):
    only_insecure = [InsecureLike()]
    monkeypatch.setattr(backend, 'get_all_keyring', lambda: only_insecure)
    with pytest.raises(policy.PolicyError) as excinfo:
        service.select_backend()
    assert InsecureLike.secret not in str(excinfo.value)


def test_explicit_null_backend_rejected(monkeypatch, strict_policy):
    from keyring.backends import null

    monkeypatch.setattr(
        service.core, 'load_keyring', lambda name: null.Keyring()
    )
    with pytest.raises(policy.PolicyError):
        service.select_named_backend('keyring.backends.null.Keyring')


def test_predicate_can_add_further_restrictions(fake_registry):
    seen = []

    def deny_interactive(candidate):
        seen.append(type(candidate).__name__)
        return not isinstance(candidate, InteractiveBackend)

    restricted = policy.ServiceAdmissionPolicy.for_service(predicate=deny_interactive)
    service.configure(restricted)
    chosen = service.select_backend()
    # secure backend still wins; the predicate was consulted for candidates
    assert isinstance(chosen, SecureBackend)
    assert 'InteractiveBackend' in seen


def test_predicate_rejecting_secure_choice_fails_closed(fake_registry):
    restricted = policy.ServiceAdmissionPolicy.for_service(
        predicate=lambda candidate: not isinstance(candidate, SecureBackend)
    )
    service.configure(restricted)
    # nothing else is compliant, so the policy refuses rather than downgrading
    with pytest.raises(policy.PolicyError):
        service.select_backend()
