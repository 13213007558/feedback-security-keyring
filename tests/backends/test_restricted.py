"""
Tests for the in-memory backend and the restricted backend view.
"""

from __future__ import annotations

import pytest

from keyring import credentials, errors
from keyring.backends import memory
from keyring.backends.restricted import (
    DELETE_PASSWORD,
    GET_CREDENTIAL,
    GET_PASSWORD,
    SET_PASSWORD,
    READ_ACTIONS,
    RestrictedKeyring,
    WRITE_ACTIONS,
)
from keyring.backend import KeyringBackend


class RecordingBackend(KeyringBackend):
    """
    Records every call that reaches it, so tests can prove the view rejects
    unauthorized operations before the underlying backend is touched.
    """

    priority = 1

    def __init__(self):
        super().__init__()
        self.calls: list[tuple[str, str, str | None]] = []

    def get_password(self, service, username):
        self.calls.append((GET_PASSWORD, service, username))
        return f'pw-{service}-{username}'

    def set_password(self, service, username, password):
        self.calls.append((SET_PASSWORD, service, username))

    def delete_password(self, service, username):
        self.calls.append((DELETE_PASSWORD, service, username))

    def get_credential(self, service, username):
        self.calls.append((GET_CREDENTIAL, service, username))
        return credentials.SimpleCredential(username or 'default', 'secret')


@pytest.fixture
def base() -> memory.MemoryKeyring:
    return memory.MemoryKeyring()


@pytest.fixture
def reader(base) -> RestrictedKeyring:
    return RestrictedKeyring(
        base,
        services={'mail'},
        usernames={'alice'},
        actions=READ_ACTIONS,
    )


@pytest.fixture
def maintainer(base) -> RestrictedKeyring:
    return RestrictedKeyring(
        base,
        services={'mail'},
        usernames={'alice', 'bob'},
        actions=WRITE_ACTIONS,
    )


class TestMemoryKeyring:
    def test_round_trip(self, base):
        assert base.get_password('mail', 'alice') is None
        base.set_password('mail', 'alice', 'secret')
        assert base.get_password('mail', 'alice') == 'secret'

    def test_overwrite(self, base):
        base.set_password('mail', 'alice', 'one')
        base.set_password('mail', 'alice', 'two')
        assert base.get_password('mail', 'alice') == 'two'

    def test_delete(self, base):
        base.set_password('mail', 'alice', 'secret')
        base.delete_password('mail', 'alice')
        assert base.get_password('mail', 'alice') is None

    def test_delete_missing_raises(self, base):
        with pytest.raises(errors.PasswordDeleteError):
            base.delete_password('mail', 'ghost')

    def test_get_credential_by_username(self, base):
        base.set_password('mail', 'alice', 'secret')
        cred = base.get_credential('mail', 'alice')
        assert isinstance(cred, credentials.SimpleCredential)
        assert (cred.username, cred.password) == ('alice', 'secret')
        assert base.get_credential('mail', 'nobody') is None

    def test_get_credential_without_username(self, base):
        base.set_password('mail', 'alice', 'a-pw')
        base.set_password('mail', 'bob', 'b-pw')
        cred = base.get_credential('mail', None)
        assert cred is not None
        assert (cred.username, cred.password) in (
            ('alice', 'a-pw'),
            ('bob', 'b-pw'),
        )
        assert base.get_credential('other', None) is None


class TestRestrictedRead:
    def test_allows_in_scope_read(self, reader, base):
        base.set_password('mail', 'alice', 'secret')
        assert reader.get_password('mail', 'alice') == 'secret'

    def test_get_credential_in_scope(self, reader, base):
        base.set_password('mail', 'alice', 'secret')
        cred = reader.get_credential('mail', 'alice')
        assert cred is not None
        assert cred.password == 'secret'

    def test_denies_other_service_before_backend(self):
        guarded = RecordingBackend()
        view = RestrictedKeyring(
            guarded, services={'mail'}, usernames=None, actions=READ_ACTIONS
        )
        with pytest.raises(errors.PermissionDeniedError):
            view.get_password('calendar', 'alice')
        assert guarded.calls == []

    def test_denies_other_username_before_backend(self):
        guarded = RecordingBackend()
        view = RestrictedKeyring(
            guarded, services={'mail'}, usernames={'alice'}, actions=READ_ACTIONS
        )
        with pytest.raises(errors.PermissionDeniedError):
            view.get_password('mail', 'mallory')
        assert guarded.calls == []

    def test_account_scoped_denies_anonymous_credential_lookup(self, reader):
        with pytest.raises(errors.PermissionDeniedError):
            reader.get_credential('mail', None)

    def test_unscoped_view_allows_anonymous_credential_lookup(self, base):
        base.set_password('mail', 'alice', 'secret')
        view = RestrictedKeyring(
            base, services={'mail'}, usernames=None, actions=READ_ACTIONS
        )
        cred = view.get_credential('mail', None)
        assert cred is not None
        assert cred.password == 'secret'


class TestRestrictedWrite:
    def test_reader_cannot_set_before_backend(self):
        guarded = RecordingBackend()
        view = RestrictedKeyring(
            guarded, services={'mail'}, usernames={'alice'}, actions=READ_ACTIONS
        )
        with pytest.raises(errors.PermissionDeniedError):
            view.set_password('mail', 'alice', 'rotated')
        assert guarded.calls == []

    def test_reader_cannot_delete_before_backend(self, reader):
        with pytest.raises(errors.PermissionDeniedError):
            reader.delete_password('mail', 'alice')

    def test_maintainer_can_set_and_delete(self, maintainer, base):
        maintainer.set_password('mail', 'alice', 'rotated')
        assert base.get_password('mail', 'alice') == 'rotated'
        maintainer.delete_password('mail', 'alice')
        assert base.get_password('mail', 'alice') is None

    def test_maintainer_scope_still_binds_service(self, maintainer):
        with pytest.raises(errors.PermissionDeniedError):
            maintainer.set_password('calendar', 'alice', 'x')

    def test_maintainer_scope_still_binds_username(self, maintainer):
        with pytest.raises(errors.PermissionDeniedError):
            maintainer.set_password('mail', 'mallory', 'x')

    def test_each_action_denied_independently(self):
        guarded = RecordingBackend()
        view = RestrictedKeyring(
            guarded,
            services={'mail'},
            usernames={'alice'},
            actions=frozenset({GET_PASSWORD}),
        )
        for action, invocation in (
            (GET_CREDENTIAL, lambda: view.get_credential('mail', 'alice')),
            (SET_PASSWORD, lambda: view.set_password('mail', 'alice', 'x')),
            (DELETE_PASSWORD, lambda: view.delete_password('mail', 'alice')),
        ):
            with pytest.raises(errors.PermissionDeniedError):
                invocation()
        assert guarded.calls == []
        assert view.get_password('mail', 'alice') == 'pw-mail-alice'
        assert guarded.calls == [(GET_PASSWORD, 'mail', 'alice')]


class TestNarrowing:
    def test_intersects_services(self, maintainer):
        child = maintainer.narrow(services={'mail', 'calendar'})
        assert child.services == frozenset({'mail'})

    def test_intersects_usernames(self, maintainer):
        child = maintainer.narrow(usernames={'bob', 'carol'})
        assert child.usernames == frozenset({'bob'})

    def test_intersects_actions(self, maintainer):
        child = maintainer.narrow(actions=READ_ACTIONS)
        assert child.actions == READ_ACTIONS
        with pytest.raises(errors.PermissionDeniedError):
            child.set_password('mail', 'bob', 'x')

    def test_cannot_widen_service(self, reader):
        child = reader.narrow()
        with pytest.raises(errors.PermissionDeniedError):
            child.get_password('calendar', 'alice')

    def test_cannot_widen_action(self, reader):
        child = reader.narrow(actions=WRITE_ACTIONS)
        with pytest.raises(errors.PermissionDeniedError):
            child.set_password('mail', 'alice', 'x')
        assert child.actions == READ_ACTIONS

    def test_chain_of_views_only_narrows(self, maintainer):
        child = maintainer.narrow(usernames={'bob'})
        grandchild = child.narrow(services={'mail'}, usernames={'alice', 'bob'})
        assert grandchild.services == frozenset({'mail'})
        assert grandchild.usernames == frozenset({'bob'})
        assert grandchild.actions == WRITE_ACTIONS

    def test_none_dimensions_remain_open_then_close(self, base):
        open_view = RestrictedKeyring(
            base, services=None, usernames=None, actions=WRITE_ACTIONS
        )
        narrowed = open_view.narrow(services={'mail'}, usernames={'alice'})
        assert narrowed.services == frozenset({'mail'})
        assert narrowed.usernames == frozenset({'alice'})
        with pytest.raises(errors.PermissionDeniedError):
            narrowed.get_password('other', 'alice')


class TestConstruction:
    def test_requires_backend(self):
        with pytest.raises(TypeError):
            RestrictedKeyring(
                object(), services={'mail'}, usernames=None, actions=READ_ACTIONS
            )

    def test_rejects_unknown_action(self, base):
        with pytest.raises(ValueError):
            RestrictedKeyring(
                base,
                services={'mail'},
                usernames=None,
                actions=frozenset({'explode'}),
            )

    def test_scopes_are_copied_defensively(self, base):
        services = {'mail'}
        view = RestrictedKeyring(
            base, services=services, usernames=None, actions=READ_ACTIONS
        )
        services.add('calendar')
        assert view.services == frozenset({'mail'})

    def test_not_auto_viable(self):
        with pytest.raises(RuntimeError):
            RestrictedKeyring.priority  # noqa: B018


class FallbackChain:
    """Minimal ordered fallback chain used to exercise restricted views."""

    def __init__(self, backends):
        self.backends = backends

    def get_password(self, service, username):
        for ring in self.backends:
            password = ring.get_password(service, username)
            if password is not None:
                return password
        return None


class TestChainedFallback:
    def test_restricted_views_chain_with_fallback(self):
        primary = memory.MemoryKeyring()
        secondary = memory.MemoryKeyring()
        secondary.set_password('mail', 'alice', 'from-secondary')

        primary_view = RestrictedKeyring(
            primary, services={'mail'}, usernames={'alice'}, actions=READ_ACTIONS
        )
        secondary_view = RestrictedKeyring(
            secondary,
            services={'mail'},
            usernames={'alice'},
            actions=READ_ACTIONS,
        )

        chain = FallbackChain([primary_view, secondary_view])
        assert chain.get_password('mail', 'alice') == 'from-secondary'

    def test_chain_falls_through_when_first_has_no_secret(self):
        primary = memory.MemoryKeyring()
        secondary = memory.MemoryKeyring()
        secondary.set_password('mail', 'alice', 'from-secondary')

        views = [
            RestrictedKeyring(
                ring,
                services={'mail'},
                usernames={'alice'},
                actions=READ_ACTIONS,
            )
            for ring in (primary, secondary)
        ]
        assert FallbackChain(views).get_password('mail', 'alice') == (
            'from-secondary'
        )

    def test_chain_enforces_scope_before_each_backend(self):
        guarded = RecordingBackend()
        view = RestrictedKeyring(
            guarded, services={'mail'}, usernames={'alice'}, actions=READ_ACTIONS
        )
        chain = FallbackChain([view])
        with pytest.raises(errors.PermissionDeniedError):
            chain.get_password('mail', 'mallory')
        assert guarded.calls == []
