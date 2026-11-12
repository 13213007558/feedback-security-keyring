"""
Restricted backend views.

A :class:`RestrictedKeyring` wraps another backend and exposes only a slice of
it. The view is handed to a component (for example a notification service) that
should only read the credentials of one service, while another maintenance
component may be given a view that can also rotate or delete them.

The restriction is enforced *inside the view*, before the wrapped backend is
invoked. An out-of-scope service or account, or an operation that is not among
the allowed actions, raises :class:`~keyring.errors.PermissionDeniedError`
without ever reaching the underlying backend.

This is a capability boundary between otherwise trusted components, not a
sandbox. It does not protect against arbitrary or malicious Python code: a
caller that already has the unrestricted backend or unrestricted Python access
is unaffected. It only keeps components from exercising a global keyring
capability beyond the scope they were deliberately given.

Derived views can only narrow the parent view, never widen it.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable

from .. import credentials, errors
from ..backend import KeyringBackend
from ..compat import properties

# Action names understood by a restricted view.
GET_PASSWORD = 'get_password'
GET_CREDENTIAL = 'get_credential'
SET_PASSWORD = 'set_password'
DELETE_PASSWORD = 'delete_password'

# Read-only access, suitable for a component that only consumes credentials.
READ_ACTIONS: frozenset[str] = frozenset({GET_PASSWORD, GET_CREDENTIAL})

# Write access on top of read access, suitable for a maintenance component.
WRITE_ACTIONS: frozenset[str] = READ_ACTIONS | frozenset(
    {SET_PASSWORD, DELETE_PASSWORD}
)

_KNOWN_ACTIONS: frozenset[str] = frozenset(
    {GET_PASSWORD, GET_CREDENTIAL, SET_PASSWORD, DELETE_PASSWORD}
)


class RestrictedKeyring(KeyringBackend):
    """
    A capability-restricted projection of another backend.

    ``backend`` is the only backend the view may reach. ``services`` and
    ``usernames`` bound the service and account names the view may touch; an
    empty collection means "no service" / "no account", while ``None`` leaves
    that dimension unrestricted. ``actions`` is the set of operations the view
    is permitted to perform.

    >>> from keyring.backends.memory import MemoryKeyring
    >>> base = MemoryKeyring()
    >>> view = RestrictedKeyring(
    ...     base, services={'mail'}, usernames={'alice'}, actions=READ_ACTIONS,
    ... )
    >>> view.get_password('mail', 'alice') is None
    True
    >>> view.get_password('other', 'alice')
    Traceback (most recent call last):
    ...
    keyring.errors.PermissionDeniedError: service 'other' is out of scope
    """

    def __init__(
        self,
        backend: KeyringBackend,
        services: Collection[str] | None,
        usernames: Collection[str] | None,
        actions: Iterable[str],
    ) -> None:
        super().__init__()
        if not isinstance(backend, KeyringBackend):
            msg = "backend must be a KeyringBackend instance"
            raise TypeError(msg)

        allowed_actions = frozenset(actions)
        unknown = allowed_actions - _KNOWN_ACTIONS
        if unknown:
            msg = f"unknown actions: {sorted(unknown)!r}"
            raise ValueError(msg)

        self._backend = backend
        self._services = None if services is None else frozenset(services)
        self._usernames = None if usernames is None else frozenset(usernames)
        self._actions = allowed_actions

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(backend={self._backend!r}, "
            f"services={self._services!r}, usernames={self._usernames!r}, "
            f"actions={sorted(self._actions)!r})"
        )

    @properties.classproperty
    def priority(cls) -> float:
        # A view is never a stand-alone, auto-detected backend.
        msg = "RestrictedKeyring is not viable without a wrapped backend"
        raise RuntimeError(msg)

    @property
    def services(self) -> frozenset[str] | None:
        """The services this view may touch, or None for any service."""
        return self._services

    @property
    def usernames(self) -> frozenset[str] | None:
        """The accounts this view may touch, or None for any account."""
        return self._usernames

    @property
    def actions(self) -> frozenset[str]:
        """The operations this view may perform."""
        return self._actions

    def narrow(
        self,
        services: Collection[str] | None = None,
        usernames: Collection[str] | None = None,
        actions: Iterable[str] | None = None,
    ) -> 'RestrictedKeyring':
        """
        Return a view that can only be more restrictive than this one.

        Each dimension is intersected with the current scope, so a derived
        view can never address a service, account, or action the parent could
        not.

        >>> from keyring.backends.memory import MemoryKeyring
        >>> parent = RestrictedKeyring(
        ...     MemoryKeyring(), services={'a', 'b'},
        ...     usernames=None, actions=WRITE_ACTIONS,
        ... )
        >>> child = parent.narrow(services={'b', 'c'}, actions=READ_ACTIONS)
        >>> child.services == frozenset({'b'})
        True
        >>> child.usernames is None
        True
        >>> child.actions == READ_ACTIONS
        True
        """
        return RestrictedKeyring(
            self._backend,
            services=self._intersect(self._services, services),
            usernames=self._intersect(self._usernames, usernames),
            actions=self._actions if actions is None else self._actions
            & frozenset(actions),
        )

    @staticmethod
    def _intersect(
        current: frozenset[str] | None,
        requested: Collection[str] | None,
    ) -> frozenset[str] | None:
        if requested is None:
            return current
        requested_set = frozenset(requested)
        return requested_set if current is None else current & requested_set

    def _authorize_service(self, action: str, service: str) -> None:
        """Reject a disallowed action or out-of-scope service."""
        if action not in self._actions:
            msg = f"action {action!r} is not allowed"
            raise errors.PermissionDeniedError(msg)
        if self._services is not None and service not in self._services:
            msg = f"service {service!r} is out of scope"
            raise errors.PermissionDeniedError(msg)

    def _authorize(
        self, action: str, service: str, username: str | None
    ) -> None:
        """
        Reject an out-of-scope request before the wrapped backend is touched.
        """
        self._authorize_service(action, service)
        # A username-less credential lookup may return any account, so it is
        # only safe when the view itself is not account-scoped.
        if self._usernames is not None and (
            username is None or username not in self._usernames
        ):
            msg = f"username {username!r} is out of scope"
            raise errors.PermissionDeniedError(msg)

    def get_password(self, service: str, username: str) -> str | None:
        self._authorize(GET_PASSWORD, service, username)
        return self._backend.get_password(service, username)

    def set_password(self, service: str, username: str, password: str) -> None:
        self._authorize(SET_PASSWORD, service, username)
        return self._backend.set_password(service, username, password)

    def delete_password(self, service: str, username: str) -> None:
        self._authorize(DELETE_PASSWORD, service, username)
        return self._backend.delete_password(service, username)

    def get_credential(
        self,
        service: str,
        username: str | None,
    ) -> credentials.Credential | None:
        self._authorize(GET_CREDENTIAL, service, username)
        return self._backend.get_credential(service, username)
