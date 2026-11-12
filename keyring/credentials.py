from __future__ import annotations

import abc
import os
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING

from . import errors

if TYPE_CHECKING:
    from .backend import KeyringBackend


class Credential(metaclass=abc.ABCMeta):
    """Abstract class to manage credentials"""

    @abc.abstractproperty
    def username(self) -> str: ...

    @abc.abstractproperty
    def password(self) -> str: ...

    def _vars(self) -> dict[str, str]:
        return dict(username=self.username, password=self.password)


class SimpleCredential(Credential):
    """Simple credentials implementation"""

    def __init__(self, username: str, password: str):
        self._username = username
        self._password = password

    @property
    def username(self) -> str:
        return self._username

    @property
    def password(self) -> str:
        return self._password


class AnonymousCredential(SimpleCredential):
    def __init__(self, password: str):
        self._password = password

    @property
    def username(self) -> str:
        raise ValueError("Anonymous credential has no username")

    def _vars(self) -> dict[str, str]:
        return dict(password=self.password)


class EnvironCredential(Credential):
    """
    Source credentials from environment variables.

    Actual sourcing is deferred until requested.

    Supports comparison by equality.

    >>> e1 = EnvironCredential('a', 'b')
    >>> e2 = EnvironCredential('a', 'b')
    >>> e3 = EnvironCredential('a', 'c')
    >>> e1 == e2
    True
    >>> e2 == e3
    False
    """

    def __init__(self, user_env_var: str, pwd_env_var: str):
        self.user_env_var = user_env_var
        self.pwd_env_var = pwd_env_var

    def __eq__(self, other: object) -> bool:
        return vars(self) == vars(other)

    def _get_env(self, env_var: str) -> str:
        """Helper to read an environment variable"""
        value = os.environ.get(env_var)
        if not value:
            raise ValueError(f'Missing environment variable:{env_var}')
        return value

    @property
    def username(self) -> str:
        return self._get_env(self.user_env_var)

    @property
    def password(self) -> str:
        return self._get_env(self.pwd_env_var)


# A callable that returns the backing credential when dereferenced. Returning
# ``None`` means no credential is available for the requested service.
CredentialLoader = Callable[[], 'Credential | None']


class ScopedCredential:
    """A restricted handle to a credential that only resolves inside a scope.

    The handle is safe to pass through the rest of an application and to log:
    it never stores the secret and cannot produce it. The underlying credential
    is fetched from the backend only when :meth:`resolve` is called while a
    :class:`credential_scope` is open, so dereferencing happens at the single
    point that needs the plaintext (for example an external authentication
    call).

    Once the scope exits the handle is permanently invalidated; any later
    :meth:`resolve` raises :class:`~keyring.errors.CredentialScopeError` and no
    further backend reads occur.

    Both :func:`repr` and :func:`str` describe the handle without revealing any
    credential material::

        >>> sc = ScopedCredential('service', 'user', lambda: None)
        >>> 'service' in repr(sc) and 'user' in repr(sc)
        True
        >>> sc.resolve()
        Traceback (most recent call last):
        ...
        keyring.errors.CredentialScopeError: ...
    """

    def __init__(
        self,
        service: str,
        username: str | None,
        loader: CredentialLoader,
    ):
        self._service = service
        self._username = username
        self._loader = loader
        self._lock = threading.RLock()
        self._scope: credential_scope | None = None
        self._closed = False

    @property
    def service(self) -> str:
        """The service this handle is bound to."""
        return self._service

    @property
    def username(self) -> str | None:
        """The requested username, if one was supplied."""
        return self._username

    @property
    def active(self) -> bool:
        """Whether the handle may currently be dereferenced."""
        with self._lock:
            return self._scope is not None and self._scope.is_active

    def _bind(self, scope: credential_scope) -> None:
        with self._lock:
            if self._closed:
                raise errors.CredentialScopeError(
                    'Scoped credential cannot be re-opened'
                )
            self._scope = scope

    def _invalidate(self) -> None:
        with self._lock:
            self._closed = True
            self._scope = None

    def resolve(self) -> Credential | None:
        """Dereference the handle, reading the backend once per call.

        Only valid while the bound :class:`credential_scope` is open. The
        returned :class:`Credential` exposes the plaintext and should not be
        retained beyond the immediate use. Raises
        :class:`~keyring.errors.CredentialScopeError` outside of the scope;
        backend failures propagate to the caller.
        """
        with self._lock:
            scope = self._scope
            if self._closed or scope is None or not scope.is_active:
                raise errors.CredentialScopeError(
                    'Scoped credential was dereferenced outside of its scope'
                )
            return self._loader()

    def __repr__(self) -> str:
        state = 'active' if self.active else 'inactive'
        return (
            f'{type(self).__name__}(service={self._service!r}, '
            f'username={self._username!r}, {state})'
        )

    __str__ = __repr__


class credential_scope:
    """Context manager that defines when scoped credentials may resolve.

    Obtain handles with :meth:`get`; they remain dereferenceable only while
    the ``with`` block is open, from any thread. On exit every handle issued
    by the scope is invalidated and can never be re-activated.

    A scope is single-use: re-entering it raises
    :class:`~keyring.errors.CredentialScopeError`.
    """

    def __init__(self, backend: KeyringBackend):
        self._backend = backend
        self._lock = threading.RLock()
        self._depth = 0
        self._closed = False
        self._handles: list[ScopedCredential] = []

    @property
    def is_active(self) -> bool:
        """Whether the scope is currently entered."""
        with self._lock:
            return self._depth > 0

    def get(self, service: str, username: str | None = None) -> ScopedCredential:
        """Return a handle bound to this scope for the given service."""
        with self._lock:
            if self._closed:
                raise errors.CredentialScopeError(
                    'Cannot issue a credential from an exhausted scope'
                )
        handle = self._backend.get_scoped_credential(service, username, self)
        handle._bind(self)
        with self._lock:
            self._handles.append(handle)
        return handle

    def __enter__(self) -> credential_scope:  # noqa: PYI034
        with self._lock:
            if self._closed:
                raise errors.CredentialScopeError(
                    'Credential scope cannot be re-entered'
                )
            self._depth += 1
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        with self._lock:
            self._depth -= 1
            if self._depth == 0:
                self._closed = True
                handles, self._handles = self._handles, []
        for handle in handles:
            handle._invalidate()
