"""
Core API functions and initialization routines.
"""

from __future__ import annotations

import configparser
import contextlib
import contextvars
import dataclasses
import logging
import os
import sys
import threading
import typing

from . import backend, credentials
from .backends import fail
from .util import platform_ as platform

LimitCallable = typing.Callable[[backend.KeyringBackend], bool]

log = logging.getLogger(__name__)

# Retained for backwards compatibility with code that inspected the module
# global; ``_manager`` below is the source of truth and keeps this in step.
_keyring_backend: backend.KeyringBackend | None = None


def _sync_legacy_backend(keyring: backend.KeyringBackend) -> None:
    global _keyring_backend
    _keyring_backend = keyring


@dataclasses.dataclass
class _Generation:
    """
    A single, immutable selection of a backend.

    Multi-step operations pin a generation for their whole lifetime, so a
    credential rotation never reads from one backend and writes to another
    even while the global selection is changing. ``references`` counts the
    operations currently pinning the generation; a retired generation is only
    released once it drops back to zero.
    """

    backend: backend.KeyringBackend
    number: int
    references: int = 0


class _BackendManager:
    """
    Owns the global backend selection and its operation-scoped lifetimes.

    The selection is split into two concerns:

    * the *current* generation, swapped wholesale by :func:`set_keyring`, and
    * the *active* generation for an operation, which is inherited by nested
      calls via a :class:`contextvars.ContextVar`.

    Only short, in-memory bookkeeping runs under ``_lock``. Backend calls
    themselves (which may block on I/O) never hold it, so a slow backend can
    not stall an unrelated selection or another thread.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._current: _Generation | None = None
        self._retired: list[_Generation] = []
        self._active = contextvars.ContextVar(
            'keyring_active_generation', default=None
        )

    @property
    def current(self) -> backend.KeyringBackend | None:
        with self._lock:
            return self._current.backend if self._current else None

    @property
    def active(self) -> backend.KeyringBackend | None:
        """The backend an enclosing session pinned, if any."""
        generation = self._active.get()
        return generation.backend if generation is not None else None

    def replace(self, keyring: backend.KeyringBackend) -> None:
        """
        Install ``keyring`` as the new global selection.

        The previous generation is retired rather than dropped, so operations
        already in flight keep using the backend they started with.
        """
        with self._lock:
            previous = self._current
            number = previous.number + 1 if previous else 1
            self._current = _Generation(backend=keyring, number=number)
            if previous is not None and previous.references:
                self._retired.append(previous)
            self._sweep()
            _sync_legacy_backend(keyring)

    def acquire(self) -> _Generation:
        """
        Return the generation an operation must use, pinning it.

        Nested calls inherit the generation already pinned by an enclosing
        :func:`backend_session`; otherwise the current global generation is
        pinned. The reference is released by :meth:`release`.
        """
        pinned = self._active.get()
        if pinned is not None:
            return pinned
        with self._lock:
            if self._current is None:
                self._current = _Generation(
                    backend=_detect_backend(), number=1
                )
                _sync_legacy_backend(self._current.backend)
            generation = self._current
            generation.references += 1
            return generation

    def bind(self, generation: _Generation) -> typing.Any:
        """Make ``generation`` the inherited one for nested calls."""
        return self._active.set(generation)

    def unbind(self, token: typing.Any) -> None:
        """Undo a :meth:`bind`."""
        self._active.reset(token)

    def release(self, generation: _Generation) -> None:
        """Drop a reference previously taken with :meth:`acquire`."""
        with self._lock:
            generation.references -= 1
            self._sweep()

    def _sweep(self) -> None:
        """Forget retired generations no operation is pinning."""
        self._retired = [
            generation
            for generation in self._retired
            if generation.references
        ]

    def retired_generations(self) -> tuple[_Generation, ...]:
        """Retired generations still pinned by in-flight operations."""
        with self._lock:
            return tuple(self._retired)


_manager = _BackendManager()


@contextlib.contextmanager
def backend_session() -> typing.Iterator[backend.KeyringBackend]:
    """
    Pin one backend generation for the duration of a (possibly multi-step)
    operation.

    Every keyring call inside the block resolves to the same backend even if
    another thread calls :func:`set_keyring` in the meantime. Nested sessions
    reuse the generation pinned by the outermost session rather than taking a
    new one, so helper functions can open their own session safely::

        with keyring.backend_session() as ring:
            secret = ring.get_password(service, user)
            ring.set_password(service, user, rotate(secret))

    The single-step :func:`get_password`/ :func:`set_password`/ ... helpers
    open an implicit session around each call, so ordinary use is unchanged.
    """
    generation = _manager.acquire()
    token = _manager.bind(generation)
    try:
        yield generation.backend
    finally:
        _manager.unbind(token)
        _manager.release(generation)


def set_keyring(keyring: backend.KeyringBackend) -> None:
    """Set current keyring backend."""
    if not isinstance(keyring, backend.KeyringBackend):
        raise TypeError("The keyring must be an instance of KeyringBackend")
    _manager.replace(keyring)


def get_keyring() -> backend.KeyringBackend:
    """Get current keyring backend."""
    active = _manager.active
    if active is not None:
        return active
    if _manager.current is None:
        init_backend()
    return typing.cast(backend.KeyringBackend, _manager.current)


def disable() -> None:
    """
    Configure the null keyring as the default.

    >>> fs = getfixture('fs')
    >>> disable()
    >>> disable()
    Traceback (most recent call last):
    ...
    RuntimeError: Refusing to overwrite...
    """
    root = platform.config_root()
    try:
        os.makedirs(root)
    except OSError:
        pass
    filename = os.path.join(root, 'keyringrc.cfg')
    if os.path.exists(filename):
        msg = f"Refusing to overwrite {filename}"
        raise RuntimeError(msg)
    with open(filename, 'w', encoding='utf-8') as file:
        file.write('[backend]\ndefault-keyring=keyring.backends.null.Keyring')


def get_password(service_name: str, username: str) -> str | None:
    """Get password from the specified service."""
    with backend_session() as keyring:
        return keyring.get_password(service_name, username)


def set_password(service_name: str, username: str, password: str) -> None:
    """Set password for the user in the specified service."""
    with backend_session() as keyring:
        keyring.set_password(service_name, username, password)


def delete_password(service_name: str, username: str) -> None:
    """Delete the password for the user in the specified service."""
    with backend_session() as keyring:
        keyring.delete_password(service_name, username)


def get_credential(
    service_name: str, username: str | None
) -> credentials.Credential | None:
    """Get a Credential for the specified service."""
    with backend_session() as keyring:
        return keyring.get_credential(service_name, username)


def recommended(backend) -> bool:
    return backend.priority >= 1


def init_backend(limit: LimitCallable | None = None):
    """
    Load a detected backend.
    """
    set_keyring(_detect_backend(limit))


def _detect_backend(limit: LimitCallable | None = None):
    """
    Return a keyring specified in the config file or infer the best available.

    Limit, if supplied, should be a callable taking a backend and returning
    True if that backend should be included for consideration.
    """

    # save the limit for the chainer to honor
    backend._limit = limit
    return (
        load_env()
        or load_config()
        or max(
            # all keyrings passing the limit filter
            filter(limit, backend.get_all_keyring()),
            default=fail.Keyring(),
            key=backend.by_priority,
        )
    )


def _load_keyring_class(keyring_name: str) -> type[backend.KeyringBackend]:
    """
    Load the keyring class indicated by name.

    These popular names are tested to ensure their presence.

    >>> popular_names = [
    ...      'keyring.backends.Windows.WinVaultKeyring',
    ...      'keyring.backends.macOS.Keyring',
    ...      'keyring.backends.kwallet.DBusKeyring',
    ...      'keyring.backends.SecretService.Keyring',
    ...  ]
    >>> list(map(_load_keyring_class, popular_names))
    [...]
    """
    module_name, _, class_name = keyring_name.rpartition('.')
    __import__(module_name)
    module = sys.modules[module_name]
    return getattr(module, class_name)


def load_keyring(keyring_name: str) -> backend.KeyringBackend:
    """
    Load the specified keyring by name (a fully-qualified name to the
    keyring, such as 'keyring.backends.file.PlaintextKeyring')
    """
    class_ = _load_keyring_class(keyring_name)
    # invoke the priority to ensure it is viable, or raise a RuntimeError
    class_.priority  # noqa: B018
    return class_()


def load_env() -> backend.KeyringBackend | None:
    """Load a keyring configured in the environment variable."""
    try:
        return load_keyring(os.environ['PYTHON_KEYRING_BACKEND'])
    except KeyError:
        return None


def _config_path():
    return platform.config_root() / 'keyringrc.cfg'


def _ensure_path(path):
    if not path.exists():
        raise FileNotFoundError(path)
    return path


def load_config() -> backend.KeyringBackend | None:
    """Load a keyring using the config file in the config root."""

    config = configparser.RawConfigParser()
    try:
        config.read(_ensure_path(_config_path()), encoding='utf-8')
    except FileNotFoundError:
        return None
    _load_keyring_path(config)

    # load the keyring class name, and then load this keyring
    try:
        if config.has_section("backend"):
            keyring_name = config.get("backend", "default-keyring").strip()
        else:
            return None

    except (configparser.NoOptionError, ImportError):
        logger = logging.getLogger('keyring')
        logger.warning(
            "Keyring config file contains incorrect values.\n"
            + f"Config file: {_config_path()}"
        )
        return None

    return load_keyring(keyring_name)


def _load_keyring_path(config: configparser.RawConfigParser) -> None:
    "load the keyring-path option (if present)"
    try:
        path = config.get("backend", "keyring-path").strip()
        sys.path.insert(0, os.path.expanduser(path))
    except (configparser.NoOptionError, configparser.NoSectionError):
        pass
