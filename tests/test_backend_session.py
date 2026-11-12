"""
Tests for generation-scoped backend selection.

The thread-barrier tests below deterministically interleave a long-running,
multi-step operation with a global backend switch to prove that:

* an in-flight operation stays bound to the backend generation it started on
  (a credential rotation never reads from A and writes to B);
* a newly started operation observes the new configuration;
* the old backend is retained until every operation pinning it finishes, then
  released -- even when the operation fails or opens nested sessions; and
* backend calls never run while holding the selection lock.
"""

from __future__ import annotations

import threading

import pytest

import keyring
import keyring.core
from keyring import backend, errors
from keyring.compat import properties


class RecordingBackend(backend.KeyringBackend):
    """In-memory backend that records every call against its tag."""

    def __init__(self, tag: str) -> None:
        super().__init__()
        self.tag = tag
        self.store: dict[tuple[str, str], str] = {}
        self.calls: list[str] = []

    @properties.classproperty
    def priority(cls) -> float:
        return 1

    def get_password(self, service: str, username: str) -> str | None:
        self.calls.append('get')
        return self.store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.calls.append('set')
        self.store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.calls.append('delete')
        self.store.pop((service, username), None)


class BlockingBackend(RecordingBackend):
    """Backend whose get blocks until an event is released."""

    def __init__(self, tag: str, gate: threading.Event) -> None:
        super().__init__(tag)
        self._gate = gate

    def get_password(self, service: str, username: str) -> str | None:
        self.calls.append('get-blocking')
        self._gate.wait(timeout=5)
        return super().get_password(service, username)


class FailingBackend(RecordingBackend):
    def get_password(self, service: str, username: str) -> str | None:
        self.calls.append('get-failing')
        raise errors.NoKeyringError("boom")


@pytest.fixture(autouse=True)
def fresh_manager():
    """Give every test an untouched global selection."""
    keyring.core._manager = keyring.core._BackendManager()
    yield
    keyring.core._manager = keyring.core._BackendManager()


def retired_backends():
    return {gen.backend for gen in keyring.core._manager.retired_generations()}


def test_single_step_api_still_works():
    ring = RecordingBackend('only')
    keyring.set_keyring(ring)

    keyring.set_password('svc', 'user', 'secret')
    assert keyring.get_password('svc', 'user') == 'secret'
    keyring.delete_password('svc', 'user')
    assert keyring.get_password('svc', 'user') is None
    assert ring.calls == ['set', 'get', 'delete', 'get']


def test_set_keyring_validates_type():
    with pytest.raises(TypeError):
        keyring.set_keyring(object())  # type: ignore[arg-type]


def test_new_operation_uses_new_configuration():
    old = RecordingBackend('old')
    new = RecordingBackend('new')
    keyring.set_keyring(old)
    keyring.set_keyring(new)

    assert keyring.get_keyring() is new
    keyring.set_password('svc', 'user', 'pw')
    assert new.store == {('svc', 'user'): 'pw'}
    assert old.store == {}
    assert retired_backends() == set()


def test_nested_session_reuses_outer_generation():
    ring = RecordingBackend('ring')
    keyring.set_keyring(ring)

    with keyring.backend_session() as outer:
        with keyring.backend_session() as inner:
            assert inner is outer
            keyring.set_password('svc', 'user', 'pw')
        # inner exit must not release the outer generation
        assert keyring.get_keyring() is ring
    assert retired_backends() == set()


def test_switch_inside_session_does_not_affect_inflight_operation():
    first = RecordingBackend('A')
    second = RecordingBackend('B')
    keyring.set_keyring(first)

    with keyring.backend_session() as pinned:
        assert pinned is first
        keyring.set_keyring(second)

        # the global selection moved on, but this operation stays on A
        assert keyring.core._manager.current is second
        assert keyring.get_keyring() is first
        assert keyring.get_password('svc', 'user') is None
        keyring.set_password('svc', 'user', 'rotated')

    assert keyring.get_keyring() is second
    assert first.store == {('svc', 'user'): 'rotated'}
    assert second.store == {}
    assert retired_backends() == set()


def test_rotation_never_reads_a_writes_b():
    """A read-modify-write stays on one backend across a mid-way switch."""
    first = RecordingBackend('A')
    second = RecordingBackend('B')
    keyring.set_keyring(first)
    keyring.set_password('svc', 'user', 'original')

    def rotate():
        with keyring.backend_session() as ring:
            current = ring.get_password('svc', 'user')
            # switch happens strictly between the read and the write
            barrier.wait()
            ring.set_password('svc', 'user', current + '+rotated')

    barrier = threading.Barrier(2)
    worker = threading.Thread(target=rotate)
    worker.start()
    barrier.wait()  # worker has read from A and is parked before the write
    keyring.set_keyring(second)
    worker.join(timeout=5)

    assert first.store[('svc', 'user')] == 'original+rotated'
    assert second.store == {}
    assert retired_backends() == set()


def test_old_backend_released_only_after_last_operation_finishes():
    first = RecordingBackend('A')
    second = RecordingBackend('B')
    keyring.set_keyring(first)

    entered = threading.Event()
    release = threading.Event()

    def long_operation():
        with keyring.backend_session():
            entered.set()
            release.wait(timeout=5)

    worker = threading.Thread(target=long_operation)
    worker.start()
    entered.wait(timeout=5)

    # retire A while the worker is still inside its session
    keyring.set_keyring(second)
    assert first in retired_backends()

    release.set()
    worker.join(timeout=5)
    assert first not in retired_backends()


def test_failed_operation_still_releases_backend():
    failing = FailingBackend('failing')
    replacement = RecordingBackend('ok')
    keyring.set_keyring(failing)

    entered = threading.Event()
    release = threading.Event()

    def failing_operation():
        with pytest.raises(errors.NoKeyringError):
            with keyring.backend_session() as ring:
                entered.set()
                release.wait(timeout=5)
                ring.get_password('svc', 'user')

    worker = threading.Thread(target=failing_operation)
    worker.start()
    entered.wait(timeout=5)
    keyring.set_keyring(replacement)
    assert failing in retired_backends()

    release.set()
    worker.join(timeout=5)
    assert failing not in retired_backends()
    assert keyring.get_keyring() is replacement


def test_concurrent_sessions_and_switches_keep_refcounts_consistent():
    backends = [RecordingBackend(tag) for tag in ('A', 'B', 'C', 'D')]
    keyring.set_keyring(backends[0])
    stop = threading.Event()
    errors_seen: list[BaseException] = []

    def worker():
        try:
            while not stop.is_set():
                with keyring.backend_session() as ring:
                    ring.get_password('svc', 'user')
                    ring.set_password('svc', 'user', 'pw')
        except BaseException as exc:  # pragma: no cover - diagnostic only
            errors_seen.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()

    for ring in backends[1:] * 5:
        keyring.set_keyring(ring)

    stop.set()
    for thread in threads:
        thread.join(timeout=5)

    assert not errors_seen
    assert keyring.get_keyring() is backends[-1]
    # every pinned generation has been released again
    assert retired_backends() == set()


def test_backend_call_does_not_hold_selection_lock():
    """
    A blocked backend call must not prevent another thread from switching the
    global selection -- proving no global lock spans the backend invocation.
    """
    gate = threading.Event()
    blocking = BlockingBackend('slow', gate)
    replacement = RecordingBackend('fast')
    keyring.set_keyring(blocking)

    started = threading.Event()

    def slow_call():
        started.set()
        keyring.get_password('svc', 'user')

    worker = threading.Thread(target=slow_call)
    worker.start()
    started.wait(timeout=5)

    # If the backend call held the lock, this would block until the timeout.
    switched = threading.Event()

    def switch():
        keyring.set_keyring(replacement)
        switched.set()

    switcher = threading.Thread(target=switch)
    switcher.start()
    assert switched.wait(timeout=2)

    gate.set()
    worker.join(timeout=5)
    switcher.join(timeout=5)
    assert keyring.get_keyring() is replacement
