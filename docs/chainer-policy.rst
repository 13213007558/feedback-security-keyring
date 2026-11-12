Chainer credential-resolution policy
====================================

``ChainerBackend`` walks candidate backends in priority order.  The
historical implementation continues to the next backend only when a
backend returns ``None``; every exception stops the walk.  That behavior
is still the default, but it is now expressed as one row set in an
executable decision table.

Why this is a security decision
-------------------------------

"Backend unavailable" is not one condition:

- **Entry missing** means the backend answered and has nothing.  Trying
  the next backend is the original purpose of chaining.
- **Permission denied** means the caller's identity is not allowed to
  read the entry.  Falling through can turn a revoked identity into a
  credential read from a less-protected store.
- **Backend locked** means the store is temporarily unreadable.  Falling
  through can serve a replica's older copy of a secret that was just
  rotated.
- **Unknown error** covers transport failures, malformed data, and
  backend bugs.  Treating it as "missing" silently converts an outage
  into a fallback read.

Decision table
--------------

Columns are the four observable outcomes.  Cells are actions.

==================  =========  ===========  =========  =============
Policy              Missing    Denied       Locked     Unknown error
==================  =========  ===========  =========  =============
chainer-default     continue   propagate    propagate  propagate
strict-source       not-found  deny         deny       deny
concealed-source    not-found  not-found    not-found  not-found
redundant-fallback  continue   deny         continue   continue
==================  =========  ===========  =========  =============

- ``continue``: query the next backend.
- ``not-found``: stop and return ``None``.
- ``propagate``: stop and re-raise the backend's exception (legacy
  compatibility).
- ``deny``: stop and raise ``keyring.errors.AccessDenied``.

``chainer-default`` is the default and preserves existing behavior.  It
is not the most secure choice, but changing it silently would break
applications that rely on exception types.

``strict-source`` binds every read to one backend named by ``source``.
It never consults a replica.  A missing entry on the source is final,
even when a lower-priority backend still holds an old copy.

``concealed-source`` is ``strict-source`` plus a public-result
concealment: denial, lock, and unknown failures are all reported as
"not found".  Use it when the caller is untrusted and must not be able to
probe account existence.  The audit event still records the true outcome
and reason.

``redundant-fallback`` is the availability-first option: a lock or
unknown failure may consult a replica, but a denial never may.  It is
appropriate only when all participating backends have equivalent
authorization and the replica is an acceptable source of a possibly
stale secret.  It is not appropriate for rotating credentials, where an
old copy is a security failure rather than a convenience.

Stale-copy scenario
-------------------

The in-memory helpers in ``keyring.testing.memory`` model the risk.
``StaleReplica`` snapshots a source once and then keeps serving that
copy:

.. code-block:: python

    from keyring.backends.chainer import ChainerBackend
    from keyring.testing.memory import MemoryBackend, StaleReplica

    class Vault(MemoryBackend):
        source_id = 'vault'
        priority = 5

    class Replica(StaleReplica):
        source_id = 'replica'
        priority = 1

    vault, replica = Vault(), Replica()
    vault.set_password('svc', 'alice', 'old-password')
    replica.snapshot_from(vault)

    vault.set_password('svc', 'alice', 'rotated-password')
    replica.get_password('svc', 'alice')       # 'old-password'
    vault.get_password('svc', 'alice')         # 'rotated-password'

If the source entry is then deleted or becomes unreadable, the default
chainer happily returns the replica's old password.  ``strict-source``
returns ``None`` instead.  The full executable example is
``tests/backends/test_chainer_policy.py::test_stale_copy_demo``.

Using a policy
--------------

.. code-block:: python

    from keyring.backends.chainer import ChainerBackend

    backend = ChainerBackend('strict-source').with_properties(source='vault')

``source`` must match a backend's ``source_id`` (or ``label``, or its
module-qualified class name).  A stable, explicitly declared identity is
required: a class name is a poor identity if the class is renamed or
vendored twice.  If no candidate matches, the read is denied rather than
silently falling back.

Diagnostics
-----------

Public denials raise ``AccessDenied``, which contains only a correlation
id.  The audit event delivered to ``policy.audit`` contains the
correlation id, policy name, outcome, action, reason, and backend
identity.  It never contains the username, service, password, or the
backend's exception message.  The default sink logs at ``WARNING`` for
denials, locks, and errors, and at ``DEBUG`` otherwise.

The backend's message is intentionally excluded because it is often
copied from an external service and may say things like "user alice does
not exist".  A caller that can tell denial from absence can use that
difference to enumerate accounts.

Limitations
-----------

- This module is an interface prototype.  Selecting a policy is explicit;
  automatic backend discovery keeps the legacy behavior.
- ``set_password`` and ``delete_password`` still use the historical
  write-to-first-blocking-backend loop.  Write policy is not part of this
  prototype.
- Source identity is trusted configuration.  A backend that lies about
  ``source_id`` defeats binding; only install backends you trust.
- Audit events are emitted through ``logging`` by default.  A deployment
  that needs tamper-evident audit should supply its own ``audit`` sink.
