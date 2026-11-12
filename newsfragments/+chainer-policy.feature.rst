``ChainerBackend`` now accepts a credential-resolution policy.  The
historical behavior remains the default; ``strict-source``,
``concealed-source``, and ``redundant-fallback`` are available for callers
that need explicit handling of missing entries, permission denials, locked
backends, and unknown errors.  Denials raise
``keyring.errors.AccessDenied`` with only a correlation id; the matching
diagnostic event records the reason without exposing account, service, or
credential data.  See ``docs/chainer-policy.rst`` for the decision table and
trade-offs.
