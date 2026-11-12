Added ``keyring.backends.restricted.RestrictedKeyring``, a backend view that
limits another backend to an explicit set of services, accounts, and actions.
Unauthorized operations raise ``keyring.errors.PermissionDeniedError`` before
the wrapped backend is reached, and derived views (``narrow``) can only shrink
the scope. An in-memory ``keyring.backends.memory.MemoryKeyring`` is provided
for testing and composition.
