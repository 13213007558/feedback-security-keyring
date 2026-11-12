Added ``keyring.backend_session()`` to pin a single backend generation for a
multi-step operation. A global ``set_keyring()`` switch now takes effect for
new operations while operations already in flight keep using the backend they
started with; an old backend is released only once every operation pinning it
finishes. Single-step calls behave as before and backend calls no longer share
a lock that could block on slow I/O.
