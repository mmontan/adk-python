"""Verifies the id()-based cache key fix under actual address reuse.

THE BUG (before fix)
====================
get_publisher_client() used id(credentials) as the cache key.  id() returns
the object's memory address.  If credentials_a is freed and credentials_b
lands at the same address, the 30-minute cache returns the wrong (stale)
client — leaking one user's GCP identity to another.

THE FIX
=======
weakref.finalize() is registered when storing a cache entry.  When credentials
are GC'd the finalizer fires immediately (CPython: same thread, synchronously)
and removes the entry before the memory can be reused.

WHAT THIS SCRIPT CHECKS
========================
1. Cache entry is evicted when credentials_a is freed.
2. A new object at the SAME ADDRESS gets a fresh client — not the stale one.

HOW ADDRESS REUSE IS FORCED
=============================
After del creds_a, addr_a sits somewhere in CPython's LIFO free-list for the
FakeCredentials size class.  Items ahead of it (freed during the finalizer
callback's internal bookkeeping) are consumed first.  We drain those by
allocating and *keeping alive* one object at a time until we land on addr_a.
"""

import sys

from google.adk.tools.pubsub import client as pubsub_client
from google.cloud import pubsub_v1

_MAX_PROBE = 500


class FakeCredentials:
  # "__weakref__" lets weakref.finalize() observe GC — mirrors real
  # google.auth credentials which are weakly referenceable.
  __slots__ = ("token", "__weakref__")

  def __init__(self, token):
    self.token = token


class FakeClient:
  """Stand-in for pubsub_v1.PublisherClient."""

  def __init__(self, name, credentials):
    self.name = name
    self.credentials_token = credentials.token

  class transport:
    @staticmethod
    def close():
      pass


_client_counter = 0


def _make_client(*args, **kwargs):
  global _client_counter
  _client_counter += 1
  return FakeClient(f"Client#{_client_counter}", kwargs["credentials"])


def main():
  pubsub_v1.PublisherClient = _make_client

  try:
    # Prime pymalloc pools for the FakeCredentials size class so creds_a
    # comes from an existing pool (not a freshly mapped arena).
    _warmup = [FakeCredentials(f"w{i}") for i in range(256)]
    del _warmup

    # ------------------------------------------------------------------ #
    # Step 1 — User A acquires a client; cache entry is created.          #
    # ------------------------------------------------------------------ #
    creds_a = FakeCredentials(token="secret-token-user-A")
    addr_a = id(creds_a)
    cache_key = (addr_a, None, id(None))

    client_a = pubsub_client.get_publisher_client(credentials=creds_a)
    print(f"[User A] addr={hex(addr_a)}  token={creds_a.token!r}  "
          f"client={client_a.name}")

    entry_before = cache_key in pubsub_client._publisher_client_cache
    print(f"  Cache entry created : "
          f"{'YES (expected)' if entry_before else 'NO  — unexpected!'}")

    # ------------------------------------------------------------------ #
    # Step 2 — Free User A's credentials; finalizer must evict the entry. #
    # ------------------------------------------------------------------ #
    del creds_a  # refcount → 0 → GC → finalizer fires synchronously

    evicted = cache_key not in pubsub_client._publisher_client_cache
    print(f"  Cache entry evicted : "
          f"{'YES (fix works!)' if evicted else 'NO  — BUG: entry survived GC!'}")

    # ------------------------------------------------------------------ #
    # Step 3 — Obtain a FakeCredentials object AT addr_a.                 #
    #                                                                      #
    # After del creds_a, addr_a is somewhere in CPython's LIFO free-list  #
    # for this size class.  Items freed by the finalizer's internal        #
    # bookkeeping may sit ahead of it.  We drain those by allocating and   #
    # *keeping alive* each non-matching object until the allocator hands   #
    # back addr_a.                                                          #
    # ------------------------------------------------------------------ #
    creds_b = None
    drains = []
    for i in range(_MAX_PROBE):
      candidate = FakeCredentials(token="secret-token-user-B")
      if id(candidate) == addr_a:
        creds_b = candidate
        break
      drains.append(candidate)   # keep alive — don't return to free-list
    del drains                   # release after creds_b is secured

    if creds_b is None:
      print(f"\nFAIL: addr_a not reused within {_MAX_PROBE} allocations.")
      sys.exit(1)

    print(f"\n[User B] addr={hex(id(creds_b))}  token={creds_b.token!r}")
    print(f"  Address matches User A's: {hex(id(creds_b))} == {hex(addr_a)}  ← reuse confirmed")

    # ------------------------------------------------------------------ #
    # Step 4 — User B requests a client.  Without the fix this would      #
    # return client_a (stale, bound to User A's token).  With the fix     #
    # the cache is empty so a fresh client is created.                    #
    # ------------------------------------------------------------------ #
    client_b = pubsub_client.get_publisher_client(credentials=creds_b)
    print(f"  client={client_b.name}  "
          f"bound to token={client_b.credentials_token!r}")

  finally:
    pubsub_client.cleanup_clients()

  # ------------------------------------------------------------------ #
  # Summary                                                              #
  # ------------------------------------------------------------------ #
  print()
  passed = evicted and (client_b is not client_a)

  if client_b is client_a:
    print("BUG PRESENT: User B got User A's stale PublisherClient.")
    print(f"  Stale client is bound to token={client_b.credentials_token!r}"
          f" — User A's secret.")
  elif not evicted:
    print("BUG PRESENT: Cache entry was not evicted on GC.")
  else:
    print("FIX VERIFIED: address reused, cache evicted, User B got a fresh client.")
    print(f"  id(creds_a) == id(creds_b) == {hex(addr_a)}")
    print(f"  client_a={client_a.name} (token={client_a.credentials_token!r})")
    print(f"  client_b={client_b.name} (token={client_b.credentials_token!r})")
    print("  No identity leak.")

  sys.exit(0 if passed else 1)


if __name__ == "__main__":
  main()
