"""Reproduces the id()-based cache key bug in pubsub/client.py.

VULNERABILITY
=============
get_publisher_client() uses id(credentials) as the cache key (client.py:62).
id() is the object's memory address.  When credentials are GC'd that address
is freed, but the 30-minute cache entry survives.  If a new credentials object
lands at the same address, the cache returns the wrong (stale) client.

HOW THE BUG IS TRIGGERED HERE
==============================
1. Patch pubsub_v1.PublisherClient with a plain function so no real GCP call
   is made and — crucially — no framework records a reference to creds_a.
2. Call get_publisher_client(credentials=creds_a) → cache[addr_a] = client_a.
3. del creds_a → refcount hits 0, memory freed immediately (no cycles).
4. creds_b = FakeCredentials() → CPython's LIFO free-list hands back addr_a.
5. get_publisher_client(credentials=creds_b) → cache hit → returns client_a.
   User B now holds User A's GCP PublisherClient.
"""

import sys

from google.adk.tools.pubsub import client as pubsub_client
from google.cloud import pubsub_v1


class FakeCredentials:
  # __slots__ keeps the object layout fixed regardless of Python version,
  # ensuring pymalloc uses a consistent size class and addr_a is reliably
  # returned to the LIFO free-list on del.
  __slots__ = ("token",)

  def __init__(self, token):
    self.token = token


class FakeClient:
  """Stand-in for pubsub_v1.PublisherClient."""

  def __init__(self, name, credentials):
    self.name = name
    # Capture the token at client-creation time — mirrors how a real
    # PublisherClient holds onto credentials for signing requests.
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
  # Patch PublisherClient so no real GCP call is made.
  pubsub_v1.PublisherClient = _make_client

  try:
    # Prime pymalloc so addr_a lands in an existing pool, not a fresh arena.
    _warmup = [FakeCredentials("warmup") for _ in range(64)]
    del _warmup

    # User A
    creds_a = FakeCredentials(token="secret-token-user-A")
    addr_a = id(creds_a)
    client_a = pubsub_client.get_publisher_client(credentials=creds_a)
    print(f"[User A] token={creds_a.token}  address={hex(addr_a)}  "
          f"client={client_a.name} (bound to token={client_a.credentials_token})")

    # Nothing else holds a reference to creds_a, so del frees it immediately.
    del creds_a

    # CPython LIFO free-list: next same-size allocation gets addr_a back.
    creds_b = FakeCredentials(token="secret-token-user-B")
    print(f"[User B] token={creds_b.token}  address={hex(id(creds_b))}")

    if id(creds_b) != addr_a:
      print("FAIL: address not reused (unexpected on CPython).")
      sys.exit(1)

    client_b = pubsub_client.get_publisher_client(credentials=creds_b)
    print(f"[User B] client={client_b.name} (bound to token={client_b.credentials_token})")

  finally:
    pubsub_client.cleanup_clients()

  if client_b is client_a:
    print("\nBUG CONFIRMED: User B got User A's PublisherClient.")
    print(f"  Client is bound to token='{client_b.credentials_token}' — User A's secret.")
    print(f"  User B's own token ('{creds_b.token}') was never used.")
    sys.exit(0)
  else:
    print("\nFAIL: cache returned a different client (unexpected).")
    sys.exit(1)


if __name__ == "__main__":
  main()
