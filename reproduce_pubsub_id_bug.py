"""Reproduces the id()-based cache key bug in pubsub/client.py.

VULNERABILITY
=============
get_publisher_client() / get_subscriber_client() use id(credentials) as
the cache key (client.py:62, 123).  id() is the object's memory address.
When credentials are garbage-collected, that address is freed — but the
cache entry lives for 30 minutes.  If a new credentials object lands at
the same address, the cache returns the wrong (stale) client.

HOW THE BUG IS TRIGGERED HERE
==============================
1. Call get_publisher_client(credentials=creds_a)  → cache[addr_a] = client_a
2. Reset the mock so it drops its internal reference to creds_a.
   (MagicMock records call_args; without reset_mock() del creds_a is a no-op.)
3. del creds_a  → refcount hits 0, memory freed immediately (no cycles).
4. creds_b = FakeCredentials()  → CPython's LIFO free-list hands back addr_a.
5. get_publisher_client(credentials=creds_b)  → cache hit → returns client_a.
   User B now holds User A's GCP PublisherClient.
"""

import sys
from unittest import mock

from google.adk.tools.pubsub import client as pubsub_client
from google.cloud import pubsub_v1


class FakeCredentials:
  pass


def main():
  clients = []

  def make_client(*a, **kw):
    m = mock.MagicMock(name=f"Client#{len(clients) + 1}")
    clients.append(m)
    return m

  with mock.patch.object(pubsub_v1, "PublisherClient", side_effect=make_client) as mock_pub:
    # Prime pymalloc so addr_a is in an existing pool, not a fresh arena.
    _warmup = [FakeCredentials() for _ in range(64)]
    del _warmup

    # User A
    creds_a = FakeCredentials()
    addr_a = id(creds_a)
    client_a = pubsub_client.get_publisher_client(credentials=creds_a)
    print(f"[User A] address={hex(addr_a)}  client={client_a.name}")

    # Release the mock's hidden reference to creds_a, then free creds_a.
    mock_pub.reset_mock()
    del creds_a

    # User B — CPython LIFO gives back addr_a immediately.
    creds_b = FakeCredentials()
    print(f"[User B] address={hex(id(creds_b))}")

    if id(creds_b) != addr_a:
      print("FAIL: address not reused (unexpected on CPython).")
      sys.exit(1)

    client_b = pubsub_client.get_publisher_client(credentials=creds_b)
    print(f"[User B] client={client_b.name}")

  pubsub_client.cleanup_clients()

  if client_b is client_a:
    print("\nBUG CONFIRMED: User B got User A's PublisherClient.")
    print("User B would publish using User A's GCP credentials.")
    sys.exit(0)
  else:
    print("\nFAIL: cache returned a different client (unexpected).")
    sys.exit(1)


if __name__ == "__main__":
  main()
