# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Reproduces the id()-based cache key bug in pubsub/client.py.

The bug: get_publisher_client() / get_subscriber_client() cache Pub/Sub
clients using id(credentials) as part of the cache key. id() returns the
memory address of a Python object. Once an object is garbage-collected its
address can be reused by the next allocation. The cache TTL is 30 minutes,
so a stale entry keyed on a freed address persists long after the original
credentials object is gone.

If User B's credentials object lands at the same memory address as User A's
(already GC'd) credentials, the cache returns User A's client to User B,
meaning User B publishes Pub/Sub messages using User A's GCP identity.

Key insight: FakeCredentials has no __del__ and no reference cycles, so
CPython frees the memory immediately when refcount drops to zero (del).
CPython's pymalloc uses a LIFO free-list, so the very next allocation of
the same size gets the just-freed address. The previous script failed
because the MagicMock records call args (keeping creds_a alive) and the
scanning loop kept recycling the candidate slot via LIFO instead of
revisiting addr_a.

No real GCP credentials or network access are required.
"""

from __future__ import annotations

import sys
from unittest import mock

from google.adk.tools.pubsub import client as pubsub_client
from google.cloud import pubsub_v1


class FakeCredentials:
  """Minimal stand-in for google.auth.credentials.Credentials."""

  pass


# ---------------------------------------------------------------------------
# Publisher bug demo
# ---------------------------------------------------------------------------


def demo_publisher_bug() -> bool:
  """Return True if the cross-user cache hit was confirmed."""
  call_count = 0
  clients_created: list[mock.MagicMock] = []

  def publisher_side_effect(*args, **kwargs):
    nonlocal call_count
    call_count += 1
    m = mock.MagicMock(name=f"PublisherClient_#{call_count}")
    clients_created.append(m)
    return m

  # Capture the mock so we can reset it (releasing its reference to creds_a).
  with mock.patch.object(
      pubsub_v1,
      "PublisherClient",
      side_effect=publisher_side_effect,
  ) as mock_pub:
    # Warmup: prime pymalloc's pool for FakeCredentials-sized objects so
    # addr_a won't fall in a freshly-mapped arena page.
    _warmup = [FakeCredentials() for _ in range(64)]
    del _warmup

    # --- User A ---
    creds_a = FakeCredentials()
    addr_a = id(creds_a)
    print(f"[User A] credentials at: {hex(addr_a)}")

    client_a = pubsub_client.get_publisher_client(credentials=creds_a)
    print(f"[User A] Got publisher client: {client_a}")

    # The mock records call_args internally, keeping creds_a alive.
    # Reset the mock so it drops its reference — otherwise del creds_a
    # would not actually free the memory.
    mock_pub.reset_mock()

    # Now del creds_a truly drops the refcount to zero.
    # FakeCredentials has no __del__ and no cycles, so CPython frees
    # the memory immediately (reference counting, not GC).
    del creds_a

    # CPython's pymalloc free-list is LIFO: the next allocation of the
    # same size class gets addr_a back.  No intervening print/loop/range
    # calls — they would steal the slot.
    creds_b = FakeCredentials()
    addr_b = id(creds_b)

    print(
        f"[User A] credentials deleted. Address {hex(addr_a)} is now free."
    )
    print(
        f"         Cache still holds entry for {hex(addr_a)} (30-min TTL)."
    )
    print(f"[User B] New credentials allocated at: {hex(addr_b)}")

    if addr_b != addr_a:
      print(
          f"\nAddress NOT reused (expected {hex(addr_a)}, got {hex(addr_b)})."
          "\nThis is unexpected on CPython with LIFO pymalloc."
          "\nThe vulnerability still exists in the code even if not triggered"
          " here."
      )
      return False

    print(f"\n[User B] Address reused: {hex(addr_b)} == {hex(addr_a)}")

    # --- User B's call ---
    client_b = pubsub_client.get_publisher_client(credentials=creds_b)
    print(f"[User B] Got publisher client: {client_b}")

    if client_b is client_a:
      print("\nBUG CONFIRMED: User B received User A's PublisherClient.")
      print(
          "User B will publish Pub/Sub messages using User A's GCP"
          " credentials."
      )
      return True
    else:
      print(
          "\nUNEXPECTED: Address was reused but a new client was created."
          " Check the cache logic."
      )
      return False


# ---------------------------------------------------------------------------
# Subscriber bug demo
# ---------------------------------------------------------------------------


def demo_subscriber_bug() -> bool:
  """Return True if the cross-user cache hit was confirmed for subscribers."""
  call_count = 0

  def subscriber_side_effect(*args, **kwargs):
    nonlocal call_count
    call_count += 1
    return mock.MagicMock(name=f"SubscriberClient_#{call_count}")

  with mock.patch.object(
      pubsub_v1,
      "SubscriberClient",
      side_effect=subscriber_side_effect,
  ) as mock_sub:
    _warmup = [FakeCredentials() for _ in range(64)]
    del _warmup

    creds_a = FakeCredentials()
    addr_a = id(creds_a)
    client_a = pubsub_client.get_subscriber_client(credentials=creds_a)

    mock_sub.reset_mock()
    del creds_a

    creds_b = FakeCredentials()
    if id(creds_b) == addr_a:
      client_b = pubsub_client.get_subscriber_client(credentials=creds_b)
      if client_b is client_a:
        print(
            f"[Subscriber] Same bug confirmed for get_subscriber_client."
        )
        return True
    else:
      print(
          f"[Subscriber] Address not reused"
          f" (got {hex(id(creds_b))}, wanted {hex(addr_a)})."
      )

  return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
  publisher_bug = demo_publisher_bug()

  print()
  subscriber_bug = demo_subscriber_bug()

  print()
  pubsub_client.cleanup_clients()
  print("[Cleanup] cleanup_clients() called.")

  print()
  if publisher_bug and subscriber_bug:
    print("=" * 60)
    print("RESULT: PASS — both publisher and subscriber bugs confirmed.")
    print("=" * 60)
    sys.exit(0)
  elif publisher_bug:
    print("=" * 60)
    print(
        "RESULT: PARTIAL — publisher bug confirmed; subscriber not reproduced."
    )
    print("=" * 60)
    sys.exit(1)
  else:
    print("=" * 60)
    print("RESULT: FAIL — could not reproduce the bug in this run.")
    print("=" * 60)
    sys.exit(1)


if __name__ == "__main__":
  main()
