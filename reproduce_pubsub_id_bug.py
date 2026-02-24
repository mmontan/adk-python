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

No real GCP credentials or network access are required: pubsub_v1 classes
are patched with mocks (same pattern as test_pubsub_client.py).
"""

from __future__ import annotations

import gc
import sys
from unittest import mock

from google.adk.tools.pubsub import client as pubsub_client
from google.cloud import pubsub_v1

# ---------------------------------------------------------------------------
# FakeCredentials: a trivially-sized object so CPython's pymalloc is likely
# to hand its slot to the very next same-sized allocation after GC.
# ---------------------------------------------------------------------------


class FakeCredentials:
  """Minimal stand-in for google.auth.credentials.Credentials."""

  pass


# ---------------------------------------------------------------------------
# Publisher bug demo
# ---------------------------------------------------------------------------

_MAX_ATTEMPTS = 10_000  # give up after this many allocations


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

  with mock.patch.object(
      pubsub_v1,
      "PublisherClient",
      side_effect=publisher_side_effect,
  ):
    # --- User A ---
    creds_a = FakeCredentials()
    addr_a = id(creds_a)
    print(f"[User A] credentials at: {hex(addr_a)}")

    client_a = pubsub_client.get_publisher_client(credentials=creds_a)
    print(f"[User A] Got publisher client: {client_a}")

    # Free User A's credentials; the cache entry for addr_a remains alive.
    del creds_a
    gc.collect()
    print(
        f"[User A] credentials deleted + GC'd. Address {hex(addr_a)} now free."
    )
    print(
        f"         Cache still holds entry for {hex(addr_a)} (30-min TTL).\n"
    )

    # --- Scan for address reuse ---
    print("[Scanning] Looking for address reuse...")
    creds_b = None
    found = False
    for attempt in range(1, _MAX_ATTEMPTS + 1):
      candidate = FakeCredentials()
      if id(candidate) == addr_a:
        creds_b = candidate
        found = True
        print(
            f"[User B] Address reused after {attempt} attempt(s):"
            f" {hex(id(creds_b))} (same as User A)"
        )
        break
      # Keep a reference to prevent immediate reuse on the next iteration;
      # then release it so memory is actually freed.
      del candidate

    if not found:
      print(
          f"[Scanning] Address {hex(addr_a)} was NOT reused in"
          f" {_MAX_ATTEMPTS} attempts."
      )
      print(
          "           This is unexpected on CPython. The bug still exists in"
          " the code;\n"
          "           address reuse just didn't occur in this run."
      )
      return False

    # --- User B's call ---
    client_b = pubsub_client.get_publisher_client(credentials=creds_b)
    print(f"[User B] Got publisher client: {client_b}\n")

    if client_b is client_a:
      print("BUG CONFIRMED: User B received User A's PublisherClient.")
      print(
          "User B will publish Pub/Sub messages using User A's GCP credentials."
      )
      return True
    else:
      # This means a new client was created — address reuse happened but
      # the cache key collision did not produce the wrong result, which
      # would be unexpected given the code.
      print(
          "UNEXPECTED: Address was reused but a new client was created."
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
  ):
    creds_a = FakeCredentials()
    addr_a = id(creds_a)
    client_a = pubsub_client.get_subscriber_client(credentials=creds_a)

    del creds_a
    gc.collect()

    for attempt in range(1, _MAX_ATTEMPTS + 1):
      candidate = FakeCredentials()
      if id(candidate) == addr_a:
        client_b = pubsub_client.get_subscriber_client(credentials=candidate)
        if client_b is client_a:
          print(
              f"[Subscriber] Same bug confirmed for get_subscriber_client"
              f" (reuse after {attempt} attempt(s))."
          )
          return True
        break
      del candidate

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
    print("RESULT: PARTIAL — publisher bug confirmed; subscriber not reproduced.")
    print("=" * 60)
    sys.exit(1)
  else:
    print("=" * 60)
    print("RESULT: FAIL — could not reproduce the bug in this run.")
    print("=" * 60)
    sys.exit(1)


if __name__ == "__main__":
  main()
