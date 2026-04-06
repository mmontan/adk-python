# Security Report: Cross-User Authentication Credential Leakage via Shared Toolset State

- **ID:** FINDING-2
- **Vulnerability:** Shared Mutable State — Cross-User OAuth / API Key Leakage
- **Severity:** Critical
- **CWE:** CWE-362 (Race Condition on Shared Resource), CWE-522 (Insufficiently Protected Credentials)
- **Status:** Active (confirmed against branch `security-assessment-cross-user` as of 2026-04-06)
- **Related reports:** `AUTH_RACE_CONDITION_REPORT.md`, `RUNNER_SHARED_STATE_REPORT.md`

## Revision History

| Date | Change |
|------|--------|
| 2026-04-06 | Initial report with reproduction script |
| 2026-04-06 | Added §Surface Expansion: Agent Registry now routes additional credentials through the same vulnerable path (commit `7913a3b7`) |

---

## Description

When `AdkWebServer` serves multiple users, it caches one `Runner` instance per `app_name`. Because a `Runner` holds a direct reference to the root `Agent`, and that `Agent` holds the same `Toolset` instances, every concurrent user request shares the exact same `Toolset` objects in memory.

Each `Toolset` that requires authentication stores a single `AuthConfig` instance variable (`self._auth_config`). Before every tool invocation, `_resolve_toolset_auth()` in `base_llm_flow.py` fetches the **current user's** credential from the credential store and writes it directly onto this shared `AuthConfig` object:

```python
# src/google/adk/flows/llm_flows/base_llm_flow.py:157-159
if credential:
    # Populate in-place for toolset to use in get_tools()
    auth_config.exchanged_auth_credential = credential  # <-- writes to shared object
```

The `auth_config` retrieved on line 139 (`tool_union.get_auth_config()`) is the same Python object returned by `self._auth_config` on the shared `Toolset` instance. There is no copy, no locking, and no per-request isolation.

---

## Root Cause Chain

```
AdkWebServer.get_runner_async()
  └── self.runner_dict[app_name]          # one Runner cached per app
        └── runner.app.root_agent         # same Agent object for all users
              └── agent.tools[i]          # same Toolset instance for all users
                    └── toolset._auth_config   # single AuthConfig object
                          └── .exchanged_auth_credential  # OVERWRITTEN per request
```

**Key source locations:**

| File | Line | Description |
|------|------|-------------|
| `src/google/adk/cli/adk_web_server.py` | 681–683 | Runner cached and returned for all users of the same app |
| `src/google/adk/flows/llm_flows/base_llm_flow.py` | 139 | `auth_config` retrieved from shared toolset instance |
| `src/google/adk/flows/llm_flows/base_llm_flow.py` | 159 | User credential written to shared `auth_config` in-place |
| `src/google/adk/tools/mcp_tool/mcp_toolset.py` | 186–193 | `self._auth_config` is a single instance variable on the toolset |
| `src/google/adk/tools/mcp_tool/mcp_toolset.py` | 203–206 | `get_tools()` reads `self._auth_config.exchanged_auth_credential` |
| `src/google/adk/auth/auth_tool.py` | 64 | `exchanged_auth_credential` field on `AuthConfig` — single value, no per-user slot |

---

## Attack Scenario

Two users, Alice and Bob, are concurrently using an ADK agent backed by an `McpToolset` or `OpenAPIToolset` that requires OAuth.

```
T=0.000  Alice's request arrives. Server fetches ALICE_TOKEN from session store.
T=0.001  Bob's request arrives.   Server fetches BOB_TOKEN from session store.
T=0.002  Alice's coroutine writes:  shared_toolset._auth_config.exchanged_auth_credential = ALICE_TOKEN
T=0.003  Bob's coroutine writes:    shared_toolset._auth_config.exchanged_auth_credential = BOB_TOKEN
                                     ^--- OVERWRITES Alice's token
T=0.004  Alice's coroutine calls get_tools() → reads shared_toolset._auth_config
                                     → gets BOB_TOKEN
T=0.005  Alice's tool call executes with BOB_TOKEN → Bob's account is accessed
```

This is an exploit on normal concurrent traffic — no special attacker capability is needed beyond having two users active simultaneously.

---

## Affected Toolsets

Any toolset implementing `get_auth_config()` is affected when used via `AdkWebServer`:

- `McpToolset` (`mcp_tool/mcp_toolset.py`)
- `OpenAPIToolset` (`openapi_tool/openapi_spec_parser/openapi_toolset.py`)
- `APIHubToolset` (`apihub_tool/apihub_toolset.py`)
- `ApplicationIntegrationToolset` (`application_integration_tool/...`)
- Any custom `BaseToolset` subclass that implements `get_auth_config()`

Individual `BaseAuthenticatedTool` subclasses are **not** affected — they handle credentials via local variables.

---

## Reproduction

The script below demonstrates the race condition without a real OAuth server. It uses a mock toolset to expose the exact shared-state mutation and confirm that User A's credential is visible during User B's invocation.

### Setup

```bash
# From repo root
uv venv --python python3.11 .venv
source .venv/bin/activate
uv sync --extra test
```

### Reproduction Script

Save as `reproduce_finding_2.py` and run with `python reproduce_finding_2.py`.

```python
"""
Reproduction script for FINDING-2: Cross-User Auth Credential Leakage.

Demonstrates that concurrent requests to a shared Toolset instance cause
one user's OAuth token to be read during another user's tool execution.

No real OAuth server or ADK server needed — the race is reproduced
at the object level by directly simulating the _resolve_toolset_auth
write pattern on a shared toolset.
"""

import asyncio
import time
from typing import Optional
from unittest.mock import AsyncMock, MagicMock

# ---------------------------------------------------------------------------
# Minimal stubs for ADK types we need to reproduce the pattern
# ---------------------------------------------------------------------------

class FakeAuthCredential:
    def __init__(self, token: str):
        self.token = token
        self.oauth2 = MagicMock(access_token=token)

    def __repr__(self):
        return f"FakeAuthCredential(token={self.token!r})"


class FakeAuthConfig:
    """Mirrors AuthConfig: a single object that holds exchanged_auth_credential."""
    def __init__(self):
        self.exchanged_auth_credential: Optional[FakeAuthCredential] = None


class FakeToolset:
    """
    Mirrors McpToolset / OpenAPIToolset pattern:
    - One instance shared across all users (cached in Runner)
    - _auth_config is an instance variable
    - get_auth_config() returns the same object every call
    - get_tools() reads from self._auth_config.exchanged_auth_credential
    """
    def __init__(self, name: str):
        self.name = name
        self._auth_config = FakeAuthConfig()

    def get_auth_config(self) -> FakeAuthConfig:
        return self._auth_config  # returns the SHARED instance

    def get_tools(self) -> str:
        """Simulate what McpToolset.get_tools() does: read exchanged credential."""
        cred = self._auth_config.exchanged_auth_credential
        if cred:
            return f"[{self.name}] Using credential: {cred.token}"
        return f"[{self.name}] No credential set"


# ---------------------------------------------------------------------------
# The vulnerable function — mirrors base_llm_flow._resolve_toolset_auth
# ---------------------------------------------------------------------------

async def resolve_toolset_auth_VULNERABLE(
    user_id: str,
    user_token: str,
    toolset: FakeToolset,
    delay_after_write: float = 0.0,
) -> None:
    """
    Mirrors the vulnerable code path:
      auth_config = tool_union.get_auth_config()   # gets shared object
      credential = await get_auth_credential(...)   # user-specific
      auth_config.exchanged_auth_credential = credential  # WRITES to shared object
    """
    # Step 1: get the shared auth_config object
    auth_config = toolset.get_auth_config()

    # Step 2: fetch the user-specific credential (simulate async DB/session lookup)
    await asyncio.sleep(0.01)  # simulate I/O
    credential = FakeAuthCredential(token=user_token)

    # Step 3: THE VULNERABILITY — write user credential onto shared object
    auth_config.exchanged_auth_credential = credential
    print(f"  [T={time.time():.4f}] {user_id}: wrote token '{user_token}' to shared auth_config")

    # Simulate delay between write and tool execution (e.g., LLM round-trip)
    await asyncio.sleep(delay_after_write)

    # Step 4: tool execution reads from the now-potentially-overwritten shared object
    result = toolset.get_tools()
    print(f"  [T={time.time():.4f}] {user_id}: get_tools() returned → {result}")

    # Detect the leak
    actual_token = toolset._auth_config.exchanged_auth_credential.token
    if actual_token != user_token:
        print(f"\n  *** CREDENTIAL LEAK DETECTED ***")
        print(f"      {user_id} expected token '{user_token}'")
        print(f"      but shared auth_config holds  '{actual_token}'")


# ---------------------------------------------------------------------------
# Test 1: Sequential (no race — baseline)
# ---------------------------------------------------------------------------

async def test_sequential():
    print("=" * 60)
    print("TEST 1: Sequential requests (no race — baseline)")
    print("=" * 60)
    toolset = FakeToolset("my-api")

    await resolve_toolset_auth_VULNERABLE("alice", "ALICE_TOKEN", toolset)
    await resolve_toolset_auth_VULNERABLE("bob",   "BOB_TOKEN",   toolset)

    print("Result: No leak in sequential mode (expected)\n")


# ---------------------------------------------------------------------------
# Test 2: Concurrent — demonstrates the race condition
# ---------------------------------------------------------------------------

async def test_concurrent_race():
    print("=" * 60)
    print("TEST 2: Concurrent requests (race condition)")
    print("=" * 60)

    # One shared toolset — same object for all users, as in AdkWebServer
    shared_toolset = FakeToolset("my-api")

    leaked_tokens = []

    async def user_request(user_id: str, user_token: str, write_delay: float):
        auth_config = shared_toolset.get_auth_config()

        # Fetch credential (simulate async session lookup)
        await asyncio.sleep(0.01)
        credential = FakeAuthCredential(token=user_token)

        # THE VULNERABLE WRITE
        auth_config.exchanged_auth_credential = credential
        print(f"  [T={time.time():.4f}] {user_id}: wrote '{user_token}' → shared auth_config")

        # Simulate time between write and tool read (LLM thinking, network, etc.)
        await asyncio.sleep(write_delay)

        # Read — may see another user's token
        seen_token = shared_toolset._auth_config.exchanged_auth_credential.token
        result = shared_toolset.get_tools()
        print(f"  [T={time.time():.4f}] {user_id}: get_tools() → {result}")

        if seen_token != user_token:
            leaked_tokens.append((user_id, user_token, seen_token))

    # Alice writes, then Bob writes before Alice reads
    await asyncio.gather(
        user_request("alice", "ALICE_OAUTH_TOKEN", write_delay=0.05),
        user_request("bob",   "BOB_OAUTH_TOKEN",   write_delay=0.00),
    )

    print()
    if leaked_tokens:
        for victim, expected, got in leaked_tokens:
            print(f"  *** CREDENTIAL LEAK: {victim} expected '{expected}', "
                  f"but executed with '{got}' ***")
    else:
        print("  No leak detected in this run (race is timing-dependent; re-run if needed)")
    print()


# ---------------------------------------------------------------------------
# Test 3: Persistent contamination — shows the leak survives after Bob's
# request ends, affecting future requests from Charlie
# ---------------------------------------------------------------------------

async def test_persistent_contamination():
    print("=" * 60)
    print("TEST 3: Persistent contamination (token survives after request)")
    print("=" * 60)

    shared_toolset = FakeToolset("my-api")

    # Alice authenticates and uses the toolset normally
    auth_config = shared_toolset.get_auth_config()
    auth_config.exchanged_auth_credential = FakeAuthCredential("ALICE_TOKEN")
    print(f"  Alice sets token: ALICE_TOKEN")

    # Bob's request races and overwrites
    auth_config.exchanged_auth_credential = FakeAuthCredential("BOB_TOKEN")
    print(f"  Bob  sets token: BOB_TOKEN  (overwrites Alice)")

    # Bob's request finishes — auth_config still holds BOB_TOKEN
    # Now Charlie arrives (a new user, unrelated to Bob)
    await asyncio.sleep(0.01)  # Charlie's request starts after Bob finishes
    charlie_auth_config = shared_toolset.get_auth_config()

    # Charlie hasn't authenticated yet, but the toolset already has BOB_TOKEN
    existing = charlie_auth_config.exchanged_auth_credential
    print(f"  Charlie reads auth_config before his own write: '{existing.token}'")

    # Charlie's credential lookup finds his own token and writes it
    charlie_auth_config.exchanged_auth_credential = FakeAuthCredential("CHARLIE_TOKEN")

    # But if Charlie's write hadn't happened yet (e.g., credential not in store),
    # the toolset would still use BOB_TOKEN for Charlie's tool call.
    print(f"\n  *** PERSISTENCE: after Bob's request, shared_toolset retains BOB_TOKEN")
    print(f"      until the next user overwrites it. Any unauthenticated or")
    print(f"      delayed request will execute using the previous user's token. ***\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    asyncio.run(test_sequential())
    asyncio.run(test_concurrent_race())
    asyncio.run(test_persistent_contamination())
```

### Expected Output (abridged)

```
============================================================
TEST 1: Sequential requests (no race — baseline)
============================================================
  [T=...] alice: wrote token 'ALICE_TOKEN' to shared auth_config
  [T=...] alice: get_tools() returned → [my-api] Using credential: ALICE_TOKEN
  [T=...] bob: wrote token 'BOB_TOKEN' to shared auth_config
  [T=...] bob: get_tools() returned → [my-api] Using credential: BOB_TOKEN
Result: No leak in sequential mode (expected)

============================================================
TEST 2: Concurrent requests (race condition)
============================================================
  [T=...] alice: wrote 'ALICE_OAUTH_TOKEN' → shared auth_config
  [T=...] bob:   wrote 'BOB_OAUTH_TOKEN'   → shared auth_config
  [T=...] bob:   get_tools() → [my-api] Using credential: BOB_OAUTH_TOKEN
  [T=...] alice: get_tools() → [my-api] Using credential: BOB_OAUTH_TOKEN

  *** CREDENTIAL LEAK: alice expected 'ALICE_OAUTH_TOKEN', but executed with 'BOB_OAUTH_TOKEN' ***

============================================================
TEST 3: Persistent contamination
============================================================
  Alice sets token: ALICE_TOKEN
  Bob  sets token: BOB_TOKEN  (overwrites Alice)
  Charlie reads auth_config before his own write: 'BOB_TOKEN'

  *** PERSISTENCE: after Bob's request, shared_toolset retains BOB_TOKEN
      until the next user overwrites it. ...
```

---

## Impact

| Scenario | Effect |
|----------|--------|
| Concurrent OAuth users | User A's API calls execute under User B's OAuth token |
| API key toolsets | User A's key is used for User B's requests |
| Tool with destructive actions (e.g., delete, send email) | User A performs irreversible actions on User B's account |
| Audit logs | Actions are attributed to the wrong user identity |
| Compliance (GDPR, SOC 2, HIPAA) | Cross-user data access without consent or authorization |

---

## Remediation

The fix must eliminate the shared mutable field. Three options, in order of preference:

### Option A — Pass credential as argument (preferred)

Change `get_tools(readonly_context)` to accept the resolved credential directly:

```python
# Conceptual — would require interface change across all Toolset subclasses
async def get_tools(
    self,
    readonly_context: Optional[ReadonlyContext] = None,
    credential: Optional[AuthCredential] = None,  # NEW: per-request, not stored
) -> list[BaseTool]:
    ...
```

`_resolve_toolset_auth` would return a `{toolset_id: credential}` dict and pass it down instead of writing to the shared object.

### Option B — Per-invocation AuthConfig copy

Before writing, deep-copy the `AuthConfig` into the invocation context:

```python
# In _resolve_toolset_auth, replace line 159:
# auth_config.exchanged_auth_credential = credential  # REMOVE
#
# with:
invocation_auth_configs[id(tool_union)] = auth_config.model_copy(deep=True)
invocation_auth_configs[id(tool_union)].exchanged_auth_credential = credential
```

### Option C — Per-request Toolset cloning (least disruptive to interface)

In `_resolve_toolset_auth`, create a shallow clone of the toolset for the duration of the invocation and write to the clone's `auth_config`.

---

## Surface Expansion: Agent Registry (commit `7913a3b7`, 2026-04-03)

`AgentRegistry.get_mcp_toolset()` now accepts `auth_scheme` and `auth_credential` parameters and passes them directly into `McpToolset`:

```python
# src/google/adk/integrations/agent_registry/agent_registry.py
def get_mcp_toolset(
    self,
    mcp_server_name: str,
    auth_scheme: AuthScheme | None = None,
    auth_credential: AuthCredential | None = None,
) -> McpToolset:
    ...
    return McpToolset(
        ...,
        auth_scheme=auth_scheme,
        auth_credential=auth_credential,  # stored in self._auth_config
    )
```

`McpToolset.__init__` stores these in `self._auth_config`, which is the same shared instance object that `_resolve_toolset_auth` later writes `exchanged_auth_credential` onto. Any agent that constructs a toolset via `AgentRegistry` and provides credentials now has those credentials subject to the race condition described in this report.

The Agent Registry is intended for use in multi-tenant deployments (it discovers MCP servers from a centralized registry), making this a high-risk combination: the API surface that most naturally involves multiple users is precisely the one that now has more credentials flowing through the vulnerable path.

---

## Notes

- The vulnerability is present regardless of whether `InMemorySessionService` or a database-backed `SessionService` is used — the issue is at the `Toolset` object level, not the session store.
- The `SESSION_STATE` credential service does correctly scope credentials to a session, but the bug occurs **after** retrieval: the correctly-scoped credential is then written to the shared toolset, defeating the scoping.
- `BaseAuthenticatedTool` (individual tools, not toolsets) is **not** affected — it resolves credentials in local variables per invocation.
