# Security Vulnerability Report: Authentication Credential Race Condition

## Executive Summary
A critical vulnerability exists in the ADK Python runtime where authentication credentials (such as OAuth tokens and API keys) are temporarily stored in a shared global state during request processing. In a multi-user environment, this creates a race condition where concurrent requests can overwrite each other's credentials, leading to one user performing actions with another user's identity.

## Vulnerability Details

### 1. The Mechanism of Failure
The vulnerability occurs in the `BaseLlmFlow._resolve_toolset_auth` method, which is responsible for preparing authentication before tool execution.

1.  **Trigger:** Every time an agent runs, it iterates through its registered `Toolsets` (e.g., McpToolset, OpenAPIToolset) to resolve authentication.
2.  **Retrieval:** It correctly identifies the current user and retrieves their specific credential from the database/session storage.
3.  **The Flaw:** It assigns this user-specific credential to the `exchanged_auth_credential` attribute of the `AuthConfig` object.
    *   Crucially, this `AuthConfig` object is a property of the `Toolset`.
    *   In `AdkWebServer`, `Toolset` instances are cached and **shared across all users**.
4.  **The Race:** This turns the `auth_config` object into a "global variable." If two users are active simultaneously, they race to write their token to this variable.

### 2. Verified Vulnerable Code Path
**File:** `src/google/adk/flows/llm_flows/base_llm_flow.py`

```python
async def _resolve_toolset_auth(invocation_context, agent):
  for tool_union in agent.tools:
    # ...
    auth_config = tool_union.get_auth_config()
    
    # 1. Fetch the user's specific credential (CORRECT)
    credential = await CredentialManager(auth_config).get_auth_credential(callback_context)

    if credential:
      # 2. WRITE to the SHARED toolset instance (CRITICAL VULNERABILITY)
      # This overwrites the token for ALL users of this toolset
      auth_config.exchanged_auth_credential = credential 
```

### 3. Proof of Concept Scenario
Imagine two users, **Alice** and **Bob**, using an ADK agent connected to a sensitive API (e.g., Google Drive or Jira).

1.  **T=0.0s**: **Alice** sends a message. The server retrieves `ALICE_TOKEN` and writes it to `shared_toolset.auth_config`.
2.  **T=0.1s**: **Bob** sends a message. The server retrieves `BOB_TOKEN` and **overwrites** `shared_toolset.auth_config` with `BOB_TOKEN`.
3.  **T=0.2s**: **Alice's** request proceeds to execute the tool (e.g., `list_files`).
4.  **T=0.3s**: The tool reads `shared_toolset.auth_config`. It sees `BOB_TOKEN`.
5.  **Result:** **Alice** lists **Bob's** files. Alice has unintentionally hijacked Bob's session.

### 4. Affected Components
This vulnerability affects any Agent that uses:
*   `McpToolset` (Model Context Protocol)
*   `OpenAPIToolset`
*   Any custom Toolset that relies on `get_auth_config()` for credential passing.

*Note: Individual tools inheriting from `BaseAuthenticatedTool` are NOT affected, as they handle credentials in local variables.*

## Remediation Strategy
To fix this, we must remove the shared state entirely. Credentials should be treated as "Request Context," not "Tool Configuration."

1.  **Deprecate/Remove:** The `auth_config.exchanged_auth_credential` field should be removed or strictly forbidden for runtime use.
2.  **Pass by Argument:** Modify the `get_tools()` and tool execution signatures to accept the `credential` explicitly as an argument derived from the `InvocationContext`.
3.  **Context-Aware Resolution:** The `_resolve_toolset_auth` function should return a dictionary of `{toolset_id: credential}` which is passed down the stack, rather than modifying the toolsets themselves.
