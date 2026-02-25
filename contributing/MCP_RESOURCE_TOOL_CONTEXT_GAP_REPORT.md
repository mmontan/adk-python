# Security Report: LoadMcpResourceTool Strips User Context from Resource Operations

## Vulnerability Details
- **Vulnerability:** Missing User Context / Auth Bypass in Resource Fetching
- **Vulnerability Type:** Security / Privacy
- **Severity:** High
- **Source Location:** `src/google/adk/tools/load_mcp_resource_tool.py` (lines 111, 131)
- **Root Cause:** `src/google/adk/tools/mcp_tool/mcp_toolset.py` — `list_resources()` and `read_resource()` called without `readonly_context`
- **Data Types at Risk:** MCP server resources (files, database records, documents, etc.) accessible without per-user auth

## Description

`LoadMcpResourceTool` is an ADK tool that is injected into an agent's toolset when `use_mcp_resources=True`. Its job is to list available MCP resources, embed them in the LLM context, and fetch specific resources on demand.

The vulnerability is that while `LoadMcpResourceTool.run_async()` correctly receives a `tool_context` (which carries the current user's invocation context and credentials), it discards that context before delegating to the underlying `McpToolset`.

### Vulnerable Code Path

```python
# load_mcp_resource_tool.py
async def _append_resources_to_llm_request(
    self, *, tool_context: ToolContext, llm_request: LlmRequest
):
    # tool_context IS available here, but is never forwarded:
    resource_names = await self._mcp_toolset.list_resources()       # (1) no context
    # ...
    contents = await self._mcp_toolset.read_resource(resource_name) # (2) no context
```

Both `list_resources()` and `read_resource()` accept an optional `readonly_context` parameter that is left `None` in all calls made from this tool.

### What `readonly_context=None` Breaks

When `_execute_with_session()` in `McpToolset` is called with no context:

```python
async def _execute_with_session(self, coroutine_func, error_message, readonly_context=None):
    headers = {}
    # header_provider is SKIPPED because readonly_context is None:
    if self._header_provider and readonly_context:
        provider_headers = self._header_provider(readonly_context)
        ...
    # Falls back to whatever is in the shared auth_config:
    auth_headers = self._get_auth_headers()  # reads self._auth_config.exchanged_auth_credential
```

Two distinct failures result.

## Impact

### 1. Per-User `header_provider` Bypassed

If `McpToolset` was configured with a `header_provider` — the standard mechanism for per-user auth in dynamic MCP deployments — that callback is **never invoked** for any resource operation. The MCP server receives resource requests with no user-identifying headers, regardless of how the toolset was configured.

**Example:** An enterprise deployment uses `header_provider` to inject a per-user JWT into every MCP request. Tool calls correctly receive the user's JWT. Resource fetches via `LoadMcpResourceTool` silently strip the JWT, causing the MCP server to serve resources as an unauthenticated or default user.

### 2. Stale / Wrong-User Credential Used

`_get_auth_headers()` reads from `self._auth_config.exchanged_auth_credential`, a shared instance variable that is written by `_resolve_toolset_auth()` in `base_llm_flow.py`. Due to the auth credential race condition (documented separately in `AUTH_RACE_CONDITION_REPORT.md`), this field may contain a different user's token at the time the resource fetch executes.

**Consequence:** Resources are fetched using another user's identity. Depending on the MCP server, this can result in:
- Cross-user data exposure (User B's resources returned to User A)
- Privilege escalation (resource fetched under a higher-privilege user's token)
- Audit trail corruption (server-side logs attribute the access to the wrong identity)

### 3. Complete Absence of Isolation on Stdio Connections

For `stdio`-based MCP servers, the session manager uses a constant pool key (`'stdio_session'`), meaning all users share one subprocess. `LoadMcpResourceTool` making resource calls without any user context in this scenario means:

- All users see the same resource list (the MCP subprocess's current state)
- `read_resource()` reads data from a shared, potentially dirty context
- No per-user isolation exists at any layer of the call stack

## Comparison to the (Correct) Tool Execution Path

The `McpTool._run_async_impl()` method correctly handles user context:

```python
# mcp_tool.py — CORRECT pattern
async def _run_async_impl(self, *, args, tool_context: ToolContext, credential):
    auth_headers = await self._get_headers(tool_context, credential)  # per-user
    dynamic_headers = self._header_provider(
        ReadonlyContext(tool_context._invocation_context)             # per-user
    )
    session = await self._mcp_session_manager.create_session(headers=final_headers)
```

`LoadMcpResourceTool` does not replicate this pattern and is structurally inconsistent with the rest of the MCP tool surface.

## Proof of Concept

**Setup:** Two users (Alice, Bob) share an ADK agent with a `McpToolset` configured with `use_mcp_resources=True` and a `header_provider` that injects `X-User-Id: <user>`.

1. Alice sends a message. The agent calls `load_mcp_resource` to list available resources.
2. `LoadMcpResourceTool._append_resources_to_llm_request()` is invoked with Alice's `tool_context`.
3. `self._mcp_toolset.list_resources()` is called with **no context**.
4. `header_provider` is skipped. The MCP server receives the request with no `X-User-Id` header.
5. The MCP server returns the default (unauthenticated) resource list — potentially Bob's resources or a shared resource set — to Alice's session.
6. Alice's LLM context is poisoned with incorrect resources.

## Recommendation

Pass a `ReadonlyContext` derived from `tool_context` to all resource operations in `LoadMcpResourceTool`:

```python
# Conceptual fix — do not implement without full review
from ...agents.readonly_context import ReadonlyContext

async def _append_resources_to_llm_request(self, *, tool_context, llm_request):
    context = ReadonlyContext(tool_context._invocation_context)
    resource_names = await self._mcp_toolset.list_resources(readonly_context=context)
    # ...
    contents = await self._mcp_toolset.read_resource(resource_name, readonly_context=context)
```

Additionally, the root cause of why context is dropped should be addressed: `LoadMcpResourceTool` is currently a `BaseTool`, not a `BaseAuthenticatedTool`, and receives no credential from the ADK auth flow. The resource fetch path needs the same credential-resolution treatment that `McpTool._run_async_impl()` receives.
