# Architectural Remediation Plan — ADK-Python Security Audit

## Overview

This document synthesizes all 27 vulnerabilities identified in the February 2026 security audit into 8 root-cause clusters and proposes the architectural and code-level changes needed to eliminate each class. Fixing individual vulnerabilities in isolation is tractable but leaves the codebase vulnerable to new instances of the same pattern. The goal here is to identify the structural changes that close entire classes at once.

Vulnerabilities covered: VULN-1 through VULN-27 as documented in `SECURITY_VULNERABILITY_MASTER_LIST.md`.

---

## Root Cause Clusters

### Cluster 1 — Shared Mutable State on Runner

**Affects:** VULN-2 (auth race), VULN-4 (computer use leakage), VULN-7 (MCP session sharing), VULN-14 (agent mutation), VULN-15 (shared PluginManager), VULN-24 (static search filter)

**Root cause:** `AdkWebServer` caches one `Runner` per `app_name` and shares it across all concurrent users. Every mutable object on the Runner — `self.agent`, `self.plugin_manager`, toolset `_auth_config` instances, `ComputerUseToolset` browser state, `MCPSessionManager._sessions`, `VertexAiSearchTool.filter` — is shared state that races across concurrent invocations.

**Architectural fix: Runner owns only immutable configuration; all per-invocation state lives in `InvocationContext`.**

The design principle: after `Runner.__init__()` completes, no attribute of `Runner` should ever be written again. Everything that varies per-invocation must be created fresh in `_new_invocation_context()` and stored on `InvocationContext`.

Specific code changes required:

1. **`_auth_config` on toolsets** — the single highest-leverage change. Currently `_resolve_toolset_auth()` in `base_llm_flow.py` writes `auth_config.exchanged_auth_credential = credential` on the shared toolset instance. Move `exchanged_auth_credential` out of the toolset and into `InvocationContext` (e.g., `ctx.resolved_credentials: dict[str, AuthCredential]`). The toolset reads from context; it never writes to itself. This alone closes VULN-2 and eliminates the race condition that also underlies VULN-12.

2. **`PluginManager`** — either instantiate one per invocation, or enforce at the class level that all plugins are stateless. A practical enforcement: add `BasePlugin.__init_subclass__()` that introspects the subclass `__init__` and raises `TypeError` if it defines any instance variables other than configuration constants. Document this constraint prominently.

3. **`ComputerUseToolset`** — browser context (Playwright page/context objects) must be created per-user session, stored in `ArtifactService` or `InvocationContext`, and never cached on the toolset instance itself.

4. **`MCPSessionManager` session keys** — include `user_id` as an explicit key component. Replace `f'session_{md5(headers)}'` with `f'session_{user_id}_{sha256(headers)}'`. For stdio connections, replace the constant key `'stdio_session'` with a per-user key `f'stdio_{user_id}'`. This closes VULN-7 and VULN-13 together.

5. **`VertexAiSearchTool`** — remove `self.filter` from the default config path. `_build_vertex_ai_search_config()` should accept `readonly_context` and be required to derive any user-scoped filter from it. There should be no default filter at all — omitting a filter is explicit, not implicit.

6. **`support_cfc` mutation (VULN-14)** — replace the in-place `self.agent.code_executor = ...` write with a local variable in the flow layer. The agent object must not be modified after construction.

---

### Cluster 2 — Unauthenticated User Identity

**Affects:** VULN-1 (IDOR), VULN-3 (path traversal), VULN-11 (namespace injection), VULN-19 (A2A identity), VULN-25 (list_sessions filter injection), VULN-26 (RAG client-side filtering), VULN-27 (memory poisoning)

**Root cause:** `user_id` is accepted as a plain string from HTTP path parameters, A2A `context_id`, and storage APIs without any cryptographic verification. Every service that consumes `user_id` trusts it completely. The entire cross-user attack surface in the audit depends on this single assumption.

**Architectural fix: Authentication middleware at the HTTP boundary; `user_id` is server-assigned, never client-supplied.**

Two-part change:

**Part A — Authentication middleware on `AdkWebServer`:**
Add an authentication layer (pluggable, so operators can choose JWT, OAuth, API key, or mTLS) that runs before any route handler. The middleware:
1. Validates the incoming credential against a configured identity provider.
2. Derives `user_id` from the verified principal (e.g., the `sub` claim of a JWT). Never reads `user_id` from the URL path or request body.
3. Injects the verified `user_id` into the request context.
4. Route handlers read `user_id` from the verified context, not from the path parameter.

The path parameter `{user_id}` in existing routes should be removed or treated as a hint that is validated against the authenticated identity — a mismatch is a 403, not a data access.

**Part B — `user_id` sanitization as defense-in-depth:**
Even with authentication, `user_id` values may contain characters that are structurally meaningful in downstream systems. Add a central `sanitize_user_id(raw: str) -> str` function applied at every service boundary that:
- Rejects or percent-encodes `/`, `..`, null bytes, and `.` (for RAG display names)
- Enforces a maximum length
- Normalizes Unicode to NFC

Every `SessionService`, `ArtifactService`, and `MemoryService` implementation calls this before using `user_id` in a path, filter expression, or display name. This closes VULN-3, VULN-11, and VULN-27 even before full authentication is deployed.

For A2A specifically (VULN-19): when A2A server authentication is disabled, generate a random anonymous `user_id` (`A2A_ANON_{uuid4()}`). Never derive `user_id` from the caller-supplied `context_id`. Require session ownership verification (`session.user_id == derived_user_id`) after retrieval regardless of auth mode.

---

### Cluster 3 — Credentials in General-Purpose Session State

**Affects:** VULN-5 (identity leakage), VULN-9 (plaintext credential storage), VULN-12 (LoadMcpResourceTool context gap), VULN-17 (A2A session state forwarding), VULN-21 (sensitive metadata in A2A events)

**Root cause:** OAuth tokens, API keys, and service credentials are cached in `session.state` — the same flat dictionary as conversation context, user preferences, and tool results. Because `session.state` is general-purpose, it is forwarded wholesale to remote agents, logged by telemetry, and read by racing requests.

**Architectural fix: Separate sealed credential store; `session.state` is a zone-of-no-secrets.**

Two-part change:

**Part A — Use `CredentialService` exclusively for credentials:**
The `CredentialService` already exists. The missing enforcement is that tools currently bypass it and write tokens directly to `tool_context.state`. Make `CredentialService` the mandatory path:
- `CredentialManager` writes resolved tokens to `CredentialService`, never to `tool_context.state` or `session.state`.
- Tools read credentials from `CredentialService` via `tool_context.credential` (the existing pattern in `BaseAuthenticatedTool`), not from `session.state` lookups.
- `session.state` serialization applies a redaction pass: any key matching `*token*`, `*key*`, `*secret*`, `*credential*`, `*password*`, `*auth*` raises a warning and is omitted from persistence. This is defense-in-depth, not the primary control.

**Part B — Never forward `session.state` over A2A:**
`RemoteA2aAgent` passes `ClientCallContext(state=ctx.session.state)` to every outbound call. Replace this with an explicit allowlist: operators declare which `session.state` keys are safe to forward (e.g., `["locale", "user_preference_theme"]`). Keys not on the allowlist are never sent. The default allowlist is empty — no state forwarded unless explicitly opted in.

For outbound A2A event metadata (VULN-21): remove `user_id`, `session_id`, and `custom_metadata` from `_get_context_metadata()`. Replace `session_id` with a short-lived opaque correlation token that has no meaning outside the current A2A exchange.

---

### Cluster 4 — Outbound HTTP Without SSRF Validation

**Affects:** VULN-6 (load_web_page SSRF), VULN-18 (A2A SSRF)

**Root cause:** The ADK process makes outbound HTTP requests in multiple places without validating that destination URLs do not point to internal infrastructure. The process typically runs with cloud service account credentials, so SSRF carries cloud IAM privileges.

**Architectural fix: Centralized `SafeHttpClient` that enforces an SSRF blocklist before every connection.**

Create `src/google/adk/utils/safe_http_client.py` — a thin wrapper around `httpx` (or `aiohttp`) that:
1. Parses and validates the URL scheme (allow only `https`, optionally `http` for dev).
2. Resolves the hostname to an IP address.
3. Rejects the connection if the resolved IP falls in:
   - RFC 1918 private ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - Loopback: `127.0.0.0/8`, `::1`
   - Link-local / cloud metadata: `169.254.0.0/16`, `fd00::/8`
   - Any non-routable range
4. Supports a developer-configurable `trusted_domains: list[str]` allowlist that exempts specific domains from the blocklist (for on-prem deployments with internal URLs).

Every place that makes an outbound HTTP call — `load_web_page`, A2A agent card resolution, MCP HTTP/SSE connections, `ApiRegistry` — uses `SafeHttpClient`. This is a single addition that closes all current and future SSRF vulnerabilities in the codebase.

---

### Cluster 5 — String Interpolation into Query and Filter Languages

**Affects:** VULN-22 (BigQuery ML injection), VULN-23 (Spanner similarity search injection), VULN-24 (Vertex AI Search filter injection), VULN-25 (VertexAiSessionService filter injection)

**Root cause:** LLM-supplied strings (column names, table names, filter expressions) and user-supplied strings (`user_id`) are interpolated into SQL and filter expression strings using f-strings without escaping or parameterization. This is the classic injection vulnerability family applied to database and search APIs.

**Architectural fix: Two rules enforced by utility functions — parameterize values, escape identifiers, never interpolate raw input.**

**Rule 1 — Data values use parameterized bindings:**
BigQuery and Spanner already support query parameters (`@param_name`). All data values — including values derived from LLM output — must use parameterized bindings. No f-string interpolation of data values. Already correctly applied in most of the codebase; the gap is in the BigQuery ML functions and Spanner `similarity_search`.

**Rule 2 — Identifiers use central escape utilities:**
SQL identifiers (column names, table names) cannot use parameterized bindings — they must be validated and escaped. Add:

```python
# src/google/adk/utils/sql_utils.py

def escape_bq_identifier(name: str) -> str:
    """Backtick-escapes a BigQuery identifier. Raises ValueError for empty input."""
    if not name:
        raise ValueError("Identifier cannot be empty")
    return f"`{name.replace('`', '``')}`"

def escape_spanner_identifier(name: str) -> str:
    """Backtick-escapes a Spanner GoogleSQL identifier."""
    if not name:
        raise ValueError("Identifier cannot be empty")
    return f"`{name.replace('`', '``')}`"
```

All column name, table name, and ORDER BY clause construction in `query_tool.py` and `search_tool.py` must go through these functions. No other code path produces SQL identifier strings.

**Rule 3 — Replace free-form filter parameters with structured `FilterSpec`:**
`additional_filter` in Spanner `similarity_search` and `filter` in `VertexAiSearchTool` accept arbitrary filter expression strings. These cannot be made safe by escaping alone. Replace them with a structured type:

```python
@dataclass
class FilterSpec:
    field: str            # validated against an allowlist of known fields
    operator: Literal["=", "!=", "<", ">", "<=", ">=", "IN", "NOT IN"]
    value: str | int | float | list
```

The ADK assembles the filter expression string from `FilterSpec` internally, applying proper escaping. Callers — including the LLM via function declarations — receive a typed API, not a raw string injection point.

For `user_id` in filter expressions (VULN-25): pass `user_id` as a structured parameter to the API client rather than building a filter string. If the Vertex AI SDK requires a filter string, apply `user_id.replace('"', '')` and validate that the result is unchanged (reject any `user_id` that contains `"`).

---

### Cluster 6 — Insecure Defaults

**Affects:** VULN-10 (telemetry logging PII), VULN-16 (branch event isolation opt-in)

**Root cause:** Two security-relevant settings default to the insecure option. The safe behavior requires explicit configuration; the dangerous behavior works out of the box.

**Architectural fix: Invert both defaults. Establish a general policy: any flag that expands information exposure or weakens isolation must default to the restrictive value.**

Specific changes:

1. **`ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS`** — change default from `True` to `False`. Add a data classification annotation on `ToolContext` and `LlmRequest` fields: content marked `SAFE_TO_LOG` may be captured in spans; all other content is redacted. Operators who need full content in traces opt in explicitly and acknowledge the data handling implications.

2. **`_get_events(current_branch: bool = False)`** — change default to `current_branch=True`. Audit all callers of `_get_events()` and verify that callers which legitimately need cross-branch visibility explicitly pass `current_branch=False`. The safe behavior (see only your own branch) should require no argument.

General policy for the codebase: security-relevant boolean flags follow the convention that `True` means "enable the safer/more restrictive behavior." Any flag where `True` means "enable potentially unsafe behavior" should be renamed to make the semantics explicit (e.g., `allow_cross_branch_events: bool = False`).

---

### Cluster 7 — Untrusted External Content Injected into the Trusted LLM Context

**Affects:** VULN-20 (A2A unvalidated remote response injection), VULN-27 (memory poisoning via namespace collision)

**Root cause:** Content from untrusted external sources — remote A2A agent responses, RAG memory entries from poisoned namespaces — is added to the LLM's conversation context without any provenance marker. The LLM has no way to distinguish this content from content produced by trusted local tools or the authenticated user. A compromised or malicious source can inject `FunctionCall` events that trigger local tool execution.

**Architectural fix: Content provenance tagging on `Event` objects with a policy enforcement layer.**

Add a `trust_level` field to `Event`:

```python
class TrustLevel(str, Enum):
    SYSTEM = "system"       # ADK infrastructure; never overridable
    USER = "user"           # Authenticated user input
    LOCAL_TOOL = "local"    # Tool registered by the developer in this process
    MEMORY = "memory"       # Retrieved from long-term memory
    REMOTE = "remote"       # From a remote A2A agent or external retrieval
```

Assignment rules:
- Events generated by the ADK runtime (agent transfers, internal actions): `SYSTEM`
- Events from the authenticated user's HTTP request: `USER`
- Events produced by locally-registered tools: `LOCAL_TOOL`
- Events injected from `MemoryService.search_memory()`: `MEMORY`
- Events converted from A2A remote responses: `REMOTE`

**Policy enforcement in the LLM flow layer:**

Before processing events from the conversation history, the flow validates:
- `REMOTE` and `MEMORY` events may contain `Content` (text, data). They may **not** contain `FunctionCall` parts that name a tool in the local `agent.tools` registry.
- If a `REMOTE` event contains a `FunctionCall` targeting a local tool, it is converted to a `FunctionResponse` with an error message and logged as a security event. The tool is not invoked.

This breaks the injection chain for VULN-20 regardless of what a compromised remote agent returns, and for VULN-27 regardless of what memory content was poisoned.

---

### Cluster 8 — Missing Per-User Context Propagation Through Tool Chains

**Affects:** VULN-12 (LoadMcpResourceTool context gap), VULN-13 (MD5 session pool key)

**Root cause:** `InvocationContext` / `ToolContext` is passed into tool entry points but silently dropped as calls pass through abstraction layers within the MCP stack. `LoadMcpResourceTool` discards `tool_context` before calling `list_resources`. `MCPSessionManager` derives session keys from a header hash rather than explicit `user_id`.

**Architectural fix: Make `ReadonlyContext` a mandatory non-optional parameter throughout the MCP call stack.**

1. `McpToolset.list_resources()` and `read_resource()` — change signatures to require `readonly_context: ReadonlyContext` (not `Optional`). Any caller that cannot provide one is a compile-time error, surfacing the gap immediately.

2. `LoadMcpResourceTool._append_resources_to_llm_request()` — pass `ReadonlyContext(tool_context._invocation_context)` to both `list_resources()` and `read_resource()`. This is the direct fix for VULN-12.

3. `MCPSessionManager._generate_session_key()` — replace MD5 with SHA-256 (closes VULN-13), and include `user_id` from the context as an explicit key component. The session key format becomes `f'session_{user_id}_{sha256(headers_json)}'`. For stdio, `f'stdio_{user_id}'`.

---

## Prioritized Implementation Roadmap

Ordered by impact-per-effort, accounting for dependencies between clusters:

| Phase | Change | Cluster | VULNs Closed |
|---|---|---|---|
| **1** | Authentication middleware on `AdkWebServer`; `user_id` from verified identity only | 2 | 1, 3, 11, 19, 25, 26, 27 |
| **2** | Move `_auth_config` from toolset instances to `InvocationContext` | 1 | 2, 5, 12 |
| **3** | `CredentialService` as sole credential store; ban credentials in `session.state` | 3 | 9, 17, 21 |
| **4** | `SafeHttpClient` with SSRF blocklist; all outbound HTTP through it | 4 | 6, 18 |
| **5** | `PluginManager` per-invocation; `_get_events` default `current_branch=True` | 1, 6 | 15, 16 |
| **6** | `escape_identifier()` utilities; `FilterSpec` structured API; `user_id` sanitization | 5, 2 | 3, 11, 22, 23, 24, 25, 27 |
| **7** | `Event.trust_level`; policy enforcement in LLM flow | 7 | 20, 27 |
| **8** | Telemetry opt-in default; `SAFE_TO_LOG` annotation | 6 | 10 |
| **9** | `ReadonlyContext` mandatory in MCP call stack; SHA-256 + `user_id` in session keys | 8 | 12, 13 |
| **10** | Per-user MCP stdio sessions; per-user `ComputerUseToolset` browser context | 1 | 4, 7 |
| **11** | `support_cfc` local variable instead of `self.agent` mutation | 1 | 14 |
| **12** | A2A: empty default forwarded-state allowlist; VULN-8 MCP config validation | 3 | 8, 17 |

**Phase 1 alone** — adding real authentication — makes approximately half the Critical vulnerabilities require active exploitation of a second layer rather than being reachable from an unauthenticated HTTP request. It is the highest-leverage single change in the codebase.

**Phases 1–4** close all 10 Critical vulnerabilities and both SSRF vulnerabilities.

**Phases 1–6** close 22 of 27 vulnerabilities, including all High and Critical findings.

---

## What This Does Not Address

The following issues require decisions beyond code changes:

- **VULN-8 (RCE via MCP Stdio):** Whether users are ever permitted to supply MCP server configurations is a product decision. If yes, a strict schema validation and command allowlist are required. If no, the configuration surface must be locked to developers only.

- **VULN-17 / A2A state forwarding:** The A2A protocol specification may intentionally allow state forwarding between trusted agents. The remediation (allowlist of forwardable keys, default empty) changes the default behavior of the protocol. This requires coordination with the A2A spec and any interoperability partners.

- **VULN-26 (RAG client-side filtering):** Moving to server-side scope filtering requires a Vertex AI RAG API capability that may not currently exist. Until it does, the defense-in-depth fix (sanitized display names, encoding) reduces but does not eliminate the risk.
