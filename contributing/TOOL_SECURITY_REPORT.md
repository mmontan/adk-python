# Security Audit Report: Tool-Specific Vulnerabilities in ADK-Python

This report identifies critical security vulnerabilities specifically within the **Tools and Toolsets** architecture of the Agent Development Kit (ADK) for Python. These issues primarily stem from the reuse of stateful Python objects across different authenticated users.

---

### 1. Persistent Instance State Leakage (Cross-User Data Leakage)
- **Vulnerability:** Shared State / Object Singleton
- **Vulnerability Type:** Security/Privacy
- **Severity: Critical**
- **Location:** `src/google/adk/tools/` (Impacts all tools storing data in `self`)
- **Description:** Because `AdkWebServer` caches `Runner` instances, the underlying `Tool` objects are effectively singletons for the life of the server. Any tool that stores request-specific data in `self` (instance variables) instead of returning it will leak that data to the next user.
- **Specific Example:** The `PlaywrightComputer` sample stores the active browser page in `self._page`.
    - **Impact:** If User A opens a private dashboard, and User B subsequently asks for a screenshot, User B will receive a screenshot of **User A's private dashboard**. This is a direct, critical privacy violation.
- **Recommendation:** Tools must be stateless. All execution-specific state must be stored in the `ToolContext` or returned as part of the tool response. ADK should ideally instantiate tools per-request or provide a "factory" pattern for stateful tools.

### 2. Authentication Credential Race Condition
- **Vulnerability:** Concurrent Shared State Modification
- **Vulnerability Type:** Security
- **Severity: Critical**
- **Location:** `src/google/adk/flows/llm_flows/base_llm_flow.py` (method `_resolve_toolset_auth`)
- **Description:** When an agent uses a toolset with OAuth/API keys, the `base_llm_flow` fetches the user's credential and stores it in the shared toolset instance: `auth_config.exchanged_auth_credential = credential`.
- **Impact:** If User A and User B make concurrent requests to the same agent, User B's request might overwrite the shared `auth_config` with their own token while User A's tool is still executing. User A's tool call will then execute using **User B's identity/permissions**, or vice-versa.
- **Recommendation:** Authentication credentials must never be stored in the Tool/Toolset instance variables. They should be passed as arguments to the `get_tools()` and `run_async()` methods.

### 3. Insecure Default Telemetry (Sensitive Data Exposure)
- **Vulnerability:** Excessive Logging of PII/Secrets
- **Vulnerability Type:** Privacy/Security
- **Severity: High**
- **Location:** `src/google/adk/telemetry/tracing.py`
- **Description:** ADK is configured by default to capture all tool arguments (`tool_call_args`) and responses (`tool_response`) into OpenTelemetry spans.
- **Impact:** If a tool processes a password, credit card number, or SSN, that data is sent in **plain text** to the tracing backend (e.g., Google Cloud Trace, Honeycomb). This violates most data privacy regulations (GDPR, CCPA) and exposes secrets to anyone with access to the monitoring logs.
- **Recommendation:** Change the default value of `ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS` to `false`. Implement a masking or allow-list mechanism so developers must explicitly opt-in specific fields for tracing.

### 4. Global "App-Scoped" State Collision
- **Vulnerability:** Shared Memory / Broken Isolation
- **Vulnerability Type:** Security
- **Location:** `src/google/adk/sessions/in_memory_session_service.py`
- **Description:** The `InMemorySessionService` maintains an `app_state` dictionary that is shared across all users of an application name. Tools can read/write to this via `ctx.state['app:key']`.
- **Impact:** While intended for "global config," developers often use it for temporary caches. In a multi-user environment, User A's logic can be corrupted by User B's data if they both use the same "app-scoped" keys. 
- **Recommendation:** Clearly document the risks of `app_state`. In the `InMemorySessionService` (used for testing), provide a "strict mode" that warns when cross-user state is being modified.

---
**Summary Assessment:** The ADK tool architecture currently lacks "User-Safety" guarantees. It is optimized for local developer productivity where "one runner = one user." In a production web deployment, these design choices result in critical vulnerabilities where user identities, private screens, and sensitive data are systematically shared across the request boundary.
