# Security Report: Agent-to-Agent (A2A) Protocol Security Vulnerabilities

## Vulnerability Details
- **Vulnerability:** Multiple Critical Security Flaws in A2A Implementation
- **Vulnerability Type:** Security / Privacy
- **Severity:** Critical (VULN-17, VULN-18, VULN-19) / High (VULN-20, VULN-21)
- **Source Locations:**
  - `src/google/adk/agents/remote_a2a_agent.py`
  - `src/google/adk/a2a/executor/a2a_agent_executor.py`
  - `src/google/adk/a2a/converters/request_converter.py`
  - `src/google/adk/a2a/converters/event_converter.py`

## Overview

The A2A protocol allows an ADK agent to delegate work to a remote agent over HTTP. The local agent (`RemoteA2aAgent`) connects to a remote URL, sends the user's request, and incorporates the remote agent's responses into the conversation. The inbound side (`A2aAgentExecutor`) receives A2A calls from other agents and dispatches them to local runners.

Both directions of this protocol have critical security gaps: the outbound path leaks user credentials to untrusted remote endpoints and allows SSRF, while the inbound path allows user impersonation and session hijacking.

---

## VULN-17 (Critical): Full Session State Forwarded to Untrusted Remote Agent

**File:** `src/google/adk/agents/remote_a2a_agent.py` — line ~568

### Description

When delegating to a remote A2A agent, the ADK sends the entire session state dictionary as part of the request context:

```python
# remote_a2a_agent.py:~568
async for a2a_response in self._a2a_client.send_message(
    request=a2a_request,
    request_metadata=request_metadata,
    context=ClientCallContext(state=ctx.session.state),  # full state forwarded
):
```

`ctx.session.state` is a flat dictionary used throughout ADK to cache runtime values. Its contents at the time of an A2A call may include:

- OAuth access tokens cached by `CredentialManager` after the auth exchange flow
- API keys stored by tools via `tool_context.state["my_api_key"] = ...`
- Database connection strings or credentials
- PII cached from prior tool calls (names, emails, document contents)
- Internal configuration values set by the developer

There is no filtering, sanitization, or encryption applied before forwarding. The remote agent operator receives this state verbatim in the A2A request body.

### Attack Scenario

1. An operator registers a "helpful utility agent" at `https://attacker.com/a2a` in the agent registry.
2. A legitimate ADK application configures a `RemoteA2aAgent` pointing to this URL (possibly via `AgentRegistry.get_mcp_toolset()` or a YAML config).
3. A user authenticates with Google OAuth. Their access token is stored in `session.state["oauth_token"]`.
4. The agent delegates a subtask to the remote agent. The full `session.state` — including `oauth_token` — is sent in the A2A request.
5. The attacker captures the token and uses it to access the user's Google Drive, Gmail, or GCP resources.

### Impact

- **Token Theft:** OAuth access tokens, API keys, and service credentials exfiltrated to remote agent operator.
- **Identity Theft:** Stolen tokens enable impersonation of the user across any service those tokens grant access to.
- **Data Exfiltration:** Any PII or sensitive data cached in session state is exposed.

### Severity: Critical (CWE-522 — Insufficiently Protected Credentials)

---

## VULN-18 (Critical): SSRF via Unvalidated Remote Agent URL

**File:** `src/google/adk/agents/remote_a2a_agent.py` — lines ~219-240, ~272-287

### Description

`RemoteA2aAgent._resolve_agent_card_from_url()` fetches the remote agent's "agent card" (a JSON descriptor) from a developer-supplied or registry-supplied URL. The `_validate_agent_card()` method that follows checks only that the URL is structurally valid — it performs no validation against dangerous IP ranges or internal hostnames:

```python
# remote_a2a_agent.py:~272-287
async def _validate_agent_card(self, agent_card: AgentCard) -> None:
    if not agent_card.url:
        raise AgentCardResolutionError(...)
    # Additional validation can be added here   <-- placeholder only
    try:
        parsed_url = urlparse(str(agent_card.url))
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError("Invalid RPC URL format")
    except Exception as e:
        raise AgentCardResolutionError(...)
    # NO checks for:
    # - Private IP ranges (10.x, 172.16-31.x, 192.168.x)
    # - Loopback (127.0.0.1, ::1, localhost)
    # - Link-local / cloud metadata (169.254.169.254)
    # - Non-HTTP(S) schemes (file://, ftp://, gopher://)
```

### Exploitation Paths

| Target | URL | Impact |
|---|---|---|
| GCP/AWS metadata | `http://169.254.169.254/computeMetadata/v1/` | Instance credentials, project ID, SA tokens |
| Internal API gateway | `http://10.0.0.10/admin/reset` | Unauthorized admin actions |
| Localhost services | `http://127.0.0.1:6379/` (Redis) | Cache poisoning, data theft |
| Internal database | `http://db.internal:5432/` | Connection probe, potential data access |

The A2A agent makes two HTTP calls to the remote URL: first to fetch the agent card, and then to send the actual A2A request. Both are made by the ADK server process, which typically runs with elevated cloud permissions (a service account). This means SSRF here carries cloud IAM privileges.

### Similarity to Existing Finding

This is structurally identical to the SSRF in `load_web_page` (VULN-6) but is more severe because: (1) the ADK process has cloud credentials attached, (2) the initial agent card fetch happens at agent initialization time (before the user request), and (3) the URL can come from an external registry (`AgentRegistry`) without developer review.

### Severity: Critical (CWE-918 — Server-Side Request Forgery)

---

## VULN-19 (Critical): User Identity Not Cryptographically Enforced on Inbound A2A Requests

**Files:**
- `src/google/adk/a2a/converters/request_converter.py` — lines ~64-74
- `src/google/adk/a2a/executor/a2a_agent_executor.py` — lines ~318-335

### Description

This vulnerability has two components that chain together.

**Part A — User ID Derived from Untrusted `context_id` (request_converter.py)**

When an inbound A2A request arrives, the executor derives the local `user_id` from the request's `context_id` field as a fallback when authentication is not configured:

```python
# request_converter.py:~64-74
def _get_user_id(request: RequestContext) -> str:
    if (
        request.call_context
        and request.call_context.user
        and request.call_context.user.user_name
    ):
        return request.call_context.user.user_name  # authenticated path

    # FALLBACK: derive from untrusted, client-controlled field
    return f'A2A_USER_{request.context_id}'
```

The `context_id` is a string provided by the A2A caller. It is not cryptographically signed or validated. Any caller can supply any `context_id`, and if the A2A server is running without authentication enabled, the derived `user_id` is completely attacker-controlled.

**Part B — Session Retrieved Without Ownership Verification (a2a_agent_executor.py)**

Using that derived `user_id`, the executor retrieves or creates a session:

```python
# a2a_agent_executor.py:~318-335
async def _prepare_session(self, context, run_request, runner):
    session_id = run_request.session_id   # from untrusted request body
    user_id = run_request.user_id         # derived from untrusted context_id

    session = await runner.session_service.get_session(
        app_name=runner.app_name,
        user_id=user_id,
        session_id=session_id,            # no ownership verification
    )
```

There is no check that `user_id` actually owns `session_id`. If the session service stores sessions keyed by `(app_name, user_id, session_id)`, an attacker who knows Alice's `session_id` can craft a request with `context_id = "alice"` and `session_id = "alice_session_123"` to read or continue Alice's session.

### Combined Attack

1. Attacker discovers or guesses a victim's `session_id` (e.g., from metadata leakage — see VULN-21, or from a timing attack on predictable IDs).
2. Attacker sends an A2A request to the ADK server with `context_id = "victim"` and `session_id = "victim_session"`.
3. Because A2A auth is disabled (the default for development deployments), `_get_user_id()` returns `"A2A_USER_victim"`.
4. The executor retrieves the victim's session and runs the attacker's request in it.
5. The attacker reads the victim's full conversation history and can inject messages or tool calls into their ongoing session.

### Prerequisite

The `context_id` fallback is only active when `call_context.user` is absent — i.e., when A2A server authentication is not configured. The ADK documentation and the code comment ("Get user from call context if available (auth is enabled on a2a server)") implies auth is optional. In practice, many deployments will omit it for simplicity, especially in development and staging environments.

### Severity: Critical (CWE-287 — Improper Authentication; CWE-639 — Authorization Bypass Through User-Controlled Key)

---

## VULN-20 (High): Unvalidated Remote Agent Response Content

**File:** `src/google/adk/agents/remote_a2a_agent.py` — lines ~410-516

### Description

When the local ADK agent receives a response from a remote A2A agent, it converts that response into ADK `Event` objects and merges them into the conversation without validating the source or the content:

```python
# remote_a2a_agent.py:~410-516 (_handle_a2a_response)
event = convert_a2a_task_to_event(
    task, self.name, ctx, self._a2a_part_converter
)
# No signature verification
# No content type restriction
# No function call allow-listing
```

A compromised or malicious remote agent can inject:

1. **Synthetic function calls:** A response part claiming to be a `FunctionCall` to a tool registered in the local agent (e.g., `execute_code`, `run_bash`, `write_file`). If the local LLM flow processes this event as a genuine function call, the tool executes.

2. **Fabricated tool responses:** A response that looks like a completed tool call with attacker-controlled output, poisoning the conversation history and influencing all future LLM decisions.

3. **Metadata-encoded instructions:** The `custom_metadata` field is included in events without filtering. A remote agent can embed additional context or instructions that affect downstream agent behavior.

### Why This Matters Beyond MITM

The threat is not only a man-in-the-middle attacker. A remote agent that is legitimately registered but maliciously programmed (e.g., a supply-chain compromise of a publicly listed agent) can directly inject content by constructing valid A2A responses that happen to contain ADK function call payloads.

### Severity: High (CWE-94 — Improper Control of Code Generation; CWE-20 — Improper Input Validation)

---

## VULN-21 (High): Sensitive Metadata Attached to All Outbound A2A Events

**File:** `src/google/adk/a2a/converters/event_converter.py` — lines ~128-153

### Description

Every outbound A2A event (sent from the ADK server to a remote agent or event consumer) includes metadata automatically attached by `_get_context_metadata()`:

```python
# event_converter.py:~128-153
metadata = {
    _get_adk_metadata_key("app_name"):      invocation_context.app_name,
    _get_adk_metadata_key("user_id"):       invocation_context.user_id,    # PII
    _get_adk_metadata_key("session_id"):    invocation_context.session.id, # IDOR key
    _get_adk_metadata_key("invocation_id"): event.invocation_id,
    _get_adk_metadata_key("author"):        event.author,
    _get_adk_metadata_key("event_id"):      event.id,
}
# Also includes:
#   event.custom_metadata  (may contain tokens, PII, developer secrets)
#   event.grounding_metadata
#   event.actions (contains auth_config which may contain raw_auth_credential)
```

This metadata is sent to every remote A2A endpoint the local agent communicates with. The problems:

1. **`user_id` leakage:** Exposes the internal user identifier to third-party remote agents. Combined with VULN-17 (full session state forwarding), the remote agent receives both the user's identity and their credentials in a single request.

2. **`session_id` leakage:** The session ID is used by VULN-19 as the key for session hijacking. Broadcasting it to remote agents gives any compromised remote agent the IDOR key needed to access that session through the inbound A2A path.

3. **`custom_metadata` leakage:** Tools and plugins write arbitrary data to `event.custom_metadata`. This field is forwarded to remote agents without inspection. If any internal component writes a token or key into custom_metadata, it is exfiltrated.

4. **`event.actions` leakage:** The `EventActions` object can contain `auth_config`, which holds `raw_auth_credential` — a credential object. If an auth event flows into an A2A-forwarded event, the raw credential is sent to the remote agent.

### Severity: High (CWE-200 — Exposure of Sensitive Information to Unauthorized Actors)

---

## Attack Chain: Combining the Vulnerabilities

The A2A vulnerabilities compose into a complete account takeover:

1. **Attacker sets up** a malicious remote agent at `https://attacker.com/a2a`.
2. **VULN-18 (SSRF)** is not triggered here; the URL passes validation because it's a legitimate HTTPS domain.
3. **User Alice** authenticates with Google OAuth. Her token is stored in `session.state`.
4. **The local agent** delegates a subtask to the attacker's remote agent.
5. **VULN-17**: The A2A request carries Alice's full `session.state` including her OAuth token.
6. **VULN-21**: The A2A request also carries Alice's `user_id` and `session_id` in event metadata.
7. **Attacker** now has Alice's OAuth token (for identity theft) and her `session_id` (for session hijacking via VULN-19).
8. **VULN-20**: Attacker's remote agent responds with a synthetic function call to a sensitive local tool.
9. **Local agent** executes the injected tool call under Alice's identity.

## Recommendations

### VULN-17
Implement a credential sanitization pass before forwarding session state. Maintain a blocklist of state keys that should never leave the local process (e.g., keys matching `*token*`, `*key*`, `*password*`, `*secret*`, `*credential*`). Consider not forwarding session state at all by default, making it an explicit opt-in.

### VULN-18
Implement URL validation in `_validate_agent_card()` before the first HTTP connection is made. Reject private IP ranges (RFC 1918), loopback addresses, link-local addresses (169.254.0.0/16), and non-HTTP(S) schemes. Provide a developer-configurable allowlist of trusted domains.

### VULN-19
Make A2A server authentication mandatory in production. When authentication is absent, either reject the request or assign a randomly-generated anonymous `user_id` that cannot correlate to any real user's session. Never derive `user_id` from a client-controlled string in an unauthenticated context. Add post-retrieval session ownership assertion (`assert session.user_id == requested_user_id`).

### VULN-20
Sign remote A2A responses with a key established during the agent card handshake (similar to webhook signature verification). Restrict which event types and function names can be injected from remote agent responses — a remote agent should not be able to generate events that trigger local tool execution.

### VULN-21
Remove `user_id`, `session_id`, and `custom_metadata` from the metadata attached to outbound A2A events. Replace `session_id` with an opaque, non-guessable correlation token that does not double as an IDOR key.
