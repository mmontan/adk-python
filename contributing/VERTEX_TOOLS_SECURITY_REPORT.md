# Security Report: Vertex AI Tools and Services Security Vulnerabilities

## Vulnerability Details
- **Vulnerability:** Multiple Security Issues in Vertex AI Tool and Service Integrations
- **Vulnerability Type:** Security / Privacy
- **Severity:** Medium (VULN-24, VULN-25, VULN-26)
- **Source Locations:**
  - `src/google/adk/tools/vertex_ai_search_tool.py`
  - `src/google/adk/sessions/vertex_ai_session_service.py` (line 212)
  - `src/google/adk/memory/vertex_ai_rag_memory_service.py` (lines 98-103, 116-129)

---

## Positive Finding: VertexAiSessionService.get_session() Correctly Verifies Ownership

Before documenting vulnerabilities, it is worth noting that `VertexAiSessionService.get_session()` (lines 175-178) **correctly** enforces session ownership:

```python
# vertex_ai_session_service.py:175-178
if get_session_response.user_id != user_id:
    raise ValueError(
        f'Session {session_id} does not belong to user {user_id}.'
    )
```

This is the right behavior and stands in contrast to the in-memory and database session services, which have the IDOR vulnerability documented in VULN-1. This check prevents an attacker who knows a victim's `session_id` from directly fetching the session via `get_session()` through the Vertex AI backend.

---

## VULN-24 (Medium): VertexAiSearchTool Shared Static Filter Enables Cross-User Document Exposure

**File:** `src/google/adk/tools/vertex_ai_search_tool.py`

### Description

`VertexAiSearchTool` is a shared instance on the cached `Runner` (see VULN-15 context). The default `_build_vertex_ai_search_config()` returns a `VertexAISearch` config built from `self.filter` — a value set once at construction time and never varied by user:

```python
# vertex_ai_search_tool.py:130-136
def _build_vertex_ai_search_config(self, readonly_context):
    return types.VertexAISearch(
        datastore=self.data_store_id,
        data_store_specs=self.data_store_specs,
        engine=self.search_engine_id,
        filter=self.filter,           # ← static, same for every user
        max_results=self.max_results,
    )
```

Because `Runner` is shared across all concurrent users, every user's search request uses the same filter expression. In a deployment where document access should be limited per user (e.g., `filter="acl_group = 'hr'"` to restrict HR documents), an attacker or an unauthorized user who shares the same agent receives the same filter and therefore the same document access.

### Insecure Docstring Pattern

The docstring example shows the intended override pattern to make filtering per-user:

```python
# vertex_ai_search_tool.py:54-60 — docstring example
class DynamicFilterSearchTool(VertexAiSearchTool):
    def _build_vertex_ai_search_config(self, ctx):
        user_id = ctx.state.get('user_id')
        return types.VertexAISearch(
            datastore=self.data_store_id,
            engine=self.search_engine_id,
            filter=f"user_id = '{user_id}'",   # ← single-quote wrapping, no escaping
            max_results=self.max_results,
        )
```

This example embeds `user_id` from session state using single-quote wrapping — the same injection pattern as VULN-22. A `user_id` containing a single quote (e.g., `alice' OR '1'='1`) would break out of the filter string context and potentially bypass the user-scoped filter entirely:

```
filter = "user_id = 'alice' OR '1'='1'"
```

The Vertex AI Search filter syntax supports logical operators, comparison operators, and function calls. Injecting `' OR '1'='1` removes the user restriction, causing all documents in the datastore to be returned regardless of `user_id`.

### Impact

- **Without subclassing:** All users of the same agent receive the same static filter — no per-user access control for Vertex AI Search results.
- **With the example subclass:** A developer following the documented pattern implements a filter that is vulnerable to injection if `user_id` contains single-quote characters.

### Severity: Medium (CWE-284 — Improper Access Control; CWE-89 for the injection pattern)

---

## VULN-25 (Medium): VertexAiSessionService list_sessions() Filter Injection

**File:** `src/google/adk/sessions/vertex_ai_session_service.py` — line 212

### Description

`list_sessions()` builds a Vertex AI REST API filter expression by directly interpolating `user_id` into a double-quoted filter string:

```python
# vertex_ai_session_service.py:211-212
if user_id is not None:
    config['filter'] = f'user_id="{user_id}"'
```

The Vertex AI Sessions API filter syntax is a structured expression language. Double quotes delimit string values. If `user_id` contains a `"` character or filter expression keywords, the filter can be escaped and broadened. For example:

**Crafted user_id:**
```
alice" OR user_id != "nobody
```

**Resulting filter sent to Vertex AI API:**
```
user_id="alice" OR user_id != "nobody"
```

This filter matches all sessions where `user_id` is `"alice"` OR `user_id` is anything other than `"nobody"` — i.e., effectively all sessions in the agent engine.

### Relationship to VULN-1 (IDOR)

In the web server's standard request flow, `user_id` comes from the HTTP path parameter (VULN-1 context). Since VULN-1 establishes that any caller can supply any `user_id`, this filter injection is an amplification: an attacker can already request sessions for arbitrary users one at a time (VULN-1), and with filter injection they can enumerate all sessions across all users in a single call.

### Impact

- **Session enumeration:** An attacker who can supply a crafted `user_id` receives a paginated list of all sessions in the agent engine, including `session_id` values, `user_id` values, and `session_state` for every user.
- **IDOR amplification:** Supplies the session IDs needed to exploit the IDOR vulnerability (VULN-1) at scale against arbitrary users.

### Severity: Medium (CWE-89 analogous — Filter/Query Injection; CWE-284 — Improper Access Control)

---

## VULN-26 (Medium): VertexAiRagMemoryService Client-Side Filtering with Dot-Unsafe Namespace

**File:** `src/google/adk/memory/vertex_ai_rag_memory_service.py`

### Description

This vulnerability has two related components.

#### Part A — Client-Side Isolation (All Users' Memories Retrieved Before Filtering)

When a user queries memory, `search_memory()` calls the RAG retrieval API without any server-side scope filtering. The API returns chunks from the entire corpus (all users, all apps), and user/app isolation is applied client-side:

```python
# vertex_ai_rag_memory_service.py:116-129
response = rag.retrieval_query(
    text=query,
    rag_resources=self._vertex_rag_store.rag_resources,
    # No scope filter passed here
)

# TODO: Add server side filtering by app_name and user_id.  ← acknowledged by devs
for context in response.contexts.contexts:
    if not context.source_display_name.startswith(f"{app_name}.{user_id}."):
        continue
```

The `TODO` comment confirms the developers are aware this is not a server-side filter. This means:

1. **All users' memory chunks are retrieved** from the RAG corpus on every search request.
2. **User-scoped isolation relies solely on `display_name`** prefix matching in Python.
3. A vector similarity match against another user's memory chunk will be fetched from the Vertex AI API, even if filtered out before being returned to the application. This creates an information leakage surface if API responses are logged or intercepted.

#### Part B — Dot-Unsafe Display Name Format Creates Namespace Collisions

Memory entries are stored with a display name in the format:
```python
# vertex_ai_rag_memory_service.py:103
display_name=f"{session.app_name}.{session.user_id}.{session.id}"
```

Isolation in `search_memory()` uses a `startswith` prefix:
```python
context.source_display_name.startswith(f"{app_name}.{user_id}.")
```

The dot (`.`) is both the delimiter in the display name format and a character that can appear in `app_name` and `user_id` values. This creates namespace collisions when either contains a dot:

**Scenario 1 — user_id containing a dot:**
- Legitimate user: `user_id = "alice"`, entries stored as `"myapp.alice.session1"`
- Attacker's user_id: `"alice.backdoor"`, entries stored as `"myapp.alice.backdoor.session1"`
- When searching for `user_id = "alice"`, filter is `startswith("myapp.alice.")`
- The attacker's entries match: `"myapp.alice.backdoor.session1".startswith("myapp.alice.")` → **True**
- The attacker's memory entries are injected into Alice's memory search results (prompt injection via memory poisoning)

**Scenario 2 — app_name containing a dot:**
- `app_name = "my.app"`, `user_id = "bob"`, `session_id = "s1"` → display_name `"my.app.bob.s1"`
- Filter: `startswith("my.app.bob.")` → correctly matches `"my.app.bob.s1"`
- However, an app named `"my"` with `user_id = "app.bob"` stores entries as `"my.app.bob.s1"` — identical display name
- The second app's data is returned to the first app's users

### Impact

- **Memory poisoning:** An attacker with `user_id = "alice.<something>"` can inject fabricated memory facts into Alice's future LLM context by embedding misleading content in their own memory store.
- **Cross-user/cross-app data leakage:** Namespace collisions with dots in `app_name` or `user_id` cause one user's memories to appear in another's search results.
- **Bulk retrieval:** Client-side filtering means the ADK process receives (but discards) all users' semantically relevant memory chunks before applying the scope filter — all memory content crosses the application boundary.

### Severity: Medium (CWE-284 — Improper Access Control; CWE-74 — Injection via namespace collision)

---

## VertexAiCodeExecutor — No Significant New Risk

`VertexAiCodeExecutor` executes LLM-generated code via the Vertex Code Interpreter Extension. While the executor instance is technically shared across users (via the shared `Runner`), the extension's `execute()` API call passes a per-invocation `session_id`, which provides server-side isolation. The shared reference to `_code_interpreter_extension` is stateless from ADK's perspective. No new cross-user vulnerability is introduced beyond those already documented for the shared Runner pattern (VULN-14).

---

## Summary

| VULN | Component | Risk | Core Issue |
|---|---|---|---|
| 24 | `VertexAiSearchTool` | Cross-user document exposure | Static filter shared across all users; example pattern teaches filter injection |
| 25 | `VertexAiSessionService.list_sessions()` | Session enumeration | `user_id` interpolated into filter expression without escaping |
| 26 | `VertexAiRagMemoryService` | Memory poisoning; cross-user leakage | Client-side filtering; dot-unsafe display name format |

---

## Recommendations

### VULN-24
- Remove the static `self.filter` path or document explicitly that it provides **no per-user isolation**.
- Fix the docstring example to use proper filter escaping. For Vertex AI Search filter strings, string values must have single quotes escaped as `\'`. Alternatively, use the `user_id` as a structured filter only when it has been validated to contain no filter expression metacharacters (`'`, `"`, `(`, `)`, `AND`, `OR`, `NOT`).
- Consider adding a `_build_vertex_ai_search_config` that takes the current `user_id` as a parameter by default, rather than relying on developers to override it.

### VULN-25
- Sanitize `user_id` before embedding in the filter, or use a structured filter builder that handles escaping. At minimum, replace or reject `"` characters in `user_id` before constructing the filter string.
- Example fix: `f'user_id="{user_id.replace(chr(34), "")}"'` (reject if escaping changes the value).

### VULN-26
- Pass `scope` (app_name and user_id) to `rag.retrieval_query()` if the Vertex RAG API supports it, or use a separate RAG corpus per user/app to achieve server-side isolation.
- Replace the dot-delimited display name format with a URL-encoded or base64-encoded scheme that cannot create namespace collisions: `f"{b64encode(app_name.encode()).decode()}.{b64encode(user_id.encode()).decode()}.{session_id}"`.
- Until server-side filtering is implemented, add a warning to the class documentation that all users' memories are fetched on every query.
