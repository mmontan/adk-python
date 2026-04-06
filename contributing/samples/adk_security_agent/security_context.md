# ADK-Specific Security Context

This file is injected into the security agent's system prompt to give it
repo-specific architectural knowledge. Replace or extend this file when
deploying the agent against a different repository.

---

## ADK Architecture Security Highlights

### 1. Shared Runner State (Critical Risk Area)
- `runners.py` is a **1530-line stateless orchestration engine** but uses
  module-level caches and shared objects (e.g., tool registries, model
  clients). Watch for new class-level or module-level mutable dicts/lists that
  accumulate per-request data.
- Any `@staticmethod` or class-level cache on `Runner`, `LlmAgent`, or
  `BaseAgent` that stores invocation-scoped data is a cross-user leak.

### 2. Session / State Isolation
- `Session.state` is the per-user key-value store. If a tool writes to
  `ctx.session.state` using a key derived from user input without namespacing,
  one user can overwrite another's state.
- `InvocationContext` is created fresh per invocation — but services
  (`SessionService`, `MemoryService`, `ArtifactService`) are shared singletons.
  Look for service-level caches keyed without `user_id` or `app_name`.

### 3. Tool Ecosystem (tools/ — 52 files)
- **BigQuery / Spanner tools**: GQL and SQL are constructed via string
  interpolation. Any new tool accepting user-provided table names, column
  names, or filter expressions is an injection risk.
- **Vertex AI tools**: API calls to `aiplatform` endpoints. Watch for
  user-controlled `endpoint_id` or `location` values forwarded without
  validation (SSRF/confused-deputy risk).
- **MCP tools** (`mcp_tool/`): Tool invocations cross trust boundaries.
  Prompt injection via MCP server responses flowing back into the agent's
  instruction context is a concern.
- **Code executor** (`code_executors/`): Sandboxed, but watch for new
  executor implementations that bypass the sandbox.

### 4. A2A Protocol (`a2a/`)
- Agent-to-Agent messages arrive from external agents. Treat `a2a` message
  payloads as **untrusted input**. Prompt injection in `message.content` can
  hijack the receiving agent's behavior.
- Authentication of peer agents relies on tokens — watch for new endpoints
  that skip token validation.

### 5. Credential / Auth Flows (`auth/`)
- OAuth tokens stored in `session.state` under predictable keys could be
  read by another session if isolation fails.
- New credential service implementations that cache tokens at class level
  (not per `user_id`) are a cross-user token exposure risk.

### 6. FastAPI / CLI Server (`cli/fast_api.py`, `cli/adk_web_server.py`)

Both files contribute routes to the same served app. `fast_api.py` is used
directly by `adk deploy cloud_run` and any caller of `get_fast_api_app()`;
routes registered there are **reachable in production** unless explicitly
gated. Always audit both files together.

**When either file is in the diff, perform a route surface audit:**

1. Extract every `@app.get/post/put/delete/patch` line added in the diff.
2. For each new route, check:
   - **Auth**: is there a `Depends(...)` call in the function signature?
     Absence of auth on a route that touches files, sessions, or user data
     is at minimum High severity.
   - **Blast radius**: does the handler body call `open()`, `shutil`,
     `Path.write_*` / `Path.unlink`, `os.remove`, `subprocess`, or
     `importlib`? File-write + no auth = Critical (unauthenticated RCE
     vector in an agent framework that imports Python from the agents dir).
   - **Always registered?**: is the route inside an `if web:`, `if debug:`,
     or similar guard, or registered unconditionally? An unconditional
     file-write route is a production attack surface regardless of
     documented intent.
3. Flag WIP/experimental promotions: if the diff removes a `WIP`, `debug`,
   `experimental`, or feature-flag guard from a route handler, treat the
   route as newly exposed and apply the three checks above.

**Other CLI server concerns:**
- Endpoints that proxy user-controlled URLs without an allowlist (SSRF).
- File-read endpoints that return raw content without path canonicalization.
- Debug/verbose response modes defaulting to on.

### 7. Evaluation Framework (`evaluation/`)
- Eval datasets may contain user-supplied content. Template injection in
  judge prompts built from eval data is a risk.

### 8. Sensitive File Paths to Scrutinize
When the diff touches these paths, always call `get_file_content` for the
full file before completing the analysis:
- `src/google/adk/runners.py`
- `src/google/adk/tools/` (any file)
- `src/google/adk/auth/`
- `src/google/adk/sessions/`
- `src/google/adk/a2a/`
- `src/google/adk/cli/fast_api.py`
- `src/google/adk/cli/adk_web_server.py`
- `src/google/adk/code_executors/`
