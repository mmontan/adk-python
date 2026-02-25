# Security Report: Shared Mutable State in Runner Causes Cross-User Contamination

## Vulnerability Details
- **Vulnerability:** Multiple Concurrent Shared State Mutations
- **Vulnerability Type:** Security / Privacy
- **Severity:** Critical (VULN-14, VULN-15) / Major (VULN-16)
- **Source Locations:**
  - `src/google/adk/runners.py` (lines ~126, ~194-197, ~1361, ~1368)
  - `src/google/adk/agents/invocation_context.py` (line ~359)
  - `src/google/adk/cli/adk_web_server.py` (line ~527)
- **Root Cause:** One `Runner` instance is cached per app and shared across all concurrent users

## Architectural Context

The `AdkWebServer` caches one `Runner` per `app_name` and serves all users from it:

```python
# adk_web_server.py:~527
async def get_runner_async(self, app_name: str) -> Runner:
    if app_name in self.runner_dict:
        return self.runner_dict[app_name]  # same Runner for every user
```

The `Runner` holds direct references to shared objects: `self.agent`, `self.plugin_manager`, `self.artifact_service`, `self.memory_service`, `self.credential_service`. Each concurrent user invocation receives references to these same objects. This design is intentional for performance, but three of these shared objects have security-critical mutation patterns.

---

## VULN-14 (Medium): Shared Agent Object Mutated During `support_cfc` Initialization

**File:** `src/google/adk/runners.py` — approximately line 1361

### Description

When a `RunConfig` with `support_cfc=True` is used, the runner mutates the shared agent object in-place:

```python
# runners.py:1353-1361 — within _new_invocation_context()
if run_config.support_cfc and hasattr(self.agent, 'canonical_model'):
    ...
    if not isinstance(self.agent.code_executor, BuiltInCodeExecutor):
        self.agent.code_executor = BuiltInCodeExecutor()  # writes to shared self.agent
```

`self.agent` is the same instance used by every concurrent user of the Runner.

### Exploitability Qualification

**Important:** The standard `adk_web_server.py` API endpoints construct `RunConfig` internally and do not expose `support_cfc` to end users:

```python
# adk_web_server.py:1589 — user requests cannot set support_cfc
run_config=RunConfig(streaming_mode=stream_mode)
```

This mutation is therefore **developer-triggered**, not directly exploitable by an end user through the standard web interface. It is reached only when a developer uses the `Runner` Python API directly and passes `RunConfig(support_cfc=True)`.

### Why It Remains a Valid Design Defect

The mutation is still architecturally wrong because:

1. **No locking:** The write to `self.agent.code_executor` is unsynchronized. If `support_cfc=True` is used in one concurrent call while another call is mid-execution and reading `self.agent.code_executor`, there is a data race.
2. **Permanent state change:** Once triggered, all subsequent invocations — including those that do not use `support_cfc` — run against the modified agent. The developer's original `code_executor` configuration is silently discarded.
3. **Precedent pattern:** If future code paths add similar mutations of `self.agent` triggered by user-controllable `RunConfig` fields, the same design allows those to become user-exploitable without any additional access control change.

### Impact

- Silent, permanent modification of agent configuration for all users after the first `support_cfc=True` invocation.
- Concurrent race condition on `self.agent.code_executor` if multiple invocations reach this code simultaneously.

### Severity: Medium (CWE-362 — Race Condition on Shared Resource; design defect, not directly user-exploitable via web API)

---

## VULN-15 (Critical): Shared `PluginManager` Exposes All Users' Invocation Contexts to Plugins

**File:** `src/google/adk/runners.py` — approximately lines 126, 1368

### Description

The single `PluginManager` instance created at Runner startup is passed into every `InvocationContext`:

```python
# runners.py:~126
self.plugin_manager = PluginManager(plugins=plugins, ...)

# runners.py:~1368 — inside _new_invocation_context()
return InvocationContext(
    ...
    plugin_manager=self.plugin_manager,  # same instance for all users
)
```

Plugin hooks receive the full `InvocationContext` which contains `user_id`, `session.state`, `session.events`, and all agent state for the current invocation. If any plugin accumulates state across calls — even inadvertently via a simple instance variable — it becomes a cross-user data channel.

The built-in plugins that are highest risk under this model:

- **`global_instruction_plugin.py`** — modifies instructions for every user; shared state here affects all users simultaneously.
- **`context_filter_plugin.py`** — filters context visible to the agent; a stateful bug here changes what all users see.
- **`bigquery_agent_analytics_plugin.py`** — accumulates analytics; may correlate users across sessions.
- **`save_files_as_artifacts_plugin.py`** — writes artifacts; shared state could misdirect writes.

### Minimal Proof of Concept (Inadvertent Leakage Pattern)

```python
class LoggingPlugin(BasePlugin):
    def __init__(self):
        self.last_user_id = None   # instance variable — shared across all invocations

    async def before_run(self, ctx):
        self.last_user_id = ctx.user_id  # written during User A's request

    async def after_run(self, ctx):
        # During User B's request, self.last_user_id still == User A's ID
        logger.info(f"Previous user: {self.last_user_id}")  # leaks User A's identity to logs
```

### Impact

- Any plugin with instance-level state leaks data between users.
- A malicious plugin (installed by an operator) can passively collect every user's `user_id`, session state, tool outputs, and conversation history.
- There is no isolation mechanism between one user's plugin execution and another's.

### Severity: Critical (CWE-362, CWE-863 — Incorrect Authorization)

---

## VULN-16 (Major): Branch-Based Event Isolation Defaults to Off in Multi-Agent Hierarchies

**File:** `src/google/adk/agents/invocation_context.py` — approximately line 359

### Description

In multi-agent hierarchies, each agent branch is assigned a unique branch identifier to prevent sibling agents from seeing each other's conversation history. However, the internal `_get_events()` method defaults to returning the full, unfiltered event stream:

```python
# invocation_context.py
def _get_events(
    self,
    *,
    current_invocation: bool = False,
    current_branch: bool = False,  # DEFAULTS TO FALSE — no branch filtering
) -> list[Event]:
    results = self.session.events
    if current_invocation:
        results = [e for e in results if e.invocation_id == self.invocation_id]
    if current_branch:   # only applied if explicitly requested
        results = [e for e in results if e.branch == self.branch]
    return results
```

Any agent that calls `_get_events()` without explicitly passing `current_branch=True` receives the entire session event history — including events from all sibling agents in the hierarchy.

### Attack Scenario

```
Coordinator
├── ResearchAgent  (branch: root.research)  — searches for sensitive documents
└── SummaryAgent   (branch: root.summary)   — summarizes findings
```

If `SummaryAgent` calls `_get_events()` without `current_branch=True`, it sees `ResearchAgent`'s full history. In a more targeted scenario: a sub-agent expressly designed to extract sibling context can call this method to harvest another agent's tool outputs, retrieved credentials, or PII.

This is especially dangerous because the branch model is the **primary isolation mechanism** in multi-agent deployments. Its opt-in rather than opt-out design means any agent that doesn't call it correctly — including all third-party or user-supplied agents — silently gets full cross-branch visibility.

### Impact

- Sibling agents can observe each other's complete conversation history, tool calls, and tool responses.
- In agentic pipelines where different agents handle different users' data, this creates cross-user data leakage at the orchestration layer.
- Agent-level privacy boundaries (e.g., "Agent A handles HR data, Agent B handles Finance") are not enforced.

### Severity: Major (CWE-200 — Information Exposure)

---

## Relationship to Existing Findings

VULN-14 and VULN-15 amplify the previously documented **Auth Credential Race Condition** (`AUTH_RACE_CONDITION_REPORT.md`). That report identified the toolset `auth_config` as a shared mutation point. This report identifies two additional shared mutation points — `self.agent` and `self.plugin_manager` — that sit at a higher level in the call stack, making them harder to fix incrementally.

## Remediation

### VULN-14
Replace the in-place mutation with a per-invocation copy of the agent:
```python
# Conceptual fix — requires full design review
import copy
invocation_agent = copy.copy(self.agent)
if not isinstance(invocation_agent.code_executor, BuiltInCodeExecutor):
    invocation_agent.code_executor = BuiltInCodeExecutor()
```
Alternatively, move the `support_cfc` check into the flow layer using a local variable rather than mutating the agent object.

### VULN-15
Create a `PluginManager` per invocation (or enforce that all registered plugins are stateless):
```python
# Conceptual fix
plugin_manager = self.plugin_manager.create_scoped_instance(invocation_id)
```
At minimum, document that plugins MUST NOT store instance-level state, and add a CI lint or test check to detect instance variables in plugin subclasses.

### VULN-16
Invert the default: make branch filtering opt-out rather than opt-in:
```python
def _get_events(
    self,
    *,
    current_invocation: bool = False,
    current_branch: bool = True,   # default to True for safe behavior
) -> list[Event]:
```
Audit all callers of `_get_events()` to confirm they behave correctly under the new default.
