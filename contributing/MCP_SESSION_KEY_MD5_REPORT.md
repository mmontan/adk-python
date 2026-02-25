# Security Report: MD5 Used as MCP Session Pool Key

## Vulnerability Details
- **Vulnerability:** Use of Broken Cryptographic Hash (MD5) for Security-Sensitive Key Derivation
- **Vulnerability Type:** Security (CWE-328: Use of Weak Hash)
- **Severity:** Medium
- **Source Location:** `src/google/adk/tools/mcp_tool/mcp_session_manager.py` (line 265)
- **Data Types at Risk:** MCP client sessions carrying user authentication headers (Bearer tokens, API keys, Basic auth credentials)

## Description

The `MCPSessionManager` pools and reuses MCP client sessions keyed by a hash of the authentication headers sent to the MCP server. This pooling is the mechanism by which different users (with different credentials) are isolated into separate sessions.

The pool key is derived using MD5:

```python
# mcp_session_manager.py:263-266
if merged_headers:
    headers_json = json.dumps(merged_headers, sort_keys=True)
    headers_hash = hashlib.md5(headers_json.encode()).hexdigest()  # MD5
    return f'session_{headers_hash}'
```

MD5 has been cryptographically broken since 1996 and practical chosen-prefix collision attacks have been demonstrated against it. Using MD5 for a security boundary means an adversary who can control or influence header content can engineer a hash collision to bypass session isolation.

## The Security Boundary Being Protected

The session pool is a **security boundary**: it is the mechanism that ensures User A (with token `TOKEN_A`) gets a different MCP session than User B (with token `TOKEN_B`). If two different sets of headers produce the same MD5 hash, both users are served the same cached session — the session that was created first, with whichever user's credentials were used at that time.

## Attack Scenario

**Prerequisites:**
- The attacker (Mallory) can influence the value of at least one HTTP header sent to the MCP server. This is realistic in deployments where:
  - The `header_provider` derives headers from user-controlled input (e.g., a custom field, a user-set preference, a forwarded header)
  - The MCP server URL or connection params are partially user-controlled

**Steps:**
1. Mallory identifies the target: Alice's session was created with headers `{"Authorization": "Bearer ALICE_TOKEN"}`, which has MD5 hash `K_A`.
2. Mallory constructs a set of headers `H_M` (e.g., a crafted `Authorization` value or a crafted value in any header field she controls) such that `MD5(H_M) == K_A`. This is feasible using known MD5 collision techniques.
3. Mallory sends a request. The session manager computes `MD5(H_M) == K_A`, finds Alice's cached session in the pool, and returns it.
4. Mallory's MCP tool calls now execute on Alice's authenticated session.

**Result:** Mallory gains full access to Alice's MCP session and all resources/state accessible via Alice's token, without knowing Alice's token.

## Realistic Exploitation Difficulty

- **High-controlled-input scenarios (e.g., user supplies a custom header value):** Practical. MD5 chosen-prefix collisions can be computed in hours on commodity hardware.
- **Low-controlled-input scenarios (server controls all headers):** Low. Attacker would need to pre-image-attack MD5, which is not practically feasible.

The vulnerability is most dangerous in API-gateway deployments where the `header_provider` is fed by per-user metadata that users can partially influence.

## Supporting Evidence: Correct Usage Elsewhere in the Codebase

The same codebase correctly uses SHA-256 for a structurally identical key-derivation operation in `auth_tool.py`:

```python
# auth_tool.py:48 — uses SHA-256
return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()[:16]
```

The use of MD5 in `mcp_session_manager.py` is inconsistent with the security posture applied elsewhere and has no performance justification given the small input size (a JSON-serialized headers dict).

## Recommendation

Replace `hashlib.md5` with `hashlib.sha256` in `_generate_session_key()`:

```python
# mcp_session_manager.py:265 — proposed fix
headers_hash = hashlib.sha256(headers_json.encode()).hexdigest()
return f'session_{headers_hash}'
```

This is a one-line change with no functional impact. SHA-256 is already imported (transitively) and used elsewhere in the project.

## Additional Defense-in-Depth Measures

Even after switching to SHA-256, the session pool design relies on headers being a sufficient proxy for user identity. Consider:

1. **Explicit user-scoped session keys:** Include a user ID or session ID in the pool key rather than relying solely on the headers hash.
2. **Short session TTLs:** Expire and recreate sessions after a configurable timeout to limit the window during which a stale session could be accessed.
3. **Per-invocation sessions for sensitive operations:** For high-security deployments, avoid session pooling entirely and create a fresh MCP session for each agent invocation.
