# Security Report: Identity Leakage via Automatic Credential Forwarding

## Vulnerability Details
*   **Vulnerability:** Identity / Credential Leakage
*   **Vulnerability Type:** Security
*   **Severity:** Critical
*   **Source Locations:** 
    *   `src/google/adk/tools/api_registry.py` (Service Account Tokens)
    *   `src/google/adk/tools/mcp_tool/mcp_toolset.py` (User OAuth Tokens)
*   **Data Types:** Google Cloud Access Tokens, OAuth 2.0 Access Tokens

## Description
The ADK-Python framework automatically forwards sensitive authentication credentials to third-party MCP (Model Context Protocol) servers without validating the destination's identity or audience. This occurs in two primary areas:

### 1. Service Account Leakage (`ApiRegistry`)
When the `ApiRegistry` discovers an MCP server, it automatically retrieves the ADK's own environment credentials (the Service Account token) and attaches them as an `Authorization: Bearer` header to the connection parameters.

### 2. User OAuth Token Leakage (`McpToolset`)
When a user configures an MCP server that requires authentication, the `McpToolset` retrieves the user's exchanged OAuth 2.0 access token and attaches it to the request headers.

In both cases, if the MCP server URL is malicious or compromised, the attacker receiving the request will capture the raw access token.

## The Attack Scenario
1.  An attacker hosts a malicious MCP server (e.g., at `https://attacker.com/mcp`).
2.  The server is either registered in the GCP API Registry or configured manually by a user (e.g., via an agent config).
3.  The ADK initiates a connection/handshake with the attacker's server.
4.  The ADK automatically sends the `Authorization: Bearer <TOKEN>` header.
5.  The attacker captures the token and uses it to impersonate the ADK or the User, gaining access to their private Google Cloud data (BigQuery, GCS, etc.).

## Source Code Analysis

### In `src/google/adk/tools/api_registry.py`:
```python
# Line 100: Internal SA credentials are fetched and sent to unverified 'mcp_server_url'
headers = self._get_auth_headers()
return McpToolset(
    connection_params=StreamableHTTPConnectionParams(
        url=mcp_server_url,
        headers=headers, # <--- Leakage
    ),
    ...
)
```

### In `src/google/adk/tools/mcp_tool/mcp_toolset.py`:
```python
# Line 196: User's private OAuth tokens are forwarded to the MCP server
def _get_auth_headers(self) -> Optional[Dict[str, str]]:
    # ...
    if credential.oauth2:
      headers = {"Authorization": f"Bearer {credential.oauth2.access_token}"}
    return headers
```

## Impact
*   **Identity Theft:** Attackers can steal the identity of the application service account or the end-user.
*   **Data Exfiltration:** Attackers gain direct API access to the victim's GCP resources, bypassing all application-level controls.
*   **Lateral Movement:** Stolen tokens can be used to attack other services within the same cloud organization.

## Recommendation
1.  **Use ID Tokens with Audience Validation:** Generate Google OIDC Identity Tokens (ID Tokens) with the `target_audience` set to the specific URL of the MCP server. ID Tokens are audience-bound and cannot be replayed at different domains.
2.  **Strict Domain Whitelisting:** Implement a whitelist for trusted MCP server domains.
3.  **Prohibit Automatic Forwarding:** Credentials should only be sent if the developer has explicitly configured them for a specific, verified endpoint.
