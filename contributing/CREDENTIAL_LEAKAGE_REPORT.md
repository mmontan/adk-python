# Security Report: Identity Leakage via Automatic Credential Forwarding in ApiRegistry

## Vulnerability Details
*   **Vulnerability:** Identity / Credential Leakage
*   **Vulnerability Type:** Security
*   **Severity:** Critical
*   **Source Location:** `src/google/adk/tools/api_registry.py`
*   **Data Type:** Google Cloud Access Token (Bearer Token)

## Description
The `ApiRegistry` service is designed to discover and connect to MCP (Model Context Protocol) servers. When it discovers a server, it automatically retrieves the ADK's own environment credentials (using `google.auth.default()`) and attaches them as an `Authorization: Bearer` header to all outgoing requests to that server.

The core vulnerability is that these credentials—which represent the **full identity and permissions of the ADK service account**—are sent to the destination URL without any validation of the target's identity or audience.

### The Attack Scenario
1.  An attacker registers a malicious MCP server in the Google Cloud API Registry (or a legitimate entry is compromised to point to an attacker-controlled domain).
2.  The ADK application, using `ApiRegistry`, discovers this server.
3.  The ADK automatically initiates a connection to `https://attacker-controlled-domain.com`.
4.  In the first request (handshake), the ADK sends its own Service Account access token in the `Authorization` header.
5.  The attacker captures the token and uses it to impersonate the ADK, gaining access to any Google Cloud resources the ADK is authorized to use (e.g., BigQuery, Cloud Storage, Vertex AI).

## Source Code Analysis
In `src/google/adk/tools/api_registry.py`:

```python
# Line 99: URL is retrieved from the registry
mcp_server_url = server["urls"][0]

# Line 100: Internal SA credentials are fetched
headers = self._get_auth_headers()

# Line 106: The token is attached to the connection parameters
return McpToolset(
    connection_params=StreamableHTTPConnectionParams(
        url=mcp_server_url,
        headers=headers, # <--- Leakage occurs here
    ),
    ...
)
```

## Impact
*   **Full Service Account Compromise:** An attacker can steal the ADK's identity and perform any action the service account is permitted to do.
*   **Data Exfiltration:** If the ADK has access to sensitive data (e.g., in BigQuery or GCS), the attacker can use the stolen token to download that data directly from the GCP APIs, bypassing all ADK-level logging or controls.
*   **Lateral Movement:** The stolen token can be used to access other internal Google Cloud services within the same project or organization.

## Recommendation
1.  **Use ID Tokens with Audience Validation:** Instead of sending an Access Token, the ADK should generate a Google OIDC Identity Token (ID Token) with the `target_audience` set specifically to the URL of the MCP server. This ensures the token is useless if sent to a different domain.
2.  **Domain Whitelisting:** Implement a strict whitelist of trusted domains for the API Registry. The ADK should refuse to send credentials to any domain not explicitly trusted by the administrator.
3.  **Manual Credential Management:** Do not automatically forward environment credentials. Require the developer to explicitly configure authentication for each discovered toolset if authentication is required.
