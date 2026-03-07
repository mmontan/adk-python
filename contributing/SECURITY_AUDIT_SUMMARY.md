# ADK-Python Security Audit Summary

This document summarizes the findings of a comprehensive security audit of the ADK-Python framework, conducted in March 2026. The audit focused on multi-tenancy, cross-user isolation, and secure tool execution.

## Executive Summary
The audit identified **11 critical and high-severity vulnerabilities** that fundamentally compromise user isolation, data privacy, and system integrity in multi-tenant or public-facing deployments. The root cause is a systemic architectural reliance on **shared state** across authenticated users.

## 1. The Core Architectural Flaw: Shared State
The `AdkWebServer` caches and reuses `Runner`, `Agent`, and `Tool` instances across all users. This "Shared Runner" model breaks the fundamental security boundary between different authenticated users, leading to systematic data leakage and identity theft.

## 2. Critical Vulnerability Categories

### Identity & Access Control
*   **IDOR in Session/Artifact APIs:** All FastAPI endpoints lack authentication, allowing unauthorized access to any user's chat history and files.
*   **Auth Credential Race Condition:** User A's OAuth tokens can be "stolen" by User B's concurrent request due to shared instance variables.
*   **Identity Leakage (ApiRegistry & MCP):** The framework automatically forwards the ADK's Service Account token and the User's OAuth token to unverified third-party MCP servers.

### Filesystem & Command Execution
*   **Artifact Path Traversal:** Lack of sanitization on `user_id` allows attackers to escape the application directory and perform arbitrary file operations on the host OS.
*   **RCE via MCP Stdio:** Attackers can execute arbitrary local shell commands via user-controlled agent configurations.
*   **MCP Session Sharing:** All users share a single local OS process for `stdio` MCP tools, leaking state across the user boundary.

### Data & Privacy Leakage
*   **Computer Use Data Leakage:** Shared browser state allows one user to see screenshots/cookies from another user's session.
*   **SSRF in Built-in Tools:** `load_web_page` lacks IP blacklisting, allowing access to internal networks and cloud metadata services.
*   **Excessive Telemetry Logging:** Tool arguments and responses (including passwords/PII) are logged in plain text by default.
*   **Plain-text Credential Storage:** OAuth tokens are stored unencrypted in the session database.

## 3. Documentation & Evidence
The following detailed reports and PoC scripts have been created:

| Resource | Description |
| :--- | :--- |
| `contributing/SECURITY_VULNERABILITY_MASTER_LIST.md` | Consolidated list of all 11 findings. |
| `contributing/CREDENTIAL_LEAKAGE_REPORT.md` | Detailed analysis of token forwarding risks. |
| `contributing/ARTIFACT_PATH_TRAVERSAL_REPORT.md` | PoC and analysis of filesystem escape. |
| `contributing/AUTH_RACE_CONDITION_REPORT.md` | Analysis of concurrent state modification. |
| `reproduce_artifact_traversal.py` | PoC script for arbitrary file write. |
| `reproduce_auth_race.py` | PoC script for identity theft. |

## 4. Conclusion & Recommendation
ADK-Python is currently **unsuitable for production use in multi-user environments**. A significant architectural refactor is required to move away from shared state and implement strict, request-scoped isolation for all Runners, Agents, and Tools.
