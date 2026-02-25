# Security Vulnerability Report: Path Traversal in Artifact Service

## Executive Summary
A critical path traversal vulnerability was identified in the `FileArtifactService` of ADK-Python. Due to insufficient sanitization of the `user_id` and `session_id` parameters, an attacker can manipulate the storage paths to read, write, or delete files outside of the intended artifacts directory on the host filesystem.

## Vulnerability Details

### 1. Unsanitized Path Construction
The `FileArtifactService` constructs the base directory for a user's artifacts by joining the `root_dir` with the `user_id` and `session_id` provided in the API request.

*   **Location:** `src/google/adk/artifacts/file_artifact_service.py`
*   **The Flaw:** The `_base_root` and `_session_artifacts_dir` functions use raw string concatenation/joining with the `user_id` and `session_id` without validating that they do not contain path traversal sequences like `..`.

```python
def _base_root(self, user_id: str, /) -> Path:
    return self.root_dir / "users" / user_id

def _session_artifacts_dir(base_root: Path, session_id: str) -> Path:
    return base_root / "sessions" / session_id / "artifacts"
```

### 2. Failure of `resolve()` to Prevent Escapes
While the service attempts to use `.resolve()` and `.relative_to()` to protect the `filename` (artifact name), it does so *after* the `scope_root` has already been corrupted by a malicious `user_id`.

If a `user_id` of `../../` is provided, the `scope_root` resolves to the application's parent directory. Any subsequent "safe" `filename` will then be written relative to that escaped directory.

## Impact
An attacker can:
1.  **Arbitrary File Write:** Upload malicious files (e.g., `.bashrc`, SSH `authorized_keys`, or configuration files) to any location the application has write access to.
2.  **Data Exfiltration:** Read any file on the system (within the enforced `/versions/{version}/` structure) by first saving a "fake" artifact that points to a sensitive location via path traversal in the ID.
3.  **System Instability:** Delete critical system or application files by exploiting the `delete_artifact` endpoint with traversal IDs.

## Proof of Concept
The following attack was successfully executed:
1.  Target `user_id` set to `../../secret_data`.
2.  `save_artifact` called with `filename='stolen_secret'`.
3.  Result: The file was written to `/absolute/path/to/secret_data/artifacts/stolen_secret/versions/0/stolen_secret`, completely escaping the `test_artifacts_root` directory.

## Root Cause Analysis
The application trusts `user_id` and `session_id` as safe path segments because they are often assumed to be simple UUIDs or alphanumeric strings. However, as they are sourced directly from URL path parameters in `adk_web_server.py`, they can contain any URL-encoded character, including `..`.

## Remediation Strategy
1.  **Strict ID Validation:** Implement a regex check on all `user_id` and `session_id` parameters to ensure they only contain alphanumeric characters, hyphens, and underscores.
2.  **Path Anchor Verification:** In `FileArtifactService`, always verify that the final `artifact_dir` is a child of the original `self.root_dir` using `.resolve()` and a prefix check, rather than relying on a dynamically constructed `scope_root`.
3.  **Basename Enforcement:** Use `os.path.basename()` on all ID components before using them in path construction to strip any directory information.
