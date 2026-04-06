# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pathlib import Path
from typing import Any

from adk_security_agent.settings import DEV_MODE
from adk_security_agent.settings import GITHUB_BASE_URL
from adk_security_agent.settings import IS_INTERACTIVE
from adk_security_agent.settings import OWNER
from adk_security_agent.settings import REPO
from adk_security_agent.utils import error_response
from adk_security_agent.utils import get_diff
from adk_security_agent.utils import get_github_file_content
from adk_security_agent.utils import get_request
from adk_security_agent.utils import post_request
from adk_security_agent.utils import read_file
from adk_security_agent.utils import run_graphql_query
from google.adk import Agent
from requests.exceptions import RequestException

# Allowed labels this agent may apply.
ALLOWED_LABELS = ["security-review-needed"]

# Optional repo-specific context injected into the system prompt.
_SECURITY_CONTEXT = read_file(
    str(Path(__file__).parent / "security_context.md")
)

if DEV_MODE:
  APPROVAL_INSTRUCTION = (
      "You are running in DEV MODE. The `add_security_comment` and"
      " `add_label_to_pr` tools will NOT write anything to GitHub — they are"
      " safe dry-run no-ops. Call them as normal so the full assessment"
      " workflow runs, then present the complete findings to the user."
  )
elif IS_INTERACTIVE:
  APPROVAL_INSTRUCTION = (
      "Present your findings to the user and wait for explicit approval before"
      " posting the security assessment comment or applying any label to the PR."
  )
else:
  APPROVAL_INSTRUCTION = (
      "Do not ask the user for approval before posting the security assessment"
      " comment or applying labels. Proceed autonomously."
  )


if _SECURITY_CONTEXT:
  _REPO_CONTEXT_SECTION = f"""
# 6. Repo-Specific Security Context

The following architectural notes are specific to the `{REPO}` repository.
Use them to sharpen your analysis beyond the general vulnerability classes above.

{_SECURITY_CONTEXT}
"""
else:
  _REPO_CONTEXT_SECTION = ""

_SYSTEM_PROMPT = f"""
# 1. Identity
You are a **Security Assessment Agent** for the GitHub repository `{OWNER}/{REPO}`.
Your role is to review pull request diffs for security vulnerabilities, report
findings in a structured format, and optionally label PRs that need human
security review.

# 2. Responsibilities
- Fetch pull request details and the unified diff.
- For security-sensitive changed files, fetch the full file content for deeper
  analysis.
- Analyze the changes against the vulnerability classes defined below.
- Post a structured security assessment comment to the PR.
- Apply the `security-review-needed` label when Critical or High findings exist.

**IMPORTANT: {APPROVAL_INSTRUCTION}**

# 3. Vulnerability Classes to Assess

## Class 1 — Cross-User Information Leak
- Shared mutable state at class/module/singleton level accessed by concurrent
  requests (e.g., class-level dicts, module globals accumulating per-request
  data).
- Session or request data persisted without per-user namespace isolation.
- Responses or artifacts from one user's context visible to another user.
- IDOR: access control based on untrusted user-supplied identifiers without
  server-side ownership verification.

## Class 2 — Injection
- SQL / GQL / filter-language injection via string interpolation or f-strings
  with unsanitized user input.
- Command injection via `subprocess`, `os.system`, `eval`, `exec` with
  user-controlled input.
- Server-Side Request Forgery (SSRF) — outbound HTTP to user-controlled URLs
  without allowlist validation.
- Path traversal — file paths constructed from user input without
  canonicalization and prefix checks.

## Class 3 — Unsanitized Markup / Output
- HTML or Markdown rendered without escaping user-controlled content (XSS).
- Template injection in Jinja2 or similar engines.
- Logging or displaying raw user input that could corrupt structured log formats.
- Prompt injection — user-controlled content forwarded unescaped into LLM
  system instructions or agent prompts.

## Class 4 — Unsafe Dependencies
- New `import` statements for packages not previously in `pyproject.toml` or
  requirements files (flag for review even if not clearly malicious).
- Use of deprecated or unsafe stdlib modules: `pickle` (arbitrary code exec),
  `yaml.load` without `Loader=`, `hashlib.md5` / `hashlib.sha1` for security
  purposes.
- Dependency version pinning removed or loosened in a way that allows
  unexpected upgrades.

## Class 5 — Secrets & Credential Handling
- Hardcoded tokens, API keys, passwords, or other secrets in source code.
- Credentials stored in plain-text logs, session state, or databases without
  encryption.
- Auth tokens forwarded to third-party or user-controlled URLs without
  validation.
- Missing token expiry / rotation handling in new auth flows.

## Class 6 — Insecure Defaults & Configuration
- Security controls that are opt-out rather than opt-in (e.g., auth disabled
  by default).
- Default values that expose sensitive data (verbose error messages with stack
  traces, debug mode on by default, permissive CORS).
- Missing rate limiting, input length limits, or resource caps on new
  endpoints or loops.

## Class 7 — Cryptography
- Use of weak or deprecated algorithms for security purposes: `MD5`, `SHA1`,
  `DES`, `RC4`.
- Hardcoded or predictable salts, IVs, or nonces.
- Use of `random` module instead of `secrets` for security-sensitive
  randomness (tokens, session IDs, nonces).

## Class 8 — Authentication & Authorization
- Missing authentication checks on new API endpoints or agent entry points.
- Privilege escalation paths — lower-privileged context accessing
  higher-privileged resources.
- JWT or OAuth token handling mistakes (missing signature verification,
  accepting `alg: none`, not validating `aud`/`iss` claims).
- **Route surface audit (mandatory when `cli/fast_api.py` or
  `cli/adk_web_server.py` is in the diff):** For every `@app.get`,
  `@app.post`, `@app.put`, `@app.delete`, `@app.patch` decorator added in
  the diff, check all three of:
  1. **Auth gate** — does the handler have a `Depends(...)` auth dependency?
     If not, and the route is reachable in production, flag at least High.
  2. **Blast radius** — does the handler perform file I/O (`open`, `shutil`,
     `Path.write_*`, `os`), subprocess execution, or dynamic module imports?
     If yes with no auth, flag Critical.
  3. **Registration scope** — is the route always registered, or gated behind
     a feature flag / configuration variable? An always-registered route with
     dangerous operations is a production attack surface even if the intent
     was dev-only.
- **WIP-to-live promotion:** if the diff removes a WIP, experimental, debug,
  or feature-flag guard from a handler that writes files, executes code, or
  accesses user data — treat it as a new unauthenticated route and apply the
  three checks above. This pattern (guard removed, auth never added) is a
  common source of unintentional exposure.

# 4. Steps

When given a PR number, follow these steps in order:

1. Call `get_pull_request_details` to retrieve PR metadata, changed file
   paths, commits, CI status, and the truncated unified diff.

2. **Skip the PR entirely** (do not comment or label) if any of the following
   is true:
   - The PR state is `CLOSED` or `MERGED`.
   - The PR already has the label `google-contributor`.
   - The PR already has a comment from this agent (look for the signature
     "🔒 *Response from ADK Security Assessment Agent*").

3. Identify security-sensitive changed file paths. For the `{REPO}` repository
   the high-priority paths are: `runners.py`, anything under `tools/`,
   `auth/`, `sessions/`, `a2a/`, `cli/`, and `code_executors/`. For other
   repos, apply judgement based on the diff and the repo-specific context
   below.

   **Additionally**, if `cli/fast_api.py` or `cli/adk_web_server.py` appears
   in the diff, immediately scan the diff for every line matching
   `@app.(get|post|put|delete|patch)` that was added (`+` lines). List each
   new route and carry that list into Step 5 for the Class 8 route surface
   audit. Do not skip this even if the file seems like a minor change.

4. For each security-sensitive changed file, call `get_file_content` with the
   PR's head commit SHA to retrieve the full file content (up to 20 KB). Use
   this to understand the full context of changed lines.

5. Analyze the diff and full file content against all 8 vulnerability classes
   above, plus any repo-specific context in Section 6.

6. Compose the structured security assessment comment (see Section 5).

7. Call `add_security_comment` to post the assessment to the PR.

8. If any finding is rated **Critical** or **High**, call `add_label_to_pr`
   with label `security-review-needed`.

# 5. Assessment Comment Format

Post the assessment as a Markdown comment using exactly this structure:

```
## Security Assessment — PR #<N>

**Summary**: <2–3 sentence description of what the PR changes and its
general security posture.>

### Findings

| Severity | Class | Location | Finding | Recommendation |
|----------|-------|----------|---------|----------------|
| 🔴 Critical | <class> | `<file>:<line>` | <short description> | <fix> |
| 🟠 High     | <class> | `<file>:<line>` | <short description> | <fix> |
| 🟡 Medium   | <class> | `<file>:<line>` | <short description> | <fix> |
| 🔵 Low/Info | <class> | `<file>:<line>` | <short description> | <fix> |

*(Omit rows for severity levels with no findings.)*

### Verdict

- [ ] No security issues found — safe to merge from a security perspective.
- [ ] Minor notes only — addressable before merge, no blocker.
- [ ] One or more issues require security review before merge.

> 🔒 *Response from ADK Security Assessment Agent*
```

Severity definitions:
- **Critical**: Directly exploitable, affects all users or allows RCE/data
  exfiltration. Must block merge.
- **High**: Exploitable under realistic conditions, significant impact. Should
  block merge.
- **Medium**: Exploitable under specific conditions or limited impact. Should
  be addressed before merge.
- **Low/Info**: Best-practice deviation, defence-in-depth concern, or
  informational note.
{_REPO_CONTEXT_SECTION}
"""


def get_pull_request_details(pr_number: int) -> dict[str, Any]:
  """Get the details of the specified pull request including the diff.

  Args:
    pr_number: Number of the GitHub pull request.

  Returns:
    A dict with status and pull_request data on success, or an error dict.
  """
  print(f"Fetching details for PR #{pr_number} from {OWNER}/{REPO}")
  query = """
    query($owner: String!, $repo: String!, $prNumber: Int!) {
      repository(owner: $owner, name: $repo) {
        pullRequest(number: $prNumber) {
          id
          number
          title
          body
          state
          headRefOid
          author {
            login
          }
          labels(last: 20) {
            nodes {
              name
            }
          }
          files(last: 100) {
            nodes {
              path
              additions
              deletions
            }
          }
          comments(last: 50) {
            nodes {
              id
              body
              createdAt
              author {
                login
              }
            }
          }
          commits(last: 50) {
            nodes {
              commit {
                url
                message
              }
            }
          }
          statusCheckRollup {
            state
            contexts(last: 20) {
              nodes {
                ... on StatusContext {
                  context
                  state
                  targetUrl
                }
                ... on CheckRun {
                  name
                  status
                  conclusion
                  detailsUrl
                }
              }
            }
          }
        }
      }
    }
  """
  variables = {"owner": OWNER, "repo": REPO, "prNumber": pr_number}
  url = f"{GITHUB_BASE_URL}/repos/{OWNER}/{REPO}/pulls/{pr_number}"

  try:
    response = run_graphql_query(query, variables)
    if "errors" in response:
      return error_response(str(response["errors"]))

    pr = response.get("data", {}).get("repository", {}).get("pullRequest")
    if not pr:
      return error_response(f"Pull Request #{pr_number} not found.")

    # Filter out main merge commits.
    pr["commits"]["nodes"] = [
        node
        for node in pr.get("commits", {}).get("nodes", [])
        if not node["commit"]["message"].startswith("Merge branch 'main' into")
    ]

    # Get diff of the PR and truncate to avoid exceeding token limits.
    # Fall back to per-file patches if the unified diff is too large (406).
    try:
      pr["diff"] = get_diff(url)[:10000]
    except RequestException:
      print(f"Unified diff unavailable for PR #{pr_number}, fetching per-file patches.")
      files_url = f"{GITHUB_BASE_URL}/repos/{OWNER}/{REPO}/pulls/{pr_number}/files"
      files = get_request(files_url, {"per_page": 100})
      patches = "\n".join(
          f"--- {f['filename']} (+{f['additions']} -{f['deletions']})\n{f.get('patch', '[binary or patch unavailable]')}"
          for f in files
      )
      pr["diff"] = patches[:10000]

    return {"status": "success", "pull_request": pr}
  except RequestException as e:
    return error_response(str(e))


def get_file_content(file_path: str, ref: str) -> dict[str, Any]:
  """Get the full content of a file at a specific commit or branch.

  Use this to read security-sensitive files changed by the PR in full,
  beyond what the truncated diff shows.

  Args:
    file_path: Path to the file within the repository (e.g.
      "src/google/adk/runners.py").
    ref: The commit SHA or branch name to fetch (use the PR's headRefOid for
      the PR's version of the file).

  Returns:
    A dict with status and file_content (truncated to 20 000 chars) on
    success, or an error dict.
  """
  print(f"Fetching file content: {file_path} @ {ref}")
  content = get_github_file_content(file_path, ref)
  if not content:
    return error_response(
        f"Could not retrieve content for {file_path} at ref {ref}."
    )
  return {
      "status": "success",
      "file_path": file_path,
      "ref": ref,
      "file_content": content[:20000],
      "truncated": len(content) > 20000,
  }


def add_security_comment(pr_number: int, comment: str) -> dict[str, Any]:
  """Post a security assessment comment to the given pull request.

  In DEV_MODE this is a no-op: the comment is returned for local display but
  nothing is written to GitHub.

  Args:
    pr_number: The number of the GitHub pull request.
    comment: The Markdown-formatted security assessment comment to post.

  Returns:
    A dict with status and the posted comment on success, or an error dict.
  """
  if DEV_MODE:
    print(
        f"[DEV MODE] Would post comment to PR #{pr_number}:\n{comment}"
    )
    return {
        "status": "dev_mode_no_op",
        "message": "DEV MODE — comment not posted to GitHub.",
        "would_have_posted": comment,
    }

  print(f"Posting security assessment comment to PR #{pr_number}")
  url = f"{GITHUB_BASE_URL}/repos/{OWNER}/{REPO}/issues/{pr_number}/comments"
  payload = {"body": comment}

  try:
    post_request(url, payload)
  except RequestException as e:
    return error_response(f"Error posting comment: {e}")

  return {
      "status": "success",
      "added_comment": comment,
  }


def add_label_to_pr(pr_number: int, label: str) -> dict[str, Any]:
  """Add a security label to the pull request.

  Only labels in the allowed list may be applied. In DEV_MODE this is a
  no-op: the label is returned for local display but nothing is written to
  GitHub.

  Args:
    pr_number: The number of the GitHub pull request.
    label: The label to add. Must be one of the allowed security labels.

  Returns:
    A dict with status and the applied label on success, or an error dict.
  """
  print(f"Attempting to add label '{label}' to PR #{pr_number}")
  if label not in ALLOWED_LABELS:
    return error_response(
        f"Label '{label}' is not in the allowed list {ALLOWED_LABELS}. "
        "Will not apply."
    )

  if DEV_MODE:
    print(f"[DEV MODE] Would apply label '{label}' to PR #{pr_number}")
    return {
        "status": "dev_mode_no_op",
        "message": "DEV MODE — label not applied to GitHub.",
        "would_have_applied": label,
    }

  # Pull Requests are special issues in GitHub; the issues endpoint works.
  label_url = (
      f"{GITHUB_BASE_URL}/repos/{OWNER}/{REPO}/issues/{pr_number}/labels"
  )
  label_payload = [label]

  try:
    response = post_request(label_url, label_payload)
  except RequestException as e:
    return error_response(f"Error applying label: {e}")

  return {
      "status": "success",
      "applied_label": label,
      "response": response,
  }


root_agent = Agent(
    model="gemini-2.5-pro",
    name="adk_security_assessment_agent",
    description="Assess the security impact of a GitHub pull request.",
    instruction=_SYSTEM_PROMPT,
    tools=[
        get_pull_request_details,
        get_file_content,
        add_security_comment,
        add_label_to_pr,
    ],
)
