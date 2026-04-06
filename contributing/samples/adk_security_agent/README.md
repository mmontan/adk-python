# ADK PR Security Assessment Agent

A security-focused PR review agent built with the Agent Development Kit (ADK).
It analyzes pull request diffs for a broad set of vulnerability classes and
posts a structured security assessment comment directly to the PR.

The agent is **portable**: all repo-specific knowledge lives in
`security_context.md`. Point it at any GitHub repo by setting environment
variables — no code changes needed.

---

## Vulnerability Classes Assessed

| # | Class | Examples |
|---|-------|---------|
| 1 | Cross-user information leak | Shared mutable state, missing namespace isolation, IDOR |
| 2 | Injection | SQL/GQL injection, command injection, SSRF, path traversal |
| 3 | Unsanitized markup / output | XSS, template injection, prompt injection |
| 4 | Unsafe dependencies | New unvetted imports, `pickle`, `yaml.load`, weak hashlib |
| 5 | Secrets & credential handling | Hardcoded tokens, plaintext credential storage |
| 6 | Insecure defaults & configuration | Opt-out auth, debug on by default, missing rate limits |
| 7 | Cryptography | Weak algorithms (MD5/SHA1/DES), `random` for security purposes |
| 8 | Authentication & authorization | Missing auth on endpoints, privilege escalation, JWT mistakes |

---

## Prerequisites

- Python 3.11+
- `GITHUB_TOKEN` with `pull-requests: write` and `contents: read` permissions
- `GOOGLE_API_KEY` for Gemini API access (or configure Vertex AI)

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GITHUB_TOKEN` | Yes | — | GitHub personal access token |
| `GOOGLE_API_KEY` | Yes | — | Gemini API key |
| `OWNER` | No | `google` | Repository owner (org or user) |
| `REPO` | No | `adk-python` | Repository name |
| `PULL_REQUEST_NUMBER` | Yes (non-interactive) | — | PR number to assess |
| `INTERACTIVE` | No | `1` | Set to `0` for fully automated (CI) mode |
| `DEV_MODE` | No | `0` | Set to `1` to run the full analysis locally without writing anything to GitHub |
| `GOOGLE_GENAI_USE_VERTEXAI` | No | `0` | Set to `1` to use Vertex AI instead of API key |

### Mode comparison

| Mode | `DEV_MODE` | `INTERACTIVE` | Behaviour |
|------|-----------|---------------|-----------|
| Dev (local, no writes) | `1` | any | Full analysis; results shown locally; **no comment or label posted** |
| Interactive (web UI, with approval) | `0` | `1` (default) | Full analysis; waits for user approval before posting |
| Autonomous (CI) | `0` | `0` | Full analysis; posts comment and label automatically |

---

## Running Locally

### Dev mode (full analysis, no GitHub writes)

Run the complete assessment pipeline — reads the diff and files from GitHub,
produces the full structured report — but never posts a comment or applies a
label. Safe to run against any PR at any time.

```bash
DEV_MODE=1 \
GITHUB_TOKEN=ghp_... \
GOOGLE_API_KEY=AIza... \
PULL_REQUEST_NUMBER=123 \
PYTHONPATH=contributing/samples \
python -m adk_security_agent.main
```

Or via the web UI (add `DEV_MODE=1` to your `.env`):

```bash
cd contributing/samples
printf "GITHUB_TOKEN=ghp_...\nGOOGLE_API_KEY=AIza...\nDEV_MODE=1\n" \
  > adk_security_agent/.env
PYTHONPATH=. adk web
# Open browser → select adk_security_agent → type "assess PR #123"
```

### Interactive mode (web UI, with approval gate before posting)

```bash
cd contributing/samples
printf "GITHUB_TOKEN=ghp_...\nGOOGLE_API_KEY=AIza...\n" \
  > adk_security_agent/.env
PYTHONPATH=. adk web
# Open browser → select adk_security_agent → type "assess PR #123"
```

### Non-interactive mode (CI / autonomous)

```bash
INTERACTIVE=0 \
GITHUB_TOKEN=ghp_... \
GOOGLE_API_KEY=AIza... \
PULL_REQUEST_NUMBER=123 \
PYTHONPATH=contributing/samples \
python -m adk_security_agent.main
```

---

## CI / GitHub Actions

The workflow at `.github/workflows/pr-security-assessment.yml` triggers on:

- **`pull_request_target`** — automatically on new/updated PRs from external
  contributors (skips PRs labeled `google-contributor`).
- **`workflow_dispatch`** — manually from the Actions tab with a PR number.

Required repository secrets:
- `ADK_TRIAGE_AGENT` — GitHub token with PR write access
- `GOOGLE_API_KEY` — Gemini API key

### Manual trigger

1. Go to **Actions → ADK PR Security Assessment → Run workflow**
2. Enter the PR number
3. Click **Run workflow**

---

## Adapting for a Different Repository

1. Copy the `adk_security_agent/` folder to your repo (or a shared samples
   location).
2. Edit `security_context.md` to describe your repo's architecture and the
   high-risk file paths specific to your codebase. Leave it empty if you want
   only the generic vulnerability classes.
3. Set `OWNER` and `REPO` environment variables (or update defaults in
   `settings.py`).
4. Update the workflow's `OWNER`/`REPO` env vars and secrets references.

No changes to `agent.py`, `utils.py`, or `main.py` are needed.

---

## Assessment Comment Format

The agent posts a comment like this to each assessed PR:

```markdown
## Security Assessment — PR #123

**Summary**: This PR adds a new BigQuery query tool that constructs SQL from
user-provided table names. The change introduces a potential SQL injection
risk and should be reviewed before merging.

### Findings

| Severity | Class | Location | Finding | Recommendation |
|----------|-------|----------|---------|----------------|
| 🔴 Critical | Injection | `tools/bq_tool.py:42` | Table name interpolated directly into SQL f-string | Use parameterized queries or an allowlist of valid table names |
| 🔵 Low/Info | Insecure default | `tools/bq_tool.py:10` | `timeout` defaults to `None` (no resource cap) | Set a sensible default timeout |

### Verdict

- [ ] No security issues found — safe to merge from a security perspective.
- [ ] Minor notes only — addressable before merge, no blocker.
- [x] One or more issues require security review before merge.

> 🔒 *Response from ADK Security Assessment Agent*
```

---

## Architecture

```
adk_security_agent/
├── __init__.py          # Package init, exports agent module
├── settings.py          # Env var config (GITHUB_TOKEN, OWNER, REPO, ...)
├── utils.py             # GitHub API helpers (GraphQL, REST, diff, file content)
├── agent.py             # Agent definition, tools, system prompt builder
├── main.py              # Bootstrap: InMemoryRunner + call_agent_async
├── security_context.md  # Repo-specific security context (injected into prompt)
└── README.md            # This file
```

The agent uses four tools:

| Tool | Purpose |
|------|---------|
| `get_pull_request_details` | GraphQL: PR metadata + diff (10 KB truncated) |
| `get_file_content` | GitHub Contents API: full file at PR head (20 KB truncated) |
| `add_security_comment` | POST assessment Markdown comment to PR |
| `add_label_to_pr` | Apply `security-review-needed` label (allowlisted) |
