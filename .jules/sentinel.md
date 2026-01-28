## 2025-02-13 - [HIGH] Add .gitignore to new agent template
**Vulnerability:** The `adk create` command generated a `.env` file containing API keys but did not create a `.gitignore` file.
**Learning:** Scaffolding tools must default to secure configuration. Assuming the user will create a `.gitignore` leads to accidental secret leakage.
**Prevention:** Always include a `.gitignore` that excludes sensitive files (like `.env`) when generating project templates.
