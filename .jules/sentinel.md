# Sentinel's Journal

## 2026-10-18 - [Command Injection in Dockerfile Generation]
**Vulnerability:** Command injection via unsanitized user inputs (`allow_origins`, `app_name`) in `cli_deploy.py` during Dockerfile generation.
**Learning:** `shlex.quote()` creates shell-safe strings, but if you wrap its output in double quotes (e.g., `"{shlex.quote(var)}"`), the shell still interprets the outer quotes, which can break paths containing spaces (e.g. `'my app'` becomes `'my app'` literal with quotes) or be unsafe in other contexts.
**Prevention:** Always use `shlex.quote()` for variables interpolated into shell commands (RUN, CMD) and DO NOT wrap the result in additional quotes unless you specifically want to quote the *quoted* string.
