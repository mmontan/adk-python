# Sentinel's Journal

## 2025-02-23 - [Command Injection via Dockerfile Generation in CLI Deploy]
**Vulnerability:** The `adk deploy` command was vulnerable to Command Injection. The `allow_origins` parameter (and others like `session_service_uri`) was directly injected into the `CMD` instruction of the generated `Dockerfile` without proper quoting. Since `CMD` in shell form is executed by `/bin/sh -c`, malicious input could execute arbitrary commands in the deployed container.
**Learning:** Even when generating configuration files (like Dockerfiles) that are executed later, input sanitization is crucial. Parameters passed to shell commands inside Dockerfiles must be quoted.
**Prevention:** Use `shlex.quote()` for all user-controlled inputs that are interpolated into shell commands or configuration files executed by a shell. In Dockerfiles, prefer the `exec` form `CMD ["executable", "param1", "param2"]` over the shell form `CMD command param1`, or ensure rigorous quoting if shell form is necessary.
