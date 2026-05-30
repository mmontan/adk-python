## 2025-02-18 - SSRF in Agent Tools
**Vulnerability:** Found unvalidated URL fetching in `load_web_page` tool, allowing access to internal IPs and metadata services.
**Learning:** Agent tools that fetch external content are prime targets for SSRF. Standard libraries like `requests` do not block internal ranges by default.
**Prevention:** Always validate URLs against a blocklist of private/reserved IPs (using `ipaddress` library) before fetching. Ensure redirects are disabled or validated. Add timeouts to prevent DoS.
