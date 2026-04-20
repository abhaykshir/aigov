# Security Policy

## Security Principles

1. **No secrets or credentials are ever logged, stored, or transmitted** — aigov detects API keys but never records their values, only their type and location.

2. **All operations are read-only** — aigov never modifies source files, cloud resources, or system configurations.

3. **All processing is local** — no telemetry, no external API calls, no data exfiltration.

4. **Minimal dependencies from trusted sources with pinned versions.**

## Reporting a Vulnerability

If you discover a security vulnerability, please open a GitHub issue or contact the maintainer directly.
