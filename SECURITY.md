# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in aigov, please report it responsibly:

1. **Do NOT open a public GitHub issue for security vulnerabilities**
2. Email: kshirabhay@gmail.com with subject "aigov security vulnerability"
3. Include: description of the vulnerability, steps to reproduce, and potential impact
4. Expected response: acknowledgment within 48 hours, fix timeline within 7 days

## Scope

This policy covers the aigov CLI tool and its published PyPI package. It does not cover third-party dependencies.

## Security Principles

1. **No secrets or credentials are ever logged, stored, or transmitted** — aigov detects API keys but never records their values, only their type and location.
2. **All operations are read-only** — aigov never modifies source files, cloud resources, or system configurations.
3. **All processing is local** — no telemetry, no external API calls, no data exfiltration.
4. **Minimal dependencies** — from trusted sources with pinned versions.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.5.x   | Yes       |
| < 0.5   | No        |
