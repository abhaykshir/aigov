# aigov

**aigov — AI Governance-as-Code CLI. Discover, classify, and govern AI systems across your infrastructure.**

---

## Why

The EU AI Act's full enforcement deadline is **2 August 2026**. Every organisation deploying AI in or selling into the EU needs a documented inventory of its AI systems — but most engineering teams have no idea how many AI integrations actually exist in their codebases. Shadow AI (ungoverned LLM integrations added by individual developers) is endemic. No open-source tool exists to automatically discover and inventory AI usage the way tools like `trivy` or `grype` handle CVEs.

aigov is that tool.

---

## Quick Start

```bash
pip install aigov
aigov scan .
```

```
                          AI Systems Found (8)
+-----------------------------------------------------------------------+
| # | Name                   | Type        | Provider    | Juris | Conf  |
|---+------------------------+-------------+-------------+-------+-------|
| 1 | Anthropic API Key      | api_service | Anthropic   | US    | ##### |
| 2 | OpenAI via openai      | api_service | OpenAI      | US    | ##### |
| 3 | sk-ant-api03-***       | api_service | Anthropic   | US    | ##### |
| 4 | filesystem             | mcp_server  | filesystem  | XX    | ##### |
| 5 | github                 | mcp_server  | github      | US    | ##### |
| 6 | LangChain via langchain| agent       | LangChain   | US    | ####. |
| 7 | DeepSeek via deepseek  | api_service | DeepSeek    | CN    | ####. |
| 8 | HuggingFace via transf.| model       | HuggingFace | US    | ####. |
+-----------------------------------------------------------------------+

Found 8 AI systems (3 API services, 2 MCP servers, 1 agent, 1 model) across 6 providers
```

Export to JSON or Markdown for compliance evidence:

```bash
aigov scan . --output json --out-file inventory.json
aigov scan . --output markdown --out-file AIINVENTORY.md
```

---

## What It Detects

| Scanner | What it finds |
|---------|--------------|
| `code.python_imports` | AI/ML library imports in Python source files — OpenAI, Anthropic, LangChain, HuggingFace, DeepSeek, and 20+ others mapped to provider and jurisdiction |
| `code.api_keys` | AI service API keys and credentials committed or hardcoded in source, config, and env files — values are never stored, only redacted previews |
| `config.mcp_servers` | MCP (Model Context Protocol) server configurations from Claude Desktop, Cursor, Windsurf, VS Code, and project-level `.mcp.json` files |

All findings include `origin_jurisdiction` (ISO 3166-1) so you can filter by geography for policy reviews.

---

## Security Principles

See [SECURITY.md](SECURITY.md) for the full policy. In brief:

1. **No secrets stored** — API keys are detected but never recorded. Only the key type, location, and a 4-char redacted preview (`sk-an****`) are kept.
2. **Read-only** — aigov never modifies source files, cloud resources, or system configurations.
3. **Local processing** — no telemetry, no external API calls, no data leaves your machine.
4. **Minimal dependencies** — small, auditable dependency tree from trusted sources.

---

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| 1 — Discovery | **Done** | Python import scanner, API key scanner, MCP server scanner |
| 2 — Risk Classification | Next | Score findings against EU AI Act Annex III, Colorado AI Act SB 205 |
| 3 — Documentation Generator | Planned | Auto-generate conformity declarations, data flow diagrams, DPIA stubs |
| 4 — Cloud Scanners | Planned | AWS Bedrock, Azure OpenAI, GCP Vertex AI, SageMaker endpoint discovery |

---

## Contributing

Contributions welcome — especially new scanners (JavaScript/TypeScript imports, Terraform AI resources, Docker image scanning) and framework classification rules. Open an issue to discuss before submitting a large PR.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
