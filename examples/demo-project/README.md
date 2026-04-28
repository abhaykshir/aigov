# aigov demo project

This is a sample AI project for testing aigov. Run `aigov scan examples/demo-project --classify --with-risk` or `aigov graph examples/demo-project --out-file graph.html` to see aigov in action.

It contains representative AI usage across four areas — `analytics/` (financial fraud + credit scoring), `hiring/` (resume screener), `support/` (customer chatbot + MCP server), `internal/` (developer tooling) — plus a `production/` directory and `.env` / `.mcp.json` / `.aigov-policy.yaml` files so the scanner, classifier, risk engine, policy engine, and graph all have something meaningful to work with.

The API key values inside `.env` are clearly fake placeholders. Do not commit real credentials to a public demo.
