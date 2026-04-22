# aigov GitHub Actions Integration

Add AI governance checks to any repository in minutes. aigov scans code and
config files checked into your repo — no cloud credentials required.

## Quick start: catch prohibited AI uses

```yaml
# .github/workflows/ai-governance.yml
name: AI Governance

on: [push, pull_request]

jobs:
  governance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: abhaykshir/aigov@v1
```

This scans the whole repo, classifies every AI system found against the EU AI
Act, and **fails the workflow** if any `prohibited` system is detected.
Everything else (high-risk, limited-risk, minimal-risk) passes through.

## Full compliance check

Scan, classify, and block on both prohibited and unreviewed high-risk systems:

```yaml
- uses: actions/checkout@v4
- uses: abhaykshir/aigov@v1
  with:
    scan-paths: "src config"       # space-separated; defaults to "."
    classify: "true"               # EU AI Act classification (default)
    frameworks: "eu_ai_act"
    fail-on: "prohibited,high_risk"
    output-file: "aigov-results.json"

- name: Upload governance report
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: aigov-results
    path: aigov-results.json
```

## Action inputs

| Input | Default | Description |
|-------|---------|-------------|
| `scan-paths` | `.` | Space-separated paths to scan |
| `classify` | `true` | Run EU AI Act classification |
| `frameworks` | `eu_ai_act` | Comma-separated frameworks |
| `fail-on` | `prohibited` | Risk levels that fail the check |
| `output-format` | `json` | Output format (`json` or `markdown`) |
| `output-file` | `aigov-results.json` | Where to save results |

**`fail-on` valid values:** `prohibited`, `high_risk`, `limited_risk`,
`minimal_risk`, `needs_review`, `unknown`

## Action outputs

| Output | Description |
|--------|-------------|
| `results-file` | Path to the JSON results file |
| `total-found` | Number of AI systems discovered |

## PR comment with scan results

Post a summary as a pull request comment whenever aigov finds something:

```yaml
name: AI Governance

on: [pull_request]

permissions:
  pull-requests: write

jobs:
  governance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: abhaykshir/aigov@v1
        id: aigov
        continue-on-error: true   # collect results even on failure
        with:
          output-file: aigov-results.json

      - name: Post PR comment
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const results = JSON.parse(fs.readFileSync('aigov-results.json', 'utf8'));
            const total = results.summary?.total_found ?? 0;
            const findings = results.findings ?? [];
            const prohibited = findings.filter(f => f.risk_classification === 'prohibited');
            const highRisk = findings.filter(f => f.risk_classification === 'high_risk');

            let body = `## aigov AI Governance Report\n\n`;
            body += `**${total}** AI system(s) found`;
            if (prohibited.length) body += ` — ⛔ **${prohibited.length} prohibited**`;
            if (highRisk.length) body += ` — ⚠️ **${highRisk.length} high-risk**`;
            body += `\n\n`;

            if (prohibited.length || highRisk.length) {
              body += `| System | Risk | Location |\n|--------|------|----------|\n`;
              [...prohibited, ...highRisk].forEach(f => {
                body += `| ${f.name} | \`${f.risk_classification}\` | ${f.source_location} |\n`;
              });
            } else if (total === 0) {
              body += `No AI systems detected in this PR.\n`;
            } else {
              body += `All systems are within acceptable risk thresholds.\n`;
            }

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body
            });
```

## Scan only (no classification)

If you just want a manifest of AI systems without policy enforcement:

```yaml
- uses: actions/checkout@v4
- uses: abhaykshir/aigov@v1
  with:
    classify: "false"
    fail-on: ""        # never fail — inventory only
```

> Note: when `classify: "false"`, all records have `risk_classification: unknown`,
> so `fail-on: prohibited` (the default) will never trigger.

## Security

aigov operates entirely on code and config files checked into your repository.
It never requires cloud credentials, makes network calls, or transmits data
outside the runner. See [SECURITY.md](../SECURITY.md) for the full policy.
