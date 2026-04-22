---
name: New Scanner
about: Propose a scanner for a new AI system type, language, or cloud provider
title: '[SCANNER] '
labels: scanner, enhancement
assignees: ''
---

## What does this scanner detect?

Describe the AI systems, services, or integrations this scanner would find. Include example providers or libraries.

## Files or services it scans

What inputs does the scanner operate on?

- [ ] Source code files (specify language/extension: e.g. `.ts`, `.js`, `*.tf`)
- [ ] Config files (specify: e.g. `docker-compose.yml`, `.env`)
- [ ] Cloud provider APIs (specify: e.g. Azure OpenAI, GCP Vertex AI)
- [ ] Other: ...

## Detection patterns

How would the scanner identify an AI system? List concrete signals:

- Import names: e.g. `import openai`, `require('@azure/openai')`
- Environment variables: e.g. `AZURE_OPENAI_KEY`
- Config keys: e.g. `model:` in a YAML file
- API endpoints: e.g. calls to `api.openai.com`
- Other: ...

## Estimated coverage

Roughly how many real-world projects would benefit from this scanner? Any data or examples?

## Are you willing to implement it?

- [ ] Yes, I'd like to implement this scanner (see CONTRIBUTING.md for the guide)
- [ ] No, I'm proposing it for someone else to pick up
