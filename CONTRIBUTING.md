# Contributing to aigov

Contributions are welcome — especially new scanners, classification rules, framework mappings, and documentation improvements. This guide explains how to contribute effectively.

---

## How to contribute

- **New scanners** — expand coverage to JS/TS imports, Terraform resources, Docker images, etc.
- **Classification rules** — improve or expand YAML rule files for EU AI Act and future frameworks
- **New regulatory frameworks** — Colorado AI Act, NIST AI RMF, ISO 42001, and more
- **Documentation** — improve examples, add tutorials, fix typos

For large changes, open an issue first to discuss the approach before submitting a PR.

---

## Development setup

```bash
git clone https://github.com/abhaykshir/aigov.git
cd aigov
pip install uv
uv pip install --system -e ".[aws]" pytest
pytest -q
```

All tests should pass before you submit a PR.

---

## Adding a new scanner

Scanners live in `src/aigov/scanners/`. Each scanner is a class that implements `BaseScanner`.

**Step 1** — Create a new file in the appropriate subdirectory:

```
src/aigov/scanners/
  code/        # source code analysis
  config/      # config file parsing
  cloud/       # cloud provider APIs
```

**Step 2** — Implement `BaseScanner`:

```python
from __future__ import annotations
from abc import ABC, abstractmethod
from aigov.core.models import AISystemRecord

class BaseScanner(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable scanner name."""

    @property
    @abstractmethod
    def description(self) -> str:
        """What this scanner looks for."""

    @property
    def requires_credentials(self) -> bool:
        """Whether this scanner needs external credentials to operate."""
        return False

    @abstractmethod
    def scan(self, paths: list[str]) -> list[AISystemRecord]:
        """Scan the given paths and return discovered AI system records.

        Implementations must never log, store, or transmit credential values —
        only record the type and location of any detected secrets per SECURITY.md.
        """
```

**Step 3** — Register your scanner in `src/aigov/scanners/__init__.py` so the scan engine picks it up.

**Step 4** — Write tests in `tests/test_scanners/`. Cover the happy path, edge cases, and the case where your scanner finds nothing.

**Step 5** — Submit a PR with a description of what the scanner finds and example output.

---

## Adding classification rules

Classification rules are YAML files in `src/aigov/frameworks/`. No Python required — compliance and legal experts can contribute directly.

**EU AI Act rules** live in `src/aigov/frameworks/eu_ai_act/`:

| File | Contents |
|------|----------|
| `prohibited.yaml` | Article 5 absolutely prohibited practices |
| `annex_iii.yaml` | Annex III high-risk system categories |
| `transparency.yaml` | Article 50 transparency obligations |

Each rule entry follows this structure (example from `annex_iii.yaml`):

```yaml
- id: biometric_categorisation
  name: Biometric categorisation system
  risk_level: high_risk
  keywords: [facial_recognition, face_detection, biometric]
  library_patterns: [deepface, face_recognition, aws_rekognition]
  required_actions:
    - Register in EU database before deployment
    - Conduct fundamental rights impact assessment
    - Implement human oversight mechanism
```

To add a new rule: copy an existing entry, adjust the fields, and submit a PR. Include a reference to the specific article or recital in your PR description.

---

## Adding a new regulatory framework

**Step 1** — Create a directory under `src/aigov/frameworks/`:

```
src/aigov/frameworks/
  eu_ai_act/        # existing
  colorado_ai_act/  # example new framework
  nist_ai_rmf/
```

**Step 2** — Add YAML rule files following the same structure as the EU AI Act rules.

**Step 3** — Create a classifier class in `src/aigov/classifiers/` that loads and applies your framework's rules.

**Step 4** — Register the framework in `src/aigov/classifiers/__init__.py` and expose it via the `--frameworks` CLI flag.

**Step 5** — Write tests and submit a PR. Include links to the regulatory source documents.

---

## PR guidelines

- All tests must pass: `pytest -q`
- Follow [SECURITY.md](SECURITY.md) — no secrets in code, read-only operations only
- Do not store, log, or transmit credential values in new scanners
- Keep PRs focused — one feature or fix per PR
- Reference the relevant regulatory text when adding classification rules

---

## Code of Conduct

Be respectful and constructive in all interactions.
