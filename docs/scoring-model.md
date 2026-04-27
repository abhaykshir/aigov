# How aigov Calculates Risk Scores

> **Disclaimer:** Risk scores are automated signals based on pattern matching and deterministic rules. They are **not legal determinations** and do not constitute legal advice. Use them as a triage and prioritisation tool; consult qualified legal counsel for compliance decisions.

aigov produces a single integer **risk score** between `0` and `100` for every classified AI system. The score is the sum of a baseline value (driven by EU AI Act classification) and four context modifiers (environment, exposure, data sensitivity, interaction type), clamped to `[0, 100]`. The same inputs always yield the same score — no LLMs, no randomness, no network calls.

The implementation lives in [`src/aigov/core/risk/scoring.py`](../src/aigov/core/risk/scoring.py); the context detector that produces the modifiers lives in [`src/aigov/core/risk/context.py`](../src/aigov/core/risk/context.py).

---

## 1. Base score (from EU AI Act classification)

| Classification     | Base score |
|--------------------|-----------:|
| `PROHIBITED`       |         95 |
| `HIGH_RISK`        |         75 |
| `LIMITED_RISK`     |         40 |
| `MINIMAL_RISK`     |         10 |
| `UNKNOWN` / `NEEDS_REVIEW` |   50 |

Records that have not been classified (`aigov scan` without `--classify`) score from a 50 baseline — neither safe nor risky, but flagged for review.

---

## 2. Context modifiers

Each context signal contributes a small additive delta. Modifiers add together; the running total is then clamped at the end.

### 2.1 Environment

Detected by scanning the file path, sibling files, `.env.<env>` filenames, and CI environment variables. See [`context.py`](../src/aigov/core/risk/context.py) for the precedence rules.

| Environment   | Modifier |
|---------------|---------:|
| `production`  |      +15 |
| `staging`     |       +5 |
| `development` |        0 |
| `test`        |       −5 |
| `unknown`     |       +5 *(treat conservatively as staging)* |

### 2.2 Exposure

Detected by scanning the source file (and nearby files in the same directory) for web framework imports — FastAPI, Flask, Django, Express — plus path hints (`/api/`, `openapi.json`).

| Exposure            | Modifier |
|---------------------|---------:|
| `public_api`        |      +20 |
| `internal_service`  |       +5 |
| `batch_offline`     |        0 |
| `unknown`           |       +5 |

### 2.3 Data sensitivity

Detected by matching keywords (`email`, `ssn`, `payment`, `password`, `patient`, `bank_account`, …) in variable names, function names, and string literals. Multiple categories may match a single record; only the **highest** modifier applies, because the regulatory cost of any single sensitive-data category dominates.

| Category    | Modifier |
|-------------|---------:|
| `pii`       |      +20 |
| `financial` |      +20 |
| `health`    |      +20 |
| `auth`      |      +15 |
| *(none)*    |        0 |

### 2.4 Interaction type

Detected by looking for HTTP route handlers, `request.form`/`request.json`, chat keywords, batch / cron decorators, and `__main__` blocks.

| Interaction              | Modifier |
|--------------------------|---------:|
| `user_facing_realtime`   |      +10 |
| `internal_tooling`       |       +3 |
| `batch_offline`          |        0 |
| `unknown`                |       +3 |

---

## 3. Final score formula

```
score = clamp(base + env_mod + exposure_mod + max(data_mods) + interaction_mod, 0, 100)
```

The score is then mapped to a categorical level:

| Score range | Level      |
|-------------|------------|
| 80 – 100    | `critical` |
| 60 – 79     | `high`     |
| 30 – 59     | `medium`   |
| 0 – 29      | `low`      |

---

## 4. Confidence

aigov also reports a **risk confidence** value between `0.0` and `1.0`:

```
confidence = record.confidence
              − 0.1  if environment is unknown
              − 0.1  if exposure is unknown
```

A score of 100 with a confidence of 0.65 is a different signal than a score of 100 with confidence 0.95 — the former tells the reviewer that important context was missing.

---

## 5. Drivers list

Every modifier that contributed to the score is appended to a `risk_drivers` list. A typical critical-severity record might surface:

```
[
  "high_risk_classification",
  "production_environment",
  "public_api",
  "pii_data",
  "user_facing_realtime"
]
```

Drivers are intentionally short and stable — both the explainer and the policy engine pattern-match against them, so renaming one is a breaking change.

---

## 6. Worked example

Imagine a resume screener that imports `openai` and `fastapi`, exposes a `/api/screen` endpoint, and accepts `email`, `resume_text`, and `candidate_name` parameters.

1. **Base score** — classified as `HIGH_RISK` (Annex III "Employment and Worker Management"): **+75**.
2. **Environment** — file lives in `demo/hiring/`; no env signal present → `unknown`: **+5**.
3. **Exposure** — `from fastapi import APIRouter` + `@router.post(...)` → `public_api`: **+20**.
4. **Data sensitivity** — `email` matches `pii`: **+20**.
5. **Interaction** — `@router.post(...)` looks like a real-time HTTP handler → `user_facing_realtime`: **+10**.

**Sum:** 75 + 5 + 20 + 20 + 10 = **130** → clamped to **100** → level `critical`.

**Drivers:** `["high_risk_classification", "unknown_environment", "public_api", "pii_data", "user_facing_realtime"]`

**Confidence:** detection confidence 0.85 − 0.1 (unknown env) = **0.75**.

The same record without the `email` parameter and without the FastAPI import would score: 75 + 5 + 5 + 0 + 3 = **88** (still critical, but the explainer would surface different recommendations).

---

## 7. Limitations and design choices

- **Same-directory only.** Context detection only walks the directory containing the source file. A `.env.production` two folders away will not influence the score.
- **No transitive inference.** If a request passes through a wrapper layer that strips PII before the model call, aigov does not see that — it only sees the keyword presence.
- **Highest-of for data sensitivity.** A record that processes both PII and financial data scores the same as one that processes only PII (+20). This avoids stacking up over the clamp ceiling for records that touch many categories.
- **`unknown` environment is treated like `staging` for scoring**, because erring on the side of "not safe" produces fewer dangerous false negatives than erring on the side of "not risky".
- **Pattern matching has false positives and false negatives.** A function called `email_handler` that processes nothing sensitive will still match `pii`. Scores are a triage signal, not a verdict.

---

## 8. Reproducing a score

`aigov scan ... --with-risk --output json` includes the full driver list, the score, the level, the confidence, and the JSON-encoded `risk_context` (in `tags["risk_context"]`). Pass that JSON to your own tooling, or re-run `aigov.core.risk.compute_risk(record, context)` directly — the function is pure and importable.
