"""Generate actionable, driver-aware explanations for an AISystemRecord.

The explainer turns the risk engine's drivers list into a short summary, a
list of risk factors a reviewer should care about, and concrete actions the
team can take. Recommendations are deterministic — no LLM, no network — so
the same finding always yields the same advice.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from aigov.core.models import AISystemRecord, RiskLevel


# ---------------------------------------------------------------------------
# Explanation dataclass
# ---------------------------------------------------------------------------

@dataclass
class Explanation:
    summary: str                              # one-sentence why-this-is-risky
    risk_factors: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    priority: str = "low"                     # critical | high | medium | low

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "risk_factors": list(self.risk_factors),
            "recommended_actions": list(self.recommended_actions),
            "priority": self.priority,
        }


# ---------------------------------------------------------------------------
# Driver → (risk_factor, recommended_actions) mapping
#
# The list of recommendations stays small per driver on purpose: a reviewer
# who sees ten boxes each with twenty bullets reads zero of them. Every line
# below should map to a real concrete decision a team can take this sprint.
# ---------------------------------------------------------------------------

_DRIVER_GUIDANCE: dict[str, dict[str, Any]] = {
    "public_api": {
        "factor": "Public-facing API endpoint exposes the model to external traffic",
        "actions": [
            "Add input validation and rate limiting to AI endpoints",
            "Implement output filtering for generated content",
        ],
    },
    "internal_service": {
        "factor": "Internal service-to-service exposure",
        "actions": [
            "Restrict callers via mTLS or signed-request auth",
            "Log and monitor all internal AI invocations",
        ],
    },
    "pii_data": {
        "factor": "System processes personally-identifiable information (PII)",
        "actions": [
            "Conduct a Data Protection Impact Assessment (DPIA)",
            "Implement data minimization — only pass necessary data to the AI model",
            "Add PII redaction before model input",
        ],
    },
    "financial_data": {
        "factor": "System processes financial data (payments, accounts, salaries)",
        "actions": [
            "Add audit logging for all AI-assisted financial decisions",
            "Implement human-in-the-loop for decisions above threshold",
        ],
    },
    "health_data": {
        "factor": "System processes health or medical data",
        "actions": [
            "Verify HIPAA / GDPR special-category lawful basis with counsel",
            "Apply de-identification before model input where feasible",
        ],
    },
    "auth_data": {
        "factor": "System handles credentials or auth tokens",
        "actions": [
            "Ensure secrets never reach model input or logs",
            "Rotate any credentials that may have been observed by the model",
        ],
    },
    "production_environment": {
        "factor": "Deployed in production",
        "actions": [
            "Implement model monitoring and observability",
            "Add fallback / circuit-breaker for model failures",
        ],
    },
    "staging_environment": {
        "factor": "Deployed in staging — promotion to production imminent",
        "actions": [
            "Complete pre-production review before promotion",
        ],
    },
    "user_facing_realtime": {
        "factor": "Handles real-time user-facing input",
        "actions": [
            "Add content filtering for AI responses",
            "Implement user feedback mechanism",
            "Add AI disclosure per Article 50",
        ],
    },
    "internal_tooling": {
        "factor": "Used as internal tooling",
        "actions": [
            "Document operator runbooks for failure modes",
        ],
    },
    "high_risk_classification": {
        "factor": "Classified as HIGH RISK under EU AI Act Annex III",
        "actions": [
            "Complete EU AI Act Annex IV technical documentation",
            "Establish human oversight mechanism per Article 14",
            "Register in EU AI database per Article 49",
        ],
    },
    "limited_risk_classification": {
        "factor": "Classified as LIMITED RISK — Article 50 transparency obligations apply",
        "actions": [
            "Add AI-interaction disclosure at the start of every session",
            "Label any AI-generated content (Article 50(4))",
        ],
    },
    "minimal_risk_classification": {
        "factor": "Classified as MINIMAL RISK by aigov heuristics",
        "actions": [
            "No additional EU AI Act controls required — keep monitoring for drift",
        ],
    },
    "unknown_environment": {
        "factor": "Deployment environment could not be determined",
        "actions": [
            "Tag the deployment with a `.env.<env>` file or named directory so risk scoring picks it up",
        ],
    },
}


# Drivers that the scoring engine emits but that don't on their own warrant a
# recommendation (they're surfaced by adjacent drivers). Keeping them on this
# list keeps the explanation list focused.
_DRIVERS_WITHOUT_GUIDANCE = frozenset({
    "unknown",
    "test_environment",
    "development_environment",
    "batch_offline",
    "prohibited_classification",
})


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def explain(record: AISystemRecord) -> Explanation:
    """Return a human-readable explanation for *record*.

    Pulls driver, classification, score, and context tags off the record. If
    the risk engine has not run, the explanation degrades gracefully — the
    classification alone is enough to produce useful guidance.
    """
    drivers = _drivers(record)
    classification = record.risk_classification or RiskLevel.UNKNOWN
    risk_level = record.risk_level or ""
    risk_score = record.risk_score if record.risk_score is not None else 0
    context = _context(record)

    # PROHIBITED short-circuits everything: there's only one correct action.
    if classification == RiskLevel.PROHIBITED:
        return Explanation(
            summary=(
                "This system likely violates Article 5 of the EU AI Act "
                "(prohibited AI practice) and may not be placed on the EU "
                "market in any form."
            ),
            risk_factors=[
                "Classified as PROHIBITED under Article 5 by aigov heuristics",
            ],
            recommended_actions=[
                "Cease usage immediately. This system likely violates Article 5 of the EU AI Act.",
                "Engage qualified EU AI Act legal counsel to confirm or contest the classification",
                "Document the cessation decision with date, scope, and authorising person",
            ],
            priority="critical",
        )

    factors: list[str] = []
    actions: list[str] = []
    seen_actions: set[str] = set()  # de-dupe across drivers

    for driver in drivers:
        guidance = _DRIVER_GUIDANCE.get(driver)
        if guidance is None:
            continue
        factors.append(guidance["factor"])
        for action in guidance["actions"]:
            if action not in seen_actions:
                actions.append(action)
                seen_actions.add(action)

    summary = _build_summary(drivers, classification, risk_score, context)
    priority = _priority(risk_level, classification, risk_score)

    # Minimal-risk records with no contextual drivers should still get *some*
    # actionable text — but a short list, not the kitchen sink.
    if not actions:
        actions.append("No additional EU AI Act controls required — keep monitoring for drift")
    if not factors:
        factors.append("No elevated risk drivers detected")

    return Explanation(
        summary=summary,
        risk_factors=factors,
        recommended_actions=actions,
        priority=priority,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _drivers(record: AISystemRecord) -> list[str]:
    if record.risk_drivers:
        return list(record.risk_drivers)
    return []


def _context(record: AISystemRecord) -> dict[str, Any]:
    raw = record.tags.get("risk_context", "")
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}


def _int(raw: Any) -> int:
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def _build_summary(
    drivers: list[str],
    classification: RiskLevel,
    risk_score: int,
    context: dict[str, Any],
) -> str:
    """Compose a sentence like:

    "This system processes PII via a public API in production using an LLM,
    creating significant regulatory and security risk."
    """
    sensitivity = context.get("data_sensitivity") or []
    sens_phrase = _sensitivity_phrase(sensitivity)
    exposure_phrase = _exposure_phrase(drivers)
    env_phrase = _env_phrase(drivers)

    clauses = ["This system"]
    clauses.append(sens_phrase)
    if exposure_phrase:
        clauses.append(exposure_phrase)
    if env_phrase:
        clauses.append(env_phrase)

    head = " ".join(c for c in clauses if c)
    tail = _severity_tail(classification, risk_score)
    return f"{head}, {tail}"


def _sensitivity_phrase(categories: list[str]) -> str:
    if "pii" in categories and "financial" in categories:
        return "processes PII and financial data"
    if "pii" in categories:
        return "processes PII"
    if "financial" in categories:
        return "processes financial data"
    if "health" in categories:
        return "processes health data"
    if "auth" in categories:
        return "handles authentication credentials"
    return "operates"


def _exposure_phrase(drivers: list[str]) -> str:
    if "public_api" in drivers:
        return "via a public API"
    if "internal_service" in drivers:
        return "as an internal service"
    return ""


def _env_phrase(drivers: list[str]) -> str:
    if "production_environment" in drivers:
        return "in production"
    if "staging_environment" in drivers:
        return "in staging"
    return ""


def _severity_tail(classification: RiskLevel, risk_score: int) -> str:
    if classification == RiskLevel.HIGH_RISK or risk_score >= 80:
        return "creating significant regulatory and security risk."
    if classification == RiskLevel.LIMITED_RISK or risk_score >= 60:
        return "creating moderate regulatory exposure under Article 50 transparency obligations."
    if risk_score >= 30:
        return "creating moderate risk that warrants monitoring."
    return "creating minimal apparent risk under aigov heuristics."


def _priority(risk_level: str, classification: RiskLevel, risk_score: int) -> str:
    """Prefer the risk engine's level, fall back to classification mapping."""
    if risk_level in {"critical", "high", "medium", "low"}:
        return risk_level
    if classification == RiskLevel.HIGH_RISK:
        return "high"
    if classification == RiskLevel.LIMITED_RISK:
        return "medium"
    if classification == RiskLevel.MINIMAL_RISK:
        return "low"
    if risk_score >= 80:
        return "critical"
    if risk_score >= 60:
        return "high"
    if risk_score >= 30:
        return "medium"
    return "low"
