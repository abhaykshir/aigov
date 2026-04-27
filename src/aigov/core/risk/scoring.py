"""Deterministic risk scoring.

``compute_risk()`` combines an EU-AI-Act classification with deployment
context (environment, exposure, data sensitivity, interaction type) into a
0-100 score, a categorical level, and an explicit list of drivers.

The function is pure: same inputs → same outputs. No file I/O, no network.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aigov.core.models import AISystemRecord, RiskLevel


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class RiskResult:
    risk_score: int          # 0..100, clamped
    risk_level: str          # critical / high / medium / low
    drivers: list[str]       # human-readable reasons the score landed here
    confidence: float        # 0..1, derived from classification confidence and unknown context signals


# ---------------------------------------------------------------------------
# Modifier tables
# ---------------------------------------------------------------------------

_BASE_SCORES: dict[RiskLevel, int] = {
    RiskLevel.PROHIBITED:    95,
    RiskLevel.HIGH_RISK:     75,
    RiskLevel.LIMITED_RISK:  40,
    RiskLevel.MINIMAL_RISK:  10,
    RiskLevel.UNKNOWN:       50,
    RiskLevel.NEEDS_REVIEW:  50,
}

_ENVIRONMENT_MODIFIERS: dict[str, int] = {
    "production":  15,
    "staging":      5,
    "development":  0,
    "test":        -5,
    "unknown":      5,   # treat unknown conservatively, like staging
}

_EXPOSURE_MODIFIERS: dict[str, int] = {
    "public_api":      20,
    "internal_service": 5,
    "batch_offline":    0,
    "unknown":          5,
}

# Highest-of for data_sensitivity — multiple categories don't stack because
# the regulatory cost of any single sensitive-data category dominates.
_DATA_SENSITIVITY_MODIFIERS: dict[str, int] = {
    "pii":       20,
    "financial": 20,
    "health":    20,
    "auth":      15,
}

_INTERACTION_MODIFIERS: dict[str, int] = {
    "user_facing_realtime": 10,
    "internal_tooling":      3,
    "batch_offline":         0,
    "unknown":               3,
}

# Threshold → label, applied in descending order.
_LEVEL_BANDS: list[tuple[int, str]] = [
    (80, "critical"),
    (60, "high"),
    (30, "medium"),
    (0,  "low"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_risk(record: AISystemRecord, context: dict[str, Any]) -> RiskResult:
    """Score *record* using its classification plus the *context* from enrich()."""
    base_level = record.risk_classification or RiskLevel.UNKNOWN
    score = _BASE_SCORES.get(base_level, 50)

    drivers: list[str] = [f"{base_level.value}_classification"]

    score, drivers = _apply_environment(score, drivers, context.get("environment", "unknown"))
    score, drivers = _apply_exposure(score, drivers, context.get("exposure", "unknown"))
    score, drivers = _apply_data_sensitivity(score, drivers, context.get("data_sensitivity") or [])
    score, drivers = _apply_interaction(score, drivers, context.get("interaction_type", "unknown"))

    score = max(0, min(100, score))
    level = _score_to_level(score)
    confidence = _confidence(record, context)

    return RiskResult(risk_score=score, risk_level=level, drivers=drivers, confidence=confidence)


# ---------------------------------------------------------------------------
# Modifier helpers — each returns the new (score, drivers) tuple
# ---------------------------------------------------------------------------

def _apply_environment(score: int, drivers: list[str], env: str) -> tuple[int, list[str]]:
    delta = _ENVIRONMENT_MODIFIERS.get(env, _ENVIRONMENT_MODIFIERS["unknown"])
    if delta != 0 or env in {"unknown", "staging"}:
        # We always log production/staging/test/unknown so the user can audit
        # the score; development with delta 0 is the silent default.
        if env != "development":
            drivers.append(f"{env}_environment")
    return score + delta, drivers


def _apply_exposure(score: int, drivers: list[str], exposure: str) -> tuple[int, list[str]]:
    delta = _EXPOSURE_MODIFIERS.get(exposure, _EXPOSURE_MODIFIERS["unknown"])
    if exposure != "batch_offline":
        # batch_offline contributes 0 and is the silent default; everything
        # else is a driver worth surfacing.
        drivers.append(exposure)
    return score + delta, drivers


def _apply_data_sensitivity(
    score: int,
    drivers: list[str],
    categories: list[str],
) -> tuple[int, list[str]]:
    if not categories:
        return score, drivers
    # Pick the category contributing the highest modifier; ties resolve to
    # the first listed in the input.
    chosen = max(categories, key=lambda c: _DATA_SENSITIVITY_MODIFIERS.get(c, 0))
    delta = _DATA_SENSITIVITY_MODIFIERS.get(chosen, 0)
    if delta:
        drivers.append(f"{chosen}_data")
    return score + delta, drivers


def _apply_interaction(score: int, drivers: list[str], interaction: str) -> tuple[int, list[str]]:
    delta = _INTERACTION_MODIFIERS.get(interaction, _INTERACTION_MODIFIERS["unknown"])
    if interaction != "batch_offline":
        drivers.append(interaction)
    return score + delta, drivers


def _score_to_level(score: int) -> str:
    for threshold, label in _LEVEL_BANDS:
        if score >= threshold:
            return label
    return "low"


def _confidence(record: AISystemRecord, context: dict[str, Any]) -> float:
    confidence = float(record.confidence)
    if context.get("environment") == "unknown":
        confidence -= 0.1
    if context.get("exposure") == "unknown":
        confidence -= 0.1
    return max(0.0, min(1.0, confidence))
