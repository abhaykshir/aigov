"""Tests for aigov.core.explainer.explain()."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from aigov.core.explainer import Explanation, explain
from aigov.core.models import AISystemRecord, AISystemType, DeploymentType, RiskLevel


# ---------------------------------------------------------------------------
# Helpers — build a record with whatever risk-engine tags the test needs.
# ---------------------------------------------------------------------------

def _record(
    *,
    classification: RiskLevel = RiskLevel.MINIMAL_RISK,
    drivers: list[str] | None = None,
    risk_level: str | None = None,
    risk_score: int | None = None,
    context: dict | None = None,
) -> AISystemRecord:
    tags: dict[str, str] = {}
    # Context still flows through ``risk_context`` for transparency / debugging;
    # the explainer reads sensitivity from there to compose its summary.
    if context is not None:
        tags["risk_context"] = json.dumps(context)

    return AISystemRecord(
        id="r1",
        name="thing",
        description="",
        source_scanner="test",
        source_location="src/x.py",
        discovery_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        confidence=0.9,
        system_type=AISystemType.API_SERVICE,
        provider="OpenAI",
        deployment_type=DeploymentType.CLOUD_API,
        risk_classification=classification,
        tags=tags,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_drivers=list(drivers) if drivers is not None else None,
    )


# ---------------------------------------------------------------------------
# Driver-specific recommendations
# ---------------------------------------------------------------------------

class TestDriverRecommendations:
    def test_public_api_yields_api_specific_actions(self):
        rec = _record(
            classification=RiskLevel.LIMITED_RISK,
            drivers=["public_api", "limited_risk_classification"],
        )
        ex = explain(rec)
        joined = " ".join(ex.recommended_actions).lower()
        assert "rate limit" in joined or "rate-limit" in joined or "rate limiting" in joined
        assert "input validation" in joined or "output filtering" in joined

    def test_pii_data_yields_dpia_action(self):
        rec = _record(
            classification=RiskLevel.HIGH_RISK,
            drivers=["pii_data", "high_risk_classification"],
        )
        ex = explain(rec)
        joined = " ".join(ex.recommended_actions).lower()
        assert "dpia" in joined or "data protection impact" in joined

    def test_financial_data_yields_audit_action(self):
        rec = _record(
            classification=RiskLevel.HIGH_RISK,
            drivers=["financial_data"],
        )
        ex = explain(rec)
        joined = " ".join(ex.recommended_actions).lower()
        assert "audit" in joined

    def test_production_environment_yields_monitoring_action(self):
        rec = _record(drivers=["production_environment"])
        ex = explain(rec)
        joined = " ".join(ex.recommended_actions).lower()
        assert "monitoring" in joined or "circuit-breaker" in joined or "circuit breaker" in joined

    def test_user_facing_realtime_yields_disclosure_action(self):
        rec = _record(drivers=["user_facing_realtime"])
        ex = explain(rec)
        joined = " ".join(ex.recommended_actions).lower()
        assert "disclosure" in joined or "article 50" in joined

    def test_high_risk_yields_annex_iv_action(self):
        rec = _record(
            classification=RiskLevel.HIGH_RISK,
            drivers=["high_risk_classification"],
        )
        ex = explain(rec)
        joined = " ".join(ex.recommended_actions).lower()
        assert "annex iv" in joined

    def test_high_risk_includes_eu_database_action(self):
        rec = _record(
            classification=RiskLevel.HIGH_RISK,
            drivers=["high_risk_classification"],
        )
        ex = explain(rec)
        joined = " ".join(ex.recommended_actions).lower()
        assert "eu ai database" in joined or "article 49" in joined


# ---------------------------------------------------------------------------
# Prohibited short-circuit
# ---------------------------------------------------------------------------

class TestProhibited:
    def test_prohibited_short_circuits_to_cease(self):
        rec = _record(classification=RiskLevel.PROHIBITED, drivers=["high_risk_classification"])
        ex = explain(rec)
        joined = " ".join(ex.recommended_actions).lower()
        assert "cease" in joined
        assert "article 5" in joined

    def test_prohibited_priority_is_critical(self):
        rec = _record(classification=RiskLevel.PROHIBITED)
        assert explain(rec).priority == "critical"


# ---------------------------------------------------------------------------
# Minimal-risk fallback
# ---------------------------------------------------------------------------

class TestMinimalFallback:
    def test_minimal_with_no_drivers_still_returns_actionable_text(self):
        rec = _record(classification=RiskLevel.MINIMAL_RISK, drivers=[])
        ex = explain(rec)
        assert ex.recommended_actions, "expected at least one recommendation"
        assert ex.risk_factors, "expected at least one risk factor entry"
        assert ex.priority == "low"

    def test_minimal_summary_indicates_low_risk(self):
        rec = _record(classification=RiskLevel.MINIMAL_RISK, drivers=[])
        ex = explain(rec)
        assert "minimal" in ex.summary.lower() or "low" in ex.summary.lower() or "monitoring" in ex.summary.lower()


# ---------------------------------------------------------------------------
# Recommendations are non-empty for every level
# ---------------------------------------------------------------------------

class TestNonEmptyForEveryLevel:
    @pytest.mark.parametrize("level", [
        RiskLevel.PROHIBITED,
        RiskLevel.HIGH_RISK,
        RiskLevel.LIMITED_RISK,
        RiskLevel.MINIMAL_RISK,
        RiskLevel.UNKNOWN,
    ])
    def test_every_level_yields_recommendations(self, level):
        rec = _record(classification=level)
        ex = explain(rec)
        assert ex.recommended_actions, f"empty actions for {level}"
        assert ex.summary, f"empty summary for {level}"


# ---------------------------------------------------------------------------
# Summary composition
# ---------------------------------------------------------------------------

class TestSummary:
    def test_summary_mentions_pii_when_pii_in_context(self):
        rec = _record(
            classification=RiskLevel.HIGH_RISK,
            drivers=["public_api", "pii_data", "production_environment"],
            context={"data_sensitivity": ["pii"]},
        )
        ex = explain(rec)
        s = ex.summary.lower()
        assert "pii" in s
        assert "public api" in s
        assert "production" in s

    def test_summary_handles_no_drivers(self):
        rec = _record(classification=RiskLevel.MINIMAL_RISK, drivers=[])
        ex = explain(rec)
        assert ex.summary  # non-empty
        assert ex.summary.endswith(".")


# ---------------------------------------------------------------------------
# Priority resolution
# ---------------------------------------------------------------------------

class TestPriority:
    def test_priority_uses_risk_engine_level_when_set(self):
        rec = _record(
            classification=RiskLevel.MINIMAL_RISK,
            risk_level="critical",
        )
        assert explain(rec).priority == "critical"

    def test_priority_falls_back_to_classification(self):
        rec = _record(classification=RiskLevel.HIGH_RISK)
        assert explain(rec).priority == "high"

    def test_minimal_classification_yields_low_priority(self):
        rec = _record(classification=RiskLevel.MINIMAL_RISK)
        assert explain(rec).priority == "low"


# ---------------------------------------------------------------------------
# Dedup — drivers shouldn't produce duplicate action lines
# ---------------------------------------------------------------------------

def test_recommendations_are_deduped_across_drivers():
    rec = _record(
        classification=RiskLevel.HIGH_RISK,
        drivers=["public_api", "high_risk_classification", "user_facing_realtime"],
    )
    ex = explain(rec)
    assert len(ex.recommended_actions) == len(set(ex.recommended_actions))


# ---------------------------------------------------------------------------
# Explanation dataclass shape
# ---------------------------------------------------------------------------

def test_explanation_to_dict_has_expected_keys():
    rec = _record(classification=RiskLevel.MINIMAL_RISK)
    ex = explain(rec)
    d = ex.to_dict()
    assert set(d.keys()) == {"summary", "risk_factors", "recommended_actions", "priority"}
    assert isinstance(d["risk_factors"], list)
    assert isinstance(d["recommended_actions"], list)
