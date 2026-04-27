"""Tests for aigov.core.risk.scoring.compute_risk()."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from aigov.core.models import AISystemRecord, AISystemType, DeploymentType, RiskLevel
from aigov.core.risk.scoring import RiskResult, compute_risk


def _record(risk: RiskLevel = RiskLevel.UNKNOWN, confidence: float = 0.9) -> AISystemRecord:
    return AISystemRecord(
        id="r1",
        name="thing",
        description="",
        source_scanner="test",
        source_location="src/app.py",
        discovery_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        confidence=confidence,
        system_type=AISystemType.API_SERVICE,
        provider="OpenAI",
        deployment_type=DeploymentType.CLOUD_API,
        risk_classification=risk,
    )


def _ctx(**overrides) -> dict:
    base = {
        "environment": "development",
        "exposure": "batch_offline",
        "data_sensitivity": [],
        "interaction_type": "batch_offline",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Base scores
# ---------------------------------------------------------------------------

class TestBaseScores:
    @pytest.mark.parametrize("level,expected", [
        (RiskLevel.PROHIBITED, 95),
        (RiskLevel.HIGH_RISK, 75),
        (RiskLevel.LIMITED_RISK, 40),
        (RiskLevel.MINIMAL_RISK, 10),
        (RiskLevel.UNKNOWN, 50),
    ])
    def test_base_score_for_each_classification(self, level, expected):
        rec = _record(level)
        result = compute_risk(rec, _ctx())
        # development env=0, batch_offline exposure=0, no sensitivity, batch interaction=0
        assert result.risk_score == expected


# ---------------------------------------------------------------------------
# Modifiers
# ---------------------------------------------------------------------------

class TestEnvironmentModifiers:
    @pytest.mark.parametrize("env,delta", [
        ("production",  15),
        ("staging",      5),
        ("development",  0),
        ("test",        -5),
        ("unknown",      5),
    ])
    def test_environment_adds_modifier(self, env, delta):
        rec = _record(RiskLevel.LIMITED_RISK)  # base 40
        result = compute_risk(rec, _ctx(environment=env))
        assert result.risk_score == 40 + delta


class TestExposureModifiers:
    @pytest.mark.parametrize("exposure,delta", [
        ("public_api",      20),
        ("internal_service", 5),
        ("batch_offline",    0),
        ("unknown",          5),
    ])
    def test_exposure_adds_modifier(self, exposure, delta):
        rec = _record(RiskLevel.LIMITED_RISK)  # base 40
        result = compute_risk(rec, _ctx(exposure=exposure))
        assert result.risk_score == 40 + delta


class TestDataSensitivity:
    def test_pii_adds_20(self):
        rec = _record(RiskLevel.LIMITED_RISK)
        result = compute_risk(rec, _ctx(data_sensitivity=["pii"]))
        assert result.risk_score == 60

    def test_auth_adds_15(self):
        rec = _record(RiskLevel.LIMITED_RISK)
        result = compute_risk(rec, _ctx(data_sensitivity=["auth"]))
        assert result.risk_score == 55

    def test_multiple_categories_take_highest(self):
        rec = _record(RiskLevel.LIMITED_RISK)
        # auth (15) + pii (20) → highest is 20
        result = compute_risk(rec, _ctx(data_sensitivity=["auth", "pii"]))
        assert result.risk_score == 60

    def test_no_sensitivity_no_change(self):
        rec = _record(RiskLevel.LIMITED_RISK)
        result = compute_risk(rec, _ctx(data_sensitivity=[]))
        assert result.risk_score == 40


class TestInteractionModifiers:
    @pytest.mark.parametrize("interaction,delta", [
        ("user_facing_realtime", 10),
        ("internal_tooling",      3),
        ("batch_offline",         0),
        ("unknown",               3),
    ])
    def test_interaction_adds_modifier(self, interaction, delta):
        rec = _record(RiskLevel.LIMITED_RISK)
        result = compute_risk(rec, _ctx(interaction_type=interaction))
        assert result.risk_score == 40 + delta


# ---------------------------------------------------------------------------
# Clamping
# ---------------------------------------------------------------------------

class TestClamping:
    def test_score_does_not_exceed_100(self):
        rec = _record(RiskLevel.PROHIBITED)  # base 95
        ctx = _ctx(
            environment="production",       # +15
            exposure="public_api",          # +20
            data_sensitivity=["pii"],       # +20
            interaction_type="user_facing_realtime",  # +10
        )
        result = compute_risk(rec, ctx)
        assert result.risk_score == 100  # clamped from 160

    def test_score_does_not_drop_below_0(self):
        # Confect a record whose base is 10 but ctx pulls it negative.
        rec = _record(RiskLevel.MINIMAL_RISK)  # base 10
        ctx = _ctx(environment="test")  # -5 → 5 → still ≥ 0
        result = compute_risk(rec, ctx)
        assert result.risk_score >= 0


# ---------------------------------------------------------------------------
# Levels
# ---------------------------------------------------------------------------

class TestLevels:
    def test_critical_at_80(self):
        rec = _record(RiskLevel.HIGH_RISK)  # base 75
        result = compute_risk(rec, _ctx(environment="production"))  # +15 → 90
        assert result.risk_level == "critical"

    def test_high_at_60(self):
        rec = _record(RiskLevel.LIMITED_RISK)  # base 40
        result = compute_risk(rec, _ctx(exposure="public_api"))  # +20 → 60
        assert result.risk_level == "high"

    def test_medium_at_30(self):
        rec = _record(RiskLevel.LIMITED_RISK)  # base 40
        result = compute_risk(rec, _ctx())  # +0 → 40
        assert result.risk_level == "medium"

    def test_low_below_30(self):
        rec = _record(RiskLevel.MINIMAL_RISK)  # base 10
        result = compute_risk(rec, _ctx())  # +0 → 10
        assert result.risk_level == "low"


# ---------------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------------

class TestDrivers:
    def test_drivers_includes_classification(self):
        rec = _record(RiskLevel.HIGH_RISK)
        result = compute_risk(rec, _ctx())
        assert any("high_risk" in d for d in result.drivers)

    def test_drivers_includes_environment_when_significant(self):
        rec = _record(RiskLevel.LIMITED_RISK)
        result = compute_risk(rec, _ctx(environment="production"))
        assert "production_environment" in result.drivers

    def test_drivers_includes_exposure(self):
        rec = _record(RiskLevel.LIMITED_RISK)
        result = compute_risk(rec, _ctx(exposure="public_api"))
        assert "public_api" in result.drivers

    def test_drivers_includes_data_sensitivity(self):
        rec = _record(RiskLevel.LIMITED_RISK)
        result = compute_risk(rec, _ctx(data_sensitivity=["pii"]))
        assert "pii_data" in result.drivers

    def test_drivers_includes_interaction(self):
        rec = _record(RiskLevel.LIMITED_RISK)
        result = compute_risk(rec, _ctx(interaction_type="user_facing_realtime"))
        assert "user_facing_realtime" in result.drivers


# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------

class TestConfidence:
    def test_starts_from_record_confidence(self):
        rec = _record(RiskLevel.HIGH_RISK, confidence=0.85)
        result = compute_risk(rec, _ctx())  # known env + exposure
        assert result.confidence == pytest.approx(0.85)

    def test_unknown_environment_drops_confidence_by_0_1(self):
        rec = _record(RiskLevel.HIGH_RISK, confidence=0.9)
        result = compute_risk(rec, _ctx(environment="unknown"))
        assert result.confidence == pytest.approx(0.8)

    def test_unknown_exposure_drops_confidence_by_0_1(self):
        rec = _record(RiskLevel.HIGH_RISK, confidence=0.9)
        result = compute_risk(rec, _ctx(exposure="unknown"))
        assert result.confidence == pytest.approx(0.8)

    def test_both_unknown_drops_confidence_by_0_2(self):
        rec = _record(RiskLevel.HIGH_RISK, confidence=0.9)
        result = compute_risk(rec, _ctx(environment="unknown", exposure="unknown"))
        assert result.confidence == pytest.approx(0.7)

    def test_confidence_clamps_at_zero(self):
        rec = _record(RiskLevel.HIGH_RISK, confidence=0.05)
        result = compute_risk(rec, _ctx(environment="unknown", exposure="unknown"))
        assert result.confidence >= 0.0


def test_returns_risk_result_dataclass():
    rec = _record(RiskLevel.HIGH_RISK)
    result = compute_risk(rec, _ctx())
    assert isinstance(result, RiskResult)
    assert isinstance(result.risk_score, int)
    assert isinstance(result.risk_level, str)
    assert isinstance(result.drivers, list)
    assert isinstance(result.confidence, float)
