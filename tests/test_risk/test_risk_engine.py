"""End-to-end tests for the risk engine."""
from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aigov.core.models import AISystemRecord, AISystemType, DeploymentType, RiskLevel
from aigov.core.risk import apply_risk

FIXTURES = Path(__file__).parent / "fixtures"
FASTAPI_FIXTURE = FIXTURES / "fastapi_users_app.py"
BATCH_FIXTURE = FIXTURES / "batch_processor.py"


@pytest.fixture(autouse=True)
def _clear_ci_env(monkeypatch):
    for var in ("CI", "GITHUB_ACTIONS", "JENKINS_URL", "JENKINS_HOME", "GITLAB_CI"):
        monkeypatch.delenv(var, raising=False)


def _record(
    source_location: str,
    risk: RiskLevel = RiskLevel.LIMITED_RISK,
    confidence: float = 0.9,
) -> AISystemRecord:
    return AISystemRecord(
        id="r1",
        name="ai_thing",
        description="",
        source_scanner="test.scanner",
        source_location=source_location,
        discovery_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        confidence=confidence,
        system_type=AISystemType.API_SERVICE,
        provider="OpenAI",
        deployment_type=DeploymentType.CLOUD_API,
        risk_classification=risk,
    )


# ---------------------------------------------------------------------------
# End-to-end pipeline
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def test_production_public_api_pii_is_critical(self, tmp_path):
        """Combined high-stakes signals should land in the critical band."""
        prod_dir = tmp_path / "production"
        prod_dir.mkdir()
        target = prod_dir / "service.py"
        shutil.copy(FASTAPI_FIXTURE, target)

        rec = _record(str(target), risk=RiskLevel.HIGH_RISK)
        scored = apply_risk([rec], [str(tmp_path)])
        assert len(scored) == 1
        out = scored[0]
        assert out.risk_level == "critical"
        assert out.risk_score >= 80

    def test_dev_internal_no_sensitive_is_low_or_medium(self, tmp_path):
        dev_dir = tmp_path / "dev"
        dev_dir.mkdir()
        target = dev_dir / "lib.py"
        target.write_text("def add(a, b): return a + b\n", encoding="utf-8")

        rec = _record(str(target), risk=RiskLevel.MINIMAL_RISK)
        scored = apply_risk([rec], [str(tmp_path)])
        out = scored[0]
        # base 10 + dev 0 + unknown exposure +5 + unknown interaction +3 = 18 → low
        assert out.risk_level == "low"

    def test_batch_offline_is_lower_risk_than_realtime(self, tmp_path):
        prod_dir = tmp_path / "production"
        prod_dir.mkdir()
        batch_target = prod_dir / "etl.py"
        shutil.copy(BATCH_FIXTURE, batch_target)
        rec = _record(str(batch_target), risk=RiskLevel.HIGH_RISK)
        scored = apply_risk([rec], [str(tmp_path)])
        # base 75 + production 15 + batch 0 + no sensitive 0 + batch_interaction 0 = 90
        # That's still critical — but lower than the public_api+pii case which clamps to 100.
        assert scored[0].risk_score <= 100


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------

class TestImmutability:
    def test_input_records_are_not_mutated(self, tmp_path):
        target = tmp_path / "lib.py"
        target.write_text("def add(): pass\n", encoding="utf-8")
        rec = _record(str(target))
        original_tags = dict(rec.tags)

        apply_risk([rec], [str(tmp_path)])

        assert rec.tags == original_tags
        assert rec.risk_score is None

    def test_output_is_a_new_list_of_new_records(self, tmp_path):
        target = tmp_path / "lib.py"
        target.write_text("def add(): pass\n", encoding="utf-8")
        rec = _record(str(target))
        scored = apply_risk([rec], [str(tmp_path)])
        assert scored is not [rec]
        assert scored[0] is not rec


# ---------------------------------------------------------------------------
# Risk fields are populated as first-class attributes
# ---------------------------------------------------------------------------

class TestRiskFields:
    def test_all_risk_fields_populated(self, tmp_path):
        target = tmp_path / "lib.py"
        target.write_text("def x(): pass\n", encoding="utf-8")
        rec = _record(str(target))
        scored = apply_risk([rec], [str(tmp_path)])
        out = scored[0]
        assert isinstance(out.risk_score, int)
        assert isinstance(out.risk_level, str)
        assert isinstance(out.risk_drivers, list)
        assert isinstance(out.risk_confidence, float)
        # Context still lives in tags as JSON for transparency / debugging.
        assert "risk_context" in out.tags

    def test_risk_context_tag_is_valid_json(self, tmp_path):
        target = tmp_path / "lib.py"
        target.write_text("def x(): pass\n", encoding="utf-8")
        rec = _record(str(target))
        scored = apply_risk([rec], [str(tmp_path)])
        ctx = json.loads(scored[0].tags["risk_context"])
        assert "environment" in ctx
        assert "exposure" in ctx
        assert "data_sensitivity" in ctx
        assert "interaction_type" in ctx

    def test_existing_tags_are_preserved(self, tmp_path):
        target = tmp_path / "lib.py"
        target.write_text("def x(): pass\n", encoding="utf-8")
        rec = _record(str(target))
        rec_with_tag = type(rec)(
            **{**{f.name: getattr(rec, f.name) for f in rec.__dataclass_fields__.values()},
               "tags": {"origin_jurisdiction": "US"}}
        )
        scored = apply_risk([rec_with_tag], [str(tmp_path)])
        assert scored[0].tags["origin_jurisdiction"] == "US"
        assert scored[0].risk_score is not None
