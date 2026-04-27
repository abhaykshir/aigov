"""Tests for aigov.core.policy.evaluate_policies()."""
from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aigov.core.models import AISystemRecord, AISystemType, DeploymentType, RiskLevel
from aigov.core.policy import (
    Policy,
    PolicyResult,
    evaluate_policies,
    evaluate_policies_against,
    load_policies,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _record(
    *,
    name: str = "thing",
    classification: RiskLevel = RiskLevel.MINIMAL_RISK,
    risk_score: int | None = None,
    risk_level: str | None = None,
    exposure: str | None = None,
    environment: str | None = None,
    data_sensitivity: list[str] | None = None,
    interaction_type: str | None = None,
    jurisdiction: str = "US",
    system_type: AISystemType = AISystemType.API_SERVICE,
    allowlisted: bool = False,
) -> AISystemRecord:
    tags: dict[str, str] = {"origin_jurisdiction": jurisdiction}
    # Context fields still live in the JSON-encoded ``risk_context`` tag —
    # the policy engine reads them through that path.
    ctx: dict = {}
    if exposure is not None:
        ctx["exposure"] = exposure
    if environment is not None:
        ctx["environment"] = environment
    if data_sensitivity is not None:
        ctx["data_sensitivity"] = data_sensitivity
    if interaction_type is not None:
        ctx["interaction_type"] = interaction_type
    if ctx:
        tags["risk_context"] = json.dumps(ctx)
    if allowlisted:
        tags["allowlisted"] = "true"
        tags["allowlist_reason"] = "approved by board"

    return AISystemRecord(
        id="r-" + name,
        name=name,
        description="",
        source_scanner="test",
        source_location="src/x.py",
        discovery_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        confidence=0.9,
        system_type=system_type,
        provider="OpenAI",
        deployment_type=DeploymentType.CLOUD_API,
        risk_classification=classification,
        tags=tags,
        risk_score=risk_score,
        risk_level=risk_level,
    )


def _write_policy_file(tmp_path: Path, policies: list[dict]) -> Path:
    p = tmp_path / ".aigov-policy.yaml"
    import yaml
    p.write_text(yaml.safe_dump({"policies": policies}), encoding="utf-8")
    return p


def _policy(**overrides) -> Policy:
    base = dict(name="p1", description="", condition={"system_type": "api_service"}, action="fail")
    base.update(overrides)
    return Policy(**base)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

class TestLoad:
    def test_missing_file_returns_empty_list(self, tmp_path):
        assert load_policies(tmp_path / "does-not-exist.yaml") == []

    def test_malformed_yaml_returns_empty_list(self, tmp_path):
        p = tmp_path / ".aigov-policy.yaml"
        p.write_text("not: [valid: yaml", encoding="utf-8")
        assert load_policies(p) == []

    def test_invalid_policies_skipped(self, tmp_path):
        p = _write_policy_file(tmp_path, [
            {"name": "good", "condition": {"system_type": "api_service"}, "action": "fail"},
            {"description": "missing name", "condition": {"x": 1}, "action": "fail"},
            {"name": "bad-action", "condition": {"x": 1}, "action": "explode"},
        ])
        policies = load_policies(p)
        assert [pol.name for pol in policies] == ["good"]


# ---------------------------------------------------------------------------
# Single-condition matchers
# ---------------------------------------------------------------------------

class TestRiskScoreCondition:
    def test_ge_threshold(self):
        rec_pass = _record(risk_score=85)
        rec_fail = _record(risk_score=70)
        pol = _policy(name="hi", condition={"risk_score": ">=80"}, action="fail")
        result = evaluate_policies_against([rec_pass, rec_fail], [pol])
        assert len(result.failures) == 1
        assert result.failures[0].record is rec_pass

    def test_lt_threshold(self):
        rec_match = _record(risk_score=10)
        rec_no = _record(risk_score=80)
        pol = _policy(name="lo", condition={"risk_score": "<30"}, action="warn")
        result = evaluate_policies_against([rec_match, rec_no], [pol])
        assert [m.record for m in result.warnings] == [rec_match]

    def test_int_value_means_equality(self):
        rec1 = _record(risk_score=42)
        rec2 = _record(risk_score=43)
        pol = _policy(condition={"risk_score": 42})
        result = evaluate_policies_against([rec1, rec2], [pol])
        assert [m.record for m in result.failures] == [rec1]


class TestExposureCondition:
    def test_exposure_match(self):
        public = _record(name="api", exposure="public_api")
        internal = _record(name="rpc", exposure="internal_service")
        pol = _policy(condition={"exposure": "public_api"})
        result = evaluate_policies_against([public, internal], [pol])
        assert [m.record for m in result.failures] == [public]


class TestDataSensitivityCondition:
    def test_pii_match(self):
        with_pii = _record(name="hr", data_sensitivity=["pii"])
        without = _record(name="etl", data_sensitivity=[])
        pol = _policy(condition={"data_sensitivity": "pii"})
        result = evaluate_policies_against([with_pii, without], [pol])
        assert [m.record for m in result.failures] == [with_pii]

    def test_list_in_record_intersects_expected_list(self):
        rec = _record(data_sensitivity=["financial", "auth"])
        pol = _policy(condition={"data_sensitivity": ["pii", "financial"]})
        result = evaluate_policies_against([rec], [pol])
        assert len(result.failures) == 1


class TestJurisdictionCondition:
    def test_single_value(self):
        cn = _record(name="zh", jurisdiction="CN")
        us = _record(name="en", jurisdiction="US")
        pol = _policy(condition={"jurisdiction": "CN"})
        result = evaluate_policies_against([cn, us], [pol])
        assert [m.record for m in result.failures] == [cn]

    def test_list_of_values(self):
        cn = _record(name="zh", jurisdiction="CN")
        ru = _record(name="ru", jurisdiction="RU")
        us = _record(name="en", jurisdiction="US")
        pol = _policy(condition={"jurisdiction": ["CN", "RU"]})
        result = evaluate_policies_against([cn, ru, us], [pol])
        assert {m.record.name for m in result.failures} == {"zh", "ru"}


class TestEnvironmentCondition:
    def test_environment_match(self):
        prod = _record(name="prod", environment="production")
        dev = _record(name="dev", environment="development")
        pol = _policy(condition={"environment": "production"})
        result = evaluate_policies_against([prod, dev], [pol])
        assert [m.record for m in result.failures] == [prod]


class TestSystemTypeCondition:
    def test_system_type_match(self):
        api = _record(name="api", system_type=AISystemType.API_SERVICE)
        mcp = _record(name="mcp", system_type=AISystemType.MCP_SERVER)
        pol = _policy(condition={"system_type": "api_service"})
        result = evaluate_policies_against([api, mcp], [pol])
        assert [m.record for m in result.failures] == [api]


# ---------------------------------------------------------------------------
# Multi-condition AND logic
# ---------------------------------------------------------------------------

class TestAndLogic:
    def test_all_conditions_must_match(self):
        # Matches both: HIGH_RISK PII in production
        full = _record(
            name="full",
            classification=RiskLevel.HIGH_RISK,
            data_sensitivity=["pii"],
            environment="production",
        )
        # Misses environment
        partial = _record(
            name="partial",
            classification=RiskLevel.HIGH_RISK,
            data_sensitivity=["pii"],
            environment="development",
        )
        pol = _policy(
            name="block-pii-prod",
            condition={
                "data_sensitivity": "pii",
                "environment": "production",
            },
        )
        result = evaluate_policies_against([full, partial], [pol])
        assert [m.record for m in result.failures] == [full]


# ---------------------------------------------------------------------------
# Actions: fail vs warn
# ---------------------------------------------------------------------------

class TestActions:
    def test_fail_action_lands_in_failures(self):
        rec = _record(exposure="public_api")
        pol = _policy(condition={"exposure": "public_api"}, action="fail")
        result = evaluate_policies_against([rec], [pol])
        assert len(result.failures) == 1
        assert len(result.warnings) == 0
        assert result.has_failures

    def test_warn_action_lands_in_warnings(self):
        rec = _record(exposure="public_api")
        pol = _policy(condition={"exposure": "public_api"}, action="warn")
        result = evaluate_policies_against([rec], [pol])
        assert len(result.warnings) == 1
        assert len(result.failures) == 0
        assert not result.has_failures

    def test_no_match_lands_in_passed(self):
        rec = _record(exposure="batch_offline")
        pol = _policy(condition={"exposure": "public_api"})
        result = evaluate_policies_against([rec], [pol])
        assert result.passed == [pol]


# ---------------------------------------------------------------------------
# Allowlist suppression
# ---------------------------------------------------------------------------

class TestAllowlistSkipping:
    def test_allowlisted_record_does_not_match_any_policy(self):
        rec = _record(exposure="public_api", allowlisted=True)
        pol = _policy(condition={"exposure": "public_api"})
        result = evaluate_policies_against([rec], [pol])
        assert result.failures == []
        assert result.warnings == []
        # The policy still ends up in `passed` because nothing matched.
        assert result.passed == [pol]

    def test_non_allowlisted_alongside_allowlisted_still_triggers(self):
        approved = _record(name="approved", exposure="public_api", allowlisted=True)
        unapproved = _record(name="unapproved", exposure="public_api")
        pol = _policy(condition={"exposure": "public_api"})
        result = evaluate_policies_against([approved, unapproved], [pol])
        assert [m.record for m in result.failures] == [unapproved]


# ---------------------------------------------------------------------------
# Top-level helper that loads from disk
# ---------------------------------------------------------------------------

class TestEvaluatePolicies:
    def test_missing_policy_file_returns_empty_result(self, tmp_path):
        rec = _record(exposure="public_api")
        result = evaluate_policies([rec], tmp_path / "missing.yaml")
        assert result.failures == []
        assert result.warnings == []
        assert result.passed == []

    def test_end_to_end_yaml_to_match(self, tmp_path):
        path = _write_policy_file(tmp_path, [
            {
                "name": "block-public-llm",
                "description": "Block public-facing LLM services",
                "condition": {"exposure": "public_api", "system_type": "api_service"},
                "action": "fail",
            },
            {
                "name": "warn-high-score",
                "description": "Warn on high risk_score",
                "condition": {"risk_score": ">=70"},
                "action": "warn",
            },
        ])
        rec_a = _record(name="api", exposure="public_api", risk_score=85)
        rec_b = _record(name="batch", exposure="batch_offline", risk_score=20)
        result = evaluate_policies([rec_a, rec_b], path)
        assert {m.policy.name for m in result.failures} == {"block-public-llm"}
        assert {m.policy.name for m in result.warnings} == {"warn-high-score"}
