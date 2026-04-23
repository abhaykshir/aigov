from __future__ import annotations

import hashlib
import textwrap
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from aigov.core.custom_rules import (
    CustomRule,
    CustomRules,
    RuleAction,
    RuleMatch,
    _parse_rule,
)
from aigov.core.models import (
    AISystemRecord,
    AISystemType,
    DeploymentType,
    RiskLevel,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS = datetime(2026, 4, 22, 10, 0, 0, tzinfo=timezone.utc)


def _rec(
    name: str = "openai",
    provider: str = "OpenAI",
    description: str = "",
    source_location: str = "src/app.py:1",
    risk: RiskLevel = RiskLevel.MINIMAL_RISK,
    tags: dict | None = None,
) -> AISystemRecord:
    record_id = hashlib.sha1(name.encode()).hexdigest()[:12]
    return AISystemRecord(
        id=record_id,
        name=name,
        description=description,
        source_scanner="code.python_imports",
        source_location=source_location,
        discovery_timestamp=_TS,
        confidence=0.90,
        system_type=AISystemType.API_SERVICE,
        provider=provider,
        deployment_type=DeploymentType.CLOUD_API,
        risk_classification=risk,
        classification_rationale="baseline",
        tags=tags or {"origin_jurisdiction": "US"},
    )


def _keyword_rule(keywords: list[str], risk: RiskLevel = RiskLevel.HIGH_RISK) -> CustomRule:
    return CustomRule(
        name="Test keyword rule",
        description="",
        match=RuleMatch(keywords=keywords),
        action=RuleAction(risk_level=risk, reason="Keyword policy triggered"),
    )


def _jurisdiction_rule(codes: list[str], risk: RiskLevel = RiskLevel.PROHIBITED) -> CustomRule:
    return CustomRule(
        name="Restricted jurisdiction",
        description="",
        match=RuleMatch(jurisdiction=codes),
        action=RuleAction(risk_level=risk, reason="Jurisdiction policy triggered"),
    )


def _provider_rule(providers: list[str], risk: RiskLevel = RiskLevel.LIMITED_RISK) -> CustomRule:
    return CustomRule(
        name="Provider governance",
        description="",
        match=RuleMatch(providers=providers),
        action=RuleAction(risk_level=risk, reason="Provider policy triggered"),
    )


def _rules_yaml(rules: list[dict]) -> str:
    return yaml.dump({"custom_rules": rules})


# ---------------------------------------------------------------------------
# TestRuleMatchKeywords
# ---------------------------------------------------------------------------

class TestRuleMatchKeywords:
    def test_keyword_match_in_name(self) -> None:
        rule = _keyword_rule(["patient"])
        rec = _rec(name="patient-data-model")
        assert rule.matches(rec)

    def test_keyword_match_in_description(self) -> None:
        rule = _keyword_rule(["clinical"])
        rec = _rec(name="ml-model", description="Handles clinical diagnosis data")
        assert rule.matches(rec)

    def test_keyword_match_in_source_location(self) -> None:
        rule = _keyword_rule(["health"])
        rec = _rec(source_location="src/health_module/predict.py:42")
        assert rule.matches(rec)

    def test_keyword_case_insensitive(self) -> None:
        rule = _keyword_rule(["PATIENT"])
        rec = _rec(name="patient-ai")
        assert rule.matches(rec)

    def test_keyword_any_of_list_matches(self) -> None:
        rule = _keyword_rule(["credit", "loan", "mortgage"])
        rec = _rec(name="loan-underwriter")
        assert rule.matches(rec)

    def test_keyword_none_match(self) -> None:
        rule = _keyword_rule(["patient", "clinical"])
        rec = _rec(name="image-classifier", description="Identifies objects in photos")
        assert not rule.matches(rec)

    def test_empty_keyword_list_never_matches(self) -> None:
        m = RuleMatch(keywords=[], jurisdiction=[], providers=[])
        assert not m.matches(_rec())


# ---------------------------------------------------------------------------
# TestRuleMatchJurisdiction
# ---------------------------------------------------------------------------

class TestRuleMatchJurisdiction:
    def test_jurisdiction_match(self) -> None:
        rule = _jurisdiction_rule(["CN", "RU"])
        rec = _rec(tags={"origin_jurisdiction": "CN"})
        assert rule.matches(rec)

    def test_jurisdiction_no_match(self) -> None:
        rule = _jurisdiction_rule(["CN", "RU"])
        rec = _rec(tags={"origin_jurisdiction": "US"})
        assert not rule.matches(rec)

    def test_jurisdiction_missing_tag_no_match(self) -> None:
        rule = _jurisdiction_rule(["CN"])
        rec = _rec(tags={})
        assert not rule.matches(rec)

    def test_jurisdiction_exact_code_required(self) -> None:
        rule = _jurisdiction_rule(["CN"])
        rec = _rec(tags={"origin_jurisdiction": "cn"})  # lowercase
        assert not rule.matches(rec)


# ---------------------------------------------------------------------------
# TestRuleMatchProviders
# ---------------------------------------------------------------------------

class TestRuleMatchProviders:
    def test_provider_exact_match(self) -> None:
        rule = _provider_rule(["OpenAI"])
        rec = _rec(provider="OpenAI")
        assert rule.matches(rec)

    def test_provider_case_insensitive(self) -> None:
        rule = _provider_rule(["openai"])
        rec = _rec(provider="OpenAI")
        assert rule.matches(rec)

    def test_provider_case_insensitive_other_direction(self) -> None:
        rule = _provider_rule(["OpenAI", "Anthropic"])
        rec = _rec(provider="anthropic")
        assert rule.matches(rec)

    def test_provider_no_match(self) -> None:
        rule = _provider_rule(["OpenAI"])
        rec = _rec(provider="HuggingFace")
        assert not rule.matches(rec)

    def test_provider_partial_not_sufficient(self) -> None:
        rule = _provider_rule(["Open"])
        rec = _rec(provider="OpenAI")
        assert not rule.matches(rec)


# ---------------------------------------------------------------------------
# TestCombinedMatch (AND logic)
# ---------------------------------------------------------------------------

class TestCombinedMatch:
    def test_keywords_and_jurisdiction_both_match(self) -> None:
        m = RuleMatch(keywords=["patient"], jurisdiction=["CN"])
        rec = _rec(name="patient-ai", tags={"origin_jurisdiction": "CN"})
        assert m.matches(rec)

    def test_keywords_and_jurisdiction_only_keyword_matches(self) -> None:
        m = RuleMatch(keywords=["patient"], jurisdiction=["CN"])
        rec = _rec(name="patient-ai", tags={"origin_jurisdiction": "US"})
        assert not m.matches(rec)

    def test_keywords_and_jurisdiction_only_jurisdiction_matches(self) -> None:
        m = RuleMatch(keywords=["patient"], jurisdiction=["CN"])
        rec = _rec(name="image-classifier", tags={"origin_jurisdiction": "CN"})
        assert not m.matches(rec)

    def test_all_three_criteria_must_match(self) -> None:
        m = RuleMatch(
            keywords=["credit"],
            jurisdiction=["US"],
            providers=["OpenAI"],
        )
        rec = _rec(name="credit-scorer", provider="OpenAI", tags={"origin_jurisdiction": "US"})
        assert m.matches(rec)

    def test_all_three_criteria_one_fails(self) -> None:
        m = RuleMatch(
            keywords=["credit"],
            jurisdiction=["US"],
            providers=["OpenAI"],
        )
        rec = _rec(name="credit-scorer", provider="Anthropic", tags={"origin_jurisdiction": "US"})
        assert not m.matches(rec)


# ---------------------------------------------------------------------------
# TestRiskEscalation
# ---------------------------------------------------------------------------

class TestRiskEscalation:
    def test_minimal_escalates_to_high_risk(self) -> None:
        rule = _keyword_rule(["patient"], risk=RiskLevel.HIGH_RISK)
        rec = _rec(name="patient-ai", risk=RiskLevel.MINIMAL_RISK)
        result = CustomRules([rule]).apply([rec])[0]
        assert result.risk_classification == RiskLevel.HIGH_RISK

    def test_unknown_escalates_to_limited(self) -> None:
        rule = _provider_rule(["OpenAI"], risk=RiskLevel.LIMITED_RISK)
        rec = _rec(risk=RiskLevel.UNKNOWN)
        result = CustomRules([rule]).apply([rec])[0]
        assert result.risk_classification == RiskLevel.LIMITED_RISK

    def test_needs_review_escalates_to_prohibited(self) -> None:
        rule = _jurisdiction_rule(["CN"], risk=RiskLevel.PROHIBITED)
        rec = _rec(risk=RiskLevel.NEEDS_REVIEW, tags={"origin_jurisdiction": "CN"})
        result = CustomRules([rule]).apply([rec])[0]
        assert result.risk_classification == RiskLevel.PROHIBITED

    def test_no_downgrade_high_risk_to_limited(self) -> None:
        rule = _provider_rule(["OpenAI"], risk=RiskLevel.LIMITED_RISK)
        rec = _rec(risk=RiskLevel.HIGH_RISK)
        result = CustomRules([rule]).apply([rec])[0]
        assert result.risk_classification == RiskLevel.HIGH_RISK

    def test_no_downgrade_prohibited_to_high_risk(self) -> None:
        rule = _keyword_rule(["patient"], risk=RiskLevel.HIGH_RISK)
        rec = _rec(name="patient-ai", risk=RiskLevel.PROHIBITED)
        result = CustomRules([rule]).apply([rec])[0]
        assert result.risk_classification == RiskLevel.PROHIBITED

    def test_same_level_stays_same(self) -> None:
        rule = _keyword_rule(["patient"], risk=RiskLevel.HIGH_RISK)
        rec = _rec(name="patient-ai", risk=RiskLevel.HIGH_RISK)
        result = CustomRules([rule]).apply([rec])[0]
        assert result.risk_classification == RiskLevel.HIGH_RISK


# ---------------------------------------------------------------------------
# TestCustomRuleTags
# ---------------------------------------------------------------------------

class TestCustomRuleTags:
    def test_custom_rule_name_tag_added(self) -> None:
        rule = _keyword_rule(["patient"])
        rec = _rec(name="patient-ai")
        result = CustomRules([rule]).apply([rec])[0]
        assert result.tags["custom_rule_name"] == "Test keyword rule"

    def test_custom_rule_reason_tag_added(self) -> None:
        rule = _keyword_rule(["patient"])
        rec = _rec(name="patient-ai")
        result = CustomRules([rule]).apply([rec])[0]
        assert result.tags["custom_rule_reason"] == "Keyword policy triggered"

    def test_existing_tags_preserved(self) -> None:
        rule = _keyword_rule(["patient"])
        rec = _rec(name="patient-ai", tags={"origin_jurisdiction": "US", "eu_ai_act_category": "test"})
        result = CustomRules([rule]).apply([rec])[0]
        assert result.tags["origin_jurisdiction"] == "US"
        assert result.tags["eu_ai_act_category"] == "test"

    def test_rationale_appended_to_existing(self) -> None:
        rule = _keyword_rule(["patient"])
        rec = _rec(name="patient-ai", risk=RiskLevel.MINIMAL_RISK)
        result = CustomRules([rule]).apply([rec])[0]
        assert "baseline" in result.classification_rationale
        assert "Keyword policy triggered" in result.classification_rationale

    def test_rationale_set_when_no_existing(self) -> None:
        import dataclasses
        rule = _keyword_rule(["patient"])
        rec = dataclasses.replace(_rec(name="patient-ai"), classification_rationale=None)
        result = CustomRules([rule]).apply([rec])[0]
        assert result.classification_rationale == "Keyword policy triggered"

    def test_non_matching_record_unchanged(self) -> None:
        rule = _keyword_rule(["patient"])
        rec = _rec(name="image-classifier")
        result = CustomRules([rule]).apply([rec])[0]
        assert result is rec  # same object — no copy made

    def test_originals_not_mutated(self) -> None:
        rule = _keyword_rule(["patient"])
        rec = _rec(name="patient-ai", risk=RiskLevel.MINIMAL_RISK)
        original_risk = rec.risk_classification
        original_tags = dict(rec.tags)
        CustomRules([rule]).apply([rec])
        assert rec.risk_classification == original_risk
        assert rec.tags == original_tags


# ---------------------------------------------------------------------------
# TestMultipleRules
# ---------------------------------------------------------------------------

class TestMultipleRules:
    def test_highest_risk_rule_wins(self) -> None:
        rules = [
            _keyword_rule(["patient"], risk=RiskLevel.LIMITED_RISK),
            _keyword_rule(["patient"], risk=RiskLevel.HIGH_RISK),
        ]
        rec = _rec(name="patient-ai", risk=RiskLevel.MINIMAL_RISK)
        result = CustomRules(rules).apply([rec])[0]
        assert result.risk_classification == RiskLevel.HIGH_RISK

    def test_winning_rule_name_in_tags(self) -> None:
        rule_low = CustomRule(
            name="low rule", description="",
            match=RuleMatch(keywords=["patient"]),
            action=RuleAction(risk_level=RiskLevel.LIMITED_RISK, reason="low reason"),
        )
        rule_high = CustomRule(
            name="high rule", description="",
            match=RuleMatch(keywords=["patient"]),
            action=RuleAction(risk_level=RiskLevel.HIGH_RISK, reason="high reason"),
        )
        rec = _rec(name="patient-ai", risk=RiskLevel.MINIMAL_RISK)
        result = CustomRules([rule_low, rule_high]).apply([rec])[0]
        assert result.tags["custom_rule_name"] == "high rule"
        assert result.tags["custom_rule_reason"] == "high reason"

    def test_all_reasons_appended_to_rationale(self) -> None:
        rule_a = CustomRule(
            name="rule A", description="",
            match=RuleMatch(keywords=["patient"]),
            action=RuleAction(risk_level=RiskLevel.LIMITED_RISK, reason="reason A"),
        )
        rule_b = CustomRule(
            name="rule B", description="",
            match=RuleMatch(keywords=["patient"]),
            action=RuleAction(risk_level=RiskLevel.HIGH_RISK, reason="reason B"),
        )
        rec = _rec(name="patient-ai")
        result = CustomRules([rule_a, rule_b]).apply([rec])[0]
        assert "reason A" in result.classification_rationale
        assert "reason B" in result.classification_rationale

    def test_unrelated_rule_does_not_apply(self) -> None:
        rules = [
            _keyword_rule(["patient"], risk=RiskLevel.HIGH_RISK),
            _keyword_rule(["credit"], risk=RiskLevel.PROHIBITED),  # won't match
        ]
        rec = _rec(name="patient-ai", risk=RiskLevel.MINIMAL_RISK)
        result = CustomRules(rules).apply([rec])[0]
        assert result.risk_classification == RiskLevel.HIGH_RISK  # only patient rule applied


# ---------------------------------------------------------------------------
# TestCustomRulesLoad
# ---------------------------------------------------------------------------

class TestCustomRulesLoad:
    def test_missing_file_silently_ignored(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        cr = CustomRules.load()
        assert cr._rules == []

    def test_explicit_missing_path_silently_ignored(self, tmp_path: Path) -> None:
        cr = CustomRules.load(path=tmp_path / "nonexistent.yaml")
        assert cr._rules == []

    def test_malformed_yaml_returns_empty(self, tmp_path: Path) -> None:
        bad = tmp_path / ".aigov-rules.yaml"
        bad.write_text("{{{{ not yaml", encoding="utf-8")
        cr = CustomRules.load(path=bad)
        assert cr._rules == []

    def test_valid_rules_loaded(self, tmp_path: Path) -> None:
        rules_file = tmp_path / ".aigov-rules.yaml"
        rules_file.write_text(
            textwrap.dedent("""\
                custom_rules:
                  - name: "Test rule"
                    description: "Test"
                    match:
                      keywords: ["patient"]
                    action:
                      risk_level: high_risk
                      reason: "HIPAA review required"
            """),
            encoding="utf-8",
        )
        cr = CustomRules.load(path=rules_file)
        assert len(cr._rules) == 1
        assert cr._rules[0].name == "Test rule"
        assert cr._rules[0].action.risk_level == RiskLevel.HIGH_RISK

    def test_malformed_rule_skipped_valid_kept(self, tmp_path: Path) -> None:
        rules_file = tmp_path / ".aigov-rules.yaml"
        rules_file.write_text(
            textwrap.dedent("""\
                custom_rules:
                  - name: "Good rule"
                    match:
                      keywords: ["patient"]
                    action:
                      risk_level: high_risk
                      reason: "ok"
                  - name: ""
                    match:
                      keywords: ["test"]
                    action:
                      risk_level: high_risk
                      reason: "bad — empty name"
                  - name: "Another good rule"
                    match:
                      jurisdiction: ["CN"]
                    action:
                      risk_level: prohibited
                      reason: "ok"
            """),
            encoding="utf-8",
        )
        cr = CustomRules.load(path=rules_file)
        assert len(cr._rules) == 2
        assert cr._rules[0].name == "Good rule"
        assert cr._rules[1].name == "Another good rule"

    def test_auto_discovery_from_cwd(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        rules_file = tmp_path / ".aigov-rules.yaml"
        rules_file.write_text(
            textwrap.dedent("""\
                custom_rules:
                  - name: "Auto-discovered rule"
                    match:
                      providers: ["TestCo"]
                    action:
                      risk_level: limited_risk
                      reason: "auto discovered"
            """),
            encoding="utf-8",
        )
        cr = CustomRules.load()  # no path — uses cwd
        assert len(cr._rules) == 1
        assert cr._rules[0].name == "Auto-discovered rule"

    def test_empty_custom_rules_key(self, tmp_path: Path) -> None:
        rules_file = tmp_path / ".aigov-rules.yaml"
        rules_file.write_text("custom_rules: []\n", encoding="utf-8")
        cr = CustomRules.load(path=rules_file)
        assert cr._rules == []

    def test_no_rules_apply_returns_same_objects(self) -> None:
        cr = CustomRules([])
        records = [_rec("a"), _rec("b")]
        result = cr.apply(records)
        assert result is records


# ---------------------------------------------------------------------------
# TestParseRule
# ---------------------------------------------------------------------------

class TestParseRule:
    def test_valid_keywords_rule(self) -> None:
        rule = _parse_rule({
            "name": "Test",
            "description": "A test",
            "match": {"keywords": ["patient", "clinical"]},
            "action": {"risk_level": "high_risk", "reason": "HIPAA"},
        })
        assert rule.name == "Test"
        assert rule.match.keywords == ["patient", "clinical"]
        assert rule.action.risk_level == RiskLevel.HIGH_RISK
        assert rule.action.reason == "HIPAA"

    def test_valid_jurisdiction_rule(self) -> None:
        rule = _parse_rule({
            "name": "Geo block",
            "match": {"jurisdiction": ["CN", "RU"]},
            "action": {"risk_level": "prohibited", "reason": "geo policy"},
        })
        assert rule.match.jurisdiction == ["CN", "RU"]
        assert rule.action.risk_level == RiskLevel.PROHIBITED

    def test_valid_providers_rule(self) -> None:
        rule = _parse_rule({
            "name": "LLM governance",
            "match": {"providers": ["OpenAI", "Anthropic"]},
            "action": {"risk_level": "limited_risk", "reason": "board approval needed"},
        })
        assert rule.match.providers == ["OpenAI", "Anthropic"]

    def test_all_risk_levels_accepted(self) -> None:
        for level in RiskLevel:
            rule = _parse_rule({
                "name": f"rule-{level.value}",
                "match": {"keywords": ["test"]},
                "action": {"risk_level": level.value, "reason": "ok"},
            })
            assert rule.action.risk_level == level

    def test_risk_level_case_insensitive(self) -> None:
        rule = _parse_rule({
            "name": "Test",
            "match": {"keywords": ["x"]},
            "action": {"risk_level": "HIGH_RISK", "reason": "ok"},
        })
        assert rule.action.risk_level == RiskLevel.HIGH_RISK

    def test_missing_name_raises(self) -> None:
        with pytest.raises(ValueError, match="name"):
            _parse_rule({
                "match": {"keywords": ["test"]},
                "action": {"risk_level": "high_risk", "reason": "ok"},
            })

    def test_empty_name_raises(self) -> None:
        with pytest.raises(ValueError, match="name"):
            _parse_rule({
                "name": "",
                "match": {"keywords": ["test"]},
                "action": {"risk_level": "high_risk", "reason": "ok"},
            })

    def test_empty_match_raises(self) -> None:
        with pytest.raises(ValueError, match="match"):
            _parse_rule({
                "name": "No criteria",
                "match": {},
                "action": {"risk_level": "high_risk", "reason": "ok"},
            })

    def test_unknown_risk_level_raises(self) -> None:
        with pytest.raises(ValueError, match="risk_level"):
            _parse_rule({
                "name": "Test",
                "match": {"keywords": ["test"]},
                "action": {"risk_level": "extreme", "reason": "ok"},
            })

    def test_missing_risk_level_raises(self) -> None:
        with pytest.raises(ValueError, match="risk_level"):
            _parse_rule({
                "name": "Test",
                "match": {"keywords": ["test"]},
                "action": {"reason": "no level"},
            })

    def test_non_dict_item_raises(self) -> None:
        with pytest.raises(ValueError):
            _parse_rule("not a dict")

    def test_empty_keyword_strings_filtered(self) -> None:
        rule = _parse_rule({
            "name": "Test",
            "match": {"keywords": ["patient", "", "  "]},
            "action": {"risk_level": "high_risk", "reason": "ok"},
        })
        assert rule.match.keywords == ["patient"]


# ---------------------------------------------------------------------------
# TestIntegrationWithEngine
# ---------------------------------------------------------------------------

class TestIntegrationWithEngine:
    """Verify that classify_results applies custom rules after EU AI Act classification."""

    def test_custom_rules_applied_via_classify_results(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        rules_file = tmp_path / ".aigov-rules.yaml"
        rules_file.write_text(
            textwrap.dedent("""\
                custom_rules:
                  - name: "OpenAI governance"
                    match:
                      providers: ["OpenAI"]
                    action:
                      risk_level: high_risk
                      reason: "Board approval required for all OpenAI usage"
            """),
            encoding="utf-8",
        )

        from aigov.core.engine import ScanResult, classify_results
        record = _rec(provider="OpenAI", risk=RiskLevel.MINIMAL_RISK)
        result = ScanResult(records=[record], scanned_paths=["."])
        result._compute_summaries()

        classified = classify_results(result, ["eu_ai_act"])
        found = classified.records[0]
        assert found.risk_classification == RiskLevel.HIGH_RISK
        assert found.tags.get("custom_rule_name") == "OpenAI governance"

    def test_explicit_rules_path_via_classify_results(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "my-org-rules.yaml"
        rules_file.write_text(
            textwrap.dedent("""\
                custom_rules:
                  - name: "CN block"
                    match:
                      jurisdiction: ["CN"]
                    action:
                      risk_level: prohibited
                      reason: "Company policy"
            """),
            encoding="utf-8",
        )

        from aigov.core.engine import ScanResult, classify_results
        record = _rec(tags={"origin_jurisdiction": "CN"})
        result = ScanResult(records=[record], scanned_paths=["."])
        result._compute_summaries()

        classified = classify_results(result, ["eu_ai_act"], rules_path=rules_file)
        found = classified.records[0]
        assert found.risk_classification == RiskLevel.PROHIBITED

    def test_custom_rule_escalates_above_eu_ai_act(self, tmp_path: Path) -> None:
        """Custom rule correctly escalates a record beyond its EU AI Act baseline."""
        rules_file = tmp_path / ".aigov-rules.yaml"
        rules_file.write_text(
            textwrap.dedent("""\
                custom_rules:
                  - name: "AWS high risk"
                    match:
                      providers: ["AWS"]
                    action:
                      risk_level: high_risk
                      reason: "Internal policy mandates review for all AWS AI"
            """),
            encoding="utf-8",
        )
        from aigov.core.engine import ScanResult, classify_results
        # A generic AWS API service — EU AI Act alone would leave it at minimal/limited risk.
        record = _rec(provider="AWS", risk=RiskLevel.MINIMAL_RISK)
        result = ScanResult(records=[record], scanned_paths=["."])
        result._compute_summaries()

        classified = classify_results(result, ["eu_ai_act"], rules_path=rules_file)
        found = classified.records[0]
        assert found.risk_classification == RiskLevel.HIGH_RISK
        assert found.tags.get("custom_rule_name") == "AWS high risk"

    def test_missing_rules_file_no_error_in_classify(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist.yaml"
        from aigov.core.engine import ScanResult, classify_results
        record = _rec()
        result = ScanResult(records=[record], scanned_paths=["."])
        result._compute_summaries()
        # Must not raise
        classified = classify_results(result, ["eu_ai_act"], rules_path=missing)
        assert len(classified.records) == 1
