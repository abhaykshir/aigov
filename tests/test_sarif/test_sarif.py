from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aigov.core.models import (
    AISystemRecord,
    AISystemType,
    DeploymentType,
    RiskLevel,
)
from aigov.core.sarif import (
    _INFORMATION_URI,
    _RULES,
    _SARIF_SCHEMA,
    _TOOL_NAME,
    _TOOL_VERSION,
    _parse_location,
    _record_to_sarif_result,
    records_to_sarif,
    to_sarif,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS = datetime(2026, 4, 22, 10, 0, 0, tzinfo=timezone.utc)


def _make_record(
    name: str = "gpt-4",
    provider: str = "OpenAI",
    system_type: AISystemType = AISystemType.API_SERVICE,
    deployment_type: DeploymentType = DeploymentType.CLOUD_API,
    risk: RiskLevel = RiskLevel.LIMITED_RISK,
    rationale: str = "Test rationale",
    source_location: str = "src/app.py:42",
    tags: dict | None = None,
) -> AISystemRecord:
    record_id = hashlib.sha1(name.encode()).hexdigest()[:12]
    return AISystemRecord(
        id=record_id,
        name=name,
        description=f"Test record for {name}",
        source_scanner="code.python_imports",
        source_location=source_location,
        discovery_timestamp=_TS,
        confidence=0.90,
        system_type=system_type,
        provider=provider,
        deployment_type=deployment_type,
        risk_classification=risk,
        classification_rationale=rationale,
        tags=tags or {"origin_jurisdiction": "US", "eu_ai_act_category": ""},
    )


def _make_prohibited() -> AISystemRecord:
    return _make_record(
        name="social-scorer",
        provider="InternalAI",
        system_type=AISystemType.MODEL,
        deployment_type=DeploymentType.SELF_HOSTED,
        risk=RiskLevel.PROHIBITED,
        rationale="Social scoring system — Article 5(1)(c)",
        source_location="src/scoring/model.py:101",
        tags={"origin_jurisdiction": "CN", "eu_ai_act_category": "Prohibited practice"},
    )


def _make_high_risk() -> AISystemRecord:
    return _make_record(
        name="rekognition",
        provider="AWS",
        system_type=AISystemType.MODEL,
        risk=RiskLevel.HIGH_RISK,
        rationale="Biometric identification — EU AI Act Annex III item 1(a)",
        source_location="src/vision/biometric.py:55",
        tags={
            "origin_jurisdiction": "US",
            "eu_ai_act_category": "Biometric identification and categorisation",
        },
    )


def _make_minimal_risk() -> AISystemRecord:
    return _make_record(
        name="grammar-check",
        provider="Grammarly",
        risk=RiskLevel.MINIMAL_RISK,
        rationale="Simple grammar correction tool with no significant risk.",
        source_location="src/editor/grammar.py:10",
    )


def _make_needs_review() -> AISystemRecord:
    return _make_record(
        name="unknown-model",
        provider="InternalAI",
        risk=RiskLevel.NEEDS_REVIEW,
        rationale="Custom rule flagged this system for manual review.",
        source_location="config/ai-models.yaml:7",
    )


def _make_arn_record() -> AISystemRecord:
    return _make_record(
        name="bedrock-claude",
        provider="AWS",
        risk=RiskLevel.LIMITED_RISK,
        rationale="AWS Bedrock foundation model.",
        source_location="arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3",
    )


def _make_url_record() -> AISystemRecord:
    return _make_record(
        name="mcp-server",
        provider="Local",
        risk=RiskLevel.MINIMAL_RISK,
        rationale="Local MCP server.",
        source_location="mcp://localhost:3000/server",
    )


def _build_scan_result(records: list[AISystemRecord]):
    from aigov.core.engine import ScanResult
    result = ScanResult(
        records=records,
        scanners_run=["code.python_imports"],
        scanned_paths=["."],
        duration_seconds=0.5,
    )
    result._compute_summaries()
    return result


def _parsed(records: list[AISystemRecord]) -> dict:
    return json.loads(records_to_sarif(records))


# ---------------------------------------------------------------------------
# SARIF document structure
# ---------------------------------------------------------------------------

class TestSARIFStructure:
    def test_schema_field(self) -> None:
        doc = _parsed([_make_record()])
        assert doc["$schema"] == _SARIF_SCHEMA

    def test_version_is_2_1_0(self) -> None:
        doc = _parsed([_make_record()])
        assert doc["version"] == "2.1.0"

    def test_has_runs_array(self) -> None:
        doc = _parsed([_make_record()])
        assert isinstance(doc["runs"], list)

    def test_single_run(self) -> None:
        doc = _parsed([_make_record()])
        assert len(doc["runs"]) == 1

    def test_tool_driver_name(self) -> None:
        doc = _parsed([_make_record()])
        assert doc["runs"][0]["tool"]["driver"]["name"] == _TOOL_NAME

    def test_tool_driver_version(self) -> None:
        doc = _parsed([_make_record()])
        assert doc["runs"][0]["tool"]["driver"]["version"] == _TOOL_VERSION

    def test_tool_driver_information_uri(self) -> None:
        doc = _parsed([_make_record()])
        assert doc["runs"][0]["tool"]["driver"]["informationUri"] == _INFORMATION_URI

    def test_results_is_list(self) -> None:
        doc = _parsed([_make_record()])
        assert isinstance(doc["runs"][0]["results"], list)

    def test_result_count_matches_records(self) -> None:
        records = [_make_record("a"), _make_record("b"), _make_high_risk()]
        doc = _parsed(records)
        assert len(doc["runs"][0]["results"]) == 3

    def test_to_sarif_accepts_scan_result(self) -> None:
        result = _build_scan_result([_make_record()])
        doc = json.loads(to_sarif(result))
        assert doc["version"] == "2.1.0"
        assert len(doc["runs"][0]["results"]) == 1


# ---------------------------------------------------------------------------
# Risk level → SARIF level mapping
# ---------------------------------------------------------------------------

class TestRiskLevelMapping:
    def test_prohibited_maps_to_error(self) -> None:
        result = _record_to_sarif_result(_make_prohibited())
        assert result["level"] == "error"

    def test_prohibited_rule_id(self) -> None:
        result = _record_to_sarif_result(_make_prohibited())
        assert result["ruleId"] == "ai-governance/prohibited"

    def test_high_risk_maps_to_warning(self) -> None:
        result = _record_to_sarif_result(_make_high_risk())
        assert result["level"] == "warning"

    def test_high_risk_rule_id(self) -> None:
        result = _record_to_sarif_result(_make_high_risk())
        assert result["ruleId"] == "ai-governance/high-risk"

    def test_limited_risk_maps_to_note(self) -> None:
        result = _record_to_sarif_result(_make_record(risk=RiskLevel.LIMITED_RISK))
        assert result["level"] == "note"

    def test_limited_risk_rule_id(self) -> None:
        result = _record_to_sarif_result(_make_record(risk=RiskLevel.LIMITED_RISK))
        assert result["ruleId"] == "ai-governance/limited-risk"

    def test_minimal_risk_maps_to_none(self) -> None:
        result = _record_to_sarif_result(_make_minimal_risk())
        assert result["level"] == "none"

    def test_minimal_risk_rule_id(self) -> None:
        result = _record_to_sarif_result(_make_minimal_risk())
        assert result["ruleId"] == "ai-governance/minimal-risk"

    def test_needs_review_maps_to_warning(self) -> None:
        result = _record_to_sarif_result(_make_needs_review())
        assert result["level"] == "warning"

    def test_needs_review_rule_id(self) -> None:
        result = _record_to_sarif_result(_make_needs_review())
        assert result["ruleId"] == "ai-governance/needs-review"

    def test_unknown_maps_to_none(self) -> None:
        rec = _make_record(risk=RiskLevel.UNKNOWN)
        result = _record_to_sarif_result(rec)
        assert result["level"] == "none"

    def test_none_risk_treated_as_unknown(self) -> None:
        rec = _make_record(risk=RiskLevel.UNKNOWN)
        rec.risk_classification = None
        result = _record_to_sarif_result(rec)
        assert result["level"] == "none"

    def test_rule_index_is_integer(self) -> None:
        result = _record_to_sarif_result(_make_high_risk())
        assert isinstance(result["ruleIndex"], int)

    def test_rule_index_matches_rules_array(self) -> None:
        rec = _make_high_risk()
        result = _record_to_sarif_result(rec)
        rule_id = result["ruleId"]
        index = result["ruleIndex"]
        assert _RULES[index]["id"] == rule_id


# ---------------------------------------------------------------------------
# Location parsing
# ---------------------------------------------------------------------------

class TestLocationParsing:
    def test_file_with_line_is_physical_location(self) -> None:
        loc = _parse_location("src/app.py:42")
        assert "physicalLocation" in loc

    def test_file_with_line_extracts_uri(self) -> None:
        loc = _parse_location("src/app.py:42")
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "src/app.py"

    def test_file_with_line_extracts_line_number(self) -> None:
        loc = _parse_location("src/app.py:42")
        assert loc["physicalLocation"]["region"]["startLine"] == 42

    def test_plain_file_no_line(self) -> None:
        loc = _parse_location("docker-compose.yml")
        assert "physicalLocation" in loc
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "docker-compose.yml"
        assert "region" not in loc["physicalLocation"]

    def test_nested_path_with_line(self) -> None:
        loc = _parse_location("infrastructure/terraform/main.tf:15")
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "infrastructure/terraform/main.tf"
        assert loc["physicalLocation"]["region"]["startLine"] == 15

    def test_arn_becomes_logical_location(self) -> None:
        arn = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3"
        loc = _parse_location(arn)
        assert "logicalLocations" in loc
        assert loc["logicalLocations"][0]["name"] == arn

    def test_arn_with_account_id(self) -> None:
        arn = "arn:aws:sagemaker:us-east-1:123456789012:model/my-model"
        loc = _parse_location(arn)
        assert "logicalLocations" in loc

    def test_mcp_url_becomes_logical_location(self) -> None:
        url = "mcp://localhost:3000/server"
        loc = _parse_location(url)
        assert "logicalLocations" in loc
        assert loc["logicalLocations"][0]["name"] == url

    def test_kubernetes_url_becomes_logical_location(self) -> None:
        url = "k8s://default/deployment/my-ai-app"
        loc = _parse_location(url)
        assert "logicalLocations" in loc

    def test_docker_url_becomes_logical_location(self) -> None:
        url = "docker://registry.example.com/my-model:latest"
        loc = _parse_location(url)
        assert "logicalLocations" in loc

    def test_arn_record_in_sarif(self) -> None:
        rec = _make_arn_record()
        result = _record_to_sarif_result(rec)
        loc = result["locations"][0]
        assert "logicalLocations" in loc

    def test_file_record_in_sarif(self) -> None:
        rec = _make_record(source_location="src/main.py:10")
        result = _record_to_sarif_result(rec)
        loc = result["locations"][0]
        assert "physicalLocation" in loc

    def test_windows_backslash_normalised(self) -> None:
        loc = _parse_location("src\\app\\main.py:5")
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "src/app/main.py"


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

class TestRuleDefinitions:
    def _rules_by_id(self) -> dict[str, dict]:
        return {r["id"]: r for r in _RULES}

    def test_all_five_rules_present(self) -> None:
        ids = {r["id"] for r in _RULES}
        assert ids == {
            "ai-governance/prohibited",
            "ai-governance/high-risk",
            "ai-governance/limited-risk",
            "ai-governance/minimal-risk",
            "ai-governance/needs-review",
        }

    def test_rules_included_in_sarif_document(self) -> None:
        doc = _parsed([_make_record()])
        driver_rules = doc["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in driver_rules}
        assert "ai-governance/prohibited" in rule_ids
        assert "ai-governance/high-risk" in rule_ids
        assert "ai-governance/limited-risk" in rule_ids
        assert "ai-governance/minimal-risk" in rule_ids
        assert "ai-governance/needs-review" in rule_ids

    def test_prohibited_has_short_description(self) -> None:
        rules = self._rules_by_id()
        assert "EU AI Act Article 5" in rules["ai-governance/prohibited"]["shortDescription"]["text"]

    def test_high_risk_has_short_description(self) -> None:
        rules = self._rules_by_id()
        assert "Annex III" in rules["ai-governance/high-risk"]["shortDescription"]["text"]

    def test_limited_risk_has_short_description(self) -> None:
        rules = self._rules_by_id()
        assert "Article 50" in rules["ai-governance/limited-risk"]["shortDescription"]["text"]

    def test_minimal_risk_has_short_description(self) -> None:
        rules = self._rules_by_id()
        assert "Minimal Risk" in rules["ai-governance/minimal-risk"]["shortDescription"]["text"]

    def test_needs_review_has_short_description(self) -> None:
        rules = self._rules_by_id()
        assert "Review" in rules["ai-governance/needs-review"]["shortDescription"]["text"]

    def test_all_rules_have_full_description(self) -> None:
        for rule in _RULES:
            assert "fullDescription" in rule
            assert len(rule["fullDescription"]["text"]) > 20

    def test_all_rules_have_default_configuration(self) -> None:
        for rule in _RULES:
            assert "defaultConfiguration" in rule
            assert "level" in rule["defaultConfiguration"]

    def test_prohibited_default_level_is_error(self) -> None:
        rules = self._rules_by_id()
        assert rules["ai-governance/prohibited"]["defaultConfiguration"]["level"] == "error"

    def test_high_risk_default_level_is_warning(self) -> None:
        rules = self._rules_by_id()
        assert rules["ai-governance/high-risk"]["defaultConfiguration"]["level"] == "warning"

    def test_limited_risk_default_level_is_note(self) -> None:
        rules = self._rules_by_id()
        assert rules["ai-governance/limited-risk"]["defaultConfiguration"]["level"] == "note"

    def test_minimal_risk_default_level_is_none(self) -> None:
        rules = self._rules_by_id()
        assert rules["ai-governance/minimal-risk"]["defaultConfiguration"]["level"] == "none"

    def test_all_rules_have_help_uri(self) -> None:
        for rule in _RULES:
            assert "helpUri" in rule
            assert rule["helpUri"].startswith("https://")


# ---------------------------------------------------------------------------
# Message content
# ---------------------------------------------------------------------------

class TestSARIFMessage:
    def test_message_contains_system_name(self) -> None:
        rec = _make_record(name="my-model")
        result = _record_to_sarif_result(rec)
        assert "my-model" in result["message"]["text"]

    def test_message_contains_provider(self) -> None:
        rec = _make_record(provider="Anthropic")
        result = _record_to_sarif_result(rec)
        assert "Anthropic" in result["message"]["text"]

    def test_message_contains_risk_classification(self) -> None:
        rec = _make_high_risk()
        result = _record_to_sarif_result(rec)
        assert "HIGH RISK" in result["message"]["text"]

    def test_message_contains_rationale(self) -> None:
        rec = _make_record(rationale="Biometric system under Annex III.")
        result = _record_to_sarif_result(rec)
        assert "Biometric system under Annex III." in result["message"]["text"]

    def test_message_has_fallback_when_no_rationale(self) -> None:
        rec = _make_record(rationale="")
        rec.classification_rationale = None
        result = _record_to_sarif_result(rec)
        assert result["message"]["text"]


# ---------------------------------------------------------------------------
# Properties bag
# ---------------------------------------------------------------------------

class TestSARIFProperties:
    def test_properties_has_provider(self) -> None:
        result = _record_to_sarif_result(_make_record(provider="OpenAI"))
        assert result["properties"]["provider"] == "OpenAI"

    def test_properties_has_system_type(self) -> None:
        result = _record_to_sarif_result(_make_record(system_type=AISystemType.MODEL))
        assert result["properties"]["system_type"] == "model"

    def test_properties_has_origin_jurisdiction(self) -> None:
        rec = _make_record(tags={"origin_jurisdiction": "DE", "eu_ai_act_category": ""})
        result = _record_to_sarif_result(rec)
        assert result["properties"]["origin_jurisdiction"] == "DE"

    def test_properties_has_confidence(self) -> None:
        result = _record_to_sarif_result(_make_record())
        assert "confidence" in result["properties"]
        assert isinstance(result["properties"]["confidence"], float)

    def test_properties_eu_category_included_when_present(self) -> None:
        rec = _make_high_risk()
        result = _record_to_sarif_result(rec)
        assert result["properties"]["eu_ai_act_category"] == "Biometric identification and categorisation"

    def test_properties_eu_category_omitted_when_empty(self) -> None:
        rec = _make_record(tags={"origin_jurisdiction": "US", "eu_ai_act_category": ""})
        result = _record_to_sarif_result(rec)
        assert "eu_ai_act_category" not in result["properties"]

    def test_properties_no_raw_tags_blob(self) -> None:
        rec = _make_record(tags={"origin_jurisdiction": "US", "eu_ai_act_category": "", "internal_secret": "xyz"})
        result = _record_to_sarif_result(rec)
        assert "tags" not in result["properties"]
        assert "internal_secret" not in result["properties"]


# ---------------------------------------------------------------------------
# Security — no sensitive data in SARIF output
# ---------------------------------------------------------------------------

class TestSARIFSecurity:
    def test_api_key_value_not_in_sarif(self) -> None:
        raw_key = "sk-FULL-SECRET-DO-NOT-EXPORT-abcdef123456"
        rec = _make_record()
        rec.tags["api_key_value"] = raw_key
        output = records_to_sarif([rec])
        assert raw_key not in output

    def test_api_key_preview_not_exported_as_field(self) -> None:
        rec = _make_record()
        rec.tags["api_key_preview"] = "sk-ab"
        result = _record_to_sarif_result(rec)
        assert "api_key_preview" not in result["properties"]

    def test_raw_tags_blob_not_in_sarif(self) -> None:
        rec = _make_record(tags={
            "origin_jurisdiction": "US",
            "eu_ai_act_category": "",
            "highly_sensitive": "do-not-export",
        })
        output = records_to_sarif([rec])
        assert "do-not-export" not in output

    def test_description_not_in_sarif_output(self) -> None:
        """Record description is internal and must not appear verbatim in SARIF results."""
        rec = _make_record()
        rec.description = "INTERNAL_DESCRIPTION_TOKEN_12345"
        output = records_to_sarif([rec])
        # description is not a standard SARIF field — should not leak via properties
        result = json.loads(output)
        for r in result["runs"][0]["results"]:
            assert "INTERNAL_DESCRIPTION_TOKEN_12345" not in json.dumps(r["properties"])

    def test_no_full_tags_dict_in_output(self) -> None:
        rec = _make_record()
        output = records_to_sarif([rec])
        data = json.loads(output)
        for r in data["runs"][0]["results"]:
            assert "tags" not in r.get("properties", {})


# ---------------------------------------------------------------------------
# Empty scan
# ---------------------------------------------------------------------------

class TestSARIFEmpty:
    def test_empty_records_valid_sarif(self) -> None:
        doc = _parsed([])
        assert doc["version"] == "2.1.0"
        assert "$schema" in doc
        assert len(doc["runs"]) == 1

    def test_empty_records_zero_results(self) -> None:
        doc = _parsed([])
        assert doc["runs"][0]["results"] == []

    def test_empty_scan_result_valid_sarif(self) -> None:
        result = _build_scan_result([])
        doc = json.loads(to_sarif(result))
        assert doc["runs"][0]["results"] == []

    def test_empty_sarif_has_rules(self) -> None:
        doc = _parsed([])
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 5

    def test_sarif_is_valid_json(self) -> None:
        output = records_to_sarif([])
        parsed = json.loads(output)
        assert isinstance(parsed, dict)


# ---------------------------------------------------------------------------
# CLI: scan --output sarif
# ---------------------------------------------------------------------------

class TestScanSARIFCLI:
    def test_scan_sarif_exit_zero(self, tmp_path: Path) -> None:
        from aigov.cli.main import app
        runner = CliRunner()
        src = tmp_path / "app.py"
        src.write_text("import openai\n", encoding="utf-8")
        result = runner.invoke(app, ["scan", str(tmp_path), "--classify", "--output", "sarif"])
        assert result.exit_code == 0, result.output

    def test_scan_sarif_output_is_valid_json(self, tmp_path: Path) -> None:
        from aigov.cli.main import app
        runner = CliRunner()
        src = tmp_path / "app.py"
        src.write_text("import openai\n", encoding="utf-8")
        out = tmp_path / "out.sarif"
        result = runner.invoke(app, ["scan", str(tmp_path), "--classify", "--output", "sarif", "--out-file", str(out)])
        assert result.exit_code == 0, result.output
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert doc["version"] == "2.1.0"

    def test_scan_sarif_to_file(self, tmp_path: Path) -> None:
        from aigov.cli.main import app
        runner = CliRunner()
        src = tmp_path / "app.py"
        src.write_text("import anthropic\n", encoding="utf-8")
        out = tmp_path / "results.sarif"
        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--classify", "--output", "sarif", "--out-file", str(out)],
        )
        assert result.exit_code == 0, result.output
        assert out.exists()
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert doc["version"] == "2.1.0"
        assert "$schema" in doc

    def test_scan_sarif_has_findings(self, tmp_path: Path) -> None:
        from aigov.cli.main import app
        runner = CliRunner()
        src = tmp_path / "app.py"
        src.write_text("import openai\nimport anthropic\n", encoding="utf-8")
        out = tmp_path / "out.sarif"
        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--classify", "--output", "sarif", "--out-file", str(out)],
        )
        assert result.exit_code == 0, result.output
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert len(doc["runs"][0]["results"]) >= 1


# ---------------------------------------------------------------------------
# CLI: export --format sarif
# ---------------------------------------------------------------------------

class TestExportSARIFCLI:
    def _write_scan_json(self, tmp_path: Path, records: list[AISystemRecord]) -> Path:
        data = {
            "aigov_version": "0.2.1",
            "summary": {"total_found": len(records), "scanners_run": [], "scanned_paths": ["."]},
            "warnings": [],
            "findings": [r.to_dict() for r in records],
        }
        p = tmp_path / "results.json"
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return p

    def test_export_sarif_exit_zero(self, tmp_path: Path) -> None:
        from aigov.cli.main import app
        runner = CliRunner()
        scan_file = self._write_scan_json(tmp_path, [_make_record()])
        result = runner.invoke(app, ["export", str(scan_file), "--format", "sarif"])
        assert result.exit_code == 0, result.output

    def test_export_sarif_stdout_is_valid_sarif(self, tmp_path: Path) -> None:
        from aigov.cli.main import app
        runner = CliRunner()
        scan_file = self._write_scan_json(tmp_path, [_make_record()])
        result = runner.invoke(app, ["export", str(scan_file), "--format", "sarif"])
        assert result.exit_code == 0, result.output
        doc = json.loads(result.output.strip())
        assert doc["version"] == "2.1.0"
        assert "$schema" in doc

    def test_export_sarif_to_file(self, tmp_path: Path) -> None:
        from aigov.cli.main import app
        runner = CliRunner()
        scan_file = self._write_scan_json(tmp_path, [_make_record(), _make_high_risk()])
        out = tmp_path / "results.sarif"
        result = runner.invoke(
            app,
            ["export", str(scan_file), "--format", "sarif", "--out-file", str(out)],
        )
        assert result.exit_code == 0, result.output
        assert out.exists()
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert len(doc["runs"][0]["results"]) == 2

    def test_export_sarif_no_sensitive_data(self, tmp_path: Path) -> None:
        from aigov.cli.main import app
        runner = CliRunner()
        rec = _make_record()
        rec.tags["api_key_value"] = "sk-FULL-SECRET-KEY-SHOULD-NOT-APPEAR"
        scan_file = self._write_scan_json(tmp_path, [rec])
        result = runner.invoke(app, ["export", str(scan_file), "--format", "sarif"])
        assert result.exit_code == 0, result.output
        assert "sk-FULL-SECRET-KEY-SHOULD-NOT-APPEAR" not in result.output

    def test_export_sarif_preserves_risk_levels(self, tmp_path: Path) -> None:
        from aigov.cli.main import app
        runner = CliRunner()
        scan_file = self._write_scan_json(tmp_path, [_make_prohibited(), _make_high_risk()])
        result = runner.invoke(app, ["export", str(scan_file), "--format", "sarif"])
        assert result.exit_code == 0, result.output
        doc = json.loads(result.output.strip())
        levels = {r["level"] for r in doc["runs"][0]["results"]}
        assert "error" in levels
        assert "warning" in levels
