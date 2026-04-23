from __future__ import annotations

import csv
import json
import hashlib
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aigov.core.exporter import (
    GRC_FIELDS,
    record_to_grc_row,
    records_from_scan_json,
    to_csv,
    to_flat_json,
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


def _make_record(
    name: str = "openai",
    provider: str = "OpenAI",
    system_type: AISystemType = AISystemType.API_SERVICE,
    deployment_type: DeploymentType = DeploymentType.CLOUD_API,
    risk: RiskLevel = RiskLevel.LIMITED_RISK,
    rationale: str = "Test rationale",
    tags: dict | None = None,
) -> AISystemRecord:
    record_id = hashlib.sha1(name.encode()).hexdigest()[:12]
    return AISystemRecord(
        id=record_id,
        name=name,
        description=f"Test record for {name}",
        source_scanner="code.python_imports",
        source_location=f"src/{name}.py:1",
        discovery_timestamp=_TS,
        confidence=0.95,
        system_type=system_type,
        provider=provider,
        deployment_type=deployment_type,
        risk_classification=risk,
        classification_rationale=rationale,
        tags=tags or {"origin_jurisdiction": "US", "eu_ai_act_category": ""},
    )


def _make_high_risk_record() -> AISystemRecord:
    return _make_record(
        name="rekognition",
        provider="AWS",
        system_type=AISystemType.MODEL,
        deployment_type=DeploymentType.CLOUD_API,
        risk=RiskLevel.HIGH_RISK,
        rationale="Biometric identification — EU AI Act Annex III item 1(a)",
        tags={
            "origin_jurisdiction": "US",
            "eu_ai_act_category": "Biometric identification and categorisation",
        },
    )


def _make_prohibited_record() -> AISystemRecord:
    return _make_record(
        name="social-scorer",
        provider="InternalAI",
        system_type=AISystemType.MODEL,
        deployment_type=DeploymentType.SELF_HOSTED,
        risk=RiskLevel.PROHIBITED,
        rationale="Social scoring system — Article 5(1)(c)",
        tags={"origin_jurisdiction": "CN", "eu_ai_act_category": "Prohibited practice"},
    )


def _make_api_key_record() -> AISystemRecord:
    """Simulates a finding from the API-key scanner (preview in tags, no raw value)."""
    return _make_record(
        name="openai-key",
        provider="OpenAI",
        system_type=AISystemType.API_SERVICE,
        deployment_type=DeploymentType.CLOUD_API,
        risk=RiskLevel.LIMITED_RISK,
        tags={
            "origin_jurisdiction": "US",
            "eu_ai_act_category": "",
            "api_key_type": "openai",
            "api_key_preview": "sk-a",
        },
    )


# ---------------------------------------------------------------------------
# CSV export tests
# ---------------------------------------------------------------------------

class TestCSVExport:
    def test_csv_headers_exact(self) -> None:
        records = [_make_record()]
        output = to_csv(records)
        reader = csv.DictReader(StringIO(output))
        assert reader.fieldnames == GRC_FIELDS

    def test_csv_all_grc_fields_present(self) -> None:
        records = [_make_record()]
        output = to_csv(records)
        reader = csv.DictReader(StringIO(output))
        row = next(reader)
        for field in GRC_FIELDS:
            assert field in row, f"Missing field: {field}"

    def test_csv_all_records_present(self) -> None:
        records = [_make_record("openai"), _make_record("anthropic"), _make_high_risk_record()]
        output = to_csv(records)
        reader = csv.DictReader(StringIO(output))
        rows = list(reader)
        assert len(rows) == 3

    def test_csv_risk_levels_included(self) -> None:
        records = [
            _make_record(risk=RiskLevel.LIMITED_RISK),
            _make_high_risk_record(),
            _make_prohibited_record(),
        ]
        output = to_csv(records)
        assert "limited_risk" in output
        assert "high_risk" in output
        assert "prohibited" in output

    def test_csv_no_api_key_values(self) -> None:
        """The raw API key value must never appear in the export."""
        rec = _make_api_key_record()
        raw_key = "sk-secret-key-value-1234567890abcdef"
        # Add a fabricated full key as a tag (should never happen in practice but test defensively)
        rec.tags["api_key_value"] = raw_key
        output = to_csv([rec])
        assert raw_key not in output

    def test_csv_api_key_preview_not_exported(self) -> None:
        """api_key_preview tag must not leak into flat export (only GRC fields are included)."""
        rec = _make_api_key_record()
        output = to_csv([rec])
        assert "api_key_preview" not in output

    def test_csv_annex_iii_category_extracted(self) -> None:
        rec = _make_high_risk_record()
        output = to_csv([rec])
        assert "Biometric identification and categorisation" in output

    def test_csv_origin_jurisdiction_extracted(self) -> None:
        rec = _make_record(tags={"origin_jurisdiction": "DE", "eu_ai_act_category": ""})
        output = to_csv([rec])
        reader = csv.DictReader(StringIO(output))
        row = next(reader)
        assert row["origin_jurisdiction"] == "DE"

    def test_csv_values_match_record(self) -> None:
        rec = _make_record()
        output = to_csv([rec])
        reader = csv.DictReader(StringIO(output))
        row = next(reader)
        assert row["id"] == rec.id
        assert row["name"] == rec.name
        assert row["provider"] == rec.provider
        assert row["system_type"] == rec.system_type.value
        assert row["deployment_type"] == rec.deployment_type.value
        assert row["risk_classification"] == "limited_risk"
        assert row["classification_rationale"] == rec.classification_rationale
        assert row["confidence"] == "0.95"

    def test_csv_empty_records(self) -> None:
        output = to_csv([])
        reader = csv.DictReader(StringIO(output))
        assert reader.fieldnames == GRC_FIELDS
        assert list(reader) == []

    def test_csv_parseable_with_csv_module(self) -> None:
        records = [_make_record("openai"), _make_high_risk_record()]
        output = to_csv(records)
        reader = csv.DictReader(StringIO(output))
        rows = list(reader)
        assert len(rows) == 2
        assert all(isinstance(r, dict) for r in rows)

    def test_csv_no_nested_objects(self) -> None:
        """CSV values must be plain strings, not JSON-encoded dicts or lists."""
        records = [_make_record()]
        output = to_csv(records)
        reader = csv.DictReader(StringIO(output))
        row = next(reader)
        for field, value in row.items():
            assert not value.startswith("{"), f"Field {field} looks like a JSON object"
            assert not value.startswith("["), f"Field {field} looks like a JSON array"


# ---------------------------------------------------------------------------
# Flat JSON export tests
# ---------------------------------------------------------------------------

class TestFlatJSONExport:
    def test_flat_json_is_array(self) -> None:
        records = [_make_record()]
        parsed = json.loads(to_flat_json(records))
        assert isinstance(parsed, list)

    def test_flat_json_all_records(self) -> None:
        records = [_make_record("openai"), _make_record("anthropic")]
        parsed = json.loads(to_flat_json(records))
        assert len(parsed) == 2

    def test_flat_json_all_grc_fields(self) -> None:
        records = [_make_record()]
        parsed = json.loads(to_flat_json(records))
        row = parsed[0]
        for field in GRC_FIELDS:
            assert field in row, f"Missing field: {field}"

    def test_flat_json_values_are_strings(self) -> None:
        """All values in the flat JSON must be plain strings — no nested dicts or lists."""
        records = [_make_record()]
        parsed = json.loads(to_flat_json(records))
        row = parsed[0]
        for field, value in row.items():
            assert isinstance(value, str), f"Field {field} is not a string: {type(value)}"

    def test_flat_json_no_api_key_values(self) -> None:
        raw_key = "sk-super-secret-key-9876"
        rec = _make_api_key_record()
        rec.tags["api_key_value"] = raw_key
        output = to_flat_json([rec])
        assert raw_key not in output

    def test_flat_json_risk_levels(self) -> None:
        records = [_make_high_risk_record(), _make_prohibited_record()]
        parsed = json.loads(to_flat_json(records))
        risk_values = {r["risk_classification"] for r in parsed}
        assert "high_risk" in risk_values
        assert "prohibited" in risk_values

    def test_flat_json_empty_records(self) -> None:
        parsed = json.loads(to_flat_json([]))
        assert parsed == []

    def test_flat_json_excludes_raw_tags_blob(self) -> None:
        """The full tags dict must not appear as a field in the flat export."""
        rec = _make_record(tags={"origin_jurisdiction": "US", "eu_ai_act_category": "", "internal": "value"})
        output = to_flat_json([rec])
        parsed = json.loads(output)
        row = parsed[0]
        assert "tags" not in row
        assert "internal" not in row


# ---------------------------------------------------------------------------
# record_to_grc_row tests
# ---------------------------------------------------------------------------

class TestRecordToGrcRow:
    def test_basic_mapping(self) -> None:
        rec = _make_record()
        row = record_to_grc_row(rec)
        assert row["id"] == rec.id
        assert row["name"] == rec.name
        assert row["provider"] == rec.provider
        assert row["system_type"] == "api_service"
        assert row["deployment_type"] == "cloud_api"
        assert row["risk_classification"] == "limited_risk"
        assert row["origin_jurisdiction"] == "US"
        assert row["annex_iii_category"] == ""
        assert row["confidence"] == "0.95"

    def test_annex_iii_from_tags(self) -> None:
        rec = _make_high_risk_record()
        row = record_to_grc_row(rec)
        assert row["annex_iii_category"] == "Biometric identification and categorisation"

    def test_missing_tags_default_to_empty(self) -> None:
        rec = _make_record()
        rec.tags = {}
        row = record_to_grc_row(rec)
        assert row["origin_jurisdiction"] == ""
        assert row["annex_iii_category"] == ""

    def test_no_risk_classification(self) -> None:
        rec = _make_record(risk=RiskLevel.UNKNOWN)
        rec.risk_classification = None
        row = record_to_grc_row(rec)
        assert row["risk_classification"] == ""

    def test_discovery_timestamp_is_iso(self) -> None:
        rec = _make_record()
        row = record_to_grc_row(rec)
        parsed = datetime.fromisoformat(row["discovery_timestamp"])
        assert parsed == _TS


# ---------------------------------------------------------------------------
# records_from_scan_json tests
# ---------------------------------------------------------------------------

class TestRecordsFromScanJson:
    def _scan_envelope(self, records: list[AISystemRecord]) -> dict:
        return {
            "aigov_version": "0.2.0",
            "summary": {"total_found": len(records)},
            "findings": [r.to_dict() for r in records],
        }

    def test_parses_scan_envelope(self) -> None:
        records = [_make_record("openai"), _make_record("anthropic")]
        data = self._scan_envelope(records)
        result = records_from_scan_json(data)
        assert len(result) == 2
        assert {r.name for r in result} == {"openai", "anthropic"}

    def test_parses_plain_array(self) -> None:
        records = [_make_record()]
        data = [r.to_dict() for r in records]
        result = records_from_scan_json(data)
        assert len(result) == 1

    def test_skips_malformed_entries(self) -> None:
        records = [_make_record()]
        findings = [r.to_dict() for r in records]
        findings.append({"bad": "entry"})
        data = {"findings": findings}
        result = records_from_scan_json(data)
        assert len(result) == 1

    def test_empty_findings(self) -> None:
        result = records_from_scan_json({"findings": []})
        assert result == []

    def test_missing_findings_key(self) -> None:
        result = records_from_scan_json({"summary": {}})
        assert result == []


# ---------------------------------------------------------------------------
# CLI export command tests
# ---------------------------------------------------------------------------

class TestExportCLI:
    def _write_scan_json(self, tmp_path: Path, records: list[AISystemRecord]) -> Path:
        data = {
            "aigov_version": "0.2.0",
            "summary": {"total_found": len(records), "scanners_run": [], "scanned_paths": ["."]},
            "warnings": [],
            "findings": [r.to_dict() for r in records],
        }
        p = tmp_path / "results.json"
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return p

    def test_export_csv_to_stdout(self, tmp_path: Path) -> None:
        from aigov.cli.main import app
        runner = CliRunner()
        scan_file = self._write_scan_json(tmp_path, [_make_record()])
        result = runner.invoke(app, ["export", str(scan_file), "--format", "csv"])
        assert result.exit_code == 0, result.output
        assert "id,name,provider" in result.output

    def test_export_csv_to_file(self, tmp_path: Path) -> None:
        from aigov.cli.main import app
        runner = CliRunner()
        scan_file = self._write_scan_json(tmp_path, [_make_record(), _make_high_risk_record()])
        out = tmp_path / "inventory.csv"
        result = runner.invoke(app, ["export", str(scan_file), "--format", "csv", "--out-file", str(out)])
        assert result.exit_code == 0, result.output
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        reader = csv.DictReader(StringIO(content))
        rows = list(reader)
        assert len(rows) == 2

    def test_export_json_to_stdout(self, tmp_path: Path) -> None:
        from aigov.cli.main import app
        runner = CliRunner()
        scan_file = self._write_scan_json(tmp_path, [_make_record()])
        result = runner.invoke(app, ["export", str(scan_file), "--format", "json"])
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output.strip())
        assert isinstance(parsed, list)
        assert len(parsed) == 1

    def test_export_json_to_file(self, tmp_path: Path) -> None:
        from aigov.cli.main import app
        runner = CliRunner()
        scan_file = self._write_scan_json(tmp_path, [_make_record()])
        out = tmp_path / "export.json"
        result = runner.invoke(app, ["export", str(scan_file), "--format", "json", "--out-file", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        parsed = json.loads(out.read_text(encoding="utf-8"))
        assert isinstance(parsed, list)

    def test_export_missing_file(self, tmp_path: Path) -> None:
        from aigov.cli.main import app
        runner = CliRunner()
        result = runner.invoke(app, ["export", str(tmp_path / "nonexistent.json")])
        assert result.exit_code != 0

    def test_export_invalid_format(self, tmp_path: Path) -> None:
        from aigov.cli.main import app
        runner = CliRunner()
        scan_file = self._write_scan_json(tmp_path, [_make_record()])
        result = runner.invoke(app, ["export", str(scan_file), "--format", "xml"])
        assert result.exit_code != 0
        assert "xml" in result.output

    def test_export_invalid_json_input(self, tmp_path: Path) -> None:
        from aigov.cli.main import app
        runner = CliRunner()
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json at all", encoding="utf-8")
        result = runner.invoke(app, ["export", str(bad_file)])
        assert result.exit_code != 0

    def test_export_csv_no_sensitive_data_in_output(self, tmp_path: Path) -> None:
        """Exporting a record with a fabricated raw key in tags must not expose it."""
        from aigov.cli.main import app
        runner = CliRunner()
        rec = _make_api_key_record()
        rec.tags["api_key_value"] = "sk-FULL-SECRET-KEY-DO-NOT-EXPORT"
        data = {"findings": [rec.to_dict()]}
        scan_file = tmp_path / "results.json"
        scan_file.write_text(json.dumps(data), encoding="utf-8")
        result = runner.invoke(app, ["export", str(scan_file), "--format", "csv"])
        assert result.exit_code == 0
        assert "sk-FULL-SECRET-KEY-DO-NOT-EXPORT" not in result.output


# ---------------------------------------------------------------------------
# scan --output csv integration test
# ---------------------------------------------------------------------------

class TestScanCSVOutput:
    def test_scan_csv_via_main_app(self, tmp_path: Path) -> None:
        from aigov.cli.main import app
        runner = CliRunner()
        # Write a minimal Python file that imports openai so the scanner finds it
        src = tmp_path / "app.py"
        src.write_text("import openai\n", encoding="utf-8")
        out = tmp_path / "inventory.csv"
        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--classify", "--output", "csv", "--out-file", str(out)],
        )
        assert result.exit_code == 0, result.output
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        reader = csv.DictReader(StringIO(content))
        assert reader.fieldnames == GRC_FIELDS
        rows = list(reader)
        assert len(rows) >= 1
        names = [r["name"] for r in rows]
        assert any("openai" in n.lower() for n in names)

    def test_scan_csv_to_stdout(self, tmp_path: Path) -> None:
        from aigov.cli.main import app
        runner = CliRunner()
        src = tmp_path / "app.py"
        src.write_text("import anthropic\n", encoding="utf-8")
        result = runner.invoke(app, ["scan", str(tmp_path), "--classify", "--output", "csv"])
        assert result.exit_code == 0, result.output
        assert "id,name,provider" in result.output
