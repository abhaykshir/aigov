from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aigov.core.baseline import DriftReport, compare_to_baseline, save_baseline
from aigov.core.engine import ScanResult
from aigov.core.models import AISystemRecord, AISystemType, DeploymentType, RiskLevel


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _record(
    name: str = "openai-client",
    record_id: str = "aaaa1111bbbb2222",
    risk: RiskLevel = RiskLevel.LIMITED_RISK,
    provider: str = "OpenAI",
    location: str = "/app/main.py",
) -> AISystemRecord:
    return AISystemRecord(
        id=record_id,
        name=name,
        description=f"Test record: {name}",
        source_scanner="code.python_imports",
        source_location=location,
        discovery_timestamp=_now(),
        confidence=0.9,
        system_type=AISystemType.API_SERVICE,
        provider=provider,
        deployment_type=DeploymentType.CLOUD_API,
        risk_classification=risk,
        tags={"origin_jurisdiction": "US"},
    )


def _result(*records: AISystemRecord) -> ScanResult:
    r = ScanResult(records=list(records), scanners_run=["code.python_imports"])
    r._compute_summaries()
    return r


# ---------------------------------------------------------------------------
# save_baseline
# ---------------------------------------------------------------------------

class TestSaveBaseline:
    def test_creates_file(self, tmp_path):
        dest = tmp_path / "baseline.json"
        save_baseline(_result(_record()), path=dest)
        assert dest.exists()

    def test_returns_path(self, tmp_path):
        dest = tmp_path / "baseline.json"
        returned = save_baseline(_result(_record()), path=dest)
        assert returned == dest

    def test_json_is_valid(self, tmp_path):
        dest = tmp_path / "baseline.json"
        save_baseline(_result(_record()), path=dest)
        data = json.loads(dest.read_text())
        assert isinstance(data, dict)

    def test_saved_at_present(self, tmp_path):
        dest = tmp_path / "baseline.json"
        save_baseline(_result(_record()), path=dest)
        data = json.loads(dest.read_text())
        assert "saved_at" in data
        # Must be a parseable ISO datetime
        datetime.fromisoformat(data["saved_at"])

    def test_findings_written(self, tmp_path):
        dest = tmp_path / "baseline.json"
        save_baseline(_result(_record(name="gpt4"), _record(name="langchain", record_id="cc")), path=dest)
        data = json.loads(dest.read_text())
        assert len(data["findings"]) == 2

    def test_record_ids_in_findings(self, tmp_path):
        dest = tmp_path / "baseline.json"
        rec = _record(record_id="myid1234")
        save_baseline(_result(rec), path=dest)
        data = json.loads(dest.read_text())
        ids = [f["id"] for f in data["findings"]]
        assert "myid1234" in ids

    def test_no_credential_values_in_output(self, tmp_path):
        dest = tmp_path / "baseline.json"
        rec = _record(name="sk-ant-api03-****")  # redacted key name, not value
        save_baseline(_result(rec), path=dest)
        raw = dest.read_text()
        # No raw key-like strings (the fixture name itself is a redacted preview)
        assert "sk-ant-api03-abcdefghijklmnop" not in raw

    def test_overwrites_existing(self, tmp_path):
        dest = tmp_path / "baseline.json"
        save_baseline(_result(_record(name="old")), path=dest)
        save_baseline(_result(_record(name="new", record_id="newid")), path=dest)
        data = json.loads(dest.read_text())
        names = [f["name"] for f in data["findings"]]
        assert "new" in names
        assert "old" not in names

    def test_default_path_name(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        save_baseline(_result(_record()))
        assert (tmp_path / ".aigov-baseline.json").exists()


# ---------------------------------------------------------------------------
# compare_to_baseline — no baseline
# ---------------------------------------------------------------------------

class TestCompareNoBaseline:
    def test_missing_file_no_exception(self, tmp_path):
        result = _result(_record())
        report = compare_to_baseline(result, baseline_path=tmp_path / "nonexistent.json")
        assert isinstance(report, DriftReport)

    def test_all_current_treated_as_new(self, tmp_path):
        r1 = _record(name="r1", record_id="id1")
        r2 = _record(name="r2", record_id="id2")
        result = _result(r1, r2)
        report = compare_to_baseline(result, baseline_path=tmp_path / "nonexistent.json")
        assert len(report.new_systems) == 2

    def test_no_removed_when_no_baseline(self, tmp_path):
        result = _result(_record())
        report = compare_to_baseline(result, baseline_path=tmp_path / "missing.json")
        assert report.removed_systems == []

    def test_no_changed_when_no_baseline(self, tmp_path):
        result = _result(_record())
        report = compare_to_baseline(result, baseline_path=tmp_path / "missing.json")
        assert report.changed_classification == []

    def test_baseline_date_is_none_when_no_file(self, tmp_path):
        result = _result(_record())
        report = compare_to_baseline(result, baseline_path=tmp_path / "missing.json")
        assert report.baseline_date is None

    def test_has_drift_true_when_no_baseline(self, tmp_path):
        result = _result(_record())
        report = compare_to_baseline(result, baseline_path=tmp_path / "missing.json")
        assert report.has_drift is True


# ---------------------------------------------------------------------------
# compare_to_baseline — round-trip (no changes)
# ---------------------------------------------------------------------------

class TestCompareRoundTrip:
    def test_no_drift_on_identical_scan(self, tmp_path):
        baseline_path = tmp_path / "bl.json"
        rec = _record()
        result = _result(rec)
        save_baseline(result, path=baseline_path)
        report = compare_to_baseline(result, baseline_path=baseline_path)
        assert report.has_drift is False

    def test_unchanged_count_correct(self, tmp_path):
        baseline_path = tmp_path / "bl.json"
        result = _result(
            _record(name="a", record_id="id_a"),
            _record(name="b", record_id="id_b"),
            _record(name="c", record_id="id_c"),
        )
        save_baseline(result, path=baseline_path)
        report = compare_to_baseline(result, baseline_path=baseline_path)
        assert report.unchanged_count == 3

    def test_new_and_removed_empty_on_same_scan(self, tmp_path):
        baseline_path = tmp_path / "bl.json"
        result = _result(_record())
        save_baseline(result, path=baseline_path)
        report = compare_to_baseline(result, baseline_path=baseline_path)
        assert report.new_systems == []
        assert report.removed_systems == []
        assert report.changed_classification == []

    def test_baseline_date_populated(self, tmp_path):
        baseline_path = tmp_path / "bl.json"
        before = datetime.now(timezone.utc)
        save_baseline(_result(_record()), path=baseline_path)
        after = datetime.now(timezone.utc)
        report = compare_to_baseline(_result(_record()), baseline_path=baseline_path)
        assert report.baseline_date is not None
        assert before <= report.baseline_date <= after


# ---------------------------------------------------------------------------
# compare_to_baseline — new systems detected
# ---------------------------------------------------------------------------

class TestNewSystemsDetected:
    def test_new_system_appears_in_report(self, tmp_path):
        baseline_path = tmp_path / "bl.json"
        save_baseline(_result(_record(name="existing", record_id="old_id")), path=baseline_path)
        current = _result(
            _record(name="existing", record_id="old_id"),
            _record(name="newcomer", record_id="new_id"),
        )
        report = compare_to_baseline(current, baseline_path=baseline_path)
        assert len(report.new_systems) == 1
        assert report.new_systems[0].name == "newcomer"

    def test_has_drift_true_on_new_system(self, tmp_path):
        baseline_path = tmp_path / "bl.json"
        save_baseline(_result(_record(record_id="a")), path=baseline_path)
        current = _result(_record(record_id="a"), _record(name="new", record_id="b"))
        report = compare_to_baseline(current, baseline_path=baseline_path)
        assert report.has_drift is True

    def test_unchanged_count_excludes_new(self, tmp_path):
        baseline_path = tmp_path / "bl.json"
        save_baseline(_result(_record(record_id="a")), path=baseline_path)
        current = _result(_record(record_id="a"), _record(name="new", record_id="b"))
        report = compare_to_baseline(current, baseline_path=baseline_path)
        assert report.unchanged_count == 1  # "a" unchanged


# ---------------------------------------------------------------------------
# compare_to_baseline — removed systems detected
# ---------------------------------------------------------------------------

class TestRemovedSystemsDetected:
    def test_removed_system_appears_in_report(self, tmp_path):
        baseline_path = tmp_path / "bl.json"
        save_baseline(
            _result(
                _record(name="stays", record_id="a"),
                _record(name="gone", record_id="b"),
            ),
            path=baseline_path,
        )
        current = _result(_record(name="stays", record_id="a"))
        report = compare_to_baseline(current, baseline_path=baseline_path)
        assert len(report.removed_systems) == 1
        assert report.removed_systems[0].name == "gone"

    def test_has_drift_true_on_removal(self, tmp_path):
        baseline_path = tmp_path / "bl.json"
        save_baseline(_result(_record(record_id="a"), _record(name="x", record_id="b")), path=baseline_path)
        report = compare_to_baseline(_result(_record(record_id="a")), baseline_path=baseline_path)
        assert report.has_drift is True


# ---------------------------------------------------------------------------
# compare_to_baseline — classification changes detected
# ---------------------------------------------------------------------------

class TestClassificationChanges:
    def test_reclassified_system_detected(self, tmp_path):
        baseline_path = tmp_path / "bl.json"
        old_rec = _record(record_id="shared_id", risk=RiskLevel.LIMITED_RISK)
        save_baseline(_result(old_rec), path=baseline_path)

        new_rec = _record(record_id="shared_id", risk=RiskLevel.HIGH_RISK)
        report = compare_to_baseline(_result(new_rec), baseline_path=baseline_path)

        assert len(report.changed_classification) == 1
        old, new = report.changed_classification[0]
        assert old.risk_classification == RiskLevel.LIMITED_RISK
        assert new.risk_classification == RiskLevel.HIGH_RISK

    def test_changed_classification_has_drift(self, tmp_path):
        baseline_path = tmp_path / "bl.json"
        save_baseline(_result(_record(record_id="x", risk=RiskLevel.MINIMAL_RISK)), path=baseline_path)
        report = compare_to_baseline(
            _result(_record(record_id="x", risk=RiskLevel.HIGH_RISK)),
            baseline_path=baseline_path,
        )
        assert report.has_drift is True

    def test_same_classification_not_in_changed(self, tmp_path):
        baseline_path = tmp_path / "bl.json"
        rec = _record(record_id="stable", risk=RiskLevel.LIMITED_RISK)
        save_baseline(_result(rec), path=baseline_path)
        report = compare_to_baseline(_result(rec), baseline_path=baseline_path)
        assert report.changed_classification == []


# ---------------------------------------------------------------------------
# DriftReport dataclass
# ---------------------------------------------------------------------------

class TestDriftReport:
    def test_has_drift_false_when_empty(self):
        report = DriftReport(
            new_systems=[],
            removed_systems=[],
            changed_classification=[],
            unchanged_count=5,
            baseline_date=_now(),
        )
        assert report.has_drift is False

    def test_has_drift_true_when_new(self):
        report = DriftReport(
            new_systems=[_record()],
            removed_systems=[],
            changed_classification=[],
            unchanged_count=0,
            baseline_date=_now(),
        )
        assert report.has_drift is True

    def test_has_drift_true_when_removed(self):
        report = DriftReport(
            new_systems=[],
            removed_systems=[_record()],
            changed_classification=[],
            unchanged_count=0,
            baseline_date=_now(),
        )
        assert report.has_drift is True

    def test_has_drift_true_when_reclassified(self):
        rec = _record()
        report = DriftReport(
            new_systems=[],
            removed_systems=[],
            changed_classification=[(rec, rec)],
            unchanged_count=1,
            baseline_date=_now(),
        )
        assert report.has_drift is True

    def test_to_dict_structure(self):
        rec = _record()
        report = DriftReport(
            new_systems=[rec],
            removed_systems=[],
            changed_classification=[],
            unchanged_count=0,
            baseline_date=_now(),
        )
        d = report.to_dict()
        assert "has_drift" in d
        assert "new_systems" in d
        assert "removed_systems" in d
        assert "changed_classification" in d
        assert "unchanged_count" in d
        assert "baseline_date" in d

    def test_to_dict_serializable(self):
        rec = _record()
        report = DriftReport(
            new_systems=[rec],
            removed_systems=[],
            changed_classification=[],
            unchanged_count=0,
            baseline_date=_now(),
        )
        # Must not raise
        out = json.dumps(report.to_dict())
        assert len(out) > 0

    def test_to_dict_changed_classification_format(self):
        old = _record(record_id="x", risk=RiskLevel.LIMITED_RISK)
        new = _record(record_id="x", risk=RiskLevel.HIGH_RISK)
        report = DriftReport(
            new_systems=[],
            removed_systems=[],
            changed_classification=[(old, new)],
            unchanged_count=0,
            baseline_date=_now(),
        )
        d = report.to_dict()
        assert len(d["changed_classification"]) == 1
        assert "old" in d["changed_classification"][0]
        assert "new" in d["changed_classification"][0]


# ---------------------------------------------------------------------------
# fail-on-drift logic (via CLI exit code)
# ---------------------------------------------------------------------------

class TestFailOnDrift:
    def test_fail_on_drift_exit_1_for_prohibited(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from aigov.cli.baseline import app

        baseline_path = tmp_path / "bl.json"
        # Empty baseline so all current systems are new
        save_baseline(_result(), path=baseline_path)

        runner = CliRunner()

        # Patch the scan to return a prohibited system without actually scanning
        from aigov.core.baseline import compare_to_baseline as real_compare
        prohibited_rec = _record(risk=RiskLevel.PROHIBITED)

        from unittest.mock import patch, MagicMock
        mock_report = DriftReport(
            new_systems=[prohibited_rec],
            removed_systems=[],
            changed_classification=[],
            unchanged_count=0,
            baseline_date=_now(),
        )

        with patch("aigov.cli.baseline._run_scan_and_classify") as mock_scan, \
             patch("aigov.cli.baseline.compare_to_baseline") as mock_compare:
            mock_scan.return_value = _result(prohibited_rec)
            mock_compare.return_value = mock_report

            result = runner.invoke(app, [
                "diff", "--fail-on-drift",
                f"--baseline={baseline_path}",
            ])
            assert result.exit_code == 1

    def test_fail_on_drift_exit_1_for_high_risk(self, tmp_path):
        from typer.testing import CliRunner
        from aigov.cli.baseline import app
        from unittest.mock import patch

        high_risk_rec = _record(risk=RiskLevel.HIGH_RISK)
        mock_report = DriftReport(
            new_systems=[high_risk_rec],
            removed_systems=[],
            changed_classification=[],
            unchanged_count=0,
            baseline_date=_now(),
        )

        runner = CliRunner()
        with patch("aigov.cli.baseline._run_scan_and_classify") as ms, \
             patch("aigov.cli.baseline.compare_to_baseline") as mc:
            ms.return_value = _result(high_risk_rec)
            mc.return_value = mock_report
            result = runner.invoke(app, ["diff", "--fail-on-drift"])
            assert result.exit_code == 1

    def test_fail_on_drift_exit_0_for_minimal(self, tmp_path):
        from typer.testing import CliRunner
        from aigov.cli.baseline import app
        from unittest.mock import patch

        minimal_rec = _record(risk=RiskLevel.MINIMAL_RISK)
        mock_report = DriftReport(
            new_systems=[minimal_rec],
            removed_systems=[],
            changed_classification=[],
            unchanged_count=0,
            baseline_date=_now(),
        )

        runner = CliRunner()
        with patch("aigov.cli.baseline._run_scan_and_classify") as ms, \
             patch("aigov.cli.baseline.compare_to_baseline") as mc:
            ms.return_value = _result(minimal_rec)
            mc.return_value = mock_report
            result = runner.invoke(app, ["diff", "--fail-on-drift"])
            assert result.exit_code == 0

    def test_no_fail_on_drift_flag_always_exits_0(self):
        from typer.testing import CliRunner
        from aigov.cli.baseline import app
        from unittest.mock import patch

        prohibited_rec = _record(risk=RiskLevel.PROHIBITED)
        mock_report = DriftReport(
            new_systems=[prohibited_rec],
            removed_systems=[],
            changed_classification=[],
            unchanged_count=0,
            baseline_date=_now(),
        )

        runner = CliRunner()
        with patch("aigov.cli.baseline._run_scan_and_classify") as ms, \
             patch("aigov.cli.baseline.compare_to_baseline") as mc:
            ms.return_value = _result(prohibited_rec)
            mc.return_value = mock_report
            # No --fail-on-drift flag
            result = runner.invoke(app, ["diff"])
            assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

class TestBaselineSecurity:
    def test_baseline_file_has_no_raw_api_keys(self, tmp_path):
        dest = tmp_path / "bl.json"
        # Record with a name that looks like a redacted key (as API key scanner would produce)
        rec = _record(name="sk-ant-****", location="/app/.env")
        save_baseline(_result(rec), path=dest)
        raw = dest.read_text()
        # Real key values would look like sk-ant-api03-<base64>, never stored
        import re
        assert not re.search(r"sk-ant-api03-[A-Za-z0-9+/]{40,}", raw)

    def test_compare_with_corrupted_baseline_no_crash(self, tmp_path):
        baseline_path = tmp_path / "bl.json"
        baseline_path.write_text("{corrupt: json: !!!", encoding="utf-8")
        result = _result(_record())
        # Must not raise — treats everything as new
        report = compare_to_baseline(result, baseline_path=baseline_path)
        assert isinstance(report, DriftReport)
        assert len(report.new_systems) == 1
