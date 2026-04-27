from __future__ import annotations

import json
from pathlib import Path

import pytest

from aigov.cli.check_risk import main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _results_file(tmp_path: Path, findings: list[dict]) -> str:
    p = tmp_path / "results.json"
    p.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    return str(p)


def _finding(
    risk: str,
    name: str = "Test System",
    loc: str = "src/app.py:1",
    tags: dict | None = None,
) -> dict:
    return {
        "id": "abc123",
        "name": name,
        "risk_classification": risk,
        "source_location": loc,
        "tags": tags or {},
    }


def _allowlisted(risk: str, name: str = "Approved System", reason: str = "Approved by board 2026-01-15") -> dict:
    return _finding(
        risk,
        name=name,
        tags={"allowlisted": "true", "allowlist_reason": reason},
    )


# ---------------------------------------------------------------------------
# Clean / passing cases
# ---------------------------------------------------------------------------

class TestCheckRiskPass:
    def test_empty_results_pass(self, tmp_path):
        f = _results_file(tmp_path, [])
        assert main([f]) == 0

    def test_minimal_risk_does_not_trigger_failure(self, tmp_path):
        f = _results_file(tmp_path, [_finding("minimal_risk")])
        assert main([f]) == 0

    def test_limited_risk_does_not_trigger_with_default_fail_on(self, tmp_path):
        f = _results_file(tmp_path, [_finding("limited_risk")])
        assert main([f]) == 0

    def test_unknown_does_not_trigger_with_default_fail_on(self, tmp_path):
        f = _results_file(tmp_path, [_finding("unknown")])
        assert main([f]) == 0

    def test_needs_review_does_not_trigger_with_default_fail_on(self, tmp_path):
        f = _results_file(tmp_path, [_finding("needs_review")])
        assert main([f]) == 0

    def test_high_risk_does_not_trigger_with_default_fail_on(self, tmp_path):
        f = _results_file(tmp_path, [_finding("high_risk")])
        assert main([f]) == 0

    def test_none_risk_classification_does_not_trigger(self, tmp_path):
        finding = {"id": "x", "name": "Null Risk", "risk_classification": None, "source_location": ""}
        f = _results_file(tmp_path, [finding])
        assert main([f]) == 0

    def test_multiple_clean_records_pass(self, tmp_path):
        findings = [
            _finding("minimal_risk", name="System A"),
            _finding("limited_risk", name="System B"),
            _finding("high_risk", name="System C"),
        ]
        f = _results_file(tmp_path, findings)
        assert main([f]) == 0


# ---------------------------------------------------------------------------
# Failure cases
# ---------------------------------------------------------------------------

class TestCheckRiskFail:
    def test_prohibited_triggers_failure(self, tmp_path):
        f = _results_file(tmp_path, [_finding("prohibited")])
        assert main([f]) == 1

    def test_high_risk_triggers_when_configured(self, tmp_path):
        f = _results_file(tmp_path, [_finding("high_risk")])
        assert main([f, "--fail-on", "high_risk"]) == 1

    def test_limited_risk_triggers_when_configured(self, tmp_path):
        f = _results_file(tmp_path, [_finding("limited_risk")])
        assert main([f, "--fail-on", "limited_risk"]) == 1

    def test_multiple_fail_on_levels_match_first(self, tmp_path):
        f = _results_file(tmp_path, [_finding("prohibited")])
        assert main([f, "--fail-on", "prohibited,high_risk"]) == 1

    def test_multiple_fail_on_levels_match_second(self, tmp_path):
        f = _results_file(tmp_path, [_finding("high_risk")])
        assert main([f, "--fail-on", "prohibited,high_risk"]) == 1

    def test_only_matching_records_trigger(self, tmp_path):
        findings = [
            _finding("minimal_risk", name="Safe System"),
            _finding("prohibited", name="Bad Actor"),
        ]
        f = _results_file(tmp_path, findings)
        assert main([f]) == 1

    def test_all_prohibited_records_trigger(self, tmp_path):
        findings = [
            _finding("prohibited", name="System A"),
            _finding("prohibited", name="System B"),
        ]
        f = _results_file(tmp_path, findings)
        assert main([f]) == 1

    def test_fail_on_is_case_insensitive(self, tmp_path):
        f = _results_file(tmp_path, [_finding("PROHIBITED")])
        assert main([f, "--fail-on", "prohibited"]) == 1

    def test_fail_on_flag_is_case_insensitive(self, tmp_path):
        f = _results_file(tmp_path, [_finding("prohibited")])
        assert main([f, "--fail-on", "PROHIBITED"]) == 1


# ---------------------------------------------------------------------------
# Error / bad input cases
# ---------------------------------------------------------------------------

class TestCheckRiskErrors:
    def test_missing_file_returns_2(self, tmp_path):
        assert main([str(tmp_path / "nonexistent.json")]) == 2

    def test_invalid_json_returns_2(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("not valid json", encoding="utf-8")
        assert main([str(p)]) == 2

    def test_empty_file_returns_2(self, tmp_path):
        p = tmp_path / "empty.json"
        p.write_text("", encoding="utf-8")
        assert main([str(p)]) == 2

    def test_missing_findings_key_is_treated_as_empty(self, tmp_path):
        p = tmp_path / "no_findings.json"
        p.write_text(json.dumps({"summary": {}}), encoding="utf-8")
        assert main([str(p)]) == 0


# ---------------------------------------------------------------------------
# Output / messaging (smoke-test that output is printed without crash)
# ---------------------------------------------------------------------------

class TestCheckRiskOutput:
    def test_pass_message_printed(self, tmp_path, capsys):
        f = _results_file(tmp_path, [])
        main([f])
        captured = capsys.readouterr()
        assert "PASSED" in captured.out

    def test_fail_message_printed(self, tmp_path, capsys):
        f = _results_file(tmp_path, [_finding("prohibited", name="SocialScorer")])
        main([f])
        captured = capsys.readouterr()
        assert "FAILED" in captured.out
        assert "SocialScorer" in captured.out

    def test_fail_message_includes_location(self, tmp_path, capsys):
        f = _results_file(tmp_path, [_finding("prohibited", loc="src/scoring.py:42")])
        main([f])
        captured = capsys.readouterr()
        assert "src/scoring.py:42" in captured.out

    def test_fail_on_levels_shown_in_pass_message(self, tmp_path, capsys):
        f = _results_file(tmp_path, [_finding("minimal_risk")])
        main([f, "--fail-on", "prohibited"])
        captured = capsys.readouterr()
        assert "prohibited" in captured.out


# ---------------------------------------------------------------------------
# Allowlist bypass — records tagged allowlisted=true do not trigger failures
# ---------------------------------------------------------------------------

class TestCheckRiskAllowlist:
    def test_allowlisted_high_risk_does_not_trigger(self, tmp_path):
        """A HIGH_RISK record marked allowlisted in tags must not fail CI."""
        f = _results_file(
            tmp_path,
            [_allowlisted("high_risk", name="Approved Resume Screener")],
        )
        assert main([f, "--fail-on", "high_risk"]) == 0

    def test_allowlisted_prohibited_does_not_trigger(self, tmp_path):
        """Even PROHIBITED records are bypassed when explicitly allowlisted."""
        f = _results_file(tmp_path, [_allowlisted("prohibited")])
        assert main([f]) == 0

    def test_non_allowlisted_high_risk_still_triggers(self, tmp_path):
        """A HIGH_RISK record without the allowlist tag still fails CI."""
        f = _results_file(tmp_path, [_finding("high_risk")])
        assert main([f, "--fail-on", "high_risk"]) == 1

    def test_mixed_allowlisted_and_non_allowlisted(self, tmp_path):
        """Allowlisted records are skipped; the unlisted one still triggers."""
        findings = [
            _allowlisted("high_risk", name="Approved Tool"),
            _finding("high_risk", name="Unapproved Tool"),
        ]
        f = _results_file(tmp_path, findings)
        assert main([f, "--fail-on", "high_risk"]) == 1

    def test_allowlist_reason_is_printed(self, tmp_path, capsys):
        """The allowlist reason must surface so reviewers can audit the bypass."""
        reason = "Approved by AI governance board 2026-01-15"
        findings = [_allowlisted("high_risk", name="ApprovedSystem", reason=reason)]
        f = _results_file(tmp_path, findings)
        main([f, "--fail-on", "high_risk"])
        captured = capsys.readouterr()
        assert "Skipped (allowlisted)" in captured.out
        assert "ApprovedSystem" in captured.out
        assert reason in captured.out

    def test_allowlisted_string_false_does_not_skip(self, tmp_path):
        """Only `allowlisted: "true"` triggers the skip — anything else is ignored."""
        finding = _finding(
            "high_risk",
            tags={"allowlisted": "false", "allowlist_reason": "ignored"},
        )
        f = _results_file(tmp_path, [finding])
        assert main([f, "--fail-on", "high_risk"]) == 1

    def test_allowlisted_missing_reason_prints_placeholder(self, tmp_path, capsys):
        """When the reason tag is missing, the skip line still names the record."""
        finding = _finding(
            "high_risk",
            name="QuietBypass",
            tags={"allowlisted": "true"},
        )
        f = _results_file(tmp_path, [finding])
        main([f, "--fail-on", "high_risk"])
        captured = capsys.readouterr()
        assert "Skipped (allowlisted)" in captured.out
        assert "QuietBypass" in captured.out
