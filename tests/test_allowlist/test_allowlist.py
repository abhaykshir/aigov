from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from aigov.core.allowlist import Allowlist, AllowlistEntry
from aigov.core.models import AISystemRecord, AISystemType, DeploymentType, RiskLevel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_record(name: str = "test-chatbot", record_id: str = "abc123def456") -> AISystemRecord:
    return AISystemRecord(
        id=record_id,
        name=name,
        description="Test AI system",
        source_scanner="code.python_imports",
        source_location="/app/main.py",
        discovery_timestamp=datetime.now(timezone.utc),
        confidence=0.9,
        system_type=AISystemType.API_SERVICE,
        provider="OpenAI",
        deployment_type=DeploymentType.CLOUD_API,
        risk_classification=RiskLevel.LIMITED_RISK,
        tags={"origin_jurisdiction": "US"},
    )


_ALLOWLIST_YAML = """\
approved:
  - id: "abc123def456"
    reason: "Approved by AI governance board 2026-01-15"
  - name_pattern: "internal-*"
    reason: "Internal tools approved under policy AI-2026-003"
"""

_NAME_ONLY_YAML = """\
approved:
  - name_pattern: "test-*"
    reason: "Test pattern match"
"""


# ---------------------------------------------------------------------------
# Allowlist.load()
# ---------------------------------------------------------------------------

class TestAllowlistLoad:
    def test_missing_file_returns_empty(self, tmp_path):
        al = Allowlist.load(tmp_path / "nonexistent.yaml")
        assert al._entries == []

    def test_missing_file_no_exception(self, tmp_path):
        al = Allowlist.load(tmp_path / "nonexistent.yaml")
        assert isinstance(al, Allowlist)

    def test_loads_entries_from_yaml(self, tmp_path):
        p = tmp_path / ".aigov-allowlist.yaml"
        p.write_text(_ALLOWLIST_YAML, encoding="utf-8")
        al = Allowlist.load(p)
        assert len(al._entries) == 2

    def test_entry_id_loaded(self, tmp_path):
        p = tmp_path / ".aigov-allowlist.yaml"
        p.write_text(_ALLOWLIST_YAML, encoding="utf-8")
        al = Allowlist.load(p)
        assert any(e.id == "abc123def456" for e in al._entries)

    def test_entry_name_pattern_loaded(self, tmp_path):
        p = tmp_path / ".aigov-allowlist.yaml"
        p.write_text(_ALLOWLIST_YAML, encoding="utf-8")
        al = Allowlist.load(p)
        assert any(e.name_pattern == "internal-*" for e in al._entries)

    def test_entry_reason_loaded(self, tmp_path):
        p = tmp_path / ".aigov-allowlist.yaml"
        p.write_text(_ALLOWLIST_YAML, encoding="utf-8")
        al = Allowlist.load(p)
        reasons = [e.reason for e in al._entries]
        assert "Approved by AI governance board 2026-01-15" in reasons

    def test_malformed_yaml_returns_empty(self, tmp_path):
        p = tmp_path / ".aigov-allowlist.yaml"
        p.write_text(": : : invalid yaml {{{{", encoding="utf-8")
        al = Allowlist.load(p)
        assert al._entries == []

    def test_empty_file_returns_empty(self, tmp_path):
        p = tmp_path / ".aigov-allowlist.yaml"
        p.write_text("", encoding="utf-8")
        al = Allowlist.load(p)
        assert al._entries == []

    def test_auto_discover_uses_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        p = tmp_path / ".aigov-allowlist.yaml"
        p.write_text(_ALLOWLIST_YAML, encoding="utf-8")
        al = Allowlist.load()  # no path arg — should auto-discover
        assert len(al._entries) == 2


# ---------------------------------------------------------------------------
# Allowlist.is_approved()
# ---------------------------------------------------------------------------

class TestIsApproved:
    def test_id_match(self, tmp_path):
        p = tmp_path / "al.yaml"
        p.write_text(_ALLOWLIST_YAML, encoding="utf-8")
        al = Allowlist.load(p)
        rec = _make_record(record_id="abc123def456")
        approved, reason = al.is_approved(rec)
        assert approved is True
        assert "governance board" in reason

    def test_id_no_match(self, tmp_path):
        p = tmp_path / "al.yaml"
        p.write_text(_ALLOWLIST_YAML, encoding="utf-8")
        al = Allowlist.load(p)
        rec = _make_record(record_id="unrelated-id")
        approved, _ = al.is_approved(rec)
        assert approved is False

    def test_name_pattern_glob_match(self, tmp_path):
        p = tmp_path / "al.yaml"
        p.write_text(_NAME_ONLY_YAML, encoding="utf-8")
        al = Allowlist.load(p)
        rec = _make_record(name="test-chatbot")
        approved, reason = al.is_approved(rec)
        assert approved is True
        assert "Test pattern match" in reason

    def test_name_pattern_no_match(self, tmp_path):
        p = tmp_path / "al.yaml"
        p.write_text(_NAME_ONLY_YAML, encoding="utf-8")
        al = Allowlist.load(p)
        rec = _make_record(name="production-llm")
        approved, _ = al.is_approved(rec)
        assert approved is False

    def test_internal_prefix_match(self, tmp_path):
        p = tmp_path / "al.yaml"
        p.write_text(_ALLOWLIST_YAML, encoding="utf-8")
        al = Allowlist.load(p)
        # Use a record_id that does NOT match the id entry so name_pattern is tested
        rec = _make_record(name="internal-chatbot-v2", record_id="unrelated-id-xyz")
        approved, reason = al.is_approved(rec)
        assert approved is True
        assert "AI-2026-003" in reason

    def test_empty_allowlist_approves_nothing(self):
        al = Allowlist([])
        rec = _make_record()
        approved, _ = al.is_approved(rec)
        assert approved is False


# ---------------------------------------------------------------------------
# Allowlist.apply()
# ---------------------------------------------------------------------------

class TestApply:
    def test_approved_record_tagged(self, tmp_path):
        p = tmp_path / "al.yaml"
        p.write_text(_ALLOWLIST_YAML, encoding="utf-8")
        al = Allowlist.load(p)
        rec = _make_record(record_id="abc123def456")
        results = al.apply([rec])
        assert results[0].tags.get("allowlisted") == "true"

    def test_approved_record_has_reason_tag(self, tmp_path):
        p = tmp_path / "al.yaml"
        p.write_text(_ALLOWLIST_YAML, encoding="utf-8")
        al = Allowlist.load(p)
        rec = _make_record(record_id="abc123def456")
        results = al.apply([rec])
        assert "governance board" in results[0].tags.get("allowlist_reason", "")

    def test_unapproved_record_not_tagged(self, tmp_path):
        p = tmp_path / "al.yaml"
        p.write_text(_ALLOWLIST_YAML, encoding="utf-8")
        al = Allowlist.load(p)
        rec = _make_record(record_id="not-in-list")
        results = al.apply([rec])
        assert "allowlisted" not in results[0].tags

    def test_original_record_not_mutated(self, tmp_path):
        p = tmp_path / "al.yaml"
        p.write_text(_ALLOWLIST_YAML, encoding="utf-8")
        al = Allowlist.load(p)
        rec = _make_record(record_id="abc123def456")
        original_tags = dict(rec.tags)
        al.apply([rec])
        assert rec.tags == original_tags  # original unchanged

    def test_mixed_batch(self, tmp_path):
        p = tmp_path / "al.yaml"
        p.write_text(_ALLOWLIST_YAML, encoding="utf-8")
        al = Allowlist.load(p)
        approved = _make_record(record_id="abc123def456", name="approved")
        unapproved = _make_record(record_id="other-id", name="unapproved")
        results = al.apply([approved, unapproved])
        assert results[0].tags.get("allowlisted") == "true"
        assert "allowlisted" not in results[1].tags

    def test_empty_list_returns_empty(self):
        al = Allowlist([])
        assert al.apply([]) == []

    def test_empty_allowlist_returns_records_unchanged(self):
        al = Allowlist([])
        rec = _make_record()
        results = al.apply([rec])
        assert results[0] is rec  # same object, no copy needed


# ---------------------------------------------------------------------------
# Engine integration — classify_results respects the allowlist
# ---------------------------------------------------------------------------

class TestClassifyResultsAllowlist:
    def test_allowlisted_record_tagged_after_classify(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        rec = _make_record(record_id="abc123def456")
        allowlist_file = tmp_path / ".aigov-allowlist.yaml"
        allowlist_file.write_text(_ALLOWLIST_YAML, encoding="utf-8")

        from aigov.core.engine import ScanResult, classify_results
        result = ScanResult(records=[rec], scanners_run=["code.python_imports"])
        result._compute_summaries()
        classified = classify_results(result, ["eu_ai_act"])

        tagged = [r for r in classified.records if r.tags.get("allowlisted") == "true"]
        assert len(tagged) == 1
        assert tagged[0].id == "abc123def456"

    def test_no_allowlist_file_does_not_error(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)  # no .aigov-allowlist.yaml in tmp_path
        rec = _make_record()

        from aigov.core.engine import ScanResult, classify_results
        result = ScanResult(records=[rec], scanners_run=["code.python_imports"])
        result._compute_summaries()
        # Must not raise
        classified = classify_results(result, ["eu_ai_act"])
        assert len(classified.records) == 1
        assert "allowlisted" not in classified.records[0].tags

    def test_unapproved_record_unchanged_after_classify(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        rec = _make_record(record_id="not-in-list")
        allowlist_file = tmp_path / ".aigov-allowlist.yaml"
        allowlist_file.write_text(_ALLOWLIST_YAML, encoding="utf-8")

        from aigov.core.engine import ScanResult, classify_results
        result = ScanResult(records=[rec], scanners_run=["code.python_imports"])
        result._compute_summaries()
        classified = classify_results(result, ["eu_ai_act"])

        assert "allowlisted" not in classified.records[0].tags
