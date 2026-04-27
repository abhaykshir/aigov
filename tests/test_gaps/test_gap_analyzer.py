from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

from aigov.core.gaps import GapAnalyzer, GapReport, _EU_AI_ACT_DEADLINE
from aigov.core.models import (
    AISystemRecord,
    AISystemType,
    DeploymentType,
    RiskLevel,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_record(
    risk: RiskLevel,
    name: str = "Test System",
    record_id: str = "test-id",
) -> AISystemRecord:
    return AISystemRecord(
        id=record_id,
        name=name,
        description=f"A test AI system classified as {risk.value}",
        source_scanner="test.scanner",
        source_location="src/test.py:1",
        discovery_timestamp=datetime.now(timezone.utc),
        confidence=0.9,
        system_type=AISystemType.MODEL,
        provider="TestProvider",
        deployment_type=DeploymentType.CLOUD_API,
        risk_classification=risk,
    )


@pytest.fixture
def analyzer() -> GapAnalyzer:
    return GapAnalyzer()


@pytest.fixture
def high_risk_record() -> AISystemRecord:
    return _make_record(RiskLevel.HIGH_RISK, name="Resume Screener", record_id="hr-1")


@pytest.fixture
def limited_risk_record() -> AISystemRecord:
    return _make_record(RiskLevel.LIMITED_RISK, name="Customer Chatbot", record_id="lr-1")


@pytest.fixture
def minimal_risk_record() -> AISystemRecord:
    return _make_record(RiskLevel.MINIMAL_RISK, name="Spam Filter", record_id="mr-1")


@pytest.fixture
def prohibited_record() -> AISystemRecord:
    return _make_record(RiskLevel.PROHIBITED, name="Social Scoring System", record_id="pb-1")


# ---------------------------------------------------------------------------
# HIGH_RISK: 9 gaps, critical priority, 120h effort
# ---------------------------------------------------------------------------

class TestHighRisk:
    def test_gap_count(self, analyzer, high_risk_record):
        report = analyzer.analyze([high_risk_record])
        analysis = report.systems[0]
        assert len(analysis.gaps) == 9

    def test_priority_is_critical(self, analyzer, high_risk_record):
        report = analyzer.analyze([high_risk_record])
        assert report.systems[0].priority == "critical"

    def test_effort_in_range(self, analyzer, high_risk_record):
        report = analyzer.analyze([high_risk_record])
        effort = report.systems[0].estimated_effort_hours
        assert 120 <= effort <= 160

    def test_article_references(self, analyzer, high_risk_record):
        report = analyzer.analyze([high_risk_record])
        articles = {g.article_reference for g in report.systems[0].gaps}
        assert "Article 9" in articles
        assert "Article 10" in articles
        assert "Article 11" in articles
        assert "Article 12" in articles
        assert "Article 13" in articles
        assert "Article 14" in articles
        assert "Article 15" in articles
        assert "Article 43" in articles
        assert "Article 49" in articles

    def test_gap_statuses_are_valid(self, analyzer, high_risk_record):
        report = analyzer.analyze([high_risk_record])
        valid_statuses = {"missing", "partial", "unknown"}
        for gap in report.systems[0].gaps:
            assert gap.status in valid_statuses

    def test_remediation_steps_non_empty(self, analyzer, high_risk_record):
        report = analyzer.analyze([high_risk_record])
        for gap in report.systems[0].gaps:
            assert len(gap.remediation_steps) > 0

    def test_gaps_are_independent_instances(self, analyzer, high_risk_record):
        # Calling analyze twice should produce independent gap objects
        report1 = analyzer.analyze([high_risk_record])
        report2 = analyzer.analyze([high_risk_record])
        assert report1.systems[0].gaps is not report2.systems[0].gaps
        assert report1.systems[0].gaps[0] is not report2.systems[0].gaps[0]


# ---------------------------------------------------------------------------
# LIMITED_RISK: 2 gaps, medium priority, 8h effort
# ---------------------------------------------------------------------------

class TestLimitedRisk:
    def test_gap_count(self, analyzer, limited_risk_record):
        report = analyzer.analyze([limited_risk_record])
        analysis = report.systems[0]
        assert 1 <= len(analysis.gaps) <= 2

    def test_exactly_two_gaps(self, analyzer, limited_risk_record):
        report = analyzer.analyze([limited_risk_record])
        assert len(report.systems[0].gaps) == 2

    def test_priority_is_medium(self, analyzer, limited_risk_record):
        report = analyzer.analyze([limited_risk_record])
        assert report.systems[0].priority == "medium"

    def test_effort_in_range(self, analyzer, limited_risk_record):
        report = analyzer.analyze([limited_risk_record])
        effort = report.systems[0].estimated_effort_hours
        assert 8 <= effort <= 16

    def test_article_50_referenced(self, analyzer, limited_risk_record):
        report = analyzer.analyze([limited_risk_record])
        articles = {g.article_reference for g in report.systems[0].gaps}
        assert "Article 50" in articles

    def test_status_is_unknown(self, analyzer, limited_risk_record):
        report = analyzer.analyze([limited_risk_record])
        for gap in report.systems[0].gaps:
            assert gap.status == "unknown"


# ---------------------------------------------------------------------------
# MINIMAL_RISK: 0 gaps, low priority, 0h effort
# ---------------------------------------------------------------------------

class TestMinimalRisk:
    def test_no_gaps(self, analyzer, minimal_risk_record):
        report = analyzer.analyze([minimal_risk_record])
        assert len(report.systems[0].gaps) == 0

    def test_priority_is_low(self, analyzer, minimal_risk_record):
        report = analyzer.analyze([minimal_risk_record])
        assert report.systems[0].priority == "low"

    def test_zero_effort(self, analyzer, minimal_risk_record):
        report = analyzer.analyze([minimal_risk_record])
        assert report.systems[0].estimated_effort_hours == 0


# ---------------------------------------------------------------------------
# PROHIBITED: 1 gap, immediate cessation, critical, 0h effort
# ---------------------------------------------------------------------------

class TestProhibited:
    def test_exactly_one_gap(self, analyzer, prohibited_record):
        report = analyzer.analyze([prohibited_record])
        assert len(report.systems[0].gaps) == 1

    def test_gap_is_immediate_cessation(self, analyzer, prohibited_record):
        report = analyzer.analyze([prohibited_record])
        gap = report.systems[0].gaps[0]
        assert "cessation" in gap.requirement_name.lower() or "cessation" in gap.description.lower()

    def test_article_5_referenced(self, analyzer, prohibited_record):
        report = analyzer.analyze([prohibited_record])
        gap = report.systems[0].gaps[0]
        assert gap.article_reference == "Article 5"

    def test_priority_is_critical(self, analyzer, prohibited_record):
        report = analyzer.analyze([prohibited_record])
        assert report.systems[0].priority == "critical"

    def test_zero_effort(self, analyzer, prohibited_record):
        report = analyzer.analyze([prohibited_record])
        assert report.systems[0].estimated_effort_hours == 0

    def test_status_is_missing(self, analyzer, prohibited_record):
        report = analyzer.analyze([prohibited_record])
        assert report.systems[0].gaps[0].status == "missing"


# ---------------------------------------------------------------------------
# UNKNOWN / NEEDS_REVIEW: treated as minimal (no actionable gaps)
# ---------------------------------------------------------------------------

class TestUnknownRisk:
    def test_unknown_gets_no_gaps(self, analyzer):
        record = _make_record(RiskLevel.UNKNOWN, record_id="unk-1")
        report = analyzer.analyze([record])
        assert len(report.systems[0].gaps) == 0

    def test_needs_review_gets_no_gaps(self, analyzer):
        record = _make_record(RiskLevel.NEEDS_REVIEW, record_id="nr-1")
        report = analyzer.analyze([record])
        assert len(report.systems[0].gaps) == 0


# ---------------------------------------------------------------------------
# Overall summary calculations
# ---------------------------------------------------------------------------

class TestOverallSummary:
    def test_total_systems(self, analyzer, high_risk_record, limited_risk_record, minimal_risk_record):
        report = analyzer.analyze([high_risk_record, limited_risk_record, minimal_risk_record])
        assert report.overall_summary["total_systems"] == 3

    def test_total_gaps_calculation(self, analyzer, high_risk_record, limited_risk_record, minimal_risk_record):
        report = analyzer.analyze([high_risk_record, limited_risk_record, minimal_risk_record])
        # 9 (high) + 2 (limited) + 0 (minimal) = 11
        assert report.overall_summary["total_gaps"] == 11

    def test_effort_range_calculation(self, analyzer, high_risk_record, limited_risk_record):
        report = analyzer.analyze([high_risk_record, limited_risk_record])
        # 1 HIGH_RISK: 120-160h, 1 LIMITED_RISK: 8-16h
        assert report.overall_summary["estimated_effort_min_hours"] == 128  # 120+8
        assert report.overall_summary["estimated_effort_max_hours"] == 176  # 160+16

    def test_effort_zero_when_no_regulated_systems(self, analyzer, minimal_risk_record):
        report = analyzer.analyze([minimal_risk_record])
        assert report.overall_summary["estimated_effort_min_hours"] == 0
        assert report.overall_summary["estimated_effort_max_hours"] == 0

    def test_systems_by_risk_counts(self, analyzer, high_risk_record, limited_risk_record, minimal_risk_record):
        report = analyzer.analyze([high_risk_record, limited_risk_record, minimal_risk_record])
        by_risk = report.overall_summary["systems_by_risk"]
        assert by_risk.get("high_risk", 0) == 1
        assert by_risk.get("limited_risk", 0) == 1
        assert by_risk.get("minimal_risk", 0) == 1

    def test_deadline_field(self, analyzer, minimal_risk_record):
        report = analyzer.analyze([minimal_risk_record])
        assert report.deadline == _EU_AI_ACT_DEADLINE
        assert report.overall_summary["deadline"] == "2026-08-02"

    def test_days_until_deadline_positive_before_cutoff(self, analyzer, minimal_risk_record):
        report = analyzer.analyze([minimal_risk_record])
        days = report.overall_summary["days_until_deadline"]
        # As of April 2026, the deadline is still in the future
        assert days > 0

    def test_days_until_deadline_calculation(self, analyzer, minimal_risk_record):
        report = analyzer.analyze([minimal_risk_record])
        expected = (_EU_AI_ACT_DEADLINE - date.today()).days
        assert report.overall_summary["days_until_deadline"] == expected

    def test_empty_records(self, analyzer):
        report = analyzer.analyze([])
        assert report.overall_summary["total_systems"] == 0
        assert report.overall_summary["total_gaps"] == 0
        assert report.overall_summary["estimated_effort_min_hours"] == 0
        assert report.overall_summary["estimated_effort_max_hours"] == 0
        assert len(report.systems) == 0

    def test_multiple_high_risk_systems(self, analyzer):
        records = [
            _make_record(RiskLevel.HIGH_RISK, name=f"HR System {i}", record_id=f"hr-{i}")
            for i in range(3)
        ]
        report = analyzer.analyze(records)
        assert report.overall_summary["total_gaps"] == 27  # 3 * 9
        assert report.overall_summary["estimated_effort_min_hours"] == 360  # 3 * 120
        assert report.overall_summary["estimated_effort_max_hours"] == 480  # 3 * 160


# ---------------------------------------------------------------------------
# GapReport structure
# ---------------------------------------------------------------------------

class TestGapReportStructure:
    def test_one_system_analysis_per_record(self, analyzer, high_risk_record, limited_risk_record):
        report = analyzer.analyze([high_risk_record, limited_risk_record])
        assert len(report.systems) == 2

    def test_record_references_preserved(self, analyzer, high_risk_record):
        report = analyzer.analyze([high_risk_record])
        assert report.systems[0].record is high_risk_record

    def test_gap_report_has_deadline(self, analyzer, minimal_risk_record):
        report = analyzer.analyze([minimal_risk_record])
        assert isinstance(report.deadline, date)
        assert report.deadline == date(2026, 8, 2)

    def test_requirement_names_are_unique_per_system(self, analyzer, high_risk_record):
        report = analyzer.analyze([high_risk_record])
        names = [g.requirement_name for g in report.systems[0].gaps]
        assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# Disclaimer in gap report markdown output
# ---------------------------------------------------------------------------

class TestGapReportDisclaimer:
    def test_markdown_includes_legal_disclaimer(self, analyzer, high_risk_record):
        from aigov.core.reporter import gap_report_to_markdown
        report = analyzer.analyze([high_risk_record])
        md = gap_report_to_markdown(report)
        assert "not legal advice" in md.lower()
        assert "automated signal" in md.lower() or "pattern matching" in md.lower()
