"""Integration tests: scan → classify pipeline."""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from rich.console import Console

from aigov.core.engine import ScanEngine, ScanResult, classify_results
from aigov.core.models import AISystemRecord, RiskLevel
from aigov.core.reporter import print_risk_summary, print_table, to_json, to_markdown


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# resume_screener.py: the file path normalizes to "resume screener" which is an
# annex_iii_4 keyword, and OpenAI appears in annex_iii_4 cloud_services —
# together they provide 2 signal hits, triggering HIGH_RISK Employment.
_RESUME_SCREENER_SRC = "import openai\n"

# chatbot.py: the file path provides the "chatbot" keyword for transparency_1
# and "anthropic" matches its library_patterns → 2 signal hits → LIMITED_RISK.
_CHATBOT_SRC = "import anthropic\n"

# A plain data pipeline — no AI risk signals.
_PIPELINE_SRC = "import pandas as pd\nimport numpy as np\n"


@pytest.fixture(scope="module")
def project_dir(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("scan_classify_project")
    (d / "resume_screener.py").write_text(_RESUME_SCREENER_SRC, encoding="utf-8")
    (d / "chatbot.py").write_text(_CHATBOT_SRC, encoding="utf-8")
    (d / "pipeline.py").write_text(_PIPELINE_SRC, encoding="utf-8")
    return d


@pytest.fixture(scope="module")
def scan_result(project_dir) -> ScanResult:
    return ScanEngine(paths=[str(project_dir)], enabled_scanners=["code.python_imports"]).run()


@pytest.fixture(scope="module")
def classified_result(scan_result) -> ScanResult:
    return classify_results(scan_result, ["eu_ai_act"])


# ---------------------------------------------------------------------------
# Scan basics (pre-classification)
# ---------------------------------------------------------------------------

def test_scan_detects_openai(scan_result):
    providers = {r.provider for r in scan_result.records}
    assert "OpenAI" in providers


def test_scan_detects_anthropic(scan_result):
    providers = {r.provider for r in scan_result.records}
    assert "Anthropic" in providers


def test_scan_does_not_detect_pandas_as_ai(scan_result):
    # pandas is a data-processing library, not an AI system
    providers = {r.provider for r in scan_result.records}
    assert "pandas" not in providers


# ---------------------------------------------------------------------------
# Classification outcomes
# ---------------------------------------------------------------------------

def _records_from_file(result: ScanResult, stem: str) -> list[AISystemRecord]:
    """Return records whose source_location contains the given file stem."""
    return [
        r for r in result.records
        if stem in r.source_location
    ]


def test_resume_screener_classified_high_risk_employment(classified_result):
    recs = _records_from_file(classified_result, "resume_screener")
    assert recs, "Expected at least one record from resume_screener.py"
    rec = recs[0]
    assert rec.risk_classification == RiskLevel.HIGH_RISK, (
        f"Expected HIGH_RISK, got {rec.risk_classification}. "
        f"Rationale: {rec.classification_rationale}"
    )
    assert "Employment" in (rec.classification_rationale or ""), (
        f"Expected 'Employment' in rationale: {rec.classification_rationale}"
    )


def test_chatbot_classified_limited_risk_transparency(classified_result):
    recs = _records_from_file(classified_result, "chatbot")
    assert recs, "Expected at least one record from chatbot.py"
    rec = recs[0]
    assert rec.risk_classification == RiskLevel.LIMITED_RISK, (
        f"Expected LIMITED_RISK, got {rec.risk_classification}. "
        f"Rationale: {rec.classification_rationale}"
    )


def test_all_records_have_rationale(classified_result):
    for rec in classified_result.records:
        assert rec.classification_rationale, (
            f"Record {rec.name!r} has no classification_rationale"
        )
        assert len(rec.classification_rationale) > 20


def test_all_records_have_confidence_adjustment_tag(classified_result):
    for rec in classified_result.records:
        assert "confidence_adjustment" in rec.tags, (
            f"Record {rec.name!r} missing confidence_adjustment tag"
        )
        assert rec.tags["confidence_adjustment"] in {"high", "medium", "low"}


def test_classify_results_does_not_mutate_originals(scan_result):
    # Every original record should still have UNKNOWN risk after classification
    for rec in scan_result.records:
        assert rec.risk_classification == RiskLevel.UNKNOWN, (
            f"Original record {rec.name!r} was mutated to {rec.risk_classification}"
        )


# ---------------------------------------------------------------------------
# Risk summary output
# ---------------------------------------------------------------------------

def test_print_risk_summary_does_not_raise(classified_result):
    buf = Console(file=io.StringIO(), highlight=False)
    print_risk_summary(classified_result, console=buf)


def test_risk_summary_not_printed_for_unclassified(scan_result):
    buf = io.StringIO()
    con = Console(file=buf, highlight=False)
    print_risk_summary(scan_result, console=con)
    assert buf.getvalue() == "", "Risk summary should be empty for unclassified results"


# ---------------------------------------------------------------------------
# Reporter integration
# ---------------------------------------------------------------------------

def test_print_table_with_classification_does_not_raise(classified_result):
    buf = Console(file=io.StringIO(), highlight=False)
    print_table(classified_result, console=buf)


def test_json_output_includes_classification_rationale(classified_result):
    raw = json.loads(to_json(classified_result))
    for finding in raw["findings"]:
        assert "risk_classification" in finding
        assert "classification_rationale" in finding
        assert finding["classification_rationale"] is not None


def test_markdown_output_includes_risk_section(classified_result):
    md = to_markdown(classified_result)
    assert "Risk Classification" in md
    assert "HIGH RISK" in md or "LIMITED RISK" in md


# ---------------------------------------------------------------------------
# Supported frameworks validation
# ---------------------------------------------------------------------------

def test_unknown_framework_raises(scan_result):
    with pytest.raises(ValueError, match="Unknown framework"):
        classify_results(scan_result, ["nonexistent_framework"])


def test_eu_ai_act_is_supported(scan_result):
    result = classify_results(scan_result, ["eu_ai_act"])
    assert isinstance(result, ScanResult)


# ---------------------------------------------------------------------------
# JSON round-trip: save scan → load → classify
# ---------------------------------------------------------------------------

def test_json_roundtrip_classify(tmp_path, scan_result):
    from aigov.core.models import AISystemRecord

    # Serialize the unclassified scan
    serialised = to_json(scan_result)
    raw = json.loads(serialised)

    # Reconstruct records from JSON
    records = [AISystemRecord.from_dict(f) for f in raw["findings"]]
    assert len(records) == len(scan_result.records)

    # Re-classify the reconstructed records
    from aigov.core.engine import ScanResult
    reloaded = ScanResult(
        records=records,
        scanners_run=raw["summary"]["scanners_run"],
        scanned_paths=raw["summary"]["scanned_paths"],
        duration_seconds=raw["summary"]["duration_seconds"],
    )
    reloaded._compute_summaries()

    classified = classify_results(reloaded, ["eu_ai_act"])
    resume_recs = _records_from_file(classified, "resume_screener")
    assert resume_recs
    assert resume_recs[0].risk_classification == RiskLevel.HIGH_RISK
