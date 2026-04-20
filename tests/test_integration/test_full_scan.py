"""Integration tests: ScanEngine → all scanners → reporter pipeline."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aigov.core.engine import ScanEngine, ScanResult
from aigov.core.models import AISystemType
from aigov.core.reporter import to_json, to_markdown, print_table
from rich.console import Console

# ---------------------------------------------------------------------------
# Fixture: a minimal project dir that every scanner should hit
# ---------------------------------------------------------------------------

_PYTHON_SRC = """\
import openai
import anthropic
from langchain_openai import ChatOpenAI
from transformers import pipeline

client = openai.OpenAI()
"""

_ENV_SRC = """\
OPENAI_API_KEY=sk-ant-INTFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE
HF_TOKEN=hf_INTfakeFAKEfakeFAKEfakeFAKEfake
"""

_MCP_SRC = """\
{
  "mcpServers": {
    "integration-server": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
      "env": {
        "SECRET_KEY": "FAKE_SECRET_NEVER_REAL"
      }
    }
  }
}
"""

# Values that must never appear verbatim in any output
_SECRETS = [
    "INTFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
    "INTfakeFAKEfakeFAKEfakeFAKEfake",
    "FAKE_SECRET_NEVER_REAL",
]


@pytest.fixture(scope="module")
def project_dir(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("integration_project")
    (d / "app.py").write_text(_PYTHON_SRC, encoding="utf-8")
    (d / ".env").write_text(_ENV_SRC, encoding="utf-8")
    (d / ".mcp.json").write_text(_MCP_SRC, encoding="utf-8")
    return d


@pytest.fixture(scope="module")
def scan_result(project_dir) -> ScanResult:
    engine = ScanEngine(paths=[str(project_dir)])
    return engine.run()


# ---------------------------------------------------------------------------
# Engine basics
# ---------------------------------------------------------------------------

def test_scan_completes(scan_result):
    assert isinstance(scan_result, ScanResult)


def test_duration_is_positive(scan_result):
    assert scan_result.duration_seconds > 0


def test_all_three_scanners_ran(scan_result):
    assert "code.python_imports" in scan_result.scanners_run
    assert "code.api_keys" in scan_result.scanners_run
    assert "config.mcp_servers" in scan_result.scanners_run


def test_records_are_sorted_by_confidence_desc(scan_result):
    confidences = [r.confidence for r in scan_result.records]
    assert confidences == sorted(confidences, reverse=True)


# ---------------------------------------------------------------------------
# Each scanner found something
# ---------------------------------------------------------------------------

def _scanners(result: ScanResult) -> set[str]:
    return {r.source_scanner for r in result.records}


def _providers(result: ScanResult) -> set[str]:
    return {r.provider for r in result.records}


def test_python_imports_scanner_found_results(scan_result):
    assert "code.python_imports" in _scanners(scan_result)


def test_api_keys_scanner_found_results(scan_result):
    assert "code.api_keys" in _scanners(scan_result)


def test_mcp_scanner_found_results(scan_result):
    assert "config.mcp_servers" in _scanners(scan_result)


def test_openai_detected(scan_result):
    assert "OpenAI" in _providers(scan_result)


def test_anthropic_detected(scan_result):
    assert "Anthropic" in _providers(scan_result)


def test_mcp_server_detected(scan_result):
    mcp_recs = [r for r in scan_result.records if r.system_type == AISystemType.MCP_SERVER]
    assert mcp_recs, "Expected at least one MCP server record"


# ---------------------------------------------------------------------------
# Deduplication: stable IDs across two scans of the same project
# ---------------------------------------------------------------------------

def test_stable_ids_across_rescans(project_dir):
    result_a = ScanEngine(paths=[str(project_dir)]).run()
    result_b = ScanEngine(paths=[str(project_dir)]).run()
    ids_a = {r.id for r in result_a.records}
    ids_b = {r.id for r in result_b.records}
    assert ids_a == ids_b, "Record IDs are not stable across rescans"


def test_no_duplicate_ids(scan_result):
    ids = [r.id for r in scan_result.records]
    assert len(ids) == len(set(ids)), "Duplicate record IDs found"


# ---------------------------------------------------------------------------
# Summaries
# ---------------------------------------------------------------------------

def test_total_found_matches_records_length(scan_result):
    assert scan_result.total_found == len(scan_result.records)


def test_by_type_sums_to_total(scan_result):
    assert sum(scan_result.by_type.values()) == scan_result.total_found


def test_by_provider_sums_to_total(scan_result):
    assert sum(scan_result.by_provider.values()) == scan_result.total_found


def test_by_jurisdiction_sums_to_total(scan_result):
    assert sum(scan_result.by_jurisdiction.values()) == scan_result.total_found


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def test_json_output_is_valid(scan_result):
    raw = to_json(scan_result)
    data = json.loads(raw)  # must not raise
    assert "findings" in data
    assert "summary" in data


def test_json_summary_fields(scan_result):
    data = json.loads(to_json(scan_result))
    summary = data["summary"]
    assert "total_found" in summary
    assert "by_type" in summary
    assert "by_provider" in summary
    assert "by_jurisdiction" in summary
    assert "scanners_run" in summary
    assert "scanned_paths" in summary


def test_json_findings_have_required_fields(scan_result):
    data = json.loads(to_json(scan_result))
    required = {"id", "name", "source_scanner", "source_location", "system_type",
                 "provider", "confidence", "discovery_timestamp", "deployment_type"}
    for finding in data["findings"]:
        missing = required - finding.keys()
        assert not missing, f"Finding missing fields: {missing}"


# ---------------------------------------------------------------------------
# CRITICAL: no secret values in any output
# ---------------------------------------------------------------------------

def _all_strings_in_dict(obj) -> list[str]:
    out: list[str] = []

    def _walk(o):
        if isinstance(o, str):
            out.append(o)
        elif isinstance(o, dict):
            for v in o.values():
                _walk(v)
        elif isinstance(o, list):
            for v in o:
                _walk(v)

    _walk(obj)
    return out


def test_no_secrets_in_records(scan_result):
    for rec in scan_result.records:
        strings = _all_strings_in_dict(rec.to_dict())
        for secret in _SECRETS:
            for s in strings:
                assert secret not in s, f"Secret leaked in record for {rec.provider!r}"


def test_no_secrets_in_json_output(scan_result):
    serialised = to_json(scan_result)
    for secret in _SECRETS:
        assert secret not in serialised, f"Secret {secret[:8]!r}... leaked in JSON output"


def test_no_secrets_in_markdown_output(scan_result):
    md = to_markdown(scan_result)
    for secret in _SECRETS:
        assert secret not in md, f"Secret {secret[:8]!r}... leaked in Markdown output"


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------

def test_markdown_has_summary_section(scan_result):
    md = to_markdown(scan_result)
    assert "## Summary" in md


def test_markdown_has_findings_section(scan_result):
    md = to_markdown(scan_result)
    assert "## Findings" in md


def test_markdown_shows_total_count(scan_result):
    md = to_markdown(scan_result)
    assert str(scan_result.total_found) in md


# ---------------------------------------------------------------------------
# Rich table (smoke test — just ensure it doesn't raise)
# ---------------------------------------------------------------------------

def test_print_table_does_not_raise(scan_result):
    import io
    buf_console = Console(file=io.StringIO(), highlight=False)
    print_table(scan_result, console=buf_console)


# ---------------------------------------------------------------------------
# Selective scanner execution
# ---------------------------------------------------------------------------

def test_run_single_scanner(project_dir):
    result = ScanEngine(
        paths=[str(project_dir)],
        enabled_scanners=["code.python_imports"],
    ).run()
    assert result.scanners_run == ["code.python_imports"]
    assert all(r.source_scanner == "code.python_imports" for r in result.records)


def test_unknown_scanner_raises(project_dir):
    with pytest.raises(ValueError, match="Unknown scanner"):
        ScanEngine(paths=[str(project_dir)], enabled_scanners=["nonexistent.scanner"])


# ---------------------------------------------------------------------------
# Empty project — no false positives
# ---------------------------------------------------------------------------

def test_empty_project_returns_no_records(tmp_path):
    (tmp_path / "hello.py").write_text("print('hello world')\n", encoding="utf-8")
    result = ScanEngine(paths=[str(tmp_path)]).run()
    assert result.records == []
    assert result.total_found == 0
