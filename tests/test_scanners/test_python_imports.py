from __future__ import annotations

from pathlib import Path

import pytest

from aigov.core.models import AISystemType, DeploymentType
from aigov.scanners.code.python_imports import PythonImportsScanner

_FIXTURE_SRC = Path(__file__).parent.parent / "fixtures" / "sample_ai_app.py"


@pytest.fixture(scope="module")
def records(tmp_path_factory):
    # Copy to a neutral dir so the scanner doesn't skip it
    # (scanner now skips paths whose components are in {"fixtures", "tests", ...}).
    tmp = tmp_path_factory.mktemp("py_imports_scan")
    f = tmp / "sample_ai_app.py"
    f.write_text(_FIXTURE_SRC.read_text(encoding="utf-8"), encoding="utf-8")
    return PythonImportsScanner().scan([str(f)])


def _providers(recs) -> set[str]:
    return {r.provider for r in recs}


# --- Basic scanner metadata ---

def test_scanner_name():
    assert PythonImportsScanner().name == "code.python_imports"


def test_scanner_does_not_require_credentials():
    assert PythonImportsScanner().requires_credentials is False


# --- Fixture detection ---

def test_finds_openai(records):
    assert "OpenAI" in _providers(records)


def test_finds_langchain(records):
    assert "LangChain" in _providers(records)


def test_finds_huggingface(records):
    assert "HuggingFace" in _providers(records)


def test_finds_deepseek(records):
    assert "DeepSeek" in _providers(records)


def test_finds_alibaba(records):
    assert "Alibaba (Qwen/Tongyi)" in _providers(records)


# --- System type classification ---

def test_openai_is_api_service(records):
    openai_recs = [r for r in records if r.provider == "OpenAI"]
    assert all(r.system_type == AISystemType.API_SERVICE for r in openai_recs)


def test_langchain_is_agent(records):
    lc_recs = [r for r in records if r.provider == "LangChain"]
    assert all(r.system_type == AISystemType.AGENT for r in lc_recs)


def test_huggingface_is_model(records):
    hf_recs = [r for r in records if r.provider == "HuggingFace"]
    assert all(r.system_type == AISystemType.MODEL for r in hf_recs)


# --- Deployment type ---

def test_openai_is_cloud_api(records):
    openai_recs = [r for r in records if r.provider == "OpenAI"]
    assert all(r.deployment_type == DeploymentType.CLOUD_API for r in openai_recs)


def test_huggingface_is_self_hosted(records):
    hf_recs = [r for r in records if r.provider == "HuggingFace"]
    assert all(r.deployment_type == DeploymentType.SELF_HOSTED for r in hf_recs)


# --- Jurisdiction tagging (origin_jurisdiction uses ISO 3166-1 alpha-2) ---

def test_all_records_have_origin_jurisdiction(records):
    for rec in records:
        assert "origin_jurisdiction" in rec.tags, f"{rec.provider} missing origin_jurisdiction tag"
        assert len(rec.tags["origin_jurisdiction"]) == 2, (
            f"{rec.provider} jurisdiction should be a 2-letter ISO code, got {rec.tags['origin_jurisdiction']!r}"
        )


def test_openai_tagged_us(records):
    openai_recs = [r for r in records if r.provider == "OpenAI"]
    assert openai_recs, "OpenAI record not found"
    assert all(r.tags["origin_jurisdiction"] == "US" for r in openai_recs)


def test_deepseek_tagged_cn(records):
    ds_recs = [r for r in records if r.provider == "DeepSeek"]
    assert ds_recs, "DeepSeek record not found"
    assert all(r.tags["origin_jurisdiction"] == "CN" for r in ds_recs)


def test_alibaba_tagged_cn(records):
    ali_recs = [r for r in records if r.provider == "Alibaba (Qwen/Tongyi)"]
    assert ali_recs, "Alibaba record not found"
    assert all(r.tags["origin_jurisdiction"] == "CN" for r in ali_recs)


@pytest.mark.parametrize("import_line,provider,expected_jurisdiction", [
    ("import mistralai\n", "Mistral", "FR"),
    ("import cohere\n", "Cohere", "CA"),
    ("import anthropic\n", "Anthropic", "US"),
    ("import zhipuai\n", "Zhipu AI (GLM/ChatGLM)", "CN"),
    ("import qianfan\n", "Baidu (ERNIE/Wenxin)", "CN"),
    ("import volcengine\n", "ByteDance (Doubao/Skylark)", "CN"),
    ("import moonshot\n", "Moonshot AI (Kimi)", "CN"),
    ("import sensenova\n", "SenseTime", "CN"),
])
def test_jurisdiction_per_provider(tmp_path, import_line, provider, expected_jurisdiction):
    f = tmp_path / "app.py"
    f.write_text(import_line, encoding="utf-8")
    recs = PythonImportsScanner().scan([str(f)])
    matching = [r for r in recs if r.provider == provider]
    assert matching, f"No record found for provider {provider!r}"
    assert matching[0].tags["origin_jurisdiction"] == expected_jurisdiction


# --- Confidence ---

def test_confidence_is_0_85(records):
    assert all(r.confidence == 0.85 for r in records)


# --- Source location includes file path and line number ---

def test_source_location_format(records):
    for rec in records:
        assert ":" in rec.source_location, f"Expected 'path:line' format, got: {rec.source_location}"
        path_part, line_part = rec.source_location.rsplit(":", 1)
        assert int(line_part) > 0
        assert path_part.endswith(".py")


# --- Deduplication: same provider found via multiple imports → one record ---

def test_langchain_deduplicated(records):
    lc_recs = [r for r in records if r.provider == "LangChain"]
    assert len(lc_recs) == 1, f"Expected 1 LangChain record (deduplicated), got {len(lc_recs)}"


# --- Graceful error handling on unparseable files ---

def test_skips_syntax_error_files(tmp_path):
    bad_file = tmp_path / "bad.py"
    bad_file.write_text("def broken(\n", encoding="utf-8")
    scanner = PythonImportsScanner()
    result = scanner.scan([str(bad_file)])
    assert result == []


# --- Ignore directories ---

def test_skips_venv_directory(tmp_path):
    venv_dir = tmp_path / ".venv" / "lib"
    venv_dir.mkdir(parents=True)
    ai_file = venv_dir / "openai_usage.py"
    ai_file.write_text("import openai\n", encoding="utf-8")
    scanner = PythonImportsScanner()
    result = scanner.scan([str(tmp_path)])
    assert not any(r.provider == "OpenAI" for r in result)


# --- to_dict serialisation ---

def test_to_dict_is_json_safe(records):
    import json
    for rec in records:
        d = rec.to_dict()
        json.dumps(d)  # must not raise
