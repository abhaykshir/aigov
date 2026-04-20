from __future__ import annotations

import json
from pathlib import Path

import pytest

from aigov.core.models import AISystemType, DeploymentType
from aigov.scanners.code.api_keys import ApiKeysScanner, _redact

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures"
FIXTURE_PY = FIXTURE_DIR / "fake_keys_app.py"
FIXTURE_ENV = FIXTURE_DIR / "fake_keys.env"

# The actual fake key values present in the fixture files.
# We verify NONE of these appear verbatim in any record.
_REAL_KEY_FRAGMENTS = [
    "sk-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
    "sk-proj-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
    "sk-ant-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
    "hf_FAKEfakeFAKEfakeFAKEfakeFAKEfake",
    "co-FAKEfakeFAKEfakeFAKEfakeFAKEfake",
    "r8_FAKEfakeFAKEfakeFAKEfakeFAKEfake",
    "AIzaFAKE123FAKE456FAKE789FAKE012FAKE345",
    "sk-FAKEfakeFAKEfakeFAKEfakeFAKEfakeXXXX",
]


@pytest.fixture(scope="module")
def py_records(tmp_path_factory):
    # Copy to a neutral tmp dir so the scanner doesn't skip it
    # (scanner skips paths whose components are in {"tests", "fixtures", ...}).
    tmp = tmp_path_factory.mktemp("api_keys_py")
    f = tmp / "fake_keys_app.py"
    f.write_text(FIXTURE_PY.read_text(encoding="utf-8"), encoding="utf-8")
    return ApiKeysScanner().scan([str(f)])


@pytest.fixture(scope="module")
def env_records(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("api_keys_env")
    f = tmp / "fake_keys.env"
    f.write_text(FIXTURE_ENV.read_text(encoding="utf-8"), encoding="utf-8")
    return ApiKeysScanner().scan([str(f)])


def _all_string_values(rec) -> list[str]:
    """Collect every string value from a record to check for key leakage."""
    d = rec.to_dict()
    strings = []

    def _walk(obj):
        if isinstance(obj, str):
            strings.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for v in obj:
                _walk(v)

    _walk(d)
    return strings


# ---------------------------------------------------------------------------
# Scanner metadata
# ---------------------------------------------------------------------------

def test_scanner_name():
    assert ApiKeysScanner().name == "code.api_keys"


def test_scanner_does_not_require_credentials():
    assert ApiKeysScanner().requires_credentials is False


# ---------------------------------------------------------------------------
# Detection — .py fixture
# ---------------------------------------------------------------------------

def _providers(recs) -> set[str]:
    return {r.provider for r in recs}


def test_detects_openai_key(py_records):
    assert "OpenAI" in _providers(py_records)


def test_detects_anthropic_key(py_records):
    assert "Anthropic" in _providers(py_records)


def test_detects_huggingface_token(py_records):
    assert "HuggingFace" in _providers(py_records)


def test_detects_cohere_key(py_records):
    assert "Cohere" in _providers(py_records)


def test_detects_replicate_token(py_records):
    assert "Replicate" in _providers(py_records)


def test_detects_google_api_key(py_records):
    assert "Google" in _providers(py_records)


def test_detects_azure_endpoint(py_records):
    assert "Azure" in _providers(py_records)


def test_detects_deepseek_key(py_records):
    assert "DeepSeek" in _providers(py_records)


# ---------------------------------------------------------------------------
# Detection — .env fixture
# ---------------------------------------------------------------------------

def test_env_file_scanned(env_records):
    assert len(env_records) > 0, ".env file produced no records"


def test_env_detects_openai(env_records):
    assert "OpenAI" in _providers(env_records)


def test_env_detects_anthropic(env_records):
    assert "Anthropic" in _providers(env_records)


# ---------------------------------------------------------------------------
# CRITICAL: No actual key value must appear anywhere in a record
# ---------------------------------------------------------------------------

def test_no_raw_key_in_any_field_py(py_records):
    for rec in py_records:
        all_strings = _all_string_values(rec)
        for fragment in _REAL_KEY_FRAGMENTS:
            for s in all_strings:
                assert fragment not in s, (
                    f"Raw key fragment {fragment[:8]!r}... leaked into record field for {rec.provider}"
                )


def test_no_raw_key_in_any_field_env(env_records):
    for rec in env_records:
        all_strings = _all_string_values(rec)
        for fragment in _REAL_KEY_FRAGMENTS:
            for s in all_strings:
                assert fragment not in s, (
                    f"Raw key fragment {fragment[:8]!r}... leaked into record field for {rec.provider}"
                )


def test_no_raw_key_in_json_serialisation(py_records):
    serialised = json.dumps([r.to_dict() for r in py_records])
    for fragment in _REAL_KEY_FRAGMENTS:
        assert fragment not in serialised, (
            f"Raw key fragment {fragment[:8]!r}... found in JSON output"
        )


# ---------------------------------------------------------------------------
# Redaction format
# ---------------------------------------------------------------------------

def test_key_preview_format(py_records):
    for rec in py_records:
        preview = rec.tags.get("key_preview", "")
        assert preview, f"Missing key_preview tag for {rec.provider}"
        assert "****" in preview, f"key_preview should contain **** for {rec.provider}: {preview!r}"
        assert len(preview) <= 12, f"key_preview too long for {rec.provider}: {preview!r}"


def test_redact_helper_keeps_first_four():
    assert _redact("sk-ant-api03-abcdef") == "sk-a****"
    assert _redact("hf_abcdefghij") == "hf_a****"
    assert _redact("AIzaXXX") == "AIza****"


def test_redact_helper_short_value():
    # Values shorter than 4 chars should still not crash.
    result = _redact("ab")
    assert "****" in result


# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------

def test_strong_patterns_have_high_confidence(py_records):
    strong = [r for r in py_records if r.provider in {"Anthropic", "HuggingFace", "Cohere", "Replicate"}]
    assert strong, "Expected strong-pattern records"
    assert all(r.confidence == 0.95 for r in strong)


def test_deepseek_contextual_confidence(py_records):
    ds = [r for r in py_records if r.provider == "DeepSeek"]
    assert ds, "DeepSeek record not found"
    assert all(r.confidence == 0.7 for r in ds)


# ---------------------------------------------------------------------------
# Jurisdiction tags
# ---------------------------------------------------------------------------

def test_all_records_have_jurisdiction(py_records):
    for rec in py_records:
        assert "origin_jurisdiction" in rec.tags, f"{rec.provider} missing origin_jurisdiction"


def test_deepseek_jurisdiction_cn(py_records):
    ds = [r for r in py_records if r.provider == "DeepSeek"]
    assert all(r.tags["origin_jurisdiction"] == "CN" for r in ds)


def test_anthropic_jurisdiction_us(py_records):
    ant = [r for r in py_records if r.provider == "Anthropic"]
    assert all(r.tags["origin_jurisdiction"] == "US" for r in ant)


# ---------------------------------------------------------------------------
# Source location
# ---------------------------------------------------------------------------

def test_source_location_includes_line_number(py_records):
    for rec in py_records:
        assert ":" in rec.source_location
        _, line = rec.source_location.rsplit(":", 1)
        assert int(line) > 0


# ---------------------------------------------------------------------------
# File type filtering
# ---------------------------------------------------------------------------

def test_skips_unsupported_extension(tmp_path):
    f = tmp_path / "data.csv"
    f.write_text("sk-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n", encoding="utf-8")
    assert ApiKeysScanner().scan([str(f)]) == []


def test_scans_yaml_file(tmp_path):
    f = tmp_path / "config.yaml"
    f.write_text('api_key: "sk-ant-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"\n', encoding="utf-8")
    recs = ApiKeysScanner().scan([str(f)])
    assert any(r.provider == "Anthropic" for r in recs)


def test_scans_json_file(tmp_path):
    f = tmp_path / "config.json"
    f.write_text('{"hf_token": "hf_FAKEfakeFAKEfakeFAKEfakeFAKEfake"}\n', encoding="utf-8")
    recs = ApiKeysScanner().scan([str(f)])
    assert any(r.provider == "HuggingFace" for r in recs)


def test_scans_docker_compose(tmp_path):
    f = tmp_path / "docker-compose.yml"
    f.write_text("COHERE_KEY: co-FAKEfakeFAKEfakeFAKEfakeFAKEfake\n", encoding="utf-8")
    recs = ApiKeysScanner().scan([str(f)])
    assert any(r.provider == "Cohere" for r in recs)


# ---------------------------------------------------------------------------
# Binary file skipping
# ---------------------------------------------------------------------------

def test_skips_binary_file(tmp_path):
    f = tmp_path / "model.bin"
    f.write_bytes(b"\x00\x01\x02" + b"sk-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE")
    # Even if we force the extension to .py it should be skipped due to null bytes
    b = tmp_path / "binary.py"
    b.write_bytes(b"\x00\x01sk-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE")
    recs = ApiKeysScanner().scan([str(tmp_path)])
    assert recs == []


# ---------------------------------------------------------------------------
# Ignore directories
# ---------------------------------------------------------------------------

def test_skips_venv_directory(tmp_path):
    d = tmp_path / ".venv" / "lib"
    d.mkdir(parents=True)
    f = d / "config.py"
    f.write_text("sk-ant-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n", encoding="utf-8")
    assert ApiKeysScanner().scan([str(tmp_path)]) == []


def test_skips_paths_with_test_component(tmp_path):
    # "tests" is an exact component → should be skipped.
    d = tmp_path / "tests"
    d.mkdir()
    f = d / "config.env"
    f.write_text("OPENAI_API_KEY=sk-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n", encoding="utf-8")
    assert ApiKeysScanner().scan([str(tmp_path)]) == []


def test_skips_paths_with_fixture_component(tmp_path):
    # "fixtures" is an exact component → should be skipped.
    d = tmp_path / "fixtures"
    d.mkdir()
    f = d / "config.env"
    f.write_text("OPENAI_API_KEY=sk-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n", encoding="utf-8")
    assert ApiKeysScanner().scan([str(tmp_path)]) == []


# ---------------------------------------------------------------------------
# 1 MB size limit
# ---------------------------------------------------------------------------

def test_skips_large_file(tmp_path):
    f = tmp_path / "huge.py"
    # Write a file slightly over 1 MB with a key at the start.
    key_line = "sk-ant-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
    padding = "# padding\n" * 110_000  # ~1.1 MB
    f.write_text(key_line + padding, encoding="utf-8")
    assert ApiKeysScanner().scan([str(f)]) == []


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------

def test_to_dict_json_safe(py_records):
    for rec in py_records:
        json.dumps(rec.to_dict())  # must not raise
