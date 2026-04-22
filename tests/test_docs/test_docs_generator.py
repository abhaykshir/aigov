from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from aigov.core.docs_generator import DocsGenerator, _slug, _source_slug, _safe_tags
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
    provider: str = "TestProvider",
    model_id: str | None = None,
    source_scanner: str = "code.python_imports",
    source_location: str = "src/app.py:10",
    tags: dict | None = None,
) -> AISystemRecord:
    return AISystemRecord(
        id=record_id,
        name=name,
        description=f"A test AI system classified as {risk.value}",
        source_scanner=source_scanner,
        source_location=source_location,
        discovery_timestamp=datetime(2026, 4, 21, 12, 0, 0, tzinfo=timezone.utc),
        confidence=0.9,
        system_type=AISystemType.API_SERVICE,
        provider=provider,
        deployment_type=DeploymentType.CLOUD_API,
        model_identifier=model_id,
        risk_classification=risk,
        classification_rationale=f"Classified as {risk.value} based on scanner signals.",
        tags=tags or {},
    )


@pytest.fixture
def generator() -> DocsGenerator:
    return DocsGenerator()


@pytest.fixture
def high_risk_record() -> AISystemRecord:
    return _make_record(
        RiskLevel.HIGH_RISK,
        name="Resume Screener",
        record_id="hr-1",
        provider="OpenAI",
        model_id="gpt-4o",
        source_location="src/resume_screener.py:42",
        tags={
            "eu_ai_act_category": "Employment and Worker Management",
            "eu_ai_act_article": "Annex III §4",
            "confidence_adjustment": "high",
            "origin_jurisdiction": "US",
        },
    )


@pytest.fixture
def limited_risk_record() -> AISystemRecord:
    return _make_record(
        RiskLevel.LIMITED_RISK,
        name="Customer Chatbot",
        record_id="lr-1",
        provider="Anthropic",
        source_location="src/customer_chatbot.py:10",
        tags={
            "eu_ai_act_category": "Chatbot / Conversational AI",
            "eu_ai_act_article": "Article 50",
            "confidence_adjustment": "medium",
            "origin_jurisdiction": "US",
        },
    )


@pytest.fixture
def prohibited_record() -> AISystemRecord:
    return _make_record(
        RiskLevel.PROHIBITED,
        name="Social Scoring System",
        record_id="pb-1",
        provider="InternalML",
        source_location="src/social_scoring_system.py:5",
        tags={
            "eu_ai_act_category": "Social Scoring by Public Authorities",
            "eu_ai_act_article": "Article 5(1)(c)",
            "confidence_adjustment": "high",
        },
    )


@pytest.fixture
def minimal_risk_record() -> AISystemRecord:
    return _make_record(
        RiskLevel.MINIMAL_RISK,
        name="Spam Filter",
        record_id="mr-1",
        provider="InternalML",
    )


@pytest.fixture
def api_key_record() -> AISystemRecord:
    """Simulates a record from ApiKeysScanner — has sensitive-adjacent tags."""
    return _make_record(
        RiskLevel.MINIMAL_RISK,
        name="Anthropic API Key detected",
        record_id="key-1",
        provider="Anthropic",
        source_scanner="code.api_keys",
        tags={
            "key_type": "Anthropic API Key",
            "key_preview": "sk-an****",
            "origin_jurisdiction": "US",
        },
    )


# ---------------------------------------------------------------------------
# Slug helper
# ---------------------------------------------------------------------------

class TestSlug:
    def test_spaces_become_underscores(self):
        assert _slug("Resume Screener") == "resume_screener"

    def test_special_chars_stripped(self):
        assert _slug("OpenAI via openai") == "openai_via_openai"

    def test_max_length_60(self):
        long = "a" * 80
        assert len(_slug(long)) <= 60

    def test_lowercase(self):
        assert _slug("MySystem") == "mysystem"


# ---------------------------------------------------------------------------
# Source slug helper
# ---------------------------------------------------------------------------

class TestSourceSlug:
    def test_extracts_stem_from_unix_path(self):
        rec = _make_record(RiskLevel.HIGH_RISK, source_location="src/fraud_detection.py:2")
        assert _source_slug(rec) == "fraud_detection"

    def test_extracts_stem_from_windows_path(self):
        rec = _make_record(RiskLevel.HIGH_RISK, source_location=r"demo\analytics\fraud_detection.py:2")
        assert _source_slug(rec) == "fraud_detection"

    def test_strips_line_number_colon(self):
        rec = _make_record(RiskLevel.HIGH_RISK, source_location="src/resume_screener.py:42")
        assert _source_slug(rec) == "resume_screener"

    def test_strips_line_number_hash(self):
        rec = _make_record(RiskLevel.HIGH_RISK, source_location="src/app.py#L10")
        assert _source_slug(rec) == "app"

    def test_strips_line_number_hash_no_L(self):
        rec = _make_record(RiskLevel.HIGH_RISK, source_location="src/app.py#10")
        assert _source_slug(rec) == "app"

    def test_falls_back_to_name_when_no_file(self):
        rec = _make_record(RiskLevel.HIGH_RISK, name="My System", source_location="")
        assert _source_slug(rec) == "my_system"

    def test_falls_back_to_name_for_bare_dot(self):
        rec = _make_record(RiskLevel.HIGH_RISK, name="My System", source_location=".")
        assert _source_slug(rec) == "my_system"

    def test_nested_path_uses_only_stem(self):
        rec = _make_record(RiskLevel.HIGH_RISK, source_location="a/b/c/customer_chatbot.py:1")
        assert _source_slug(rec) == "customer_chatbot"

    def test_mcp_json_config_file(self):
        rec = _make_record(RiskLevel.LIMITED_RISK, source_location=r"demo\.mcp.json")
        # ".mcp" stem starts with dot — _slug strips leading underscores,
        # and Path(".mcp.json").stem == ".mcp" which slugifies to "mcp"
        result = _source_slug(rec)
        assert len(result) > 0  # should not be empty


# ---------------------------------------------------------------------------
# Safe tags
# ---------------------------------------------------------------------------

class TestSafeTags:
    def test_strips_key_preview(self, api_key_record):
        safe = _safe_tags(api_key_record)
        assert "key_preview" not in safe

    def test_strips_key_type(self, api_key_record):
        safe = _safe_tags(api_key_record)
        assert "key_type" not in safe

    def test_keeps_safe_tags(self):
        rec = _make_record(
            RiskLevel.HIGH_RISK,
            tags={"eu_ai_act_category": "Foo", "origin_jurisdiction": "US"},
        )
        safe = _safe_tags(rec)
        assert "eu_ai_act_category" in safe
        assert "origin_jurisdiction" in safe


# ---------------------------------------------------------------------------
# HIGH_RISK: Annex IV document
# ---------------------------------------------------------------------------

ANNEX_IV_SECTIONS = [
    "## 1.",
    "## 2.",
    "## 3.",
    "## 4.",
    "## 5.",
    "## 6.",
    "## 7.",
    "## 8.",
]


class TestHighRiskDoc:
    def test_annex_iv_file_created(self, generator, high_risk_record, tmp_path):
        created = generator.generate([high_risk_record], str(tmp_path))
        annex_files = [p for p in created if "_annex_iv.md" in p]
        assert len(annex_files) == 1

    def test_annex_iv_filename_slug(self, generator, high_risk_record, tmp_path):
        created = generator.generate([high_risk_record], str(tmp_path))
        annex_files = [p for p in created if "_annex_iv.md" in p]
        assert Path(annex_files[0]).name == "resume_screener_annex_iv.md"

    def test_all_8_sections_present(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        for section in ANNEX_IV_SECTIONS:
            assert section in content, f"Missing section: {section}"

    def test_section_1_general_description(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "## 1. General Description" in content

    def test_section_2_detailed_description(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "## 2. Detailed Description" in content
        assert "2.1" in content
        assert "2.2" in content
        assert "2.3" in content
        assert "2.4" in content

    def test_section_3_monitoring(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "## 3." in content
        assert "Article 12" in content
        assert "Article 14" in content

    def test_section_4_risk_management(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "## 4." in content
        assert "Article 9" in content

    def test_section_5_data_governance(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "## 5." in content
        assert "Article 10" in content

    def test_section_6_accuracy(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "## 6." in content
        assert "Article 15" in content

    def test_section_7_conformity_assessment(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "## 7." in content
        assert "Article 43" in content or "Annex" in content

    def test_section_8_eu_database(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "## 8." in content
        assert "Article 49" in content

    def test_prefilled_system_name(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "Resume Screener" in content

    def test_prefilled_provider(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "OpenAI" in content

    def test_prefilled_model_identifier(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "gpt-4o" in content

    def test_prefilled_deployment_type(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "cloud_api" in content

    def test_prefilled_source_location(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "src/resume_screener.py:42" in content

    def test_prefilled_discovery_date(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "2026-04-21" in content

    def test_prefilled_eu_ai_act_category(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "Employment and Worker Management" in content

    def test_prefilled_scanner(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "code.python_imports" in content

    def test_prefilled_rationale(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "high_risk" in content  # part of classification_rationale

    def test_todo_guidance_notes_present(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "TODO" in content
        assert "FILL IN" in content

    def test_duplicate_names_get_unique_filenames(self, generator, tmp_path):
        rec1 = _make_record(RiskLevel.HIGH_RISK, name="My System", record_id="a")
        rec2 = _make_record(RiskLevel.HIGH_RISK, name="My System", record_id="b")
        created = generator.generate([rec1, rec2], str(tmp_path))
        annex_files = sorted(p for p in created if "_annex_iv.md" in p)
        assert len(annex_files) == 2
        assert annex_files[0] != annex_files[1]


# ---------------------------------------------------------------------------
# LIMITED_RISK: Transparency document
# ---------------------------------------------------------------------------

class TestLimitedRiskDoc:
    def test_transparency_file_created(self, generator, limited_risk_record, tmp_path):
        created = generator.generate([limited_risk_record], str(tmp_path))
        transparency_files = [p for p in created if "_transparency.md" in p]
        assert len(transparency_files) == 1

    def test_transparency_filename_slug(self, generator, limited_risk_record, tmp_path):
        created = generator.generate([limited_risk_record], str(tmp_path))
        transparency_files = [p for p in created if "_transparency.md" in p]
        assert Path(transparency_files[0]).name == "customer_chatbot_transparency.md"

    def test_article_50_referenced(self, generator, limited_risk_record, tmp_path):
        generator.generate([limited_risk_record], str(tmp_path))
        content = (tmp_path / "customer_chatbot_transparency.md").read_text(encoding="utf-8")
        assert "Article 50" in content

    def test_disclosure_checklist_present(self, generator, limited_risk_record, tmp_path):
        generator.generate([limited_risk_record], str(tmp_path))
        content = (tmp_path / "customer_chatbot_transparency.md").read_text(encoding="utf-8")
        assert "- [ ]" in content

    def test_system_description_prefilled(self, generator, limited_risk_record, tmp_path):
        generator.generate([limited_risk_record], str(tmp_path))
        content = (tmp_path / "customer_chatbot_transparency.md").read_text(encoding="utf-8")
        assert "Customer Chatbot" in content
        assert "Anthropic" in content
        assert "src/customer_chatbot.py:10" in content

    def test_transparency_requirements_section(self, generator, limited_risk_record, tmp_path):
        generator.generate([limited_risk_record], str(tmp_path))
        content = (tmp_path / "customer_chatbot_transparency.md").read_text(encoding="utf-8")
        assert "Article 50 Requirements" in content or "Transparency" in content

    def test_synthetic_content_labeling_mentioned(self, generator, limited_risk_record, tmp_path):
        generator.generate([limited_risk_record], str(tmp_path))
        content = (tmp_path / "customer_chatbot_transparency.md").read_text(encoding="utf-8")
        assert "synthetic" in content.lower() or "label" in content.lower()


# ---------------------------------------------------------------------------
# PROHIBITED: Cessation notice
# ---------------------------------------------------------------------------

class TestProhibitedDoc:
    def test_prohibited_file_created(self, generator, prohibited_record, tmp_path):
        created = generator.generate([prohibited_record], str(tmp_path))
        prohibited_files = [p for p in created if "_prohibited.md" in p]
        assert len(prohibited_files) == 1

    def test_prohibited_filename_slug(self, generator, prohibited_record, tmp_path):
        created = generator.generate([prohibited_record], str(tmp_path))
        prohibited_files = [p for p in created if "_prohibited.md" in p]
        assert Path(prohibited_files[0]).name == "social_scoring_system_prohibited.md"

    def test_article_5_referenced(self, generator, prohibited_record, tmp_path):
        generator.generate([prohibited_record], str(tmp_path))
        content = (tmp_path / "social_scoring_system_prohibited.md").read_text(encoding="utf-8")
        assert "Article 5" in content

    def test_immediate_action_section_present(self, generator, prohibited_record, tmp_path):
        generator.generate([prohibited_record], str(tmp_path))
        content = (tmp_path / "social_scoring_system_prohibited.md").read_text(encoding="utf-8")
        assert "immediate" in content.lower() or "cessation" in content.lower() or "suspend" in content.lower()

    def test_system_description_prefilled(self, generator, prohibited_record, tmp_path):
        generator.generate([prohibited_record], str(tmp_path))
        content = (tmp_path / "social_scoring_system_prohibited.md").read_text(encoding="utf-8")
        assert "Social Scoring System" in content
        assert "InternalML" in content

    def test_article_5_category_prefilled(self, generator, prohibited_record, tmp_path):
        generator.generate([prohibited_record], str(tmp_path))
        content = (tmp_path / "social_scoring_system_prohibited.md").read_text(encoding="utf-8")
        assert "Social Scoring by Public Authorities" in content

    def test_remediation_guidance_present(self, generator, prohibited_record, tmp_path):
        generator.generate([prohibited_record], str(tmp_path))
        content = (tmp_path / "social_scoring_system_prohibited.md").read_text(encoding="utf-8")
        assert "remediat" in content.lower() or "decommission" in content.lower()

    def test_cessation_checklist_present(self, generator, prohibited_record, tmp_path):
        generator.generate([prohibited_record], str(tmp_path))
        content = (tmp_path / "social_scoring_system_prohibited.md").read_text(encoding="utf-8")
        assert "- [ ]" in content


# ---------------------------------------------------------------------------
# MINIMAL_RISK: no document generated (beyond index)
# ---------------------------------------------------------------------------

class TestMinimalRiskDoc:
    def test_no_compliance_doc_for_minimal_risk(self, generator, minimal_risk_record, tmp_path):
        created = generator.generate([minimal_risk_record], str(tmp_path))
        # Only index.md should be created
        non_index = [p for p in created if not p.endswith("index.md")]
        assert len(non_index) == 0

    def test_index_still_created(self, generator, minimal_risk_record, tmp_path):
        created = generator.generate([minimal_risk_record], str(tmp_path))
        assert any(p.endswith("index.md") for p in created)


# ---------------------------------------------------------------------------
# Index document
# ---------------------------------------------------------------------------

class TestIndexDoc:
    def test_index_md_always_created(self, generator, high_risk_record, tmp_path):
        created = generator.generate([high_risk_record], str(tmp_path))
        assert any(p.endswith("index.md") for p in created)

    def test_index_created_even_with_no_docs(self, generator, minimal_risk_record, tmp_path):
        created = generator.generate([minimal_risk_record], str(tmp_path))
        assert any(p.endswith("index.md") for p in created)

    def test_index_lists_high_risk_doc(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "index.md").read_text(encoding="utf-8")
        assert "Resume Screener" in content
        assert "HIGH RISK" in content

    def test_index_lists_limited_risk_doc(self, generator, limited_risk_record, tmp_path):
        generator.generate([limited_risk_record], str(tmp_path))
        content = (tmp_path / "index.md").read_text(encoding="utf-8")
        assert "Customer Chatbot" in content

    def test_index_lists_prohibited_doc(self, generator, prohibited_record, tmp_path):
        generator.generate([prohibited_record], str(tmp_path))
        content = (tmp_path / "index.md").read_text(encoding="utf-8")
        assert "Social Scoring System" in content
        assert "PROHIBITED" in content

    def test_index_mentions_minimal_risk_as_no_docs(self, generator, minimal_risk_record, tmp_path):
        generator.generate([minimal_risk_record], str(tmp_path))
        content = (tmp_path / "index.md").read_text(encoding="utf-8")
        assert "Spam Filter" in content

    def test_index_links_to_generated_files(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "index.md").read_text(encoding="utf-8")
        assert "resume_screener_annex_iv.md" in content

    def test_index_contains_next_steps(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "index.md").read_text(encoding="utf-8")
        assert "Next Steps" in content or "next steps" in content.lower()

    def test_mixed_records_index(self, generator, high_risk_record, limited_risk_record, minimal_risk_record, tmp_path):
        generator.generate([high_risk_record, limited_risk_record, minimal_risk_record], str(tmp_path))
        content = (tmp_path / "index.md").read_text(encoding="utf-8")
        assert "Resume Screener" in content
        assert "Customer Chatbot" in content
        assert "Spam Filter" in content


# ---------------------------------------------------------------------------
# Output directory creation
# ---------------------------------------------------------------------------

class TestOutputDirectory:
    def test_creates_output_dir_if_missing(self, generator, high_risk_record, tmp_path):
        nested = tmp_path / "deep" / "nested" / "dir"
        generator.generate([high_risk_record], str(nested))
        assert nested.is_dir()

    def test_returns_list_of_paths(self, generator, high_risk_record, tmp_path):
        created = generator.generate([high_risk_record], str(tmp_path))
        assert isinstance(created, list)
        assert all(isinstance(p, str) for p in created)

    def test_all_returned_paths_exist(self, generator, high_risk_record, tmp_path):
        created = generator.generate([high_risk_record], str(tmp_path))
        for path in created:
            assert Path(path).exists(), f"File not found: {path}"

    def test_empty_records_only_creates_index(self, generator, tmp_path):
        created = generator.generate([], str(tmp_path))
        assert created == [str(tmp_path / "index.md")]

    def test_correct_count_mixed(self, generator, high_risk_record, limited_risk_record, minimal_risk_record, tmp_path):
        created = generator.generate([high_risk_record, limited_risk_record, minimal_risk_record], str(tmp_path))
        # 1 annex_iv + 1 transparency + 0 (minimal) + 1 index = 3
        assert len(created) == 3


# ---------------------------------------------------------------------------
# Security: no credential values in docs
# ---------------------------------------------------------------------------

class TestSecurity:
    def test_key_preview_not_in_annex_iv(self, generator, tmp_path):
        rec = _make_record(
            RiskLevel.HIGH_RISK,
            name="Leaky System",
            tags={
                "eu_ai_act_category": "Employment",
                "key_preview": "sk-an****",
                "key_type": "Anthropic API Key",
            },
        )
        generator.generate([rec], str(tmp_path))
        # default source_location="src/app.py:10" → slug "app"
        content = (tmp_path / "app_annex_iv.md").read_text(encoding="utf-8")
        assert "sk-an****" not in content

    def test_key_type_not_in_annex_iv(self, generator, tmp_path):
        rec = _make_record(
            RiskLevel.HIGH_RISK,
            name="Leaky System",
            tags={
                "eu_ai_act_category": "Employment",
                "key_preview": "sk-an****",
                "key_type": "Anthropic API Key",
            },
        )
        generator.generate([rec], str(tmp_path))
        # default source_location="src/app.py:10" → slug "app"
        content = (tmp_path / "app_annex_iv.md").read_text(encoding="utf-8")
        assert "key_preview" not in content

    def test_no_raw_credential_patterns_in_any_doc(self, generator, tmp_path):
        high = _make_record(
            RiskLevel.HIGH_RISK,
            name="HR Tool",
            tags={"eu_ai_act_category": "Employment", "key_preview": "sk-live-abc****"},
        )
        limited = _make_record(
            RiskLevel.LIMITED_RISK,
            name="Chat Bot",
            tags={"eu_ai_act_category": "Chatbot", "key_preview": "hf_tok****"},
        )
        generator.generate([high, limited], str(tmp_path))
        for md_file in tmp_path.glob("*.md"):
            content = md_file.read_text(encoding="utf-8")
            assert "sk-live-abc****" not in content, f"Found key_preview in {md_file.name}"
            assert "hf_tok****" not in content, f"Found key_preview in {md_file.name}"

    def test_source_location_path_allowed(self, generator, high_risk_record, tmp_path):
        """File paths are safe metadata — they should appear in docs."""
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "src/resume_screener.py:42" in content

    def test_provider_name_allowed(self, generator, high_risk_record, tmp_path):
        """Provider names are safe metadata — they should appear in docs."""
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "OpenAI" in content

    def test_classification_rationale_allowed(self, generator, high_risk_record, tmp_path):
        """Rationale text is safe and useful context — should appear in docs."""
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert "high_risk" in content  # rationale mentions risk level


# ---------------------------------------------------------------------------
# File encoding and format
# ---------------------------------------------------------------------------

class TestFileFormat:
    def test_files_are_utf8(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        # If this doesn't raise, file is valid UTF-8
        (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")

    def test_annex_iv_starts_with_h1(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "resume_screener_annex_iv.md").read_text(encoding="utf-8")
        assert content.startswith("# ")

    def test_transparency_starts_with_h1(self, generator, limited_risk_record, tmp_path):
        generator.generate([limited_risk_record], str(tmp_path))
        content = (tmp_path / "customer_chatbot_transparency.md").read_text(encoding="utf-8")
        assert content.startswith("# ")

    def test_prohibited_starts_with_h1(self, generator, prohibited_record, tmp_path):
        generator.generate([prohibited_record], str(tmp_path))
        content = (tmp_path / "social_scoring_system_prohibited.md").read_text(encoding="utf-8")
        assert content.startswith("# ")

    def test_index_starts_with_h1(self, generator, high_risk_record, tmp_path):
        generator.generate([high_risk_record], str(tmp_path))
        content = (tmp_path / "index.md").read_text(encoding="utf-8")
        assert content.startswith("# ")
