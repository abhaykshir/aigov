from __future__ import annotations

from datetime import datetime, timezone

import pytest

from aigov.core.models import AISystemRecord, AISystemType, DeploymentType, RiskLevel
from aigov.frameworks.eu_ai_act import EUAIActClassifier


@pytest.fixture(scope="module")
def classifier() -> EUAIActClassifier:
    return EUAIActClassifier()


def _record(**kwargs) -> AISystemRecord:
    defaults: dict = dict(
        id="test-001",
        source_scanner="test",
        source_location="src/app.py",
        discovery_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        confidence=0.9,
        system_type=AISystemType.API_SERVICE,
        deployment_type=DeploymentType.CLOUD_API,
        description="",
        provider="unknown",
    )
    defaults.update(kwargs)
    return AISystemRecord(**defaults)


# ---------------------------------------------------------------------------
# Core classification outcomes
# ---------------------------------------------------------------------------

def test_resume_screener_openai_is_high_risk_employment(classifier):
    # Annex III category 4 — Employment and Worker Management.
    # Two keyword hits ("resume screening", "candidate scoring") without any
    # library/cloud match suffice for a HIGH_RISK classification.
    record = _record(
        name="resume_screener",
        description="AI resume screening system for candidate scoring in hiring",
        provider="OpenAI",
    )
    result = classifier.classify(record)
    assert result.risk_classification == RiskLevel.HIGH_RISK
    assert "HIGH_RISK" in result.classification_rationale
    assert "Employment" in result.classification_rationale
    assert "Annex III" in result.classification_rationale


def test_facial_recognition_deepface_is_high_risk_biometrics(classifier):
    # Annex III category 1 — Biometrics.
    # deepface is listed in annex_iii_1 library_patterns, giving one high-confidence
    # library signal.  Prohibited_2 also lists deepface, but its matching requires
    # at least one prohibited keyword (e.g. "real-time facial recognition") which
    # is absent here, so the system stays at HIGH_RISK rather than escalating.
    record = _record(
        name="facial_recognition",
        description="Facial recognition and face matching system",
        provider="deepface",
    )
    result = classifier.classify(record)
    assert result.risk_classification == RiskLevel.HIGH_RISK
    assert "HIGH_RISK" in result.classification_rationale
    assert "Biometric" in result.classification_rationale


def test_customer_chatbot_anthropic_is_limited_risk(classifier):
    # Article 50 transparency — Conversational / chatbot systems.
    # "anthropic" is a library_pattern in transparency_1.  Neither prohibited rules
    # nor any Annex III category has Anthropic in their library/cloud lists.
    record = _record(
        name="customer_chatbot",
        description="Customer service AI assistant chatbot",
        provider="Anthropic",
    )
    result = classifier.classify(record)
    assert result.risk_classification == RiskLevel.LIMITED_RISK
    assert "LIMITED_RISK" in result.classification_rationale


def test_data_pipeline_pandas_is_minimal_risk(classifier):
    # pandas is not an AI provider; no prohibited, high-risk, or transparency
    # signals should fire.
    record = _record(
        name="data_pipeline",
        description="ETL pipeline for processing and transforming data",
        provider="pandas",
    )
    result = classifier.classify(record)
    assert result.risk_classification == RiskLevel.MINIMAL_RISK


def test_social_scoring_is_prohibited(classifier):
    # Article 5(1)(c) — Social Scoring by Public Authorities.
    # Description contains "social scoring" (1 keyword) and "behavioural scoring"
    # (1 keyword) — together they satisfy the 2-keyword threshold for PROHIBITED.
    record = _record(
        name="social_scoring_platform",
        description="social scoring for public benefits using behavioural scoring of citizens",
        provider="internal",
    )
    result = classifier.classify(record)
    assert result.risk_classification == RiskLevel.PROHIBITED
    assert "PROHIBITED" in result.classification_rationale


# ---------------------------------------------------------------------------
# Rationale quality
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("record,expected_level", [
    (
        _record(name="resume_screener", description="AI resume screening system for candidate scoring", provider="OpenAI"),
        RiskLevel.HIGH_RISK,
    ),
    (
        _record(name="facial_recognition", description="Face matching and face detection system", provider="deepface"),
        RiskLevel.HIGH_RISK,
    ),
    (
        _record(name="customer_chatbot", description="Customer chatbot AI assistant", provider="Anthropic"),
        RiskLevel.LIMITED_RISK,
    ),
    (
        _record(name="data_pipeline", description="ETL data processing pipeline", provider="pandas"),
        RiskLevel.MINIMAL_RISK,
    ),
    (
        _record(name="social_scorer", description="social scoring for public benefits using behavioural scoring", provider="internal"),
        RiskLevel.PROHIBITED,
    ),
])
def test_rationale_always_populated_and_human_readable(classifier, record, expected_level):
    result = classifier.classify(record)
    assert result.risk_classification == expected_level
    rationale = result.classification_rationale
    assert rationale is not None, f"No rationale for {record.name}"
    assert len(rationale) > 40, f"Rationale too short for {record.name}: {rationale!r}"
    level_strings = {"PROHIBITED", "HIGH_RISK", "LIMITED_RISK", "MINIMAL_RISK"}
    assert any(lvl in rationale for lvl in level_strings), (
        f"Rationale for {record.name} does not name a risk level: {rationale!r}"
    )


# ---------------------------------------------------------------------------
# No sensitive data leaks into classification output
# ---------------------------------------------------------------------------

def test_no_sensitive_data_leaks_into_rationale(classifier):
    sensitive = ["employee_ssn_42", "salary_info_secret", "health_record_xyz"]
    record = _record(
        name="hr_system",
        description="HR management system for employee records",
        provider="OpenAI",
        data_categories=sensitive,
    )
    result = classifier.classify(record)
    rationale = result.classification_rationale or ""
    for value in sensitive:
        assert value not in rationale, (
            f"Sensitive value {value!r} leaked into classification_rationale"
        )


def test_no_sensitive_data_leaks_into_tags(classifier):
    sensitive = ["patient_id_007", "credit_card_num", "biometric_hash"]
    record = _record(
        name="health_app",
        description="Healthcare triage application for patient prioritization",
        provider="OpenAI",
        data_categories=sensitive,
    )
    result = classifier.classify(record)
    for tag_key, tag_value in result.tags.items():
        for value in sensitive:
            assert value not in tag_value, (
                f"Sensitive value {value!r} leaked into tag[{tag_key!r}]"
            )


# ---------------------------------------------------------------------------
# Confidence adjustment tag
# ---------------------------------------------------------------------------

def test_confidence_tag_present_for_all_levels(classifier):
    records = [
        _record(name="resume_screener", description="AI resume screening system for candidate scoring", provider="OpenAI"),
        _record(name="facial_recognition", description="Facial recognition system using deepface", provider="deepface"),
        _record(name="customer_chatbot", description="AI chatbot assistant", provider="Anthropic"),
        _record(name="data_pipeline", description="ETL pipeline", provider="pandas"),
        _record(name="social_scorer", description="social scoring behavioural scoring for public benefits", provider="internal"),
    ]
    for record in records:
        result = classifier.classify(record)
        assert "confidence_adjustment" in result.tags, (
            f"Missing confidence_adjustment tag for {record.name}"
        )
        assert result.tags["confidence_adjustment"] in {"high", "medium", "low"}, (
            f"Unexpected confidence value for {record.name}: {result.tags['confidence_adjustment']!r}"
        )


def test_library_match_yields_high_confidence(classifier):
    # deepface is a direct library_pattern match → should be high confidence
    record = _record(
        name="face_id",
        description="Face detection and face verification service",
        provider="deepface",
    )
    result = classifier.classify(record)
    assert result.tags.get("confidence_adjustment") == "high"


def test_borderline_keyword_only_match_yields_low_confidence(classifier):
    # Exactly two keyword hits, no library/cloud signal → borderline → low confidence
    record = _record(
        name="hiring_assistant",
        description="Resume screening tool for candidate scoring",
        provider="internal_hr_tool",
    )
    result = classifier.classify(record)
    assert result.risk_classification == RiskLevel.HIGH_RISK
    assert result.tags.get("confidence_adjustment") == "low"


# ---------------------------------------------------------------------------
# Prohibited keyword context requirement
# ---------------------------------------------------------------------------

def test_library_alone_does_not_trigger_prohibited(classifier):
    # deepface appears in prohibited_2 library_patterns, but without any
    # prohibited keyword (e.g. "real-time facial recognition") the classifier
    # must NOT escalate to PROHIBITED — it should remain HIGH_RISK.
    record = _record(
        name="photo_app",
        description="Apply filters and face detection effects to photos",
        provider="deepface",
    )
    result = classifier.classify(record)
    assert result.risk_classification != RiskLevel.PROHIBITED


def test_prohibited_keyword_plus_library_triggers_prohibited(classifier):
    # With both a prohibited keyword and a library signal present, PROHIBITED fires.
    record = _record(
        name="surveillance_system",
        description="real-time facial recognition system for crowd monitoring",
        provider="deepface",
    )
    result = classifier.classify(record)
    assert result.risk_classification == RiskLevel.PROHIBITED


# ---------------------------------------------------------------------------
# Classifier is read-only — calling classify twice is safe
# ---------------------------------------------------------------------------

def test_classify_does_not_mutate_shared_state(classifier):
    r1 = _record(name="resume_screener", description="AI resume screening system for candidate scoring", provider="OpenAI")
    r2 = _record(name="data_pipeline", description="ETL pipeline", provider="pandas")
    classifier.classify(r1)
    classifier.classify(r2)
    # Re-classify r1; result should be identical (no leftover state from r2)
    r1b = _record(name="resume_screener", description="AI resume screening system for candidate scoring", provider="OpenAI")
    result = classifier.classify(r1b)
    assert result.risk_classification == RiskLevel.HIGH_RISK


# ---------------------------------------------------------------------------
# classify() returns a new record — input is never mutated
# ---------------------------------------------------------------------------

def test_classify_returns_new_record_instance(classifier):
    """The classifier must not mutate the input record — it returns a copy."""
    record = _record(
        name="resume_screener",
        description="AI resume screening system for candidate scoring",
        provider="OpenAI",
    )
    original_risk = record.risk_classification
    original_rationale = record.classification_rationale
    original_tags = dict(record.tags)

    result = classifier.classify(record)

    # The returned record should have classification populated.
    assert result.risk_classification == RiskLevel.HIGH_RISK
    # The input must remain untouched.
    assert record.risk_classification == original_risk
    assert record.classification_rationale == original_rationale
    assert record.tags == original_tags
    # And it must be a different object.
    assert result is not record


def test_classify_does_not_share_tags_dict_with_input(classifier):
    """Mutating the result's tags must not bleed back into the input."""
    record = _record(name="x", description="ETL pipeline", provider="pandas")
    result = classifier.classify(record)
    assert result.tags is not record.tags
    result.tags["scratch"] = "value"
    assert "scratch" not in record.tags


# ---------------------------------------------------------------------------
# Disclaimer / classification_type tag
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rec_kwargs,expected", [
    ({"name": "resume_screener", "description": "AI resume screening system for candidate scoring", "provider": "OpenAI"}, RiskLevel.HIGH_RISK),
    ({"name": "customer_chatbot", "description": "Customer chatbot AI assistant", "provider": "Anthropic"}, RiskLevel.LIMITED_RISK),
    ({"name": "data_pipeline", "description": "ETL pipeline", "provider": "pandas"}, RiskLevel.MINIMAL_RISK),
    ({"name": "social_scorer", "description": "social scoring for public benefits using behavioural scoring", "provider": "internal"}, RiskLevel.PROHIBITED),
])
def test_classification_type_tag_added_for_every_outcome(classifier, rec_kwargs, expected):
    result = classifier.classify(_record(**rec_kwargs))
    assert result.risk_classification == expected
    assert result.tags.get("classification_type") == "automated_signal", (
        f"Missing classification_type=automated_signal disclaimer tag for {rec_kwargs['name']!r}"
    )
