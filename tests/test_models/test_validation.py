"""Tests for AISystemRecord __post_init__ field validation."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from aigov.core.models import AISystemRecord, AISystemType, DeploymentType


def _kwargs(**overrides):
    base = dict(
        id="rec-1",
        name="example",
        description="",
        source_scanner="test.scanner",
        source_location="src/app.py",
        discovery_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        confidence=0.9,
        system_type=AISystemType.API_SERVICE,
        provider="OpenAI",
        deployment_type=DeploymentType.CLOUD_API,
    )
    base.update(overrides)
    return base


def test_valid_record_constructs():
    AISystemRecord(**_kwargs())  # must not raise


@pytest.mark.parametrize("bad", [-0.01, 1.01, -1.0, 2.0, 100.0])
def test_confidence_out_of_range_rejected(bad):
    with pytest.raises(ValueError, match="confidence"):
        AISystemRecord(**_kwargs(confidence=bad))


@pytest.mark.parametrize("good", [0.0, 0.5, 1.0])
def test_confidence_at_bounds_accepted(good):
    AISystemRecord(**_kwargs(confidence=good))


@pytest.mark.parametrize("bad", ["", "   "])
def test_provider_must_be_non_empty(bad):
    with pytest.raises(ValueError, match="provider"):
        AISystemRecord(**_kwargs(provider=bad))


@pytest.mark.parametrize("bad", ["", "   "])
def test_source_location_must_be_non_empty(bad):
    with pytest.raises(ValueError, match="source_location"):
        AISystemRecord(**_kwargs(source_location=bad))


@pytest.mark.parametrize("bad", ["", "   "])
def test_source_scanner_must_be_non_empty(bad):
    with pytest.raises(ValueError, match="source_scanner"):
        AISystemRecord(**_kwargs(source_scanner=bad))
