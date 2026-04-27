"""Risk engine — enrich every record with context, then score it.

This is the only module that mutates ``tags`` on a record (via the immutable
``dataclasses.replace`` pattern used throughout aigov). Inputs are never
mutated; the output is a fresh list with new ``risk_*`` tags.
"""
from __future__ import annotations

import dataclasses
import json
from typing import Any

from aigov.core.models import AISystemRecord
from aigov.core.risk.context import enrich
from aigov.core.risk.scoring import RiskResult, compute_risk


# Tag keys written by this module. Kept stable for the reporter and JSON
# consumers; renaming would be a breaking change.
TAG_RISK_SCORE = "risk_score"
TAG_RISK_LEVEL = "risk_level"
TAG_RISK_DRIVERS = "risk_drivers"
TAG_RISK_CONFIDENCE = "risk_confidence"
TAG_RISK_CONTEXT = "risk_context"


def apply_risk(records: list[AISystemRecord], scan_paths: list[str]) -> list[AISystemRecord]:
    """Return new records with risk tags added. Originals are never mutated."""
    out: list[AISystemRecord] = []
    for record in records:
        context = enrich(record, scan_paths)
        result = compute_risk(record, context)
        out.append(_with_risk_tags(record, context, result))
    return out


def _with_risk_tags(
    record: AISystemRecord,
    context: dict[str, Any],
    result: RiskResult,
) -> AISystemRecord:
    new_tags = {
        **record.tags,
        TAG_RISK_SCORE: str(result.risk_score),
        TAG_RISK_LEVEL: result.risk_level,
        TAG_RISK_DRIVERS: ",".join(result.drivers),
        TAG_RISK_CONFIDENCE: f"{result.confidence:.2f}",
        # JSON-encode the context so the str→str typing on tags survives
        # round-tripping through to_dict() / from_dict().
        TAG_RISK_CONTEXT: json.dumps(context, sort_keys=True),
    }
    return dataclasses.replace(record, tags=new_tags)
