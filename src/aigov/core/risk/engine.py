"""Risk engine — enrich every record with context, then score it.

This is the only module that writes the risk fields on a record (via the
immutable ``dataclasses.replace`` pattern used throughout aigov). Inputs are
never mutated; the output is a fresh list of new records with ``risk_score``,
``risk_level``, ``risk_drivers`` and ``risk_confidence`` populated as
first-class fields. The full enrichment context dict is JSON-encoded into
``tags["risk_context"]`` for transparency; everything else lives on the
record itself.
"""
from __future__ import annotations

import dataclasses
import json
from typing import Any

from aigov.core.models import AISystemRecord
from aigov.core.risk.context import enrich
from aigov.core.risk.scoring import RiskResult, compute_risk


# Tag key written by this module — kept stable for consumers that introspect
# the full context payload (debugging, custom dashboards).
TAG_RISK_CONTEXT = "risk_context"


def apply_risk(records: list[AISystemRecord], scan_paths: list[str]) -> list[AISystemRecord]:
    """Return new records with risk fields added. Originals are never mutated."""
    out: list[AISystemRecord] = []
    for record in records:
        context = enrich(record, scan_paths)
        result = compute_risk(record, context)
        out.append(_with_risk(record, context, result))
    return out


def _with_risk(
    record: AISystemRecord,
    context: dict[str, Any],
    result: RiskResult,
) -> AISystemRecord:
    new_tags = {
        **record.tags,
        # JSON-encode so the str→str typing on ``tags`` survives round-tripping
        # through to_dict() / from_dict().
        TAG_RISK_CONTEXT: json.dumps(context, sort_keys=True),
    }
    return dataclasses.replace(
        record,
        risk_score=int(result.risk_score),
        risk_level=result.risk_level,
        risk_drivers=list(result.drivers),
        risk_confidence=float(result.confidence),
        tags=new_tags,
    )
