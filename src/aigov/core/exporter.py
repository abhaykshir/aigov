from __future__ import annotations

import csv
import json
from io import StringIO
from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    from aigov.core.models import AISystemRecord

# Columns exported to GRC platforms — order matters (matches spreadsheet import expectations).
GRC_FIELDS = [
    "id",
    "name",
    "provider",
    "system_type",
    "deployment_type",
    "source_location",
    "risk_classification",
    "annex_iii_category",
    "classification_rationale",
    "origin_jurisdiction",
    "confidence",
    "risk_score",
    "risk_level",
    "discovery_timestamp",
]


def record_to_grc_row(record: AISystemRecord) -> dict[str, str]:
    """Return a flat dict with only GRC-relevant fields — no raw tag blobs, no key values."""
    rl = record.risk_classification
    return {
        "id": record.id,
        "name": record.name,
        "provider": record.provider,
        "system_type": record.system_type.value,
        "deployment_type": record.deployment_type.value,
        "source_location": record.source_location,
        "risk_classification": rl.value if rl else "",
        "annex_iii_category": record.tags.get("eu_ai_act_category", ""),
        "classification_rationale": record.classification_rationale or "",
        "origin_jurisdiction": record.tags.get("origin_jurisdiction", ""),
        "confidence": f"{record.confidence:.2f}",
        "risk_score": str(record.risk_score) if record.risk_score is not None else "",
        "risk_level": record.risk_level or "",
        "discovery_timestamp": record.discovery_timestamp.isoformat(),
    }


def to_csv(records: list[AISystemRecord]) -> str:
    """Render *records* as a CSV string suitable for Excel / GRC platform import."""
    buf = StringIO()
    writer = csv.DictWriter(buf, fieldnames=GRC_FIELDS, lineterminator="\n")
    writer.writeheader()
    for rec in records:
        writer.writerow(record_to_grc_row(rec))
    return buf.getvalue()


def to_flat_json(records: list[AISystemRecord], *, indent: int = 2) -> str:
    """Render *records* as a flat JSON array — no nested objects, GRC fields only."""
    rows = [record_to_grc_row(rec) for rec in records]
    return json.dumps(rows, indent=indent, ensure_ascii=False)


def records_from_scan_json(data: Union[dict, list]) -> list[AISystemRecord]:
    """Parse *data* (from aigov scan --output json) into a list of AISystemRecord objects.

    Accepts either the full scan envelope ``{"findings": [...]}`` or a plain JSON array.
    Malformed entries are silently skipped.
    """
    from aigov.core.models import AISystemRecord

    findings: list = data if isinstance(data, list) else data.get("findings", [])
    records: list[AISystemRecord] = []
    for item in findings:
        try:
            records.append(AISystemRecord.from_dict(item))
        except (KeyError, ValueError):
            continue
    return records
