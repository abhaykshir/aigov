from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from aigov.core.engine import ScanResult
from aigov.core.models import AISystemRecord

_DEFAULT_BASELINE_PATH = ".aigov-baseline.json"
_AIGOV_VERSION = "0.2.1"


# ---------------------------------------------------------------------------
# DriftReport
# ---------------------------------------------------------------------------

@dataclass
class DriftReport:
    new_systems: list[AISystemRecord]
    removed_systems: list[AISystemRecord]
    changed_classification: list[tuple[AISystemRecord, AISystemRecord]]  # (old, new)
    unchanged_count: int
    baseline_date: Optional[datetime]  # None when no baseline file exists

    # Computed in __post_init__ — True if anything changed
    has_drift: bool = field(init=False)

    def __post_init__(self) -> None:
        self.has_drift = bool(
            self.new_systems or self.removed_systems or self.changed_classification
        )

    def to_dict(self) -> dict:
        return {
            "baseline_date": self.baseline_date.isoformat() if self.baseline_date else None,
            "has_drift": self.has_drift,
            "new_systems": [r.to_dict() for r in self.new_systems],
            "removed_systems": [r.to_dict() for r in self.removed_systems],
            "changed_classification": [
                {"old": old.to_dict(), "new": new.to_dict()}
                for old, new in self.changed_classification
            ],
            "unchanged_count": self.unchanged_count,
        }


# ---------------------------------------------------------------------------
# Save
# ---------------------------------------------------------------------------

def save_baseline(
    scan_result: ScanResult,
    path: Path | str = _DEFAULT_BASELINE_PATH,
) -> Path:
    """Persist *scan_result* as the current baseline snapshot.

    The file stores only system metadata (names, providers, locations) —
    never API key values or credential data per SECURITY.md.
    Returns the resolved path that was written.
    """
    dest = Path(path)
    payload = {
        "aigov_version": _AIGOV_VERSION,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_found": scan_result.total_found,
            "scanners_run": scan_result.scanners_run,
            "scanned_paths": scan_result.scanned_paths,
        },
        "findings": [r.to_dict() for r in scan_result.records],
    }
    dest.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return dest


# ---------------------------------------------------------------------------
# Compare
# ---------------------------------------------------------------------------

def compare_to_baseline(
    current_result: ScanResult,
    baseline_path: Path | str = _DEFAULT_BASELINE_PATH,
) -> DriftReport:
    """Compare *current_result* against the saved baseline.

    If the baseline file does not exist all current systems are treated as new,
    giving a useful first-run experience without raising an error.
    """
    bp = Path(baseline_path)

    if not bp.exists():
        return DriftReport(
            new_systems=list(current_result.records),
            removed_systems=[],
            changed_classification=[],
            unchanged_count=0,
            baseline_date=None,
        )

    try:
        raw = json.loads(bp.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return DriftReport(
            new_systems=list(current_result.records),
            removed_systems=[],
            changed_classification=[],
            unchanged_count=0,
            baseline_date=None,
        )

    saved_at_raw = raw.get("saved_at")
    baseline_date: Optional[datetime] = None
    if saved_at_raw:
        try:
            baseline_date = datetime.fromisoformat(saved_at_raw)
        except ValueError:
            pass

    baseline_by_id: dict[str, AISystemRecord] = {}
    for item in raw.get("findings", []):
        try:
            rec = AISystemRecord.from_dict(item)
            baseline_by_id[rec.id] = rec
        except (KeyError, ValueError):
            continue

    current_by_id: dict[str, AISystemRecord] = {r.id: r for r in current_result.records}

    new_systems = [r for rid, r in current_by_id.items() if rid not in baseline_by_id]
    removed_systems = [r for rid, r in baseline_by_id.items() if rid not in current_by_id]
    changed_classification = [
        (baseline_by_id[rid], current_by_id[rid])
        for rid in current_by_id
        if rid in baseline_by_id
        and baseline_by_id[rid].risk_classification != current_by_id[rid].risk_classification
    ]
    unchanged_count = sum(
        1
        for rid in current_by_id
        if rid in baseline_by_id
        and baseline_by_id[rid].risk_classification == current_by_id[rid].risk_classification
    )

    return DriftReport(
        new_systems=new_systems,
        removed_systems=removed_systems,
        changed_classification=changed_classification,
        unchanged_count=unchanged_count,
        baseline_date=baseline_date,
    )
