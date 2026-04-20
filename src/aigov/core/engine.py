from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from aigov.core.models import AISystemRecord
from aigov.scanners.base import BaseScanner

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Registry — populated at module load so imports stay lazy
# ---------------------------------------------------------------------------

def _build_registry() -> dict[str, type[BaseScanner]]:
    from aigov.scanners.code.python_imports import PythonImportsScanner
    from aigov.scanners.code.api_keys import ApiKeysScanner
    from aigov.scanners.config.mcp_servers import McpServersScanner

    scanners: list[type[BaseScanner]] = [
        PythonImportsScanner,
        ApiKeysScanner,
        McpServersScanner,
    ]
    return {cls().name: cls for cls in scanners}


_REGISTRY: dict[str, type[BaseScanner]] | None = None


def _registry() -> dict[str, type[BaseScanner]]:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = _build_registry()
    return _REGISTRY


# ---------------------------------------------------------------------------
# Deterministic record ID
# ---------------------------------------------------------------------------

def _stable_id(record: AISystemRecord) -> str:
    """Hash of (scanner, location, provider, system_type) — stable across rescans."""
    raw = "|".join([
        record.source_scanner,
        record.source_location,
        record.provider,
        record.system_type.value,
    ])
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    records: list[AISystemRecord] = field(default_factory=list)
    scanners_run: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    scanned_paths: list[str] = field(default_factory=list)

    # Derived summaries (populated by engine after scan)
    total_found: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    by_provider: dict[str, int] = field(default_factory=dict)
    by_jurisdiction: dict[str, int] = field(default_factory=dict)

    def _compute_summaries(self) -> None:
        self.total_found = len(self.records)
        self.by_type = {}
        self.by_provider = {}
        self.by_jurisdiction = {}
        for rec in self.records:
            t = rec.system_type.value
            self.by_type[t] = self.by_type.get(t, 0) + 1
            self.by_provider[rec.provider] = self.by_provider.get(rec.provider, 0) + 1
            jur = rec.tags.get("origin_jurisdiction", "XX")
            self.by_jurisdiction[jur] = self.by_jurisdiction.get(jur, 0) + 1


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class ScanEngine:
    def __init__(
        self,
        paths: list[str],
        enabled_scanners: list[str] | None = None,
    ) -> None:
        self._paths = paths
        reg = _registry()
        if enabled_scanners is None:
            self._scanners: list[BaseScanner] = [cls() for cls in reg.values()]
        else:
            unknown = [n for n in enabled_scanners if n not in reg]
            if unknown:
                raise ValueError(f"Unknown scanner(s): {', '.join(unknown)}. Available: {', '.join(reg)}")
            self._scanners = [reg[n]() for n in enabled_scanners]

    @property
    def available_scanner_names(self) -> list[str]:
        return list(_registry().keys())

    def run(
        self,
        progress_callback: "ProgressCallback | None" = None,
    ) -> ScanResult:
        result = ScanResult(scanned_paths=list(self._paths))
        start = time.monotonic()

        all_records: list[AISystemRecord] = []

        for scanner in self._scanners:
            if progress_callback:
                progress_callback(scanner.name, "start")
            try:
                found = scanner.scan(self._paths)
                all_records.extend(found)
                result.scanners_run.append(scanner.name)
            except Exception as exc:  # noqa: BLE001
                msg = f"Scanner {scanner.name!r} failed: {exc}"
                result.warnings.append(msg)
            if progress_callback:
                progress_callback(scanner.name, "done")

        # Rewrite IDs to stable hashes, then deduplicate on the stable ID.
        seen_ids: set[str] = set()
        deduped: list[AISystemRecord] = []
        for rec in all_records:
            stable = _stable_id(rec)
            if stable in seen_ids:
                continue
            seen_ids.add(stable)
            # Replace the record's id in-place via dataclass replacement.
            import dataclasses
            deduped.append(dataclasses.replace(rec, id=stable))

        # Sort: confidence descending, then source_location ascending.
        deduped.sort(key=lambda r: (-r.confidence, r.source_location))

        result.records = deduped
        result.duration_seconds = time.monotonic() - start
        result._compute_summaries()
        return result


# ---------------------------------------------------------------------------
# Progress callback type alias (for type checkers)
# ---------------------------------------------------------------------------

from typing import Callable
ProgressCallback = Callable[[str, str], None]
