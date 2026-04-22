from __future__ import annotations

import dataclasses
import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from aigov.core.models import AISystemRecord

_DEFAULT_FILENAME = ".aigov-allowlist.yaml"


@dataclass
class AllowlistEntry:
    id: Optional[str]
    name_pattern: Optional[str]
    reason: str


class Allowlist:
    """Approved AI systems that should not trigger warnings or commit blocks."""

    def __init__(self, entries: list[AllowlistEntry]) -> None:
        self._entries = entries

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Allowlist":
        """Load allowlist from *path* (defaults to .aigov-allowlist.yaml in cwd).

        Returns an empty Allowlist if the file does not exist — callers do not
        need to handle the missing-file case.
        """
        if path is None:
            path = Path.cwd() / _DEFAULT_FILENAME
        if not path.exists():
            return cls([])
        try:
            raw = path.read_text(encoding="utf-8")
            data = yaml.safe_load(raw) or {}
        except Exception:  # noqa: BLE001  malformed YAML or I/O error → empty list
            return cls([])

        entries: list[AllowlistEntry] = []
        for item in data.get("approved") or []:
            if not isinstance(item, dict):
                continue
            entries.append(AllowlistEntry(
                id=str(item["id"]) if "id" in item else None,
                name_pattern=str(item["name_pattern"]) if "name_pattern" in item else None,
                reason=str(item.get("reason", "")),
            ))
        return cls(entries)

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def is_approved(self, record: AISystemRecord) -> tuple[bool, str]:
        """Return (True, reason) if the record matches any allowlist entry."""
        for entry in self._entries:
            if entry.id and record.id == entry.id:
                return True, entry.reason
            if entry.name_pattern and fnmatch.fnmatch(record.name, entry.name_pattern):
                return True, entry.reason
        return False, ""

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------

    def apply(self, records: list[AISystemRecord]) -> list[AISystemRecord]:
        """Return records with allowlist tags applied.

        Approved records gain tags ``allowlisted=true`` and ``allowlist_reason``.
        Unapproved records are returned unchanged (new list, original unmodified).
        """
        result: list[AISystemRecord] = []
        for rec in records:
            approved, reason = self.is_approved(rec)
            if approved:
                new_tags = {**rec.tags, "allowlisted": "true", "allowlist_reason": reason}
                result.append(dataclasses.replace(rec, tags=new_tags))
            else:
                result.append(rec)
        return result
