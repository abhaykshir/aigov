from __future__ import annotations

import dataclasses
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from aigov.core.models import AISystemRecord, RiskLevel

_DEFAULT_FILENAME = ".aigov-rules.yaml"
_log = logging.getLogger(__name__)

# Risk levels ordered lowest → highest severity for escalation comparisons.
_RISK_ORDER: list[RiskLevel] = [
    RiskLevel.UNKNOWN,
    RiskLevel.NEEDS_REVIEW,
    RiskLevel.MINIMAL_RISK,
    RiskLevel.LIMITED_RISK,
    RiskLevel.HIGH_RISK,
    RiskLevel.PROHIBITED,
]
_RISK_RANK: dict[RiskLevel, int] = {lvl: i for i, lvl in enumerate(_RISK_ORDER)}


# ---------------------------------------------------------------------------
# Rule data model
# ---------------------------------------------------------------------------

@dataclass
class RuleMatch:
    keywords: list[str] = field(default_factory=list)
    jurisdiction: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)

    def matches(self, record: AISystemRecord) -> bool:
        """Return True iff every non-empty criterion matches the record (AND logic).

        Within each criterion, matching any single item is sufficient (OR).
        Returns False when no criteria are specified.
        """
        if self.keywords:
            haystack = " ".join([
                record.name,
                record.description,
                record.source_location,
            ]).lower()
            if not any(kw.lower() in haystack for kw in self.keywords):
                return False

        if self.jurisdiction:
            rec_jur = record.tags.get("origin_jurisdiction", "")
            if rec_jur not in self.jurisdiction:
                return False

        if self.providers:
            rec_prov = record.provider.lower()
            if not any(p.lower() == rec_prov for p in self.providers):
                return False

        return bool(self.keywords or self.jurisdiction or self.providers)


@dataclass
class RuleAction:
    risk_level: RiskLevel
    reason: str


@dataclass
class CustomRule:
    name: str
    description: str
    match: RuleMatch
    action: RuleAction

    def matches(self, record: AISystemRecord) -> bool:
        return self.match.matches(record)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class CustomRules:
    """User-defined governance rules layered on top of regulatory classification.

    Rules are never applied before EU AI Act classification and allowlist
    processing — this engine is always the last step so regulatory baselines
    are preserved.  Custom rules may only *escalate* risk, never downgrade.
    """

    def __init__(self, rules: list[CustomRule]) -> None:
        self._rules = rules

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "CustomRules":
        """Load rules from *path* (defaults to .aigov-rules.yaml in cwd).

        A missing file is silently ignored.  Malformed YAML or invalid rule
        entries are logged as warnings and skipped; valid rules still run.
        """
        if path is None:
            path = Path.cwd() / _DEFAULT_FILENAME
        if not path.exists():
            return cls([])

        try:
            raw = path.read_text(encoding="utf-8")
            data = yaml.safe_load(raw) or {}
        except Exception as exc:
            _log.warning("Custom rules file %s could not be loaded: %s", path, exc)
            return cls([])

        rules: list[CustomRule] = []
        for item in data.get("custom_rules") or []:
            try:
                rules.append(_parse_rule(item))
            except Exception as exc:
                _log.warning("Skipping malformed custom rule entry: %s", exc)
        return cls(rules)

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------

    def apply(self, records: list[AISystemRecord]) -> list[AISystemRecord]:
        """Return records with all matching rules applied.  Originals are never mutated."""
        if not self._rules:
            return records
        return [self._apply_to_record(rec) for rec in records]

    def _apply_to_record(self, rec: AISystemRecord) -> AISystemRecord:
        matching = [r for r in self._rules if r.matches(rec)]
        if not matching:
            return rec

        # Determine the highest risk level offered by matching rules.
        best_rule = max(matching, key=lambda r: _RISK_RANK.get(r.action.risk_level, 0))
        best_rank = _RISK_RANK.get(best_rule.action.risk_level, 0)
        current_rank = _RISK_RANK.get(rec.risk_classification or RiskLevel.UNKNOWN, 0)

        # Custom rules may only escalate — never downgrade.
        new_risk = _RISK_ORDER[best_rank] if best_rank > current_rank else rec.risk_classification

        # Append all matched rule reasons to the existing classification rationale.
        reasons = "; ".join(r.action.reason for r in matching)
        existing = rec.classification_rationale or ""
        new_rationale = f"{existing}; {reasons}" if existing else reasons

        # Tags record the primary (highest-risk) matching rule.
        new_tags = {
            **rec.tags,
            "custom_rule_name": best_rule.name,
            "custom_rule_reason": best_rule.action.reason,
        }

        return dataclasses.replace(
            rec,
            risk_classification=new_risk,
            classification_rationale=new_rationale,
            tags=new_tags,
        )


# ---------------------------------------------------------------------------
# YAML parser
# ---------------------------------------------------------------------------

def _parse_rule(item: object) -> CustomRule:
    """Parse a raw YAML mapping into a CustomRule.  Raises ValueError on bad input."""
    if not isinstance(item, dict):
        raise ValueError(f"Rule entry must be a mapping, got {type(item).__name__}")

    name = str(item.get("name") or "").strip()
    if not name:
        raise ValueError("Rule entry is missing required field 'name'")

    description = str(item.get("description") or "")

    match_data = item.get("match") or {}
    if not isinstance(match_data, dict):
        raise ValueError(f"Rule '{name}': 'match' must be a mapping")

    keywords = [str(k) for k in (match_data.get("keywords") or []) if str(k).strip()]
    jurisdiction = [str(j) for j in (match_data.get("jurisdiction") or []) if str(j).strip()]
    providers = [str(p) for p in (match_data.get("providers") or []) if str(p).strip()]

    if not (keywords or jurisdiction or providers):
        raise ValueError(
            f"Rule '{name}': 'match' must specify at least one criterion "
            "(keywords, jurisdiction, or providers)"
        )

    action_data = item.get("action") or {}
    if not isinstance(action_data, dict):
        raise ValueError(f"Rule '{name}': 'action' must be a mapping")

    risk_raw = str(action_data.get("risk_level") or "").lower().strip()
    if not risk_raw:
        raise ValueError(f"Rule '{name}': 'action.risk_level' is required")

    try:
        risk_level = RiskLevel(risk_raw)
    except ValueError:
        valid = [r.value for r in RiskLevel]
        raise ValueError(
            f"Rule '{name}': unknown risk_level '{risk_raw}'. Valid values: {valid}"
        )

    reason = str(action_data.get("reason") or "")

    return CustomRule(
        name=name,
        description=description,
        match=RuleMatch(keywords=keywords, jurisdiction=jurisdiction, providers=providers),
        action=RuleAction(risk_level=risk_level, reason=reason),
    )
