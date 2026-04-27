"""Policy-as-config engine.

Reads ``.aigov-policy.yaml`` and evaluates each policy against a list of
``AISystemRecord`` instances. Each policy is a (name, description, condition,
action) tuple. Conditions are AND-combined; the *action* is ``fail`` or
``warn``. Allowlisted records are always skipped — same posture as the
classification allowlist and ``aigov-check``.

Supported condition fields:

==================  =========================================================
Field               Match semantics
==================  =========================================================
exposure            exact string match (single value or list)
environment         exact string match (single value or list)
interaction_type    exact string match (single value or list)
system_type         exact string match against ``record.system_type.value``
risk_level          exact string match against the risk engine's level tag,
                    falling back to ``record.risk_classification.value``
risk_score          comparison string (``">=80"``, ``"<30"`` …) or int
data_sensitivity    membership — record's list contains any of the values
jurisdiction        membership — single value or list (e.g. ``["CN", "RU"]``)
==================  =========================================================

The condition language is small on purpose: simple matchers compose
better than a query DSL when the rule set lives in YAML reviewed by
non-engineers.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml

from aigov.core.models import AISystemRecord

_DEFAULT_FILENAME = ".aigov-policy.yaml"
_log = logging.getLogger(__name__)

_VALID_ACTIONS = frozenset({"fail", "warn"})

# How risk_score comparison strings are parsed. Order matters — multi-char
# operators must be tried before single-char ones.
_OPERATORS = (">=", "<=", "==", "!=", ">", "<")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Policy:
    name: str
    description: str
    condition: dict[str, Any]
    action: str  # "fail" | "warn"


@dataclass
class PolicyMatch:
    policy: Policy
    record: AISystemRecord

    @property
    def name(self) -> str:
        return self.policy.name

    @property
    def description(self) -> str:
        return self.policy.description

    @property
    def action(self) -> str:
        return self.policy.action


@dataclass
class PolicyResult:
    failures: list[PolicyMatch] = field(default_factory=list)
    warnings: list[PolicyMatch] = field(default_factory=list)
    passed: list[Policy] = field(default_factory=list)

    @property
    def has_failures(self) -> bool:
        return bool(self.failures)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_policies(path: Optional[Path] = None) -> list[Policy]:
    """Load policies from *path* (defaults to ``.aigov-policy.yaml`` in cwd).

    Missing file → empty list. Malformed YAML or invalid policy entries are
    logged as warnings and skipped; valid policies still run.
    """
    if path is None:
        path = Path.cwd() / _DEFAULT_FILENAME
    if not path.exists():
        return []

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001 — bad YAML must not crash the CLI
        _log.warning("Policy file %s could not be loaded: %s", path, exc)
        return []

    policies: list[Policy] = []
    for item in data.get("policies") or []:
        try:
            policies.append(_parse_policy(item))
        except ValueError as exc:
            _log.warning("Skipping malformed policy entry: %s", exc)
    return policies


def _parse_policy(item: object) -> Policy:
    if not isinstance(item, dict):
        raise ValueError(f"Policy entry must be a mapping, got {type(item).__name__}")

    name = str(item.get("name") or "").strip()
    if not name:
        raise ValueError("Policy entry is missing required field 'name'")

    description = str(item.get("description") or "")

    condition = item.get("condition") or {}
    if not isinstance(condition, dict):
        raise ValueError(f"Policy '{name}': 'condition' must be a mapping")
    if not condition:
        raise ValueError(f"Policy '{name}': 'condition' must specify at least one matcher")

    action = str(item.get("action") or "").lower().strip()
    if action not in _VALID_ACTIONS:
        raise ValueError(
            f"Policy '{name}': action must be one of {sorted(_VALID_ACTIONS)}, "
            f"got {action!r}"
        )

    return Policy(name=name, description=description, condition=condition, action=action)


# ---------------------------------------------------------------------------
# Field extraction — pull each condition field's value from a record
# ---------------------------------------------------------------------------

def _record_context(record: AISystemRecord) -> dict[str, Any]:
    raw = record.tags.get("risk_context", "")
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}


def _record_field(record: AISystemRecord, field_name: str) -> Any:
    """Return the record's value for a condition field, or None when missing."""
    if field_name == "system_type":
        return record.system_type.value
    if field_name == "risk_level":
        # First-class field set by the risk engine; fall back to the EU AI Act
        # classification value when the engine hasn't run.
        if record.risk_level:
            return record.risk_level
        return record.risk_classification.value if record.risk_classification else None
    if field_name == "risk_score":
        return record.risk_score
    if field_name == "jurisdiction":
        return record.tags.get("origin_jurisdiction")
    # Context-derived fields (environment, exposure, data_sensitivity,
    # interaction_type) still live in the JSON-encoded ``risk_context`` tag.
    ctx = _record_context(record)
    if field_name in ctx:
        return ctx[field_name]
    return None


# ---------------------------------------------------------------------------
# Match engine
# ---------------------------------------------------------------------------

def _match_field(field_name: str, expected: Any, actual: Any) -> bool:
    """Return True when *actual* satisfies the *expected* matcher for *field_name*."""
    if actual is None:
        return False

    if field_name == "risk_score":
        return _match_risk_score(expected, actual)

    if field_name in {"data_sensitivity", "jurisdiction"}:
        return _match_membership(expected, actual)

    # All other fields: simple string match, with list-of-strings shorthand.
    if isinstance(expected, list):
        return any(str(actual) == str(e) for e in expected)
    return str(actual) == str(expected)


def _match_risk_score(expected: Any, actual: int) -> bool:
    """Compare an int *actual* against a comparison string or numeric *expected*."""
    if isinstance(expected, (int, float)):
        return actual == int(expected)
    spec = str(expected).strip()
    op = "=="
    rest = spec
    for candidate in _OPERATORS:
        if spec.startswith(candidate):
            op = candidate
            rest = spec[len(candidate):].strip()
            break
    try:
        threshold = int(rest)
    except (TypeError, ValueError):
        return False
    if op == ">=":
        return actual >= threshold
    if op == "<=":
        return actual <= threshold
    if op == ">":
        return actual > threshold
    if op == "<":
        return actual < threshold
    if op == "!=":
        return actual != threshold
    return actual == threshold


def _match_membership(expected: Any, actual: Any) -> bool:
    """Membership match: *actual* (single value or list) intersects *expected*.

    For ``data_sensitivity`` *actual* is the list of categories detected on the
    record (``["pii", "financial"]``). For ``jurisdiction`` *actual* is a single
    string (``"US"``). The match passes if any value of *actual* appears in the
    *expected* matcher.
    """
    expected_list = expected if isinstance(expected, list) else [expected]
    expected_set = {str(e) for e in expected_list}

    if isinstance(actual, list):
        return any(str(a) in expected_set for a in actual)
    return str(actual) in expected_set


def _is_allowlisted(record: AISystemRecord) -> bool:
    flag = record.tags.get("allowlisted")
    if isinstance(flag, str):
        return flag.strip().lower() == "true"
    return bool(flag)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def evaluate_policies(
    records: Iterable[AISystemRecord],
    policy_path: Optional[Path] = None,
) -> PolicyResult:
    """Evaluate every policy against every (non-allowlisted) record.

    A policy that matches at least one record produces a ``PolicyMatch`` per
    matching record on either ``failures`` (action=fail) or ``warnings``
    (action=warn). A policy that matches nothing lands in ``passed``.
    """
    policies = load_policies(policy_path)
    return evaluate_policies_against(records, policies)


def evaluate_policies_against(
    records: Iterable[AISystemRecord],
    policies: list[Policy],
) -> PolicyResult:
    """Same as ``evaluate_policies`` but takes pre-loaded ``Policy`` objects.

    Useful when policies come from somewhere other than a YAML file.
    """
    record_list = [r for r in records if not _is_allowlisted(r)]

    result = PolicyResult()
    for policy in policies:
        matched_any = False
        for record in record_list:
            if _record_matches(policy, record):
                matched_any = True
                match = PolicyMatch(policy=policy, record=record)
                if policy.action == "fail":
                    result.failures.append(match)
                else:
                    result.warnings.append(match)
        if not matched_any:
            result.passed.append(policy)
    return result


def _record_matches(policy: Policy, record: AISystemRecord) -> bool:
    """Every condition field must match (AND logic)."""
    for field_name, expected in policy.condition.items():
        actual = _record_field(record, field_name)
        if not _match_field(field_name, expected, actual):
            return False
    return True
