"""Evaluate fail-on policies against a JSON scan result file.

Exit 0  — no findings match any configured failure rule (clean).
Exit 1  — one or more findings match; prints which ones and which rule fired.
Exit 2  — usage or I/O error (bad args, missing file, invalid JSON).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aigov-check",
        description="Check aigov scan results against fail-on policies.",
    )
    parser.add_argument(
        "input_file",
        help="JSON file produced by: aigov scan --output json --out-file <file>",
    )
    parser.add_argument(
        "--fail-on",
        default="prohibited",
        metavar="LEVELS",
        help=(
            "Comma-separated risk classification levels that trigger a failure. "
            "Valid values: prohibited, high_risk, limited_risk, minimal_risk, "
            "needs_review, unknown. Default: prohibited"
        ),
    )
    parser.add_argument(
        "--fail-on-risk-score",
        type=int,
        default=None,
        metavar="N",
        help="Fail if any finding has risk_score >= N (e.g. 80 = critical band).",
    )
    parser.add_argument(
        "--fail-on-exposure",
        default=None,
        metavar="EXPOSURE",
        help=(
            "Comma-separated exposure values that trigger a failure. "
            "Example: --fail-on-exposure public_api"
        ),
    )
    parser.add_argument(
        "--fail-on-data",
        default=None,
        metavar="CATEGORIES",
        help=(
            "Comma-separated data sensitivity categories that trigger a failure. "
            "Example: --fail-on-data pii,financial"
        ),
    )
    parser.add_argument(
        "--policy",
        default=None,
        metavar="PATH",
        help=(
            "Path to a .aigov-policy.yaml file. Each policy with action=fail "
            "that matches at least one finding causes a non-zero exit."
        ),
    )
    args = parser.parse_args(argv)

    fail_levels = {lvl.strip().lower() for lvl in args.fail_on.split(",") if lvl.strip()}
    if not fail_levels:
        print("Error: --fail-on must contain at least one risk level.", file=sys.stderr)
        return 2

    fail_exposures = _split(args.fail_on_exposure)
    fail_data = _split(args.fail_on_data)

    try:
        raw = json.loads(Path(args.input_file).read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"Error: file not found: {args.input_file}", file=sys.stderr)
        return 2
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Error reading {args.input_file}: {exc}", file=sys.stderr)
        return 2

    findings = raw.get("findings", [])

    triggered: list[tuple[dict, list[str]]] = []
    skipped_allowlisted: list[dict] = []

    for finding in findings:
        if _is_allowlisted(finding):
            if _matches_any_rule(finding, fail_levels, args.fail_on_risk_score, fail_exposures, fail_data):
                skipped_allowlisted.append(finding)
            continue

        reasons: list[str] = []
        if (finding.get("risk_classification") or "").lower() in fail_levels:
            reasons.append(f"risk_classification={finding.get('risk_classification')}")
        score = _risk_score(finding)
        if args.fail_on_risk_score is not None and score is not None and score >= args.fail_on_risk_score:
            reasons.append(f"risk_score={score} (>= {args.fail_on_risk_score})")
        exposure = _exposure(finding)
        if fail_exposures and exposure in fail_exposures:
            reasons.append(f"exposure={exposure}")
        sensitivities = _data_sensitivity(finding)
        if fail_data:
            hits = [s for s in sensitivities if s in fail_data]
            if hits:
                reasons.append(f"data_sensitivity={','.join(hits)}")
        if reasons:
            triggered.append((finding, reasons))

    # ── Allowlist suppressions: always surface for auditability ─────────────
    if skipped_allowlisted:
        print(f"Suppressed (allowlisted): {len(skipped_allowlisted)} finding(s)")
        for finding in skipped_allowlisted:
            name = finding.get("name") or finding.get("id") or "unknown"
            reason = (finding.get("tags") or {}).get("allowlist_reason") or "no reason recorded"
            print(f"  Suppressed (allowlisted): {name} — {reason}")

    # ── Policy file evaluation ──────────────────────────────────────────────
    policy_failures, policy_warnings = _evaluate_policy_file(
        args.policy, findings, suppress_allowlisted=True
    )

    if policy_warnings:
        print(f"\nPolicy warnings: {len(policy_warnings)} match(es)")
        for name, finding, desc in policy_warnings:
            target = finding.get("name") or finding.get("id") or "unknown"
            print(f"  WARN [{name}] {target} — {desc}")

    # ── Final outcome ───────────────────────────────────────────────────────
    if not triggered and not policy_failures:
        rules = _summary_rules(args.fail_on, args.fail_on_risk_score, fail_exposures, fail_data)
        print(f"\naigov check: PASSED — no findings matched: {rules}")
        return 0

    print(f"\naigov check: FAILED — {len(triggered) + len(policy_failures)} finding(s) blocked")
    for finding, reasons in triggered:
        name = finding.get("name") or finding.get("id") or "unknown"
        loc = finding.get("source_location", "")
        print(f"  [{', '.join(reasons)}] {name}  ({loc})")
    for name, finding, desc in policy_failures:
        target = finding.get("name") or finding.get("id") or "unknown"
        loc = finding.get("source_location", "")
        print(f"  POLICY [{name}] {target}  ({loc}) — {desc}")
    return 1


# ---------------------------------------------------------------------------
# Field extraction helpers (work on dicts loaded from the JSON output)
# ---------------------------------------------------------------------------

def _split(raw: str | None) -> set[str]:
    if not raw:
        return set()
    return {s.strip().lower() for s in raw.split(",") if s.strip()}


def _is_allowlisted(finding: dict) -> bool:
    tags = finding.get("tags") or {}
    flag = tags.get("allowlisted")
    if isinstance(flag, bool):
        return flag
    if isinstance(flag, str):
        return flag.strip().lower() == "true"
    return False


def _risk_score(finding: dict) -> int | None:
    if "risk_score" in finding:
        try:
            return int(finding["risk_score"])
        except (TypeError, ValueError):
            return None
    raw = (finding.get("tags") or {}).get("risk_score")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _risk_context(finding: dict) -> dict[str, Any]:
    raw = (finding.get("tags") or {}).get("risk_context")
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}


def _exposure(finding: dict) -> str | None:
    return _risk_context(finding).get("exposure")


def _data_sensitivity(finding: dict) -> list[str]:
    val = _risk_context(finding).get("data_sensitivity") or []
    return [str(v).lower() for v in val] if isinstance(val, list) else []


def _matches_any_rule(
    finding: dict,
    fail_levels: set[str],
    fail_score: int | None,
    fail_exposures: set[str],
    fail_data: set[str],
) -> bool:
    if (finding.get("risk_classification") or "").lower() in fail_levels:
        return True
    score = _risk_score(finding)
    if fail_score is not None and score is not None and score >= fail_score:
        return True
    exposure = _exposure(finding)
    if fail_exposures and exposure in fail_exposures:
        return True
    if fail_data and any(s in fail_data for s in _data_sensitivity(finding)):
        return True
    return False


def _summary_rules(
    levels: str,
    score: int | None,
    exposures: set[str],
    data: set[str],
) -> str:
    parts: list[str] = [f"levels={levels}"]
    if score is not None:
        parts.append(f"risk_score>={score}")
    if exposures:
        parts.append(f"exposure∈{{{','.join(sorted(exposures))}}}")
    if data:
        parts.append(f"data∈{{{','.join(sorted(data))}}}")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# Policy file evaluation against the dict-shaped findings in the JSON
# ---------------------------------------------------------------------------

def _evaluate_policy_file(
    policy_path: str | None,
    findings: list[dict],
    *,
    suppress_allowlisted: bool,
) -> tuple[list[tuple[str, dict, str]], list[tuple[str, dict, str]]]:
    """Evaluate a policy YAML against the dict findings.

    We don't reuse :func:`aigov.core.policy.evaluate_policies` here because
    that function expects ``AISystemRecord`` objects and the JSON dicts may be
    missing fields the dataclass would refuse (e.g. discovery_timestamp).
    Instead we re-implement the matcher against dicts using the same shared
    helpers from the policy module.
    """
    if not policy_path:
        return [], []

    try:
        from aigov.core.policy import (
            _match_field,
            load_policies,
        )
    except ImportError:
        return [], []

    policies = load_policies(Path(policy_path))
    if not policies:
        return [], []

    failures: list[tuple[str, dict, str]] = []
    warnings: list[tuple[str, dict, str]] = []

    for policy in policies:
        for finding in findings:
            if suppress_allowlisted and _is_allowlisted(finding):
                continue
            if not _finding_matches(policy, finding, _match_field):
                continue
            entry = (policy.name, finding, policy.description or "")
            if policy.action == "fail":
                failures.append(entry)
            else:
                warnings.append(entry)

    return failures, warnings


def _finding_matches(policy, finding: dict, match_field) -> bool:
    """AND-combine the policy's condition fields against a finding dict."""
    for field_name, expected in policy.condition.items():
        actual = _finding_field(finding, field_name)
        if not match_field(field_name, expected, actual):
            return False
    return True


def _finding_field(finding: dict, field_name: str) -> Any:
    if field_name == "system_type":
        return finding.get("system_type")
    if field_name == "risk_level":
        return (
            (finding.get("tags") or {}).get("risk_level")
            or finding.get("risk_level")
            or finding.get("risk_classification")
        )
    if field_name == "risk_score":
        return _risk_score(finding)
    if field_name == "jurisdiction":
        return (finding.get("tags") or {}).get("origin_jurisdiction")
    ctx = _risk_context(finding)
    if field_name in ctx:
        return ctx[field_name]
    return None


if __name__ == "__main__":
    sys.exit(main())
