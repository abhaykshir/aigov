"""Evaluate fail-on policies against a JSON scan result file.

Exit 0  — no findings match any configured failure rule (clean).
Exit 1  — one or more findings match; prints which ones and which rule fired.
Exit 2  — usage or I/O error (bad args, missing file, invalid JSON).

The CLI flags (``--fail-on``, ``--fail-on-risk-score``, ``--fail-on-exposure``,
``--fail-on-data``) and the optional ``--policy`` YAML file are *all* converted
into :class:`aigov.core.policy.Policy` objects and evaluated through the same
``evaluate_policies_against`` engine. There is no second filtering code path —
adding a new flag means appending a new ``Policy`` to the list, not writing
new comparison logic.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from aigov.core.models import AISystemRecord
from aigov.core.policy import (
    Policy,
    PolicyMatch,
    PolicyResult,
    evaluate_policies_against,
    load_policies,
)


# Synthetic policy names — used so reviewers can tell at a glance which CLI
# flag (or YAML rule) triggered a given block.
_FLAG_POLICY_PREFIX = "cli:"


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
            "that matches at least one finding causes a non-zero exit; "
            "action=warn prints a notice."
        ),
    )
    args = parser.parse_args(argv)

    fail_levels = _split(args.fail_on)
    if not fail_levels:
        print("Error: --fail-on must contain at least one risk level.", file=sys.stderr)
        return 2

    try:
        raw = json.loads(Path(args.input_file).read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"Error: file not found: {args.input_file}", file=sys.stderr)
        return 2
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Error reading {args.input_file}: {exc}", file=sys.stderr)
        return 2

    findings = raw.get("findings", [])
    records, allowlisted_records = _findings_to_records(findings)

    policies = _build_flag_policies(
        fail_levels,
        args.fail_on_risk_score,
        _split(args.fail_on_exposure),
        _split(args.fail_on_data),
    )
    if args.policy:
        policies.extend(load_policies(Path(args.policy)))

    result = evaluate_policies_against(records, policies)

    # Allowlisted records that *would* have matched something — surface them
    # so the bypass is auditable.
    suppressed = _suppressed_allowlisted(allowlisted_records, policies)
    if suppressed:
        print(f"Suppressed (allowlisted): {len(suppressed)} finding(s)")
        for record, reason in suppressed:
            print(f"  Suppressed (allowlisted): {record.name} — {reason}")

    if result.warnings:
        print(f"\nPolicy warnings: {len(result.warnings)} match(es)")
        for match in result.warnings:
            _print_match_line("WARN", match)

    if not result.failures:
        rules = _summary_rules(args.fail_on, args.fail_on_risk_score,
                               _split(args.fail_on_exposure), _split(args.fail_on_data))
        print(f"\naigov check: PASSED — no findings matched: {rules}")
        return 0

    print(f"\naigov check: FAILED — {len(result.failures)} finding(s) blocked")
    for match in result.failures:
        _print_match_line("FAIL", match)
    return 1


# ---------------------------------------------------------------------------
# CLI flags → Policy objects
# ---------------------------------------------------------------------------

def _build_flag_policies(
    fail_levels: set[str],
    fail_score: int | None,
    fail_exposures: set[str],
    fail_data: set[str],
) -> list[Policy]:
    """Translate the CLI flags into Policy objects so they share one engine."""
    policies: list[Policy] = []

    for level in sorted(fail_levels):
        policies.append(Policy(
            name=f"{_FLAG_POLICY_PREFIX}fail-on={level}",
            description=f"--fail-on {level}",
            condition={"risk_level": level},
            action="fail",
        ))

    if fail_score is not None:
        policies.append(Policy(
            name=f"{_FLAG_POLICY_PREFIX}fail-on-risk-score>={fail_score}",
            description=f"--fail-on-risk-score {fail_score}",
            condition={"risk_score": f">={fail_score}"},
            action="fail",
        ))

    if fail_exposures:
        policies.append(Policy(
            name=f"{_FLAG_POLICY_PREFIX}fail-on-exposure={','.join(sorted(fail_exposures))}",
            description=f"--fail-on-exposure {','.join(sorted(fail_exposures))}",
            condition={"exposure": sorted(fail_exposures)},
            action="fail",
        ))

    if fail_data:
        policies.append(Policy(
            name=f"{_FLAG_POLICY_PREFIX}fail-on-data={','.join(sorted(fail_data))}",
            description=f"--fail-on-data {','.join(sorted(fail_data))}",
            condition={"data_sensitivity": sorted(fail_data)},
            action="fail",
        ))

    return policies


# ---------------------------------------------------------------------------
# JSON findings → AISystemRecord (so the policy engine can evaluate them)
# ---------------------------------------------------------------------------

def _findings_to_records(findings: list[dict]) -> tuple[list[AISystemRecord], list[AISystemRecord]]:
    """Reconstruct AISystemRecord objects from JSON dicts.

    Returns ``(non_allowlisted, allowlisted)``. The policy engine itself skips
    allowlisted records, but we keep them around so we can report on them.

    Records that are too malformed to round-trip (missing required fields,
    invalid timestamps, …) are silently dropped. The risk fields, when
    present at the top level of the dict, are picked up by
    ``AISystemRecord.from_dict``.
    """
    non_allowlisted: list[AISystemRecord] = []
    allowlisted: list[AISystemRecord] = []
    for finding in findings:
        finding = _normalize_finding(finding)
        try:
            record = AISystemRecord.from_dict(finding)
        except (KeyError, ValueError, TypeError):
            continue
        if (record.tags or {}).get("allowlisted", "").strip().lower() == "true":
            allowlisted.append(record)
        else:
            non_allowlisted.append(record)
    return non_allowlisted, allowlisted


def _normalize_finding(finding: dict) -> dict:
    """Tolerate legacy / human-edited scan outputs where enum values are
    capitalised. ``RiskLevel("PROHIBITED")`` would otherwise raise."""
    rc = finding.get("risk_classification")
    if isinstance(rc, str):
        normalized = rc.lower()
        if normalized != rc:
            return {**finding, "risk_classification": normalized}
    return finding


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------

def _print_match_line(prefix: str, match: PolicyMatch) -> None:
    desc = match.policy.description or match.policy.name
    print(f"  {prefix} [{match.policy.name}] {match.record.name} ({match.record.source_location}) — {desc}")


def _suppressed_allowlisted(
    allowlisted: list[AISystemRecord],
    policies: list[Policy],
) -> list[tuple[AISystemRecord, str]]:
    """Return (record, reason) for allowlisted records that *would* have matched."""
    if not (allowlisted and policies):
        return []
    # Run the same engine against the allowlisted records, but with the
    # allowlist tag stripped so the matcher considers them.
    stripped: list[AISystemRecord] = []
    for record in allowlisted:
        new_tags = {k: v for k, v in record.tags.items() if k != "allowlisted"}
        stripped.append(_replace_tags(record, new_tags))

    result = evaluate_policies_against(stripped, policies)
    matched_ids = {m.record.id for m in result.failures + result.warnings}

    suppressed: list[tuple[AISystemRecord, str]] = []
    for record in allowlisted:
        if record.id not in matched_ids:
            continue
        reason = (record.tags or {}).get("allowlist_reason") or "no reason recorded"
        suppressed.append((record, reason))
    return suppressed


def _replace_tags(record: AISystemRecord, new_tags: dict[str, str]) -> AISystemRecord:
    import dataclasses
    return dataclasses.replace(record, tags=new_tags)


def _split(raw: str | None) -> set[str]:
    if not raw:
        return set()
    return {s.strip().lower() for s in raw.split(",") if s.strip()}


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


if __name__ == "__main__":
    sys.exit(main())
